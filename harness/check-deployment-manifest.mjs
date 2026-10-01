// Disposable schema/binding checks are not root-owned deployment qualification.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmodSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, realpathSync, symlinkSync, linkSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {parsePreviewDeploymentManifest, inspectPreviewReleaseBinding, readPreviewDeploymentManifest} from './deployment-manifest.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const refusal = reason => error => error.code === 'PRIME_DEPLOYMENT_MANIFEST' && (!reason || error.reason === reason);
const temporary = realpathSync(mkdtempSync(join(tmpdir(),'prime-deployment-manifest-check-')));
const releaseRoot = join(temporary,'release'), anchorRoot = join(temporary,'anchor');
const snapshot = Buffer.from('{"version":1,"kind":"disposable-ui-fixture"}\n');
const manifest = {version:1,kind:'prime-preview-deployment/v1',source_commit:'a'.repeat(40),release_dir:releaseRoot,
 release_digest:'b'.repeat(64),ui_integrity_sha256:sha(snapshot),qualification:'PENDING'};
const bytes = value => Buffer.from(JSON.stringify(value));
let assertions = 0;
function rejects(callback, reason) {assert.throws(callback,refusal(reason)); assertions++;}
function parseReject(value,reason) {rejects(() => parsePreviewDeploymentManifest(bytes(value)),reason);}
try {
 mkdirSync(releaseRoot); mkdirSync(anchorRoot);
 writeFileSync(join(releaseRoot,'prime-release.json'),bytes({version:'0.1.0',source_commit:manifest.source_commit}));
 writeFileSync(join(releaseRoot,'prime-ui-integrity.json'),snapshot);
 assert.deepEqual(parsePreviewDeploymentManifest(bytes(manifest)),manifest); assertions++;
 assert.equal(inspectPreviewReleaseBinding({manifest,releaseRoot}).ui_integrity_sha256,sha(snapshot)); assertions++;
 for (const key of Object.keys(manifest)) {const changed = {...manifest}; delete changed[key]; parseReject(changed,'closed-manifest-required');}
 parseReject({...manifest,owner_approved:true},'closed-manifest-required');
 parseReject({...manifest,qualification:'PASS'},'preview-profile-required');
 parseReject({...manifest,version:2},'preview-profile-required');
 parseReject({...manifest,source_commit:'A'.repeat(40)},'manifest-digest-format');
 parseReject({...manifest,release_digest:'sha256:' + manifest.release_digest},'manifest-digest-format');
 parseReject({...manifest,ui_integrity_sha256:null},'manifest-digest-format');
 parseReject({...manifest,release_dir:'relative/release'},'absolute-canonical-path-required');
 parseReject({...manifest,release_dir:releaseRoot+'/../release'},'absolute-canonical-path-required');
 parseReject({...manifest,release_dir:releaseRoot+'\u0000'},'absolute-canonical-path-required');
 const original = bytes(manifest);
 for (const malformed of [Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),original]),Buffer.from([0x7b,0x22,0xc0,0xaf,0x22,0x3a,0x31,0x7d]),
  Buffer.from(original.toString().replace('"version":1','"version":1,"version":1')),Buffer.from('{"version":'),Buffer.alloc(16385,0x20)]) {
  rejects(() => parsePreviewDeploymentManifest(malformed),'strict-json-required');
 }
 rejects(() => inspectPreviewReleaseBinding({manifest:{...manifest,source_commit:'c'.repeat(40)},releaseRoot}),'source-commit-mismatch');
 rejects(() => inspectPreviewReleaseBinding({manifest:{...manifest,ui_integrity_sha256:'c'.repeat(64)},releaseRoot}),'ui-integrity-mismatch');
 rejects(() => inspectPreviewReleaseBinding({manifest:{...manifest,release_dir:anchorRoot},releaseRoot}),'release-path-mismatch');
 const metadataPath = join(releaseRoot,'prime-release.json'), metadata = readFileSync(metadataPath);
 writeFileSync(metadataPath,'{"source_commit":"'+manifest.source_commit+'","source_commit":"'+manifest.source_commit+'"}');
 rejects(() => inspectPreviewReleaseBinding({manifest,releaseRoot}),'strict-json-required'); writeFileSync(metadataPath,metadata);
 writeFileSync(join(releaseRoot,'prime-ui-integrity.json'),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),snapshot]));
 rejects(() => inspectPreviewReleaseBinding({manifest,releaseRoot}),'strict-json-required'); writeFileSync(join(releaseRoot,'prime-ui-integrity.json'),snapshot);
 const alias = join(temporary,'release-alias'); symlinkSync(releaseRoot,alias);
 rejects(() => inspectPreviewReleaseBinding({manifest:{...manifest,release_dir:alias},releaseRoot:alias}),'release-path-mismatch');
 rmSync(metadataPath); symlinkSync(join(anchorRoot,'metadata.json'),metadataPath); writeFileSync(join(anchorRoot,'metadata.json'),metadata);
 rejects(() => inspectPreviewReleaseBinding({manifest,releaseRoot}),'regular-single-link-file-required'); rmSync(metadataPath); writeFileSync(metadataPath,metadata);
 linkSync(metadataPath,join(anchorRoot,'metadata-hardlink.json'));
 rejects(() => inspectPreviewReleaseBinding({manifest,releaseRoot}),'regular-single-link-file-required'); rmSync(join(anchorRoot,'metadata-hardlink.json'));
 const manifestPath = join(anchorRoot,'preview-deployment.json'); writeFileSync(manifestPath,original,{mode:0o644});
 // /tmp is shared, and this directory/file belong to the test UID. No mode or
 // test callback can turn them into a production protected retained anchor.
 rejects(() => readPreviewDeploymentManifest({manifestPath,releaseRoot}),'protected-root-ancestor-required');
 chmodSync(manifestPath,0o444);
 rejects(() => readPreviewDeploymentManifest({manifestPath,releaseRoot}),'protected-root-ancestor-required');
 rejects(() => readPreviewDeploymentManifest({manifestPath:join(anchorRoot,'other.json'),releaseRoot}),'manifest-filename-required');
 const inRelease = join(releaseRoot,'preview-deployment.json'); writeFileSync(inRelease,original);
 rejects(() => readPreviewDeploymentManifest({manifestPath:inRelease,releaseRoot}),'manifest-outside-release-required');
 rejects(() => readPreviewDeploymentManifest({manifestPath,releaseRoot,expectedManifestSha256:'wrong'}),'expected-manifest-digest-format');
 let protectedAnchor = 'UNPERFORMED: provide an independently retained root-owned protected Linux manifest';
 if (process.argv.length > 2) {
  if (process.argv.length !== 4) throw new Error('usage: check-deployment-manifest.mjs [PROTECTED_MANIFEST RELEASE_ROOT]');
  const result = readPreviewDeploymentManifest({manifestPath:process.argv[2],releaseRoot:process.argv[3]});
  assert.equal(result.manifest.qualification,'PENDING'); assertions++;
  const rebound = readPreviewDeploymentManifest({manifestPath:process.argv[2],releaseRoot:process.argv[3],expectedManifestSha256:result.manifest_sha256});
  assert.equal(rebound.manifest_sha256,result.manifest_sha256); assertions++;
  rejects(() => readPreviewDeploymentManifest({manifestPath:process.argv[2],releaseRoot:process.argv[3],expectedManifestSha256:'0'.repeat(64)}),'manifest-anchor-changed');
  protectedAnchor = 'PROTECTED_ANCHOR_READ: preview remains PENDING';
 }
 console.log(JSON.stringify({result:'PASS',assertions,scope:'disposable manifest schema and release binding; actual production reader refuses unprotected fixture',protected_anchor:protectedAnchor,qualification:'PENDING',full_release_digest:'NOT_CHECKED_HERE: boot must compare independent manifest pin to fullTreeDigest'}));
} finally {rmSync(temporary,{recursive:true,force:true});}
