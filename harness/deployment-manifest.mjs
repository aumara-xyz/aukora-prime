// A protected host-retained anchor for an unqualified preview, not owner approval.
import {constants, existsSync, lstatSync, openSync, closeSync, fstatSync, readSync, realpathSync} from 'node:fs';
import {basename, dirname, isAbsolute, join, parse, relative, resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {parseIngressBytes} from './ingress.mjs';
// Both paths are owned Prime layouts: source workspace or composed release.
const composed = existsSync(fileURLToPath(new URL('../prime-release.json',import.meta.url)));
const {parseStrictJson} = await import(composed?'../prime-packages/contracts/src/shared.mjs':'../packages/contracts/src/shared.mjs');

export const PREVIEW_DEPLOYMENT_MANIFEST_NAME = 'preview-deployment.json';
const KEYS = ['version','kind','source_commit','release_dir','release_digest','ui_integrity_sha256','qualification'];
const HEX = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function fail(reason) {
 throw Object.assign(new Error('PRIME_DEPLOYMENT_MANIFEST: ' + reason), {code:'PRIME_DEPLOYMENT_MANIFEST', reason});
}
function exactPath(value) {
 if (typeof value !== 'string' || value.length > 4096 || !isAbsolute(value)
  || /[\x00-\x1f\x7f]/u.test(value) || resolve(value) !== value) fail('absolute-canonical-path-required');
 return value;
}
function inside(root, path) {
 const rel = relative(root, path);
 return rel === '' || rel !== '..' && !rel.startsWith('../') && !isAbsolute(rel);
}
function identity(stat) {
 return {dev:stat.dev, ino:stat.ino, uid:stat.uid, gid:stat.gid, mode:stat.mode & 0o7777,
  nlink:stat.nlink, bytes:stat.size, mtime_ms:stat.mtimeMs, ctime_ms:stat.ctimeMs};
}
function sameIdentity(a, b) {
 return Object.keys(a).every(key => a[key] === b[key]);
}
function fileStat(path, {protectedAnchor = false} = {}) {
 let stat;
 try {stat = lstatSync(path);} catch {fail('file-unavailable');}
 if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail('regular-single-link-file-required');
 if (protectedAnchor && (stat.uid !== 0 || ![0o644,0o444].includes(stat.mode & 0o7777))) fail('root-readonly-manifest-required');
 return stat;
}
function protectedAncestors(path) {
 let current = parse(path).root;
 const paths = [current];
 for (const part of dirname(path).slice(current.length).split('/').filter(Boolean)) {
  current = join(current, part); paths.push(current);
 }
 return paths.map(path => {
  let stat;
  try {stat = lstatSync(path);} catch {fail('ancestor-unavailable');}
  // Sticky shared directories are not a production anchor. A root can deliberately
  // replace an anchor; an application or worker must have no rename/write route.
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022)) fail('protected-root-ancestor-required');
  return {path, identity:identity(stat)};
 });
}
function readStable(path, maxBytes, {protectedAnchor = false} = {}) {
 const before = fileStat(path, {protectedAnchor});
 if (before.size > maxBytes) fail('file-size-limit');
 let fd;
 try {
  fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const opened = fstatSync(fd);
  if (!sameIdentity(identity(before), identity(opened)) || !opened.isFile()) fail('file-identity-changed');
  const buffer = Buffer.alloc(maxBytes + 1);
  let length = 0, count;
  do {count = readSync(fd, buffer, length, buffer.length - length, length); length += count;}
  while (count && length < buffer.length);
  if (length > maxBytes) fail('file-size-limit');
  const after = fstatSync(fd), current = fileStat(path, {protectedAnchor});
  if (!sameIdentity(identity(opened), identity(after)) || !sameIdentity(identity(opened), identity(current)) || after.size !== length) fail('file-identity-changed');
  return {bytes:buffer.subarray(0, length), identity:identity(after)};
 } catch (error) {
  if (error.code === 'PRIME_DEPLOYMENT_MANIFEST') throw error;
  fail('file-read-refused');
 } finally {if (fd !== undefined) closeSync(fd);}
}
function strict(bytes, maxBytes) {
 try {return parseIngressBytes(bytes, parseStrictJson, {maxBytes,maxDepth:8});}
 catch {fail('strict-json-required');}
}

// This pure parser makes no assertion about filesystem protection or approval.
export function parsePreviewDeploymentManifest(bytes) {
 const value = strict(bytes, 16384);
 if (!value || typeof value !== 'object' || Array.isArray(value)
  || Object.keys(value).length !== KEYS.length || KEYS.some(key => !Object.hasOwn(value,key))) fail('closed-manifest-required');
 if (value.version !== 1 || value.kind !== 'prime-preview-deployment/v1' || value.qualification !== 'PENDING') fail('preview-profile-required');
 if (typeof value.source_commit !== 'string' || !COMMIT.test(value.source_commit)
  || typeof value.release_digest !== 'string' || !HEX.test(value.release_digest)
  || typeof value.ui_integrity_sha256 !== 'string' || !HEX.test(value.ui_integrity_sha256)) fail('manifest-digest-format');
 exactPath(value.release_dir);
 return Object.freeze(value);
}

// Inspection alone does not make this untrusted value a deployment anchor. Boot
// must call readPreviewDeploymentManifest, then independently hash the full tree.
export function inspectPreviewReleaseBinding({manifest, releaseRoot}) {
 releaseRoot = exactPath(releaseRoot);
 let rootStat, physical;
 try {rootStat = lstatSync(releaseRoot); physical = realpathSync(releaseRoot);} catch {fail('release-unavailable');}
 if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || physical !== releaseRoot || manifest.release_dir !== releaseRoot) fail('release-path-mismatch');
 const release = readStable(join(releaseRoot,'prime-release.json'), 65536);
 const metadata = strict(release.bytes,65536);
 if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata) || metadata.source_commit !== manifest.source_commit) fail('source-commit-mismatch');
 const snapshot = readStable(join(releaseRoot,'prime-ui-integrity.json'), 8388608);
 strict(snapshot.bytes,8388608);
 if (sha(snapshot.bytes) !== manifest.ui_integrity_sha256) fail('ui-integrity-mismatch');
 let after;
 try {after = lstatSync(releaseRoot);} catch {fail('release-identity-changed');}
 if (rootStat.dev !== after.dev || rootStat.ino !== after.ino || !after.isDirectory() || realpathSync(releaseRoot) !== releaseRoot) fail('release-identity-changed');
 return Object.freeze({release_identity:Object.freeze({dev:after.dev,ino:after.ino}),ui_integrity_sha256:sha(snapshot.bytes)});
}

export function readPreviewDeploymentManifest({manifestPath, releaseRoot, expectedManifestSha256} = {}) {
 manifestPath = exactPath(manifestPath); releaseRoot = exactPath(releaseRoot);
 if (basename(manifestPath) !== PREVIEW_DEPLOYMENT_MANIFEST_NAME) fail('manifest-filename-required');
 if (inside(releaseRoot,manifestPath)) fail('manifest-outside-release-required');
 if (expectedManifestSha256 !== undefined && !HEX.test(expectedManifestSha256)) fail('expected-manifest-digest-format');
 const ancestors = protectedAncestors(manifestPath);
 if (realpathSync(dirname(manifestPath)) !== dirname(manifestPath)) fail('protected-root-ancestor-required');
 const record = readStable(manifestPath,16384,{protectedAnchor:true});
 const manifestHash = sha(record.bytes);
 if (expectedManifestSha256 !== undefined && manifestHash !== expectedManifestSha256) fail('manifest-anchor-changed');
 const manifest = parsePreviewDeploymentManifest(record.bytes);
 const binding = inspectPreviewReleaseBinding({manifest,releaseRoot});
 const currentAncestors = protectedAncestors(manifestPath);
 if (ancestors.length !== currentAncestors.length || ancestors.some((entry,index) => entry.path !== currentAncestors[index].path || !sameIdentity(entry.identity,currentAncestors[index].identity))) fail('ancestor-identity-changed');
 if (!sameIdentity(record.identity,identity(fileStat(manifestPath,{protectedAnchor:true})))) fail('manifest-anchor-changed');
 return Object.freeze({manifest,manifest_sha256:manifestHash,manifest_identity:Object.freeze(record.identity),...binding});
}

// Root ownership is an OS trust boundary, not a signature or owner approval. The
// candidate tree may be writable, so this metadata check does not replace the
// independent retained full-release digest or the served UI integrity verifier.
// Parent and child should each read the anchor; child binds its read to the hash
// returned to the parent. A trusted root may still change a protected deployment.
