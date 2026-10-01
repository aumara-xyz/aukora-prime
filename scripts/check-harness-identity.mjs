// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic compiler-input/output bytes only: no install, compiler, network or real receipt migration.
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,unlinkSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {aggregateDigest,buildRecord,buildHarnessIdentity,writeHarnessIdentity,verifyHarnessIdentity,
  HARNESS_COMPILER_REQUIRED,HARNESS_IDENTITY_PATH} from './lib/artifact-integrity.mjs';

const base=mkdtempSync(join(tmpdir(),'prime-harness-identity-')),root=join(base,'prime'),source=join(root,'vendor/dsh');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const args=process.argv.slice(2);
if(args.length&&! (args.length===2&&args[0]==='--python'&&args[1]))throw new Error('usage: check-harness-identity.mjs [--python /explicit/python]');
const python=args[1]??'python3';
const put=(path,bytes)=>{mkdirSync(dirname(path),{recursive:true});writeFileSync(path,bytes);};
const json=(path,value)=>put(path,JSON.stringify(value,null,2)+'\n');
let checks=0;
try{
  const archive=Buffer.from('synthetic pinned archive bytes; this fixture invokes no extractor\n');
  const lock=Buffer.from('synthetic frozen lock; no dependencies or installation\n');
  const patchReason='synthetic source check only';
  const patch=Buffer.from(JSON.stringify({formatVersion:1,reason:patchReason,edits:[{path:'package.json',find:'synthetic-harness',replace:'synthetic-harness-patched'}]})+'\n');
  put(join(root,'vendor/dsh-source.tar.gz'),archive);put(join(source,'pnpm-lock.yaml'),lock);
  put(join(root,'patches/synthetic.patch.json'),patch);
  const pin={commit:'0'.repeat(40),archiveSha256:sha(archive),lockfileSha256:sha(lock),packageManager:'pnpm@11.7.0',cordisVersion:'4.0.2',
    localPatches:[{file:'patches/synthetic.patch.json',sha256:sha(patch),reason:patchReason}]};
  json(join(root,'upstream-dsh.json'),pin);
  for(const path of HARNESS_COMPILER_REQUIRED)put(join(source,path),path==='package.json'?'{"name":"synthetic-harness","type":"module"}\n':'// synthetic compiler input '+path+'\n');
  put(join(source,'host.js'),'// synthetic host bytes\n');put(join(source,'client.js'),'// synthetic client bytes\n');
  put(join(root,'prime-source.txt'),'synthetic Prime inventory one\n');
  const declaration={formatVersion:1,source:'vendor/dsh',record:'.dsh-build/genesis-artifacts.json',
    upstreamClientRecord:'.dsh-build/client-build-environment.json',sourceLockfile:'pnpm-lock.yaml',
    hostPatterns:['host*.js'],clientPatterns:['client.js'],requiredEntries:['host.js'],excluded:['.dsh-build/**'],
    genesisPatterns:['prime-source.txt'],uncoveredInputs:[],limits:['synthetic fixture only'],
    strip:{manifest:'strip-manifest.json',releaseManifest:'release.json',patterns:['docs/**'],keep:[],keepPolicy:['synthetic fixture'],scanExclude:{rootEntries:['node_modules'],fileNames:['package.json'],note:'synthetic fixture'}}};
  json(join(root,'scripts/artifacts-coverage.json'),declaration);
  for(const path of ['lib/artifact-integrity.mjs','lib/release-strip.mjs']){
    const target=join(root,'scripts',path);mkdirSync(dirname(target),{recursive:true});copyFileSync(fileURLToPath(new URL(path,import.meta.url)),target);
  }
  const upstream=(environment={synthetic_fixture:true})=>json(join(source,declaration.upstreamClientRecord),
    {artifacts:{fileCount:1,sha256:aggregateDigest(source,['client.js'])},environment});
  upstream();
  const coverage=()=>({sha256:sha(readFileSync(join(root,'scripts/artifacts-coverage.json'))),value:declaration});
  const bind=()=>{
    const record=buildRecord({genesisRoot:root,source,pin,coverage:coverage()});
    const identity=writeHarnessIdentity({root,source});
    json(join(source,'.dsh-build/pinned-harness-build.json'),{formatVersion:2,kind:'pinned-harness-build',
      inputs:{upstream:Object.fromEntries(['commit','archiveSha256','lockfileSha256','packageManager'].map(key=>[key,pin[key]])),localPatches:identity.identity.localPatches},
      harnessIdentity:{path:HARNESS_IDENTITY_PATH,sha256:identity.sha256},artifactCount:record.entries.length,
      provenance:{artifactRecordSha256:sha(readFileSync(join(source,declaration.record))),producer:record.producer}});
    return {identity,raw:readFileSync(join(source,HARNESS_IDENTITY_PATH)),record:sha(readFileSync(join(source,declaration.record)))};
  };
  const before=bind();assert.equal(verifyHarnessIdentity({root,source}).sha256,before.identity.sha256);checks++;
  const verifyBuilt=()=>spawnSync(python,[fileURLToPath(new URL('build-dsh.py',import.meta.url)),'--root',root,'--verify-built'],{encoding:'utf8',timeout:10_000});
  const first=verifyBuilt();assert.equal(first.status,0,first.stderr);assert.match(first.stdout,/harness-build-binding: verified 1 artifacts/);checks++;
  // Real producer inventory and upstream environment change; stable harness bytes do not.
  put(join(root,'prime-source.txt'),'synthetic Prime inventory two\n');upstream({node:'other-version',platform:'other-platform',prime_commit:'f'.repeat(40)});
  const after=bind();assert.notEqual(before.record,after.record);assert.deepEqual(after.raw,before.raw);checks++;
  assert.equal(verifyHarnessIdentity({root,source}).sha256,before.identity.sha256);checks++;
  const second=verifyBuilt();assert.equal(second.status,0,second.stderr);checks++;
  // Synthetic producer metadata is separately retained provenance. The consumer
  // compares it to that record, never to the current Prime commit/platform.
  const recordPath=join(source,declaration.record),buildPath=join(source,'.dsh-build/pinned-harness-build.json');
  const recordBytes=readFileSync(recordPath),bindingBytes=readFileSync(buildPath);
  const metadataRecord=JSON.parse(recordBytes),metadataBinding=JSON.parse(bindingBytes);
  metadataRecord.producer={node:'synthetic-other-node',platform:'synthetic-other-platform',genesisCommit:'f'.repeat(40)};
  json(recordPath,metadataRecord);metadataBinding.provenance={artifactRecordSha256:sha(readFileSync(recordPath)),producer:metadataRecord.producer};json(buildPath,metadataBinding);
  assert.equal(verifyHarnessIdentity({root,source}).sha256,before.identity.sha256);checks++;
  const provenance=verifyBuilt();assert.equal(provenance.status,0,provenance.stderr);checks++;
  put(recordPath,recordBytes);put(buildPath,bindingBytes);
  assert.ok(!JSON.stringify(after.identity).includes('other-platform'));assert.ok(!JSON.stringify(after.identity).includes('prime-source.txt'));checks++;
  const identityPath=join(source,HARNESS_IDENTITY_PATH),originalReceipt=readFileSync(join(source,'.dsh-build/pinned-harness-build.json'));
  json(join(source,'.dsh-build/pinned-harness-build.json'),{formatVersion:1,kind:'pinned-harness-build'});
  assert.throws(()=>verifyHarnessIdentity({root,source}),/fresh v2 build required/);checks++;
  const historical=verifyBuilt();assert.equal(historical.status,1);assert.match(historical.stderr,/fresh v2 build/);checks++;
  put(join(source,'.dsh-build/pinned-harness-build.json'),originalReceipt);
  const changed=(path,replacement,pattern)=>{const original=readFileSync(path);try{put(path,replacement);assert.throws(()=>verifyHarnessIdentity({root,source}),pattern);checks++;}finally{put(path,original);}};
  changed(join(root,'vendor/dsh-source.tar.gz'),'changed archive',/archive-mismatch/);
  changed(join(root,'patches/synthetic.patch.json'),'changed patch',/patch-mismatch/);
  changed(join(source,'pnpm-lock.yaml'),'changed lock',/lock-mismatch/);
  changed(join(source,'tsconfig.base.client.json'),'changed compiler config',/identity-mismatch/);
  changed(join(source,'scripts/build.ts'),'changed compiler recipe',/identity-mismatch/);
  changed(join(source,'host.js'),'changed host output',/identity-mismatch/);
  changed(join(source,'client.js'),'changed client output',/client-closure-incomplete/);
  put(join(source,'host-extra.js'),'extra synthetic covered output');assert.throws(()=>verifyHarnessIdentity({root,source}),/identity-mismatch/);checks++;unlinkSync(join(source,'host-extra.js'));
  const host=readFileSync(join(source,'host.js'));unlinkSync(join(source,'host.js'));assert.throws(()=>verifyHarnessIdentity({root,source}),/host-closure-incomplete/);checks++;put(join(source,'host.js'),host);
  changed(identityPath,JSON.stringify({...after.identity,producer:{platform:'spoof'}})+'\n',/identity-mismatch/);
  changed(identityPath,JSON.stringify({...after.identity,sha256:'f'.repeat(64)})+'\n',/identity-mismatch/);
  const client=readFileSync(join(source,'client.js'));put(join(source,'client.js'),'changed client and self-updated upstream inventory\n');upstream();
  assert.throws(()=>verifyHarnessIdentity({root,source}),/identity-mismatch/);checks++;put(join(source,'client.js'),client);upstream({node:'other-version',platform:'other-platform',prime_commit:'f'.repeat(40)});
  const compiler=join(source,'scripts/client-build-environment.ts'),compilerBytes=readFileSync(compiler);unlinkSync(compiler);
  assert.throws(()=>buildHarnessIdentity({root,source}),/compiler-input-missing/);checks++;put(compiler,compilerBytes);
  assert.equal(verifyHarnessIdentity({root,source}).sha256,before.identity.sha256);checks++;
  console.log(JSON.stringify({status:'PASS',checks,identity_sha256:before.identity.sha256,stable_across_changed_producer_inventory:true,
    scope:'synthetic inputs/output producer and consumer; no dependency install, compiler or actual DSH build',full_gate:'UNPERFORMED'}));
}finally{rmSync(base,{recursive:true,force:true});}
