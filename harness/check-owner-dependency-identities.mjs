// SPDX-License-Identifier: AGPL-3.0-or-later
// Finding 4 only: actual release consumer, bounded disposable metadata/receipt
// fixtures. No B import/compiler, dependency code, full source copy or activation.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises'
import {dirname,join,resolve} from 'node:path'
import {tmpdir} from 'node:os'
import {fileURLToPath} from 'node:url'
import {verifyReleaseUi} from './release-integrity.mjs'

const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
const copy=value=>JSON.parse(JSON.stringify(value))
const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..')
const donor='645d3213b8aede3b544269b4224ae09df06b0a42'
const faces=['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']
const temporary=await mkdtemp(join(tmpdir(),'prime-owner-dependency-')),release=join(temporary,'release')
const current=JSON.parse(await readFile(join(repo,'packages/ui/prime-authority/lib/build.json'),'utf8'))
const expected={
 declared_dependencies:[
  ['@aukora/face-layout','workspace:^','0.1.1-rc.2','prime-ui','faces/layout/package.json'],
  ['@deepseek-ai/cordis','workspace:^','4.0.2','pinned-harness','vendor/cordis/package.json'],
  ['@deepseek-ai/dsh-client-locale','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/locale/package.json'],
  ['@deepseek-ai/dsh-client-ui-renderer','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/ui-renderer/package.json'],
  ['@deepseek-ai/dsh-client-ui-slots','workspace:^','0.1.6-alpha.1','pinned-harness','packages/client/ui-slots/package.json'],
  ['@types/react','~18.3.1','18.3.31','pinned-harness','node_modules/.pnpm/@types+react@18.3.31/node_modules/@types/react/package.json'],
  ['react','^18.2.0','18.3.1','pinned-harness','node_modules/.pnpm/react@18.3.1/node_modules/react/package.json'],
 ],
 build_dependencies:[
  ['typescript',null,'6.0.3','pinned-harness','node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/package.json'],
  ['tsdown',null,'0.22.2','pinned-harness','node_modules/.pnpm/tsdown@0.22.2_oxc-resolver@11.20.0_publint@0.3.21_tsx@4.22.4_typescript@6.0.3/node_modules/tsdown/package.json'],
  ['lightningcss',null,'1.32.0','pinned-harness','node_modules/.pnpm/lightningcss@1.32.0/node_modules/lightningcss/package.json'],
 ],
}
const files=[]
let receipt,snapshot,assertions=0,redirects=0,metadataRefusals=0
async function put(path,value){
 const bytes=Buffer.isBuffer(value)?value:Buffer.from(value)
 await mkdir(dirname(join(release,path)),{recursive:true});await writeFile(join(release,path),bytes)
 return {path,bytes:bytes.length,sha256:sha(bytes)}
}
const putJson=(path,value)=>put(path,JSON.stringify(value,null,2)+'\n')
const releaseSeat=record=>record.origin==='prime-ui'?'plugins/aukora-face-layout/package.json':record.path
function remember(entry){const index=files.findIndex(item=>item.path===entry.path);if(index<0)files.push(entry);else files[index]=entry}
async function writeReceipt(value){
 value.owner_build.build_inputs_before_sha256=value.owner_build.build_inputs_after_sha256=sha(Buffer.from(JSON.stringify(value.owner_build.build_inputs)))
 const entry=await putJson('plugins/prime-authority/lib/build.json',value);remember(entry)
 snapshot.source_records[2]={...entry,path:'prime-authority/lib/build.json'}
 snapshot.files=copy(files).sort((a,b)=>a.path.localeCompare(b.path))
 const anchor=await putJson('prime-ui-integrity.json',snapshot)
 return anchor.sha256
}
async function check(value){return verifyReleaseUi({releaseRoot:release,expectedSnapshotSha256:await writeReceipt(value)})}
async function refused(value,reason){await assert.rejects(check(value),error=>error.code==='PRIME_UI_INTEGRITY'&&error.reason===reason);assertions++}

try{
 // Verify current records against independently written expected identities,
 // then copy only their ten small regular metadata files into synthetic seats.
 for(const [field,identities] of Object.entries(expected)){
  assert.deepEqual(current.owner_build.build_inputs[field].map(record=>['name','declared','version','origin','path'].map(key=>record[key])),identities);assertions++
  for(const record of current.owner_build.build_inputs[field]){
   const source=join(repo,record.origin==='prime-ui'?'packages/ui':'vendor/dsh',record.path)
   const bytes=await readFile(source),metadata=JSON.parse(bytes)
   assert.equal(metadata.name,record.name);assert.equal(metadata.version,record.version)
   assert.equal(bytes.length,record.bytes);assert.equal(sha(bytes),record.sha256);assertions++
   await put(releaseSeat(record),bytes)
  }
 }
 const baselineFiles=[]
 for(const face of faces){const path='faces/'+face+'/lib/client.js',entry=await put('plugins/aukora-face-'+face+'/lib/client.js','// bounded synthetic '+face+'\n');remember(entry);baselineFiles.push({...entry,path})}
 const layout=current.owner_build.build_inputs.declared_dependencies[0]
 baselineFiles.push({path:layout.path,bytes:layout.bytes,sha256:layout.sha256});remember({...baselineFiles.at(-1),path:releaseSeat(layout)})
 const baseline={schema_version:1,commit:donor,faces,files:baselineFiles}
 const baselineEntry=await putJson('prime-packages/ui/baseline-manifest.json',baseline);remember(baselineEntry)
 remember(await putJson('prime-served-baseline.json',{version:1,donor,files:baselineFiles,rebuilt_substitutions:false}))
 const foundationFiles=[]
 for(const path of ['src/client/index.tsx','lib/client.js','lib/build-manifest.json','package.json','tsdown.config.ts','assets/AUMARA-FULL-TRANSPARENT-ICON.png','assets/AUMARA-ICON-96.png']){
  const entry=await put('plugins/aukora-foundation/'+path,'bounded synthetic foundation '+path+'\n');foundationFiles.push({...entry,path});if(!path.startsWith('src/'))remember(entry)
 }
 const foundationEntry=await putJson('plugins/aukora-foundation/prime-import-manifest.json',{version:1,commit:donor,client_id:'@aukora/dsh-plugin-foundation',copied_exact:foundationFiles});remember(foundationEntry)
 const sourceInputs=[
  {path:'prime-authority/src/client/controller.mjs',bytes:2,sha256:sha(Buffer.from('//'))},
  {path:'prime-authority/src/client/controller.d.mts',bytes:2,sha256:sha(Buffer.from('//'))},
 ]
 const outputArtifacts=[]
 for(const path of ['client.js','client.js.map','index.js','types/client/index.d.ts','types/client/controller.d.mts','types/client/controller.mjs']){
  const entry=await put('plugins/prime-authority/lib/'+path,path.startsWith('types/client/controller.')?'//':'bounded synthetic owner '+path+'\n');remember(entry)
  outputArtifacts.push({...entry,path:'prime-authority/lib/'+path,output_path:'prime-authority/'+path})
 }
 receipt={...copy(current),artifacts:outputArtifacts.filter(record=>/^prime-authority\/client\.js(?:\.map)?$/.test(record.output_path)).map(record=>({id:'@aukora/prime-authority-ui',path:record.output_path,bytes:record.bytes,sha256:record.sha256})),
  owner_build:{...copy(current.owner_build),source_inputs:sourceInputs,source_inputs_before_sha256:sha(Buffer.from(JSON.stringify(sourceInputs))),source_inputs_after_sha256:sha(Buffer.from(JSON.stringify(sourceInputs))),output_artifacts:outputArtifacts}}
 snapshot={version:1,kind:'aukora-prime-ui-integrity/v1',donor,source_records:[{...baselineEntry,path:'baseline-manifest.json'},{...foundationEntry,path:'foundation/prime-import-manifest.json'},null],owner_source_files:sourceInputs,files:[]}
 assert.equal((await check(copy(receipt))).result,'PASS');assertions++

 // The report's exploit rehashes all dependency routes to the harmless layout.
 const redirected=copy(receipt)
 for(const field of Object.keys(expected))for(const record of redirected.owner_build.build_inputs[field])Object.assign(record,{version:layout.version,origin:'prime-ui',path:layout.path,bytes:layout.bytes,sha256:layout.sha256})
 await refused(redirected,'owner-dependency-identity');redirects++
 // Check every individual map field and every package/tool, even if all digests
 // and the explicitly supplied synthetic snapshot anchor are recomputed.
 for(const [field,identities] of Object.entries(expected))for(let index=0;index<identities.length;index++){
  for(const [key,value] of Object.entries({name:'synthetic-wrong-package',declared:'*',version:'99.0.0',origin:identities[index][3]==='prime-ui'?'pinned-harness':'prime-ui',path:identities[index][4]==='faces/layout/package.json'?'faces/sidebar/package.json':'faces/layout/package.json'})){
   const changed=copy(receipt);changed.owner_build.build_inputs[field][index][key]=value
   await refused(changed,'owner-dependency-identity');redirects++
  }
 }
 for(const field of Object.keys(expected)){
  const missing=copy(receipt);missing.owner_build.build_inputs[field].pop();await refused(missing,'owner-dependency-set')
  const extra=copy(receipt);extra.owner_build.build_inputs[field].push(copy(extra.owner_build.build_inputs[field][0]));await refused(extra,'owner-dependency-set')
  const duplicate=copy(receipt);duplicate.owner_build.build_inputs[field][1]=copy(duplicate.owner_build.build_inputs[field][0]);await refused(duplicate,'owner-dependency-identity')
 }
 // Keep maps correct but replace actual metadata at each canonical seat. Hash
 // the altered bytes into the receipt: package identity must still refuse.
 for(const [field,identities] of Object.entries(expected))for(let index=0;index<identities.length;index++){
  const record=receipt.owner_build.build_inputs[field][index],path=releaseSeat(record),original=await readFile(join(release,path))
  for(const property of ['name','version']){
   const changed=copy(receipt),metadata=JSON.parse(original);metadata[property]='synthetic-wrong-'+property
   const entry=await putJson(path,metadata);Object.assign(changed.owner_build.build_inputs[field][index],{bytes:entry.bytes,sha256:entry.sha256})
   // Rebind the baseline/snapshot for layout too, so no earlier byte mismatch
   // can conceal the actual metadata-identity guard being tested.
   if(record.origin==='prime-ui'){
    const changedBaseline=copy(baseline);Object.assign(changedBaseline.files.at(-1),{bytes:entry.bytes,sha256:entry.sha256})
    remember(entry);const changedEntry=await putJson('prime-packages/ui/baseline-manifest.json',changedBaseline);remember(changedEntry)
    snapshot.source_records[0]={...changedEntry,path:'baseline-manifest.json'}
    remember(await putJson('prime-served-baseline.json',{version:1,donor,files:changedBaseline.files,rebuilt_substitutions:false}))
   }
   await refused(changed,'owner-dependency-metadata');metadataRefusals++
  }
  await put(path,original)
  if(record.origin==='prime-ui'){
   remember({path,bytes:original.length,sha256:sha(original)});remember(baselineEntry);snapshot.source_records[0]={...baselineEntry,path:'baseline-manifest.json'}
   await putJson('prime-packages/ui/baseline-manifest.json',baseline)
   remember(await putJson('prime-served-baseline.json',{version:1,donor,files:baselineFiles,rebuilt_substitutions:false}))
  }
 }
 assert.equal((await check(copy(receipt))).result,'PASS');assertions++
 console.log(JSON.stringify({result:'PASS',assertions,packages:10,rehashed_redirects_refused:redirects,rehashed_actual_metadata_refused:metadataRefusals,
  scope:'exact current dependency identities and actual release consumer; synthetic receipts/outputs, ten real metadata files only',B_imported:false,full_build:false,runtime_changes:false}))
}finally{await rm(temporary,{recursive:true,force:true})}
