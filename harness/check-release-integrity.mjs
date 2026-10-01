// Disposable protocol fixtures only: these synthetic bytes never qualify a production build.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink} from 'node:fs/promises'
import {join,dirname,resolve} from 'node:path'
import {tmpdir} from 'node:os'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {verifyUiSource,writeUiIntegritySnapshot,verifyReleaseUi} from './release-integrity.mjs'
const sha=bytes=>createHash('sha256').update(bytes).digest('hex')
const donor='645d3213b8aede3b544269b4224ae09df06b0a42',dsh='0d1f50007f9bca3f52b06e1c3074fa14d5fb0720',lock='ca131858949bd12b2acfc227b1af7dfa3c8d65e74b234824d5c741e6421010a1'
const faces=['layout','sidebar','threads','apps','messages','memory','aumlok','documents','settings']
const temporary=await mkdtemp(join(tmpdir(),'prime-ui-integrity-check-')),source=join(temporary,'source'),release=join(temporary,'release'),ui=join(source,'packages/ui')
const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..')
// An explicit verifier argument permits checking B's handed-off file before root imports it.
// After integration the default is Prime's own verifier; production never reads another repo.
const verifierPath=resolve(process.argv[2]??join(repo,'packages/ui/scripts/verify-owner-build.mjs'))
// Synthetic build outputs retain the exact independently pinned dependency
// seats. TODO: adopt the stable harness identity schema only after its handoff;
// this fixture must not relax dependency identities to accommodate that change.
const declaredDependencies={
 '@aukora/face-layout':'workspace:^','@deepseek-ai/cordis':'workspace:^',
 '@deepseek-ai/dsh-client-locale':'workspace:^','@deepseek-ai/dsh-client-ui-renderer':'workspace:^',
 '@deepseek-ai/dsh-client-ui-slots':'workspace:^','@types/react':'~18.3.1',react:'^18.2.0',
}
const dependencySeats={
 '@aukora/face-layout':'faces/layout/package.json',
 '@deepseek-ai/cordis':'vendor/cordis/package.json',
 '@deepseek-ai/dsh-client-locale':'packages/client/locale/package.json',
 '@deepseek-ai/dsh-client-ui-renderer':'packages/client/ui-renderer/package.json',
 '@deepseek-ai/dsh-client-ui-slots':'packages/client/ui-slots/package.json',
 '@types/react':'node_modules/.pnpm/@types+react@18.3.31/node_modules/@types/react/package.json',
 react:'node_modules/.pnpm/react@18.3.1/node_modules/react/package.json',
 typescript:'node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/package.json',
 tsdown:'node_modules/.pnpm/tsdown@0.22.2_oxc-resolver@11.20.0_publint@0.3.21_tsx@4.22.4_typescript@6.0.3/node_modules/tsdown/package.json',
 lightningcss:'node_modules/.pnpm/lightningcss@1.32.0/node_modules/lightningcss/package.json',
}
async function put(root,path,content){const bytes=Buffer.from(content);await mkdir(dirname(join(root,path)),{recursive:true});await writeFile(join(root,path),bytes);return {path,bytes:bytes.length,sha256:sha(bytes)}}
const putJson=(root,path,value)=>put(root,path,JSON.stringify(value,null,2)+'\n')
const refusal=reason=>error=>error.code==='PRIME_UI_INTEGRITY'&&error.reason===reason
let assertions=0
try{
 await mkdir(release,{recursive:true})
 const baselineFiles=[]
 for(const face of faces){const entry=await put(ui,`faces/${face}/lib/client.js`,`// synthetic protocol fixture ${face}\n`);baselineFiles.push(entry);await put(release,`plugins/aukora-face-${face}/lib/client.js`,await readFile(join(ui,entry.path)))}
 const baseline={schema_version:1,commit:donor,faces,files:baselineFiles}
 await putJson(ui,'baseline-manifest.json',baseline);await putJson(release,'prime-packages/ui/baseline-manifest.json',baseline)
 await putJson(release,'prime-served-baseline.json',{version:1,donor,files:baselineFiles,rebuilt_substitutions:false})
 const foundationEntries=[]
 for(const path of ['src/client/index.tsx','lib/client.js','package.json','tsdown.config.ts','assets/AUMARA-FULL-TRANSPARENT-ICON.png','assets/AUMARA-ICON-96.png'])foundationEntries.push(await put(join(ui,'foundation'),path,`synthetic foundation ${path}\n`))
 const foundationBuild={source:Object.fromEntries(foundationEntries.filter(x=>['src/client/index.tsx','tsdown.config.ts'].includes(x.path)).map(x=>[x.path,x.sha256])),outputs:{'lib/client.js':foundationEntries.find(x=>x.path==='lib/client.js').sha256}}
 foundationEntries.push(await putJson(join(ui,'foundation'),'lib/build-manifest.json',foundationBuild))
 const foundation={version:1,commit:donor,client_id:'@aukora/dsh-plugin-foundation',baseline_face_diff:0,copied_exact:foundationEntries}
 await putJson(ui,'foundation/prime-import-manifest.json',foundation);await put(ui,'foundation/lib/index.js','// synthetic no-op\n')
 for(const entry of [...foundationEntries.filter(x=>!x.path.startsWith('src/')),{path:'prime-import-manifest.json'},{path:'lib/index.js'}])await put(release,'plugins/aukora-foundation/'+entry.path,await readFile(join(ui,'foundation',entry.path)))
 for(const path of ['prime-authority/src/client/index.ts','prime-authority/src/client/controller.mjs','prime-authority/src/client/controller.d.mts','prime-authority/src/css-modules.d.ts','prime-authority/tsconfig.client.json','adapters/transport.mjs','adapters/passkey.mjs','scripts/build-client.mjs','faces/layout/src/client/index.ts','faces/layout/package.json','faces/layout/tsconfig.json'])await put(ui,path,`synthetic owner input ${path}\n`)
 await put(ui,'faces/layout/package.json',await readFile(join(repo,'packages/ui/faces/layout/package.json')))
 await putJson(ui,'prime-authority/package.json',{name:'@aukora/prime-authority-ui',version:'0.0.0-fixture',devDependencies:declaredDependencies})
 await putJson(ui,'compatibility.json',{dsh:{commit:dsh}})
 await put(ui,'scripts/verify-owner-build.mjs',await readFile(verifierPath))
 const verifier=await import(pathToFileURL(join(ui,'scripts/verify-owner-build.mjs')).href)
 const sourceFiles=await verifier.snapshotOwnerSources({uiRoot:ui})
 const actualDsh=join(repo,'vendor/dsh'),fixtureDsh=join(source,'vendor/dsh'),pinnedInputs=[]
 for(const path of verifier.PINNED_BUILD_PATHS)pinnedInputs.push(await put(fixtureDsh,path,await readFile(join(actualDsh,path))))
 pinnedInputs.sort((a,b)=>a.path.localeCompare(b.path,'en'))
 async function dependency(name,declared){
  const path=dependencySeats[name],isLayout=name==='@aukora/face-layout'
  const bytes=await readFile(join(isLayout?join(repo,'packages/ui'):actualDsh,path)),metadata=JSON.parse(bytes)
  assert.equal(metadata.name,name,'fixture canonical metadata package name')
  const record=await put(isLayout?ui:fixtureDsh,path,bytes)
  await put(release,isLayout?'plugins/aukora-face-layout/package.json':path,bytes)
  return {name,declared,version:metadata.version,origin:isLayout?'prime-ui':'pinned-harness',...record}
 }
 const buildInputs={pinned:pinnedInputs,generated:{path:'packages/client/aukora-prime-authority/.prime-client.config.ts',bytes:Buffer.byteLength(verifier.OWNER_CONFIG),sha256:sha(Buffer.from(verifier.OWNER_CONFIG))},declared_dependencies:await Promise.all(Object.keys(declaredDependencies).sort().map(name=>dependency(name,declaredDependencies[name]))),build_dependencies:await Promise.all(['typescript','tsdown','lightningcss'].map(name=>dependency(name,null)))}
 const artifacts=[]
 for(const name of ['client.js','client.js.map']){const entry=await put(ui,'prime-authority/lib/'+name,name==='client.js'?'// synthetic protocol output\nwindow.__ModuleLoader__.load({id: "@aukora/prime-authority-ui"})\n':`synthetic owner output ${name}\n`);artifacts.push({...entry,path:'prime-authority/'+name,face:'prime-authority',id:'@aukora/prime-authority-ui'});await put(release,'plugins/prime-authority/lib/'+name,await readFile(join(ui,entry.path)))}
 await put(ui,'prime-authority/lib/index.js','// synthetic no-op\n');await put(ui,'prime-authority/lib/types/client/index.d.ts','// synthetic type\n');for(const extension of ['mjs','d.mts'])await put(ui,'prime-authority/lib/types/client/controller.'+extension,await readFile(join(ui,'prime-authority/src/client/controller.'+extension)))
 for(const path of ['package.json','lib/index.js','lib/types/client/index.d.ts','lib/types/client/controller.d.mts','lib/types/client/controller.mjs'])await put(release,'plugins/prime-authority/'+path,await readFile(join(ui,'prime-authority',path)))
 const build={version:1,source_commit:dsh,harness_receipt_sha256:'a'.repeat(64),source_lock_sha256:lock,overlay_lock_sha256:lock,mode:'client-only',legacy_hosts_mounted:false,artifacts}
 await putJson(ui,'prime-authority/lib/build.json',build)
 await assert.rejects(verifyUiSource({sourceRoot:source}),refusal('owner-source-receipt-missing'));assertions++
 // B's exact schema/verifier is exercised with protocol pins, not a compiler invocation.
 build.version=2;build.upstream_commit=dsh;build.source_commit_attribution='pinned-dsh-upstream; not Prime/UI source proof'
 const outputs=(await verifier.publishedOwnerOutputs(ui)).map(entry=>({...entry,output_path:entry.path.replace('prime-authority/lib/','prime-authority/')}))
 build.owner_build=verifier.createOwnerReceipt({sourceBefore:sourceFiles,sourceAfter:sourceFiles,buildBefore:buildInputs,buildAfter:buildInputs,outputs})
 await putJson(ui,'prime-authority/lib/build.json',build);await putJson(release,'plugins/prime-authority/lib/build.json',build)
 const written=await writeUiIntegritySnapshot({sourceRoot:source,releaseRoot:release})
 const result=await verifyReleaseUi({releaseRoot:release,expectedSnapshotSha256:written.snapshot_sha256});assert.equal(result.result,'PASS');assertions++
 for(const path of ['plugins/aukora-face-threads/lib/client.js','plugins/aukora-foundation/lib/client.js','plugins/prime-authority/lib/client.js']){const original=await readFile(join(release,path));await writeFile(join(release,path),Buffer.concat([original,Buffer.from('tampered')]));await assert.rejects(verifyReleaseUi({releaseRoot:release,expectedSnapshotSha256:written.snapshot_sha256}),refusal('file-changed'));assertions++;await writeFile(join(release,path),original)}
 const sourcePath='prime-authority/src/client/index.ts',original=await readFile(join(ui,sourcePath));await writeFile(join(ui,sourcePath),'changed source');await assert.rejects(verifyUiSource({sourceRoot:source}),refusal('file-changed'));assertions++;await writeFile(join(ui,sourcePath),original)
 const sourceReceiptPath=join(ui,'prime-authority/lib/build.json'),sourceReceiptBytes=await readFile(sourceReceiptPath),changedReceipt=JSON.parse(sourceReceiptBytes)
 changedReceipt.owner_build.source_inputs_after_sha256='0'.repeat(64);await writeFile(sourceReceiptPath,JSON.stringify(changedReceipt));await assert.rejects(verifyUiSource({sourceRoot:source}),refusal('owner-source-digest-binding'));assertions++;await writeFile(sourceReceiptPath,sourceReceiptBytes)
 changedReceipt.owner_build.source_inputs_after_sha256=build.owner_build.source_inputs_after_sha256;changedReceipt.owner_build.build_inputs_after_sha256='0'.repeat(64);await writeFile(sourceReceiptPath,JSON.stringify(changedReceipt));await assert.rejects(verifyUiSource({sourceRoot:source}),refusal('owner-build-digest-binding'));assertions++;await writeFile(sourceReceiptPath,sourceReceiptBytes)
 const snapshotPath=join(release,'prime-ui-integrity.json'),snapshotBytes=await readFile(snapshotPath),snapshot=JSON.parse(snapshotBytes)
 snapshot.files=snapshot.files.filter(x=>x.path!=='plugins/aukora-face-threads/lib/client.js');await writeFile(snapshotPath,JSON.stringify(snapshot));await assert.rejects(verifyReleaseUi({releaseRoot:release}),refusal('served-snapshot-omission'));assertions++
 await assert.rejects(verifyReleaseUi({releaseRoot:release,expectedSnapshotSha256:written.snapshot_sha256}),refusal('snapshot-trusted-pin-mismatch'));assertions++;await writeFile(snapshotPath,snapshotBytes)
 const bundlePath=join(release,'plugins/prime-authority/lib/client.js'),bundleBytes=await readFile(bundlePath);await rm(bundlePath);await symlink(join(ui,'prime-authority/lib/client.js'),bundlePath);await assert.rejects(verifyReleaseUi({releaseRoot:release}),refusal('file-symlink'));assertions++;await rm(bundlePath);await writeFile(bundlePath,bundleBytes)
 const receiptPath=join(release,'plugins/prime-authority/lib/build.json'),receipt=await readFile(receiptPath);await writeFile(receiptPath,'{"version":1,"version":1}');await assert.rejects(verifyReleaseUi({releaseRoot:release}),refusal('file-changed'));assertions++;await writeFile(receiptPath,receipt)
 await verifyReleaseUi({releaseRoot:release,expectedSnapshotSha256:written.snapshot_sha256});assertions++
 console.log(JSON.stringify({result:'PASS',assertions,scope:'disposable UI integrity protocol fixtures',production_owner_build:'UNPERFORMED: genuine source-input receipt required',single_file_mutations_rejected:3}))
}finally{await rm(temporary,{recursive:true,force:true})}
