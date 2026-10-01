// SPDX-License-Identifier: AGPL-3.0-or-later
// Test ONLY: pin separate lane artifacts into a disposable own-root snapshot.
// This is not a host installer, enrollment helper or production qualifier.
import {readFileSync,writeFileSync,mkdirSync,existsSync,readdirSync,lstatSync,realpathSync,chmodSync} from 'node:fs'
import {createHash} from 'node:crypto'
import {dirname,resolve,join,relative} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'
import {tmpdir} from 'node:os'

const repo=resolve(dirname(fileURLToPath(import.meta.url)),'../../..')
const allowed=['--ui-bundle','--ui-evidence','--host-repository','--output']
const args=process.argv.slice(2),options={}
for(let at=0;at<args.length;at+=2){
  const name=args[at],value=args[at+1]
  if(!allowed.includes(name)||options[name]!==undefined||!value||!value.startsWith('/'))throw new TypeError('SOURCE_JOIN_CLOSED_ABSOLUTE_OPTIONS_REQUIRED')
  options[name]=resolve(value)
}
if(allowed.some(name=>!options[name]))throw new TypeError('SOURCE_JOIN_ALL_OPTIONS_REQUIRED')
const hash=bytes=>createHash('sha256').update(bytes).digest('hex')
const gitEnvironment={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('GIT_'))),
  GIT_OPTIONAL_LOCKS:'0',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null'}
const run=(command,argv,cwd=repo,input)=>{
  const parameters=command==='git'?['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...argv]:argv
  const result=spawnSync(command,parameters,{cwd,input,maxBuffer:256*1024*1024,env:command==='git'?gitEnvironment:process.env})
  if(result.error||result.status!==0)throw new Error('SOURCE_JOIN_COMMAND_REFUSED:'+command+':'+(result.status??'spawn'))
  return result.stdout
}
const git=(argv,cwd=repo)=>run('git',argv,cwd)
const evidenceBytes=readFileSync(options['--ui-evidence'])
if(evidenceBytes.length>1024*1024)throw new TypeError('SOURCE_JOIN_EVIDENCE_BOUND')
const evidence=JSON.parse(evidenceBytes)
if(evidence.version!==1||!/^[a-f0-9]{40}$/.test(evidence.commit)||!Array.isArray(evidence.owned_files)||evidence.owned_files.length>64)throw new TypeError('SOURCE_JOIN_UI_PIN_REQUIRED')
const bundleBytes=readFileSync(options['--ui-bundle'])
if(evidence.bundle?.sha256!==hash(bundleBytes))throw new TypeError('SOURCE_JOIN_UI_BUNDLE_DIGEST_MISMATCH')
const output=options['--output']
const parent=realpathSync(dirname(output)),roots=[realpathSync(dirname(repo)),realpathSync(tmpdir())]
if(parent!==dirname(output)||!roots.some(root=>parent===root||parent.startsWith(root+'/')))throw new TypeError('SOURCE_JOIN_CANONICAL_OWN_SCRATCH_OUTPUT_REQUIRED')
if(existsSync(output))throw new TypeError('SOURCE_JOIN_FRESH_OUTPUT_REQUIRED')
mkdirSync(output,{mode:0o700})
const bare=join(output,'ui-objects.git'),snapshot=join(output,'snapshot')
mkdirSync(snapshot,{mode:0o700})
run('git',['init','--bare',bare])
git(['fetch','--no-tags','--no-write-fetch-head',options['--ui-bundle'],'HEAD:refs/check/ui'],bare)
if(git(['rev-parse','refs/check/ui'],bare).toString().trim()!==evidence.commit)throw new TypeError('SOURCE_JOIN_UI_COMMIT_MISMATCH')
const bridgeCommit=git(['rev-parse','HEAD']).toString().trim()
if(git(['status','--porcelain','--untracked-files=no','--','packages/runtime-bridge']).length)throw new TypeError('SOURCE_JOIN_COMMITTED_BRIDGE_REQUIRED')
run('tar',['-x','-C',snapshot],repo,git(['archive',bridgeCommit]))
const ui=[]
for(const entry of evidence.owned_files){
  if(typeof entry.path!=='string'||!/^packages\/ui\/prime-authority\/[A-Za-z0-9_./-]+$/.test(entry.path)||entry.path.split('/').includes('..')||!Number.isSafeInteger(entry.bytes)||entry.bytes<0||!/^([a-f0-9]{64})$/.test(entry.sha256))throw new TypeError('SOURCE_JOIN_UI_FILE_PIN_REQUIRED')
  const bytes=git(['show',evidence.commit+':'+entry.path],bare)
  if(bytes.length!==entry.bytes||hash(bytes)!==entry.sha256)throw new TypeError('SOURCE_JOIN_UI_FILE_DIGEST_MISMATCH')
  const target=join(snapshot,entry.path);mkdirSync(dirname(target),{recursive:true,mode:0o700});writeFileSync(target,bytes)
  ui.push({path:entry.path,bytes:bytes.length,sha256:hash(bytes)})
}
// Check the controller's whole browser-safe local import closure. A new hook
// cannot silently consume a different sibling adapter than the pinned bundle.
for(const name of ['transport.mjs','passkey.mjs','capture-review.mjs']){
  const path='packages/ui/adapters/'+name,bytes=git(['show',evidence.commit+':'+path],bare)
  if(hash(bytes)!==hash(readFileSync(join(snapshot,path))))throw new TypeError('SOURCE_JOIN_UI_ADAPTER_CLOSURE_CHANGED')
  ui.push({path,bytes:bytes.length,sha256:hash(bytes)})
}
const hostCommit='4a2cd94de1394aff53fb1afcafd6a187e4c5b8f9',host=[]
for(const name of ['owner-memory-browser.mjs','owner-memory-transport.mjs','owner-memory-ipc.mjs','owner-memory-context.mjs']){
  const path='harness/'+name,bytes=git(['show',hostCommit+':'+path],options['--host-repository'])
  mkdirSync(join(snapshot,'harness'),{recursive:true,mode:0o700});writeFileSync(join(snapshot,path),bytes)
  host.push({path,bytes:bytes.length,sha256:hash(bytes)})
}
const files=[]
function collect(root){for(const name of readdirSync(root).sort()){
  const path=join(root,name),stat=lstatSync(path)
  if(stat.isDirectory())collect(path)
  else if(stat.isFile())files.push({path:relative(snapshot,path),bytes:stat.size,sha256:hash(readFileSync(path))})
  else throw new TypeError('SOURCE_JOIN_BRIDGE_REGULAR_SOURCE_REQUIRED')
}}
collect(join(snapshot,'packages/runtime-bridge'))
const pins={version:1,kind:'owner-memory-source-join/v1',bridge_commit:bridgeCommit,ui_commit:evidence.commit,
  ui_bundle_sha256:hash(bundleBytes),ui_evidence_sha256:hash(evidenceBytes),ui_files:ui,host_commit:hostCommit,host_files:host,
  bridge_files:files,synthetic_fixture:true,production_qualification:false,postgres_runtime_tested:false,
  note:'No UI/browser observation, production credential, deployment, OS setup, accepted host record or publication. C/D use synthetic P256 and disposable SQLite; H public acceptance must refuse.'}
writeFileSync(join(output,'input-pins.json'),JSON.stringify(pins,null,2)+'\n',{mode:0o600})
const tests=['owner-memory-workflow.test.mjs','owner-memory-hook.test.mjs','owner-memory-host.test.mjs','public-memory-worker.test.mjs','worker.test.mjs']
const command=['--test',...tests.map(name=>'packages/runtime-bridge/test/'+name)]
const result=spawnSync(process.execPath,command,{cwd:snapshot,maxBuffer:16*1024*1024,env:{...process.env,
  PRIME_OWNER_HOOK_CONTROLLER:join(snapshot,'packages/ui/prime-authority/src/client/controller.mjs'),PRIME_OWNER_MEMORY_HOST_ROOT:snapshot}})
const log=Buffer.concat([result.stdout??Buffer.alloc(0),result.stderr??Buffer.alloc(0)])
writeFileSync(join(output,'checks.txt'),log,{mode:0o600})
writeFileSync(join(output,'result.json'),JSON.stringify({version:1,bridge_commit:bridgeCommit,ui_commit:evidence.commit,
  status:result.status===0?'PASS':'FAIL',exit_code:result.status,checks_sha256:hash(log),input_pins_sha256:hash(readFileSync(join(output,'input-pins.json'))),
  command:[process.execPath,...command],snapshot,remaining_blockers:result.status===0?[]:['See checks.txt; failed joined lifecycle guard is not a qualified import.']},null,2)+'\n',{mode:0o600})
function freezeSnapshot(root){for(const name of readdirSync(root)){
  const path=join(root,name),stat=lstatSync(path)
  if(stat.isDirectory())freezeSnapshot(path)
  else if(stat.isFile())chmodSync(path,0o444)
  // The source archive's existing tracked relative links stay links.
}chmodSync(root,0o555)}
freezeSnapshot(snapshot)
process.stdout.write(JSON.stringify({status:result.status===0?'PASS':'FAIL',output,bridge_commit:bridgeCommit,ui_commit:evidence.commit})+'\n')
process.exitCode=result.status===0?0:1
