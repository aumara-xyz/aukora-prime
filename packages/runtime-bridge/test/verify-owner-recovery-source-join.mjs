// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only integration runner. It installs nothing and starts no listener.
import {readFileSync,writeFileSync,mkdirSync,existsSync,readdirSync,lstatSync,realpathSync,chmodSync,readlinkSync,rmSync} from 'node:fs'
import {createHash} from 'node:crypto'
import {dirname,resolve,join,relative} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'
import {tmpdir} from 'node:os'

const repo=resolve(dirname(fileURLToPath(import.meta.url)),'../../..')
const inputs=[
  {option:'--authority-repository',path:'packages/authority',commit:'eb90fc7e890ba950917bceeff009f55179e7769c'},
  {option:'--memory-repository',path:'packages/memory',commit:'4e6d0336a286aa84e53479f0200d20d480ada5f8'},
  {option:'--ui-repository',path:'packages/ui',commit:'d9f94f1002e42bb34ca0db06c1723b1a6abc06f5'},
]
const allowed=[...inputs.map(input=>input.option),'--output'],options={}
const args=process.argv.slice(2)
for(let at=0;at<args.length;at+=2){
  const name=args[at],value=args[at+1]
  if(!allowed.includes(name)||options[name]!==undefined||typeof value!=='string'||!value.startsWith('/'))throw new TypeError('RECOVERY_JOIN_CLOSED_ABSOLUTE_OPTIONS_REQUIRED')
  options[name]=resolve(value)
}
if(allowed.some(name=>!options[name]))throw new TypeError('RECOVERY_JOIN_ALL_OPTIONS_REQUIRED')
const hash=bytes=>createHash('sha256').update(bytes).digest('hex')
const gitEnvironment={...Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('GIT_'))),
  GIT_OPTIONAL_LOCKS:'0',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null'}
function run(command,argv,cwd=repo,input){
  const result=spawnSync(command,command==='git'?['-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...argv]:argv,
    {cwd,input,maxBuffer:256*1024*1024,env:command==='git'?gitEnvironment:process.env})
  if(result.error||result.status!==0)throw new Error('RECOVERY_JOIN_COMMAND_REFUSED:'+command+':'+(result.status??'spawn'))
  return result.stdout
}
const git=(argv,cwd=repo)=>run('git',argv,cwd)
if(git(['status','--porcelain','--','packages/runtime-bridge']).length)throw new TypeError('RECOVERY_JOIN_COMMITTED_BRIDGE_REQUIRED')
const bridgeCommit=git(['rev-parse','HEAD']).toString().trim(),output=options['--output']
const parent=realpathSync(dirname(output)),roots=[realpathSync(dirname(repo)),realpathSync(tmpdir())]
if(parent!==dirname(output)||!roots.some(root=>parent===root||parent.startsWith(root+'/'))||existsSync(output))throw new TypeError('RECOVERY_JOIN_FRESH_OWN_SCRATCH_REQUIRED')
mkdirSync(output,{mode:0o700});const snapshot=join(output,'snapshot');mkdirSync(snapshot,{mode:0o700})
run('tar',['-x','-C',snapshot],repo,git(['archive',bridgeCommit]))
for(const input of inputs){
  if(git(['rev-parse',input.commit+'^{commit}'],options[input.option]).toString().trim()!==input.commit)throw new TypeError('RECOVERY_JOIN_COMMIT_PIN_REQUIRED')
  rmSync(join(snapshot,input.path),{recursive:true,force:true})
  run('tar',['-x','-C',snapshot],repo,git(['archive',input.commit,input.path],options[input.option]))
}
const files=[]
function collect(root){for(const name of readdirSync(root).sort()){
  const path=join(root,name),stat=lstatSync(path)
  if(stat.isDirectory())collect(path)
  else if(stat.isFile())files.push({path:relative(snapshot,path),bytes:stat.size,sha256:hash(readFileSync(path))})
  else if(stat.isSymbolicLink())files.push({path:relative(snapshot,path),kind:'tracked-relative-link',target:readlinkSync(path)})
  else throw new TypeError('RECOVERY_JOIN_SOURCE_TYPE_REFUSED')
}}
for(const path of ['packages/runtime-bridge',...inputs.map(input=>input.path),'packages/contracts'])collect(join(snapshot,path))
const pins={version:1,kind:'owner-recovery-source-join/v1',bridge_commit:bridgeCommit,
  dependencies:inputs.map(({path,commit})=>({path,commit})),files,synthetic_fixture:true,
  postgres_runtime_tested:false,process_isolation_tested:false,production_qualification:false,
  note:'Actual C P256 verification/durable files and D methods use disposable SQLite dialect fixtures. Cold service objects reopen existing stores. No PostgreSQL, IPC/UID qualification, real keys, deployment or stopped audit.'}
writeFileSync(join(output,'input-pins.json'),JSON.stringify(pins,null,2)+'\n',{mode:0o600})
const tests=['pilot-capture','workflow-store','owner-recovery','owner-logout','owner-forget','owner-forget-workflow']
const command=['--test',...tests.map(name=>'packages/runtime-bridge/test/'+name+'.test.mjs')]
const result=spawnSync(process.execPath,command,{cwd:snapshot,maxBuffer:16*1024*1024,env:process.env})
const log=Buffer.concat([result.stdout??Buffer.alloc(0),result.stderr??Buffer.alloc(0)])
writeFileSync(join(output,'checks.txt'),log,{mode:0o600})
const report={version:1,bridge_commit:bridgeCommit,status:result.status===0?'PASS':'FAIL',exit_code:result.status,
  command:[process.execPath,...command],checks_sha256:hash(log),input_pins_sha256:hash(readFileSync(join(output,'input-pins.json'))),snapshot,
  postgres_runtime_tested:false,process_isolation_tested:false,production_qualification:false}
writeFileSync(join(output,'result.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600})
function freeze(root){for(const name of readdirSync(root)){
  const path=join(root,name),stat=lstatSync(path)
  if(stat.isDirectory())freeze(path);else if(stat.isFile())chmodSync(path,0o444)
}chmodSync(root,0o555)}
freeze(snapshot)
process.stdout.write(JSON.stringify({status:report.status,output,bridge_commit:bridgeCommit})+'\n')
process.exitCode=result.status===0?0:1
