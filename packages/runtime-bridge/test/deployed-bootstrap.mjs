// SPDX-License-Identifier: AGPL-3.0-or-later
// SYNTHETIC local setup/worker entry. H supplies protected configs and identities.
// Does not create OS identities, credentials, directories, units, schemas or PG processes.
import {resolve} from 'node:path'
import {fileURLToPath} from 'node:url'
import {canonicalJson} from '../../contracts/src/runtime.mjs'
import {provisionNewAuthorityStore} from '../../authority/src/index.mjs'
import {startWorker} from '../src/worker.mjs'
import {createPostgresWorkflowStore} from '../src/workflow-store.mjs'
import {closed,copy} from '../src/registry.mjs'
import {IDS,dFixture,validateProfile,readRootJson,fixturePaths,authorityConfig,registryEntries,scenario,credentialId,memoryCredentialId,validateCredential,access,must} from './deployed-profile.mjs'

const DIAGNOSTIC_NAMES=new Set(['Error','TypeError','SyntaxError','RangeError','MemoryRefusal','RollbackRefusedError'])
const DIAGNOSTIC_CODES=new Set(['INVALID','UNAVAILABLE','UNAUTHORIZED','REPLAYED','RECONCILIATION_REQUIRED','SYNTHETIC_FIXTURE_REFUSED','EACCES','EPERM','ENOENT','ENOTDIR','EEXIST','EADDRINUSE','ENAMETOOLONG'])
const DIAGNOSTIC_REASONS=new Set(['IPC_PRIVATE_HOST_SOCKET_DIRECTORY_REQUIRED','IPC_PROVISIONED_SOCKET_ACCESS_REQUIRED','IPC_SOCKET_PATH_ALREADY_EXISTS','EXACT_FIXTURE_PROCESS_ID_REQUIRED','ROOT_PROTECTED_FIXTURE_FILE_REQUIRED','ROOT_PROTECTED_FIXTURE_PARENT_REQUIRED','EXACT_FIXTURE_IPC_CREDENTIAL_REQUIRED','EXACT_FIXTURE_SERVER_REQUIRED','EXACT_FIXTURE_SERVER_CREDENTIALS_REQUIRED','EXACT_FIXTURE_ROLE_REQUIRED','EXACT_PRIVATE_AUTHORITY_CHANNEL_REQUIRED'])
const DIAGNOSTIC_MESSAGES=new Map([
  ['INVALID: IPC credential identity/role','IPC_CREDENTIAL_IDENTITY_OR_ROLE_INVALID'],
  ['INVALID: IPC credential identity','IPC_CREDENTIAL_IDENTITY_INVALID'],
  ['INVALID: host IPC credentials/handler','IPC_CREDENTIALS_OR_HANDLER_INVALID'],
  ['INVALID: host IPC secret','IPC_SECRET_FORMAT_INVALID'],
  ['INVALID: absolute bounded Unix socket path','IPC_SOCKET_PATH_INVALID'],
  ['INVALID: closed trusted worker config','WORKER_CONFIG_SHAPE_INVALID'],
  ['INVALID: closed bridge fields','BRIDGE_FIELDS_INVALID'],
])
function errorData(error,key){
  if(!error||typeof error!=='object')return undefined
  try{for(let level=0,value=error;value&&level<3;value=Object.getPrototypeOf(value),level++){
    const descriptor=Object.getOwnPropertyDescriptor(value,key)
    if(descriptor)return Object.hasOwn(descriptor,'value')?descriptor.value:undefined
  }}catch{return undefined}
}
/** Closed symbolic startup diagnostics only: never raw messages, stack/cause,
 * config, paths, signatures or credentials, including for unknown errors. */
export function fixtureStartupDiagnostic(error){
  const candidateName=errorData(error,'name'),name=DIAGNOSTIC_NAMES.has(candidateName)?candidateName:'Error'
  const candidateCode=errorData(error,'code')??errorData(error,'error_code'),code=DIAGNOSTIC_CODES.has(candidateCode)?candidateCode:['TypeError','SyntaxError','RangeError'].includes(name)?'INVALID':'UNAVAILABLE'
  const message=errorData(error,'message'),reason=DIAGNOSTIC_MESSAGES.get(message)??(DIAGNOSTIC_REASONS.has(message)?message:'STARTUP_DETAIL_SUPPRESSED')
  return Object.freeze({version:1,kind:'prime-private-cd-pg-startup-diagnostic/v1',name,code,reason})
}

function server(config,path,credentials,expectedAccess){
  closed(config,['socketPath','credentials','socketAccess'])
  must(config.socketPath===path&&canonicalJson(config.socketAccess)===canonicalJson(expectedAccess),'EXACT_FIXTURE_SERVER_REQUIRED')
  must(Array.isArray(config.credentials)&&config.credentials.length===credentials.length,'EXACT_FIXTURE_SERVER_CREDENTIALS_REQUIRED')
  for(const [i,{id,role}] of credentials.entries()){
    const entry=config.credentials[i];closed(entry,['id','role','secret']);validateCredential({id:entry.id,secret:entry.secret},id);must(entry.role===role,'EXACT_FIXTURE_ROLE_REQUIRED')
  }
  return copy(config)
}
export async function buildAuthorityWorker(config){
  closed(config,['version','kind','synthetic_fixture','profile','ipc'])
  must(config.version===1&&config.kind==='prime-private-cd-pg-authority/v1'&&config.synthetic_fixture===true,'FIXTURE_AUTHORITY_CONFIG_REQUIRED')
  const profile=await validateProfile(config.profile),paths=fixturePaths(profile)
  const ipc=server(config.ipc,paths.authoritySocket,[{id:memoryCredentialId(profile),role:'memory_effect'}],access(IDS.authority,IDS.memory,IDS.authorityIpc))
  return {kind:'authority',ipc,registryEntries:registryEntries(profile),authorityConfig:authorityConfig(profile)}
}
export async function buildMemoryWorker(config){
  closed(config,['version','kind','synthetic_fixture','profile','ipc','authority_channel'])
  must(config.version===1&&config.kind==='prime-private-cd-pg-memory/v1'&&config.synthetic_fixture===true,'FIXTURE_MEMORY_CONFIG_REQUIRED')
  const profile=await validateProfile(config.profile),paths=fixturePaths(profile),helper=await dFixture()
  const ipc=server(config.ipc,paths.memorySocket,['primary','secondary'].map(owner=>({id:credentialId(profile,owner),role:'owner_control'})),access(IDS.memory,IDS.app,IDS.memoryIpc))
  closed(config.authority_channel,['socketPath','credential','socketAccess'])
  must(config.authority_channel.socketPath===paths.authoritySocket&&canonicalJson(config.authority_channel.socketAccess)===canonicalJson(access(IDS.authority,IDS.memory,IDS.authorityIpc)),'EXACT_PRIVATE_AUTHORITY_CHANNEL_REQUIRED')
  validateCredential(config.authority_channel.credential,memoryCredentialId(profile))
  return {kind:'memory',ipc,authorityChannel:copy(config.authority_channel),registryEntries:registryEntries(profile),initializeSchema:false,indexTarget:'postgres:fts:simple:v1',indexGeneration:'1',
    createPgPool:()=>helper.createWorkerPostgresPool({config:profile.postgres,fixture:profile.fixture,schema:'source',memoryUid:IDS.memory}),
    resolveHostContext({request,session}){
      const owner=['primary','secondary'].find(owner=>request?.transport==='ipc'&&request.credential_id===credentialId(profile,owner))
      must(owner,'AUTHENTICATED_FIXTURE_ACTOR_REQUIRED');const registered=profile.fixture.owners[owner]
      if(!session)return {login_owner_id:registered.owner_id}
      must(session.owner_id===registered.owner_id&&session.subject===registered.owner_subject,'FIXTURE_CHANNEL_OWNER_REQUIRED')
      return {task_id:registered.task_id,memory_host:scenario(profile,owner).host}
    }}
}
async function main(){
  const args=process.argv.slice(2)
  must([6,8].includes(args.length)&&args[0]==='--config'&&args[2]==='--role'&&args[4]==='--phase'&&['authority','memory'].includes(args[3])&&['provision','initialize','serve','verify'].includes(args[5])&&(args.length===6||args[6]==='--expected'),'CLOSED_LOCAL_FIXTURE_COMMAND_REQUIRED')
  const role=args[3],phase=args[5],config=await readRootJson(args[1],IDS[role],IDS[role+'Group'])
  const workerConfig=await (role==='authority'?buildAuthorityWorker(config):buildMemoryWorker(config))
  let report
  if(phase==='provision'){
    must(role==='authority'&&args.length===6,'AUTHORITY_LOCAL_SETUP_ONLY')
    report=provisionNewAuthorityStore({...workerConfig.authorityConfig,provisionTrustedState:true})
    must(report.ok===true&&report.status==='PROVISIONED','FRESH_AUTHORITY_STORE_REQUIRED')
  }else if(phase==='initialize'){
    must(role==='memory'&&args.length===6,'MEMORY_LOCAL_SETUP_ONLY')
    report=await (await dFixture()).initializeWorkerPostgresSchema({config:config.profile.postgres,fixture:config.profile.fixture,schema:'source',memoryUid:IDS.memory})
    const pool=await workerConfig.createPgPool()
    try{report={...report,workflow_reference_schema:await createPostgresWorkflowStore({pool}).migrate()}}finally{await pool.end()}
  }else if(phase==='verify'){
    must(role==='memory'&&args.length===8,'MEMORY_LOCAL_VERIFICATION_ONLY')
    const expected=await readRootJson(args[7],IDS.memory,IDS.memoryGroup),helper=await dFixture(),pool=await workerConfig.createPgPool()
    try{report=await helper.verifyWorkerPostgresSave({pool,fixture:config.profile.fixture,expected,project:false})}finally{await pool.end()}
  }else{
    must(args.length===6,'SERVE_HAS_NO_EXTRA_ARGUMENTS')
    const worker=await startWorker(workerConfig)
    process.stdout.write(JSON.stringify({status:'STARTED',synthetic_fixture:true,...worker.status()})+'\n')
    let stopping=false
    const stop=async()=>{if(stopping)return;stopping=true;await worker.close();process.exit(0)}
    process.once('SIGTERM',stop);process.once('SIGINT',stop);return
  }
  process.stdout.write(JSON.stringify({synthetic_fixture:true,phase,report})+'\n')
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{const diagnostic=fixtureStartupDiagnostic(error);process.stderr.write('SYNTHETIC_FIXTURE_BOOTSTRAP_REFUSED:'+diagnostic.code+'\n'+JSON.stringify(diagnostic)+'\n');process.exitCode=1})
