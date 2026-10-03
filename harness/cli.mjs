import {spawn,spawnSync} from 'node:child_process';
import {existsSync,mkdirSync,mkdtempSync,realpathSync,readFileSync,writeFileSync,chmodSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {privateDirectory,readPrivateJson,writePrivateJson,cleanOrigin} from './private-state.mjs';
import {readPreviewDeploymentManifest} from './deployment-manifest.mjs';
import {readOwnerMemoryBootConfig} from './owner-memory-boot.mjs';
import {verifyReleaseUi} from './release-integrity.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const packagesRoot=resolve(root,existsSync(resolve(root,'prime-release.json'))?'prime-packages':'packages');
const args=process.argv.slice(2),cmd=args.shift()??'help';
const value=(key,def)=>{const i=args.indexOf(key);return i<0?def:args[i+1];};
const release=resolve(root,value('--release-dir','.runtime/release'));
const state=resolve(root,value('--state-dir','.prime-state'));
const recordPath=resolve(state,'running.json');
function live(){if(!existsSync(recordPath))return{status:'stopped',pid:null,ui_url:null,version:'0.1.0',release_dir:release,release_digest:null,unavailable_capabilities:[]};const r=readPrivateJson(recordPath);if(r.ui_url)r.ui_url=cleanOrigin(r.ui_url);try{process.kill(r.pid,0);return{...r,status:r.ui_url?'running':'starting'}}catch(error){if(error.code==='ESRCH')return{...r,status:'stopped'};return{...r,status:'observation_unavailable',observation_error:error.code??'UNKNOWN'};}}
async function digest(){const entry=resolve(packagesRoot,'ops/gates.mjs');if(!existsSync(entry))throw new Error('PRIME_DIGEST_ENGINE_UNAVAILABLE');const {fullTreeDigest}=await import(pathToFileURL(entry).href);return fullTreeDigest(release).digest;}
if(cmd==='status'){const r=live();const safe={...r,ui_url:r.ui_url?new URL(r.ui_url).origin+'/':null,ui_access_file:resolve(state,'launch-url.json'),release_digest_algorithm:'aukora-prime:full-release:v1'};console.log(args.includes('--json')?JSON.stringify(safe):JSON.stringify(safe,null,2));}
else if(cmd==='stop'){const r=live();if(r.status!=='stopped'){const ps=spawnSync('ps',['-p',String(r.pid),'-o','command='],{encoding:'utf8'});if(!ps.stdout?.includes(resolve(r.release_dir,'harness/run.mjs')))throw new Error('REFUSED: process identity differs');process.kill(r.pid,'SIGTERM');console.log('Stopped owned Prime PID '+r.pid);}}
else if(cmd==='build'){const p=spawnSync(process.env.PRIME_PYTHON??'python3',[resolve(root,'scripts/build-dsh.py')],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else if(cmd==='compose'){const p=spawnSync(process.env.PRIME_PYTHON??'python3',[resolve(root,'scripts/compose.py'),release],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else if(cmd==='boot'){
 const deploymentPath=value('--deployment-manifest');if(!deploymentPath)throw new Error('PROTECTED_DEPLOYMENT_MANIFEST_REQUIRED');
 const prior=live();if(prior.status!=='stopped')throw new Error('Prime already owns a running process: '+prior.pid);
 const anchor=readPreviewDeploymentManifest({manifestPath:deploymentPath,releaseRoot:release});
 const expectedDigest=anchor.manifest.release_digest;
 const manifest=JSON.parse(readFileSync(resolve(release,'prime-release.json')));
 const releaseDigest=await digest();if(releaseDigest!==expectedDigest)throw new Error('PRIME_RELEASE_DIGEST_MISMATCH');
 await verifyReleaseUi({releaseRoot:release,expectedSnapshotSha256:anchor.manifest.ui_integrity_sha256});
 const ownerConfigPath=value('--owner-memory-config');
 if(args.includes('--owner-memory-config')&&!ownerConfigPath)throw new Error('PROTECTED_OWNER_MEMORY_CONFIG_REQUIRED');
 const ownerConfig=ownerConfigPath===undefined?undefined:readOwnerMemoryBootConfig({configPath:ownerConfigPath,releaseRoot:release,
  appDeployment:{source_commit:anchor.manifest.source_commit,release_digest:'sha256:'+releaseDigest}});
 privateDirectory(state,{create:true});for(const name of ['workspace','home','agents'])privateDirectory(resolve(state,name),{create:true});
 const env={PATH:process.env.PATH,HOME:resolve(state,'home'),DSH_HOME:resolve(state,'home'),DSH_AGENTS_HOME:resolve(state,'agents'),DSH_TELEMETRY_MODE:'DISABLED',DSH_TELEMETRY_DISABLED:'1',NODE_NO_WARNINGS:'1'};
 env.PRIME_RELEASE_DIGEST=releaseDigest;
 for(const key of ['PRIME_DEEPSEEK_KEY_FILE','PRIME_DEEPSEEK_BUDGET_FILE'])if(process.env[key])env[key]=process.env[key];
 const p=spawn(process.execPath,['--max-old-space-size=1536',resolve(release,'harness/run.mjs'),state,value('--port','18731'),deploymentPath,anchor.manifest_sha256,resolve(packagesRoot,'ops/gates.mjs'),
  ...(ownerConfig?[ownerConfigPath,ownerConfig.config_sha256]:[])],{cwd:resolve(state,'workspace'),env,stdio:['ignore','pipe','pipe','ipc']});
 const r={status:'starting',pid:p.pid,version:manifest.version,source_commit:manifest.source_commit,ui_url:null,release_dir:release,release_digest:releaseDigest,unavailable_capabilities:manifest.unavailable_capabilities,started_at:new Date().toISOString()};
 const save=()=>writePrivateJson(recordPath,r);save();
 p.on('message',message=>{if(message?.type!=='prime-ready'||message.pid!==p.pid)return;const u=new URL(message.url);if(u.pathname!=='/'||u.searchParams.size!==1||!u.searchParams.has('token'))throw new Error('PRIVATE_READY_REFUSED');r.ui_url=cleanOrigin(message.url);writePrivateJson(resolve(state,'launch-url.json'),{url:message.url,pid:p.pid});r.status='running';save();console.log('Prime UI '+r.ui_url);console.log('Running '+r.source_commit+'; unavailable: '+r.unavailable_capabilities.join(', '));});
 let buffer='';p.stdout.on('data',chunk=>{buffer+=chunk;const lines=buffer.split('\n');buffer=lines.pop();for(const line of lines)console.log(line.replace(/(token=)[^\s&'"]+/g,'$1<redacted>'));});
 p.stderr.on('data',chunk=>process.stderr.write(chunk.toString().replace(/(token=)[^\s&'"]+/g,'$1<redacted>')));
 for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>p.kill(signal));
 p.on('exit',code=>{r.status='stopped';save();process.exitCode=code??1;});
}
else if(cmd==='check'){const p=spawnSync(process.execPath,[resolve(packagesRoot,'ops/cli.mjs'),'check',args.shift()??'G1','--root',root,...args],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else if(cmd==='verify'&&args.length===0){
 // The reviewed source profile owns its exact checks and statuses. Evidence is
 // retained outside the candidate; no snapshot, credential or service is opened.
 const parent=mkdtempSync(join(realpathSync(tmpdir()),'aukora-prime-verify-'));
 const p=spawnSync(process.execPath,[resolve(packagesRoot,'ops/verify-fast.mjs'),'--root',root,'--evidence-dir',join(parent,'evidence')],{cwd:root,stdio:'inherit'});
 process.exitCode=p.status??1;
}
else if(['export','verify','restore'].includes(cmd)){const p=spawnSync(process.execPath,[resolve(packagesRoot,'memory/src/cli.mjs'),cmd,...args],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else {console.log('./prime build | compose | boot --deployment-manifest /etc/aukora-prime/preview-deployment.json [--owner-memory-config /absolute/protected/owner-memory.json] [--port 18731] [--state-dir DIR] | status --json | check G1 ... | verify | export OWNER OUTPUT | verify SNAPSHOT OWNER [RETAINED_HEADS_JSON] | restore SNAPSHOT OWNER AUTHORIZATION_JSON [RETAINED_HEADS_JSON]');}
