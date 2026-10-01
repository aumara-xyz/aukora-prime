import {spawn,spawnSync} from 'node:child_process';
import {existsSync,mkdirSync,readFileSync,writeFileSync,chmodSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const args=process.argv.slice(2),cmd=args.shift()??'help';
const value=(key,def)=>{const i=args.indexOf(key);return i<0?def:args[i+1];};
const release=resolve(root,value('--release-dir','.runtime/release'));
const state=resolve(root,value('--state-dir','.prime-state'));
const recordPath=resolve(state,'running.json');
function live(){if(!existsSync(recordPath))return{status:'stopped',pid:null,ui_url:null,version:'0.1.0',release_dir:release,release_digest:null,unavailable_capabilities:[]};const r=JSON.parse(readFileSync(recordPath));try{process.kill(r.pid,0);return{...r,status:r.ui_url?'running':'starting'}}catch{return{...r,status:'stopped'}}}
async function digest(){if(existsSync(resolve(root,'packages/ops/gates.mjs'))){const {fullTreeDigest}=await import('../packages/ops/gates.mjs');return fullTreeDigest(release);}return null;}
if(cmd==='status'){const r=live();console.log(args.includes('--json')?JSON.stringify(r):JSON.stringify(r,null,2));}
else if(cmd==='build'){const p=spawnSync(process.env.PRIME_PYTHON??'python3',[resolve(root,'scripts/build-dsh.py')],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else if(cmd==='compose'){const p=spawnSync(process.env.PRIME_PYTHON??'python3',[resolve(root,'scripts/compose.py')],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else if(cmd==='boot'){
 const prior=live();if(prior.status!=='stopped')throw new Error('Prime already owns a running process: '+prior.pid);
 if(!existsSync(resolve(release,'prime-release.json'))){const p=spawnSync(process.env.PRIME_PYTHON??'python3',[resolve(root,'scripts/compose.py')],{cwd:root,stdio:'inherit'});if(p.status!==0)process.exit(p.status??1);}
 const manifest=JSON.parse(readFileSync(resolve(release,'prime-release.json')));
 mkdirSync(state,{recursive:true,mode:0o700});mkdirSync(resolve(state,'workspace'),{recursive:true});mkdirSync(resolve(state,'home'),{recursive:true});
 const env={PATH:process.env.PATH,HOME:resolve(state,'home'),DSH_HOME:resolve(state,'home'),DSH_AGENTS_HOME:resolve(state,'agents'),DSH_TELEMETRY_MODE:'DISABLED',DSH_TELEMETRY_DISABLED:'1',NODE_NO_WARNINGS:'1'};
 const p=spawn(process.execPath,[resolve(release,'apps/cli/lib/bin.js'),'web','--profile','web','--patch',resolve(release,'prime.patch.yml'),'--host','127.0.0.1','--port',value('--port','18731'),'--no-open'],{cwd:resolve(state,'workspace'),env,stdio:['ignore','pipe','pipe']});
 const r={status:'starting',pid:p.pid,version:manifest.version,source_commit:manifest.source_commit,ui_url:null,release_dir:release,release_digest:await digest(),unavailable_capabilities:manifest.unavailable_capabilities,started_at:new Date().toISOString()};
 const save=()=>{writeFileSync(recordPath,JSON.stringify(r,null,2)+'\n',{mode:0o600});chmodSync(recordPath,0o600);};save();
 let buffer='';p.stdout.on('data',chunk=>{buffer+=chunk;const lines=buffer.split('\n');buffer=lines.pop();for(const line of lines){const m=/dsh web: (http\\S+)/.exec(line);if(m){r.ui_url=m[1];r.status='running';save();console.log('Prime UI '+r.ui_url);console.log('Running '+r.source_commit+'; unavailable: '+r.unavailable_capabilities.join(', '));}else console.log(line.replace(/(token=)[^\\s&'"]+/g,'$1<redacted>'));}});
 p.stderr.on('data',chunk=>process.stderr.write(chunk.toString().replace(/(token=)[^\\s&'"]+/g,'$1<redacted>')));
 for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>p.kill(signal));
 p.on('exit',code=>{r.status='stopped';save();process.exitCode=code??1;});
}
else if(cmd==='check'){const p=spawnSync(process.execPath,[resolve(root,'packages/ops/cli.mjs'),'check',args.shift()??'G1','--root',root,...args],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else if(['export','verify','restore'].includes(cmd)){const p=spawnSync(process.execPath,[resolve(root,'packages/memory/src/cli.mjs'),cmd,...args],{cwd:root,stdio:'inherit'});process.exitCode=p.status??1;}
else {console.log('./prime build | compose | boot [--port 18731] [--state-dir DIR] | status --json | check G1 ... | export | verify | restore --into EMPTY_DIR');}

