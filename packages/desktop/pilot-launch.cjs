// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict'
// One owner-selected CPU connection. Never reads or transfers a provider key.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {spawn}=require('node:child_process');
const {DEFAULT_ORIGIN}=require('./policy.cjs');
let temporary,tunnel,desktop,access,closing=false,closed;
const fail=()=>{throw new Error('PRIME_CPU_LAUNCH_UNAVAILABLE');};
function privateJson(file){
 if(!path.isAbsolute(file))fail();
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const st=fs.fstatSync(fd);if(!st.isFile()||st.nlink!==1||st.uid!==process.getuid()||(st.mode&0o077)||st.size>16384)fail();return JSON.parse(fs.readFileSync(fd,'utf8'));}
 finally{fs.closeSync(fd);}
}
function collect(child,input){return new Promise((resolve,reject)=>{
 const chunks=[];let size=0,done=false;
 const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(value);};
 const timer=setTimeout(()=>{child.kill();finish(new Error('CPU_ACCESS_TIMEOUT'));},15000);
 child.stdout.on('data',part=>{size+=part.length;if(size>16384){child.kill();finish(new Error('CPU_ACCESS_BOUND'));}else chunks.push(part);});
 child.stderr.on('data',()=>{});child.on('error',()=>finish(new Error('CPU_ACCESS_UNAVAILABLE')));
 child.on('close',code=>finish(code===0?undefined:new Error('CPU_ACCESS_REFUSED'),Buffer.concat(chunks)));
 child.stdin.on('error',()=>finish(new Error('CPU_ACCESS_UNAVAILABLE')));
 child.stdin.end(input);
});}
function stop(child){
 if(!child?.pid||child.exitCode!==null||child.signalCode!==null)return Promise.resolve();
 return new Promise(resolve=>{const timer=setTimeout(()=>child.kill('SIGKILL'),8000);child.once('close',()=>{clearTimeout(timer);resolve();});child.kill('SIGTERM');});
}
function cleanup(){
 if(closing)return closed;closing=true;
 return closed=(async()=>{
  await stop(desktop);await stop(access);await stop(tunnel);
  if(temporary)try{fs.rmSync(temporary,{recursive:true,force:true});}catch{}
 })();
}
for(const [signal,code]of [['SIGINT',130],['SIGTERM',143]])process.on(signal,()=>{process.exitCode=code;void cleanup();});
(async()=>{
 const config=privateJson(process.argv[2]??'');
 const required=['version','host','user','identity_file','known_hosts_file','remote_access_file','remote_port','electron_runtime'];
 if(!config||Object.keys(config).sort().join(',')!==required.sort().join(',')||config.version!==1
  ||!/^[A-Za-z0-9.-]+$/.test(config.host)||!/^[a-z_][a-z0-9_-]*$/.test(config.user)
  ||!['identity_file','known_hosts_file','remote_access_file','electron_runtime'].every(k=>typeof config[k]==='string'&&path.isAbsolute(config[k])&&!/[\x00-\x1f\x7f]/u.test(config[k]))
  ||!/^\/[A-Za-z0-9._/-]+$/.test(config.remote_access_file)||!Number.isSafeInteger(config.remote_port)||config.remote_port<1024||config.remote_port>65535)fail();
 temporary=fs.mkdtempSync(path.join(os.tmpdir(),'prime-cpu-launch-'));fs.chmodSync(temporary,0o700);
 const control=path.join(temporary,'ssh-control'),target=config.user+'@'+config.host;
 const common=['-F','/dev/null','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
  '-o','GlobalKnownHostsFile=/dev/null','-o','UserKnownHostsFile='+config.known_hosts_file,
  '-o','UpdateHostKeys=no','-o','ConnectTimeout=10','-o','ConnectionAttempts=1',
  '-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','-i',config.identity_file];
 tunnel=spawn('/usr/bin/ssh',[...common,'-N','-T','-o','ExitOnForwardFailure=yes','-o','ControlMaster=yes','-S',control,
  '-L','127.0.0.1:18731:127.0.0.1:'+config.remote_port,target],{stdio:['ignore','ignore','pipe']});
 tunnel.stderr.on('data',()=>{});let tunnelError=false;
 tunnel.on('error',()=>{tunnelError=true;});tunnel.on('close',()=>{tunnelError=true;if(desktop&&!closing){process.exitCode=1;void cleanup();}});
 const deadline=Date.now()+12000;
 while(!fs.existsSync(control)){if(closing||tunnelError||Date.now()>=deadline)fail();await new Promise(resolve=>setTimeout(resolve,100));}
 // The selected owner-private descriptor is the legitimate launch-token path.
 // Capture it directly to memory/private disk; never print tokens or cookies.
 const read=`import os,stat,json,sys\np=sys.argv[1]\nfd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\ns=os.fstat(fd)\nassert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and not(s.st_mode&0o077) and s.st_size<=16384\nb=os.read(fd,16385)\nos.close(fd)\nd=json.loads(b)\nassert set(d)=={'url','pid'} and type(d['pid']) is int and d['pid']>0\nsys.stdout.write(json.dumps(d))\n`;
 access=spawn('/usr/bin/ssh',[...common,'-T','-S',control,target,'python3 - '+config.remote_access_file],{stdio:['pipe','pipe','pipe']});
 const received=await collect(access,read);
 if(closing||tunnelError){received.fill(0);fail();}
 let launch;try{launch=JSON.parse(received.toString('utf8'));}finally{received.fill(0);}
 const remote=new URL(launch.url);
 if(!['http://127.0.0.1:'+config.remote_port,'http://localhost:'+config.remote_port].includes(remote.origin)
  ||remote.username||remote.password||remote.pathname!=='/'||remote.hash
  ||[...remote.searchParams.keys()].join(',')!=='token'||!remote.searchParams.get('token')||!Number.isSafeInteger(launch.pid)||launch.pid<1)fail();
 const local=new URL(DEFAULT_ORIGIN);local.search=remote.search;
 const file=path.join(temporary,'launch-url.json');fs.writeFileSync(file,JSON.stringify({url:local.href,pid:launch.pid}),{mode:0o600,flag:'wx'});
 const pid=String(launch.pid);launch=undefined;
 desktop=spawn(process.execPath,[path.join(__dirname,'run.cjs'),'--access-file',file,'--expected-pid',pid,'--electron-runtime',config.electron_runtime],{stdio:'inherit',cwd:__dirname});
 desktop.on('error',()=>{process.exitCode=1;void cleanup();});
 desktop.on('close',code=>{if(!closing)process.exitCode=code??1;void cleanup();});
})().catch(async()=>{await cleanup();console.error('Prime CPU launch unavailable: check the private pilot configuration, current owner launch descriptor and free loopback port 18731.');process.exitCode??=1;});
