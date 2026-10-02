// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit protected app configuration, not provisioning or worker acceptance.
import {constants,existsSync,lstatSync,openSync,closeSync,fstatSync,readSync,realpathSync} from 'node:fs';
import {dirname,isAbsolute,join,parse,relative,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {parseIngressBytes} from './ingress.mjs';
import {validateBrowserBinding} from './next-host-services.mjs';
import {createOwnerMemoryIpcBoundary} from './owner-memory-ipc.mjs';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const {parseStrictJson}=await import(new URL(owned+'contracts/src/shared.mjs',import.meta.url));
const {createIpcClient}=await import(new URL(owned+'runtime-bridge/src/ipc.mjs',import.meta.url));
const MAX_BYTES=8192,HEX=/^[a-f0-9]{64}$/,ID=/^[A-Za-z0-9_.-]{1,128}$/;
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=reason=>{throw Object.assign(new Error('PRIME_OWNER_MEMORY_CONFIG: '+reason),{code:'PRIME_OWNER_MEMORY_CONFIG',reason});};
const freeze=value=>{if(value&&typeof value==='object'){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;};
function record(value,keys,optional=[]){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype
  ||Object.keys(value).some(key=>![...keys,...optional].includes(key))
  ||keys.some(key=>!Object.hasOwn(value,key)))fail('closed-config-required');
}
function absolute(value){
 if(typeof value!=='string'||value.length>4096||!isAbsolute(value)||resolve(value)!==value||/[\x00-\x1f\x7f]/u.test(value))fail('canonical-absolute-path-required');
 return value;
}
function deployment(value){
 record(value,['source_commit','release_digest']);
 if(typeof value.source_commit!=='string'||!/^[a-f0-9]{40}$/.test(value.source_commit)
  ||typeof value.release_digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(value.release_digest))fail('deployment-pin-required');
}
function validate(value,appDeployment){
 record(value,['version','kind','app_deployment','worker_deployment','channel','browserBinding']);
 if(value.version!==1||value.kind!=='prime-owner-memory-host/v1')fail('config-profile-required');
 deployment(value.app_deployment);deployment(value.worker_deployment);deployment(appDeployment);
 if(value.app_deployment.source_commit!==appDeployment.source_commit||value.app_deployment.release_digest!==appDeployment.release_digest)fail('app-deployment-mismatch');
 record(value.channel,['socketPath','credential','socketAccess'],['limits']);
 absolute(value.channel.socketPath);
 if(Buffer.byteLength(value.channel.socketPath)>103)fail('socket-path-bound');
 record(value.channel.credential,['id','secret']);
 if(typeof value.channel.credential.id!=='string'||!ID.test(value.channel.credential.id)
  ||typeof value.channel.credential.secret!=='string'||!/^(?:[a-f0-9]{2}){32,64}$/.test(value.channel.credential.secret))fail('ipc-credential-required');
 record(value.channel.socketAccess,['server_uid','client_uid','group_gid']);
 const access=value.channel.socketAccess;
 if(Object.values(access).some(n=>!Number.isSafeInteger(n)||n<=0)||access.server_uid===access.client_uid)fail('separated-socket-access-required');
 // The existing IPC client owns the actual bounds and authenticated role. This
 // preflight only rejects unknown/invalid limits and an unusable one-call cap.
 if(value.channel.limits!==undefined){
  const limits=value.channel.limits;
  record(limits,[],['maxFrameBytes','maxOutputBytes','maxConnections','maxInflight','maxInflightPerConnection','handshakeTimeoutMs','idleTimeoutMs','requestTimeoutMs','maxRequestsPerConnection']);
  for(const [key,n]of Object.entries(limits)){
   const max=key.endsWith('Bytes')?1048576:key.endsWith('Ms')?120000:1024;
   if(!Number.isSafeInteger(n)||n<1||n>max)fail('ipc-limit-bound');
  }
  if((limits.maxFrameBytes??65536)<1024||(limits.maxOutputBytes??65536)<512
   ||(limits.maxOutputBytes??65536)>(limits.maxFrameBytes??65536)
   ||(limits.maxRequestsPerConnection??256)<2)fail('ipc-limit-bound');
 }
 try{validateBrowserBinding(value.browserBinding);}catch{fail('browser-binding-required');}
 return freeze(value);
}

/** Pure syntax/pin validation. This alone supplies no protected host input. */
export function parseOwnerMemoryBootConfig(bytes,{appDeployment}={}){
 let value;
 try{value=parseIngressBytes(bytes,parseStrictJson,{maxBytes:MAX_BYTES,maxDepth:16});}catch{fail('strict-json-required');}
 return validate(value,appDeployment);
}
const identity=stat=>({dev:stat.dev,ino:stat.ino,uid:stat.uid,gid:stat.gid,mode:stat.mode&0o7777,nlink:stat.nlink,size:stat.size,mtime_ms:stat.mtimeMs,ctime_ms:stat.ctimeMs});
const same=(a,b)=>Object.keys(a).every(key=>a[key]===b[key]);
function metadata(path){try{return lstatSync(path);}catch{fail('config-unavailable');}}
function file(path,gid){
 const stat=metadata(path);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||stat.uid!==0||stat.gid!==gid||(stat.mode&0o7777)!==0o440)fail('root-owned-0440-config-required');
 return stat;
}
function ancestors(path,gid){
 let current=parse(path).root;const paths=[current];
 for(const part of dirname(path).slice(current.length).split('/').filter(Boolean)){current=join(current,part);paths.push(current);}
 return paths.map(path=>{
  const stat=metadata(path);
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==0||(stat.mode&0o022))fail('protected-root-ancestor-required');
  if(path===paths.at(-1)&&(stat.gid!==gid||(stat.mode&0o7777)!==0o750))fail('root-owned-0750-parent-required');
  return {path,identity:identity(stat)};
 });
}

/** No discovery, chmod, credentials or state creation. Parent and child both
 * read the same root-protected config; only its path/hash crosses spawn. */
export function readOwnerMemoryBootConfig({configPath,releaseRoot,appDeployment,expectedConfigSha256}={}){
 absolute(configPath);absolute(releaseRoot);
 const rel=relative(releaseRoot,configPath);
 if(rel===''||rel!=='..'&&!rel.startsWith('../')&&!isAbsolute(rel))fail('config-outside-release-required');
 if(expectedConfigSha256!==undefined&&(typeof expectedConfigSha256!=='string'||!HEX.test(expectedConfigSha256)))fail('expected-config-hash-required');
 if(typeof process.getuid!=='function'||typeof process.getgid!=='function'||typeof process.geteuid!=='function'||typeof process.getegid!=='function'
  ||process.getuid()<=0||process.getuid()!==process.geteuid()||process.getgid()<=0||process.getgid()!==process.getegid())fail('nonroot-app-identity-required');
 const gid=process.getgid(),beforeAncestors=ancestors(configPath,gid);
 try{if(realpathSync(dirname(configPath))!==dirname(configPath))fail('protected-root-ancestor-required');}
 catch(error){if(error.code==='PRIME_OWNER_MEMORY_CONFIG')throw error;fail('protected-root-ancestor-required');}
 const before=file(configPath,gid);
 if(before.size>MAX_BYTES)fail('config-size-bound');
 let fd;
 try{
  fd=openSync(configPath,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  const opened=fstatSync(fd);
  if(!same(identity(before),identity(opened)))fail('config-identity-changed');
  const buffer=Buffer.alloc(MAX_BYTES+1);let length=0,count;
  do{count=readSync(fd,buffer,length,buffer.length-length,length);length+=count;}while(count&&length<buffer.length);
  if(length>MAX_BYTES)fail('config-size-bound');
  const bytes=buffer.subarray(0,length),configHash=hash(bytes);
  if(expectedConfigSha256!==undefined&&configHash!==expectedConfigSha256)fail('config-hash-changed');
  const config=parseOwnerMemoryBootConfig(bytes,{appDeployment});
  if(config.channel.socketAccess.client_uid!==process.getuid())fail('configured-app-uid-mismatch');
  const afterAncestors=ancestors(configPath,gid);
  if(!same(identity(opened),identity(fstatSync(fd)))||!same(identity(opened),identity(file(configPath,gid)))||opened.size!==length
   ||beforeAncestors.some((item,index)=>item.path!==afterAncestors[index]?.path||!same(item.identity,afterAncestors[index].identity)))fail('config-identity-changed');
  return Object.freeze({config,config_sha256:configHash});
 }catch(error){if(error.code==='PRIME_OWNER_MEMORY_CONFIG')throw error;fail('protected-config-read-refused');}
 finally{if(fd!==undefined)closeSync(fd);}
}

/** The actual existing authenticated IPC client is the only transport. Making
 * this object opens no channel; it creates no C/D service or qualification. */
export function createOwnerMemoryBootServices(config){
 // Detach again so a caller cannot change a channel or review pin after supply.
 const fixed=parseOwnerMemoryBootConfig(Buffer.from(JSON.stringify(config)),{appDeployment:config?.app_deployment});
 let active=true;
 const boundary=createOwnerMemoryIpcBoundary({channel:fixed.channel,deployment:fixed.worker_deployment,isActive:()=>active,
  async connect(channel){
   const client=await createIpcClient(channel);
   // Role comes from the MAC-authenticated server handshake, never the JSON
   // config or request. A read-only credential cannot enable owner controls.
   if(client.role!=='owner_control'){try{await client.close();}finally{fail('owner-control-channel-required');}}
   return client;
  }});
 const profile=fixed.browserBinding.ownerBinding.passkeyProfile;
 const services=Object.freeze({
  browserBinding:fixed.browserBinding,
  ownerMemory:Object.freeze({channel:fixed.channel,deployment:fixed.worker_deployment,guardRequest({host,origin}){
   if(!active||host!==new URL(profile.origin).host||origin!==profile.origin)return undefined;
   return profile;
  }}),
  isOwnerMemoryActive:()=>active,
  readOwnerMemoryCapability:()=>boundary.handlePublic('capability.status',{}),
 });
 return Object.freeze({services,dispose(){active=false;}});
}

/** Used only by pinned boot's pre-entry callback. Capture provide()'s owned
 * withdrawal in the same effect; a callback return alone is not a disposer. */
export function provideOwnerMemoryBootServices(host,config){
 return host.effect(function*(){
  const supplied=createOwnerMemoryBootServices(config);
  yield ()=>supplied.dispose();
  const remove=host.provide('primeNextHostServices',supplied.services);
  yield remove;
  yield async()=>{supplied.dispose();await remove();};
 },'prime protected owner-memory boot supply');
}

/** Existing preview JSON keeps its shape. Presence does not enable controls;
 * only the authenticated, still-current worker capability can remove IDs. */
export async function observeOwnerMemoryCapabilities(unavailable,services,isCurrent){
 const pending=[...unavailable];
 const current=()=>{try{return typeof isCurrent==='function'&&isCurrent()===true&&services?.isOwnerMemoryActive?.()===true;}catch{return false;}};
 if(typeof services?.readOwnerMemoryCapability!=='function'||!current())return pending;
 let observed;
 try{observed=await services.readOwnerMemoryCapability();}catch{return pending;}
 if(!current()||observed?.ok!==true||observed.available!==true||observed.public_routes!=='available'
  ||observed.public_dispatch!=='qualified-owner-memory/v1'
  ||typeof services.ownerMemory?.deployment?.source_commit!=='string'||typeof services.ownerMemory?.deployment?.release_digest!=='string'
  ||observed.qualification?.source_commit!==services.ownerMemory.deployment.source_commit
  ||observed.qualification?.release_digest!==services.ownerMemory.deployment.release_digest)return pending;
 return pending.filter(id=>id!=='owner-passkey'&&id!=='durable-memory');
}
