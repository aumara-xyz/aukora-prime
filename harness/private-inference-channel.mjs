// SPDX-License-Identifier: AGPL-3.0-or-later
// Unmounted H app → E Unix channel. Importing opens no socket or service.
// Protected PSK/identity/path/bounds are caller inputs; no credential discovery,
// owner authentication, readiness, grant, retry or model loop is supplied here.
import net from 'node:net';
import {existsSync} from 'node:fs';
import {lstat,realpath,chmod,chown,unlink} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';
import {createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
const owned=existsSync(new URL('../prime-release.json',import.meta.url))?'../prime-packages/':'../packages/';
const {canonicalJson,parseStrictJson}=await import(new URL(owned+'contracts/src/runtime.mjs',import.meta.url));
const {createPrivateInferenceDispatch,createPrivateInferenceReceiver}=await import(new URL(owned+'inference/src/private-transport.mjs',import.meta.url));

const VERSION=1,PROFILE='aukora-prime.private-inference-generate/v1';
const HEX=/^[a-f0-9]{64}$/u,ID=/^[A-Za-z0-9_.-]{1,128}$/u;
const fail=()=>Object.assign(new Error('PRIVATE_INFERENCE_CHANNEL_UNAVAILABLE'),{code:'PRIVATE_INFERENCE_CHANNEL_UNAVAILABLE'});
const invalid=()=>{throw fail();};
const closed=(value,keys)=>{
 if(!value||typeof value!=='object'||Array.isArray(value)
  ||Object.keys(value).sort().join(',')!==[...keys].sort().join(','))invalid();
};
const copy=(value,maxBytes)=>parseStrictJson(canonicalJson(value),{maxBytes,maxDepth:32});
function bounds(value){
 closed(value,['max_request_ms','max_request_bytes','max_result_bytes','handshake_timeout_ms','max_connections']);
 const limits=copy(value,1024);
 for(const [key,n] of Object.entries(limits)){
  const max=key.endsWith('_bytes')?2*1024*1024:key==='max_connections'?32:60000;
  if(!Number.isSafeInteger(n)||n<1||n>max)invalid();
 }
 if(limits.handshake_timeout_ms>limits.max_request_ms)invalid();
 // Compact inner JSON has no raw controls; outer string escaping is <=2x.
 return Object.freeze({...limits,max_frame_bytes:Math.max(1024,limits.max_request_bytes*2+512,limits.max_result_bytes+512)});
}
function accessPolicy(value){
 closed(value,['server_uid','client_uid','group_gid']);
 const access=copy(value,1024);
 if(Object.values(access).some(n=>!Number.isSafeInteger(n)||n<1)||access.server_uid===access.client_uid)invalid();
 return Object.freeze(access);
}
function identity(access,side,actual){
 if(!['client','server'].includes(side)||actual.platform!=='linux'
  ||actual.uid!==access[side==='client'?'client_uid':'server_uid']||actual.uid===0
  ||actual.euid!==actual.uid||actual.euid===0
  ||!Array.isArray(actual.groups)||!actual.groups.includes(access.group_gid))invalid();
}
function assertIdentity(access,side){
 if(typeof process.getuid!=='function'||typeof process.geteuid!=='function'
  ||typeof process.getgid!=='function'||typeof process.getgroups!=='function')invalid();
 identity(access,side,{platform:process.platform,uid:process.getuid(),euid:process.geteuid(),groups:[process.getgid(),...process.getgroups()]});
}
function pathInput(path){
 if(typeof path!=='string'||resolve(path)!==path||Buffer.byteLength(path)>103||path.includes('\0')||dirname(path)===path)invalid();
 return path;
}
function credentialInput(value){
 closed(value,['id','secret']);
 if(typeof value.id!=='string'||!ID.test(value.id)||!(value.secret instanceof Uint8Array)
  ||value.secret.byteLength<32||value.secret.byteLength>64)invalid();
 return {id:value.id,secret:Buffer.from(value.secret)};
}
const base=type=>({version:VERSION,profile:PROFILE,type});
const mac=(key,domain,value)=>createHmac('sha256',key).update(PROFILE+'\0'+domain+'\0'+canonicalJson(value)).digest('hex');
const signed=(key,domain,value)=>({...value,mac:mac(key,domain,value)});
function verify(key,domain,value){
 const {mac:signature,...message}=value;
 if(typeof signature!=='string'||!HEX.test(signature)
  ||!timingSafeEqual(Buffer.from(signature,'hex'),Buffer.from(mac(key,domain,message),'hex')))invalid();
 return message;
}
function frameProfile(value){if(value.version!==VERSION||value.profile!==PROFILE)invalid();}
function transcript({path,access,credential_id,server_nonce,client_nonce}){
 return {...base('binding'),socket_path:path,...access,credential_id,server_nonce,client_nonce};
}
function keyFor(secret,binding){return Buffer.from(mac(secret,'session',binding),'hex');}

/** Pure length-prefixed codec used by the actual channel. No socket/test hook. */
function codec(limits){
 const parse=bytes=>{
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  const value=parseStrictJson(text,{maxBytes:limits.max_frame_bytes,maxDepth:32});
  if(canonicalJson(value)!==text)invalid();
  return value;
 };
 const encode=value=>{
  const body=Buffer.from(canonicalJson(value),'utf8');
  if(!body.length||body.length>limits.max_frame_bytes)invalid();
  const header=Buffer.alloc(4);header.writeUInt32BE(body.length);
  return Buffer.concat([header,body]);
 };
 const decoder=(onFrame,onFault)=>{
  const header=Buffer.alloc(4);let head=0,body=null,used=0,stopped=false;
  return Object.freeze({push(chunk){
   if(stopped)return;
   try{
    if(!(chunk instanceof Uint8Array))invalid();
    let offset=0;
    while(offset<chunk.length&&!stopped){
     if(!body){
      const n=Math.min(4-head,chunk.length-offset);header.set(chunk.subarray(offset,offset+n),head);head+=n;offset+=n;
      if(head!==4)continue;
      const size=header.readUInt32BE();head=0;
      if(!size||size>limits.max_frame_bytes)invalid();
      body=Buffer.alloc(size);used=0;
     }
     const n=Math.min(body.length-used,chunk.length-offset);body.set(chunk.subarray(offset,offset+n),used);used+=n;offset+=n;
     if(used===body.length){const complete=body;body=null;onFrame(parse(complete));}
    }
   }catch{stopped=true;body=null;onFault(fail());}
  },close(){stopped=true;body=null;}});
 };
 return Object.freeze({encode,decoder});
}

/** One connection, one sequence-1 generate. E alone validates its envelope.
 * Nonces below are local challenge inputs; production always uses randomBytes.
 * The server constructs its signal only after authenticating this invocation. */
function peer({side,path,access,credential,nonce,limits}){
 if(!['client','server'].includes(side)||typeof nonce!=='string'||!HEX.test(nonce))invalid();
 const pin=credentialInput(credential),policy=accessPolicy(access);pathInput(path);
 let phase=side==='client'?'hello':'authenticate',key=null,binding=null,controller=null;
 const destroy=()=>{controller?.abort();phase='closed';pin.secret.fill(0);key?.fill(0);};
 const requirePhase=expected=>{if(phase!==expected)invalid();};
 const requireSize=(value,maximum)=>{if(Buffer.byteLength(canonicalJson(value))>maximum)invalid();return copy(value,maximum);};
 const envelopeText=value=>{
  // E hashes JSON.stringify(body), whose original insertion order is binding.
  // Validate without canonical-reordering the inner envelope before encoding.
  canonicalJson(value);const text=JSON.stringify(value);
  if(typeof text!=='string'||Buffer.byteLength(text)>limits.max_request_bytes)invalid();
  const detached=parseStrictJson(text,{maxBytes:limits.max_request_bytes,maxDepth:32});
  if(JSON.stringify(detached)!==text)invalid();
  return text;
 };
 const envelopeValue=text=>{
  if(typeof text!=='string'||Buffer.byteLength(text)>limits.max_request_bytes)invalid();
  const detached=parseStrictJson(text,{maxBytes:limits.max_request_bytes,maxDepth:32});
  if(JSON.stringify(detached)!==text)invalid();
  return detached;
 };
 const hello=()=>{requirePhase('authenticate');return {...base('hello'),server_nonce:nonce};};
 const accept=value=>{
  frameProfile(value);
  if(side==='client'){
   if(phase==='hello'){
    closed(value,['version','profile','type','server_nonce']);
    if(value.type!=='hello'||typeof value.server_nonce!=='string'||!HEX.test(value.server_nonce))invalid();
    binding=transcript({path,access:policy,credential_id:pin.id,server_nonce:value.server_nonce,client_nonce:nonce});
    key=keyFor(pin.secret,binding);phase='authenticated';
    return {type:'write',frame:signed(pin.secret,'client-auth',{...base('authenticate'),credential_id:pin.id,
     server_nonce:value.server_nonce,client_nonce:nonce,binding_mac:mac(pin.secret,'transcript',binding)})};
   }
   if(phase==='authenticated'){
    closed(value,['version','profile','type','credential_id','server_nonce','client_nonce','binding_mac','mac']);
    const message=verify(key,'server-auth',value);
    if(value.type!=='authenticated'||value.credential_id!==pin.id||value.server_nonce!==binding.server_nonce
     ||value.client_nonce!==nonce||message.binding_mac!==mac(key,'transcript',binding))invalid();
    phase='ready';pin.secret.fill(0);return {type:'ready'};
   }
   requirePhase('waiting');
   if(value.type==='result'){
    closed(value,['version','profile','type','seq','result','mac']);verify(key,'server-result',value);
    if(value.seq!==1)invalid();
    const result=requireSize(value.result,limits.max_result_bytes);phase='settled';return {type:'result',result};
   }
   closed(value,['version','profile','type','seq','code','mac']);verify(key,'server-refused',value);
   if(value.type!=='refused'||value.seq!==1||value.code!=='PROVIDER_OUTCOME_UNKNOWN')invalid();
   phase='settled';return {type:'refused'};
  }
  if(phase==='authenticate'){
   closed(value,['version','profile','type','credential_id','server_nonce','client_nonce','binding_mac','mac']);
   verify(pin.secret,'client-auth',value);
   if(value.type!=='authenticate'||value.credential_id!==pin.id||value.server_nonce!==nonce
    ||typeof value.client_nonce!=='string'||!HEX.test(value.client_nonce))invalid();
   binding=transcript({path,access:policy,credential_id:pin.id,server_nonce:nonce,client_nonce:value.client_nonce});
   if(value.binding_mac!==mac(pin.secret,'transcript',binding))invalid();
   key=keyFor(pin.secret,binding);phase='ready';pin.secret.fill(0);
   return {type:'write',frame:signed(key,'server-auth',{...base('authenticated'),credential_id:pin.id,
    server_nonce:nonce,client_nonce:value.client_nonce,binding_mac:mac(key,'transcript',binding)})};
  }
  if(phase==='ready'){
   closed(value,['version','profile','type','seq','envelope_json','mac']);verify(key,'client-generate',value);
   if(value.type!=='generate'||value.seq!==1)invalid();
   const envelope=envelopeValue(value.envelope_json);
   controller=new AbortController();phase='running';return {type:'generate',envelope,signal:controller.signal};
  }
  requirePhase('running');
  closed(value,['version','profile','type','seq','generate_seq','mac']);verify(key,'client-cancel',value);
  if(value.type!=='cancel'||value.seq!==2||value.generate_seq!==1)invalid();
  phase='cancelled';controller.abort();return {type:'cancel'};
 };
 return Object.freeze({hello,accept,close:destroy,
  generate(envelope){requirePhase('ready');if(side!=='client')invalid();
   const envelope_json=envelopeText(envelope);phase='waiting';
   return signed(key,'client-generate',{...base('generate'),seq:1,envelope_json});},
  cancel(){requirePhase('waiting');if(side!=='client')invalid();phase='cancelled';
   return signed(key,'client-cancel',{...base('cancel'),seq:2,generate_seq:1});},
  result(result){requirePhase('running');if(side!=='server')invalid();
   const detached=requireSize(result,limits.max_result_bytes);phase='settled';
   return signed(key,'server-result',{...base('result'),seq:1,result:detached});},
  refused(){requirePhase('running');if(side!=='server')invalid();phase='settled';
   return signed(key,'server-refused',{...base('refused'),seq:1,code:'PROVIDER_OUTCOME_UNKNOWN'});},
  get phase(){return phase;},
 });
}

async function custody(path,access,side){
 assertIdentity(access,side);
 const parent=dirname(path);let current=parent,parentStat;
 for(;;){
  const stat=await lstat(current);
  if(!stat.isDirectory()||stat.isSymbolicLink()||await realpath(current)!==current
   ||![0,access.server_uid].includes(stat.uid)||(stat.mode&0o022))invalid();
  if(current===parent){
   if(stat.uid!==access.server_uid||stat.gid!==access.group_gid||(stat.mode&0o7777)!==0o710)invalid();
   parentStat=stat;
  }
  const next=dirname(current);if(next===current)break;current=next;
 }
 let socketStat=null;
 if(side==='client'){
  socketStat=await lstat(path);
  if(!socketStat.isSocket()||socketStat.isSymbolicLink()||socketStat.uid!==access.server_uid
   ||socketStat.gid!==access.group_gid||(socketStat.mode&0o7777)!==0o660)invalid();
 }
 return {parent:parentStat,socket:socketStat};
}
const sameNode=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
function write(socket,wire,value,limits){
 const bytes=wire.encode(value);
 if(socket.destroyed||socket.writableLength+bytes.length>limits.max_frame_bytes*2+8)invalid();
 socket.write(bytes);
}
function fixedOptions(options){
 closed(options,['socketPath','socketAccess','credential','limits']);
 return {path:pathInput(options.socketPath),access:accessPolicy(options.socketAccess),
  credential:credentialInput(options.credential),limits:bounds(options.limits)};
}

/** Supply this callback to the existing RemoteDeepSeekProvider. A fresh channel
 * is created only for its one validated E submission; never reconnect/resubmit.
 * Requires actual Linux app identity. Presence of this function is no readiness. */
export function createPrivateInferenceUnixDispatch(options){
 const fixed=fixedOptions(options);assertIdentity(fixed.access,'client');
 const wire=codec(fixed.limits),connections=new Set();let disposed=false,inflight=0;
 const send=async(envelope,{signal})=>{
  if(disposed||inflight>=fixed.limits.max_connections)throw fail();
  // Reserve before custody awaits, bounding both preflights and live channels.
  inflight++;
  try{
   const before=await custody(fixed.path,fixed.access,'client');
   if(disposed||signal.aborted)throw fail();
   return await new Promise((done,reject)=>{
   const session=peer({side:'client',...fixed,nonce:randomBytes(32).toString('hex')});
   const socket=net.createConnection(fixed.path);connections.add(socket);socket.pause();socket.setNoDelay(true);
   let finished=false,decoder,timer;
   const finish=(error,result)=>{
    if(finished)return;finished=true;clearTimeout(timer);signal.removeEventListener('abort',aborted);
    decoder?.close();session.close();connections.delete(socket);socket.destroy();error?reject(fail()):done(result);
   };
   const aborted=()=>{
    // The authenticated frame names only this channel's sequence-1 invocation.
    // Disconnect also aborts the receiver. Neither proves worker quiescence.
    if(session.phase==='waiting')try{write(socket,wire,session.cancel(),fixed.limits);}catch{}
    finish(fail());
   };
   timer=setTimeout(()=>finish(fail()),fixed.limits.handshake_timeout_ms);
   socket.on('error',()=>finish(fail()));socket.on('close',()=>finish(fail()));
   socket.on('end',()=>finish(fail()));signal.addEventListener('abort',aborted,{once:true});
   if(signal.aborted){aborted();return;}
   socket.once('connect',()=>{
    void custody(fixed.path,fixed.access,'client').then(after=>{
     if(finished)return;
     if(!sameNode(before.parent,after.parent)||!sameNode(before.socket,after.socket))throw fail();
     decoder=wire.decoder(value=>{
      const action=session.accept(value);
      if(action.type==='write')write(socket,wire,action.frame,fixed.limits);
      else if(action.type==='ready'){
       clearTimeout(timer);timer=setTimeout(()=>finish(fail()),fixed.limits.max_request_ms);
       if(signal.aborted){aborted();return;}
       write(socket,wire,session.generate(envelope),fixed.limits);
      }else if(action.type==='result')finish(null,action.result);
      else finish(fail());
     },()=>finish(fail()));
     socket.on('data',chunk=>decoder.push(chunk));socket.resume();
    }).catch(()=>finish(fail()));
   });
   });
  }finally{inflight--;}
 };
 // E retains all envelope/reply validation and conservative interruption codes.
 const dispatch=createPrivateInferenceDispatch({send,max_request_ms:fixed.limits.max_request_ms,max_request_bytes:fixed.limits.max_request_bytes});
 return Object.freeze(Object.assign(dispatch,{close(){
  if(disposed)return;disposed=true;for(const socket of connections)socket.destroy();fixed.credential.secret.fill(0);
 }}));
}

/** Explicit separate-worker listener factory. It is never invoked by import or
 * mounted here. Pass the existing E service; its C gates/ledger/vault remain E's.
 * The configured Linux worker UID must differ from the app UID. This source
 * checks local process identity/endpoint custody + PSK, not SO_PEERCRED or an
 * installed-system qualification. Group/ACL/PSK provisioning needs actual review. */
export async function createPrivateInferenceUnixReceiver(options){
 closed(options,['socketPath','socketAccess','credential','limits','service']);
 const {service,...channel}=options,fixed=fixedOptions(channel);
 const receive=createPrivateInferenceReceiver({service,max_request_bytes:fixed.limits.max_request_bytes});
 const before=await custody(fixed.path,fixed.access,'server'),wire=codec(fixed.limits);
 try{await lstat(fixed.path);invalid();}catch(error){if(error.code!=='ENOENT')throw error;}
 const connections=new Map();let armed=false,closing=false,active=0,ownedSocket,closePromise;
 const server=net.createServer(socket=>{
  if(!armed||closing||connections.size>=fixed.limits.max_connections||active>=fixed.limits.max_connections){socket.destroy();return;}
  socket.setNoDelay(true);
  const session=peer({side:'server',...fixed,nonce:randomBytes(32).toString('hex')});
  let timer,decoder;
  const stop=()=>{clearTimeout(timer);decoder?.close();session.close();socket.destroy();};
  connections.set(socket,stop);socket.on('error',stop);
  timer=setTimeout(stop,fixed.limits.handshake_timeout_ms);
  decoder=wire.decoder(value=>{
   const action=session.accept(value);
   if(action.type==='write')write(socket,wire,action.frame,fixed.limits);
   else if(action.type==='cancel')stop();
   else if(action.type==='generate'){
    // The capacity charge survives timeout/disconnect until E actually settles.
    if(active>=fixed.limits.max_connections)throw fail();
    active++;clearTimeout(timer);
    timer=setTimeout(stop,fixed.limits.max_request_ms);
    void Promise.resolve().then(()=>receive(action.envelope,{signal:action.signal})).then(result=>{
     if(socket.destroyed||session.phase!=='running')return;
     write(socket,wire,session.result(result),fixed.limits);socket.end();
    },()=>{
     if(socket.destroyed||session.phase!=='running')return;
     write(socket,wire,session.refused(),fixed.limits);socket.end();
    }).catch(stop).finally(()=>{
     active--;
     // Closing the connection requests cancellation; it does not close E.
     if(!socket.destroyed){clearTimeout(timer);timer=setTimeout(stop,fixed.limits.handshake_timeout_ms);}
    });
   }
  },stop);
  socket.on('data',chunk=>decoder.push(chunk));
  socket.on('end',stop);
  socket.on('close',()=>{stop();connections.delete(socket);});
  // No successful handler may free capacity merely because its socket closes.
  // The promise's finally above is the sole active-charge release.
  try{write(socket,wire,session.hello(),fixed.limits);}catch{stop();}
 });
 server.on('error',()=>{armed=false;for(const stop of connections.values())stop();});
 try{
  await new Promise((done,reject)=>{
   const error=e=>{server.off('listening',ready);reject(e);},ready=()=>{server.off('error',error);done();};
   server.once('error',error);server.once('listening',ready);server.listen(fixed.path);
  });
  await chown(fixed.path,fixed.access.server_uid,fixed.access.group_gid);await chmod(fixed.path,0o660);
  const checked=await custody(fixed.path,fixed.access,'server'),stat=await lstat(fixed.path);
  if(!stat.isSocket()||stat.isSymbolicLink()||stat.uid!==fixed.access.server_uid||stat.gid!==fixed.access.group_gid
   ||(stat.mode&0o7777)!==0o660)invalid();
  const after={...checked,socket:stat};
  if(!sameNode(before.parent,after.parent))invalid();ownedSocket=after.socket;armed=true;
 }catch(error){
  // Failed initialization qualifies neither cleanup nor a safe retry. The
  // provisioner must reconcile any remaining endpoint before another attempt.
  server.close();for(const stop of connections.values())stop();fixed.credential.secret.fill(0);throw error;
 }
 return Object.freeze({address:fixed.path,close(){
  if(closePromise)return closePromise;closing=true;armed=false;
  for(const stop of connections.values())stop();
  closePromise=(async()=>{
   await new Promise(done=>server.close(done));
   try{const stat=await lstat(fixed.path);if(stat.isSocket()&&sameNode(stat,ownedSocket))await unlink(fixed.path);}
   catch(error){if(error.code!=='ENOENT')throw error;}
   finally{fixed.credential.secret.fill(0);}
  })();
  // Listener closure is no service drain/settlement/unsent certificate.
  return closePromise;
 }});
}

// Attached pure checks use exactly the runtime codec/state/identity predicates.
// They create no peer connection/service, and supply no successful model reply.
export const privateInferenceChannelPure=Object.freeze({bounds,accessPolicy,identity,pathInput,codec,peer});
