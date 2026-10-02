// SPDX-License-Identifier: AGPL-3.0-or-later
// Source-only authenticated process boundary. Secrets and the private socket
// directory are provisioner inputs. Channel roles authorize methods, never owners.
// This transport does not establish deployed UID separation or witness custody.
import net from 'node:net'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { chmod, chown, lstat, realpath, unlink } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { canonicalJson, parseStrictJson } from '../../contracts/src/runtime.mjs'

const VERSION = 1
const HEX = /^[a-f0-9]{64}$/
const ID = /^[A-Za-z0-9_.-]{1,128}$/
const ROLES = Object.freeze(['proposer', 'read_only', 'owner_control'])
const reads = ['capability.status', 'owner.status', 'memory.status', 'memory.cite', 'memory.recall']
const owner = ['owner.loginChallenge', 'owner.loginComplete', 'owner.logout', 'owner.approvalChallenge', 'owner.approvalComplete', 'owner.declineApproval', 'memory.save', 'memory.forget', 'memory.recover']
export const IPC_METHOD_ROLES = Object.freeze(Object.fromEntries([
  ...reads.map(method => [method, ROLES]),
  ['memory.proposeSave', Object.freeze(['proposer', 'owner_control'])],
  ['memory.proposeForget', Object.freeze(['proposer', 'owner_control'])],
  ...owner.map(method => [method, Object.freeze(['owner_control'])]),
]))
export const PUBLIC_METHODS = Object.freeze(Object.keys(IPC_METHOD_ROLES))
export const PRIVATE_AUTHORITY_METHODS = Object.freeze(['authority.propose','authority.loginChallenge','authority.loginComplete',
  'authority.authenticateSession','authority.logoutSession','authority.approvalChallenge','authority.approvalComplete','authority.declineApproval',
  'authority.status','authority.reserve','authority.claimDispatch','authority.settleMemory','authority.markOutcomeUnknown'])
const PRIVATE_ROLES = Object.freeze(['memory_effect'])
const PRIVATE_METHOD_ROLES = Object.freeze(Object.fromEntries(PRIVATE_AUTHORITY_METHODS.map(method=>[method,PRIVATE_ROLES])))
const PUBLIC_PROFILE = Object.freeze({roles:ROLES,methods:IPC_METHOD_ROLES})
const AUTHORITY_PROFILE = Object.freeze({roles:PRIVATE_ROLES,methods:PRIVATE_METHOD_ROLES})
// This is a separate fixed profile, never a union with memory/public privileges.
export const INFERENCE_AUTHORITY_METHODS = Object.freeze(['authority.propose','authority.loginChallenge','authority.loginComplete',
  'authority.authenticateSession','authority.logoutSession','authority.approvalChallenge','authority.approvalComplete','authority.declineApproval',
  'authority.status','authority.reserve','authority.claimDispatch','authority.settleInference','authority.reconcileInferenceSettlement'])
const INFERENCE_ROLES = Object.freeze(['inference_effect'])
const INFERENCE_METHOD_ROLES = Object.freeze(Object.fromEntries(INFERENCE_AUTHORITY_METHODS.map(method=>[method,INFERENCE_ROLES])))
const INFERENCE_PROFILE = Object.freeze({roles:INFERENCE_ROLES,methods:INFERENCE_METHOD_ROLES})
const mutation = method => ![...reads,'authority.authenticateSession','authority.status'].includes(method)
const DEFAULTS = Object.freeze({maxFrameBytes:65_536, maxOutputBytes:65_536, maxConnections:8,
  maxInflight:8, maxInflightPerConnection:2, handshakeTimeoutMs:2_000,
  idleTimeoutMs:30_000, requestTimeoutMs:5_000, maxRequestsPerConnection:256})
function limits(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).some(key => !Object.hasOwn(DEFAULTS,key))) throw new TypeError('INVALID: IPC limits')
  const value = {...DEFAULTS,...input}
  for (const [key,n] of Object.entries(value)) {
    const max = key.endsWith('Bytes') ? 1_048_576 : key.endsWith('Ms') ? 120_000 : 1024
    if (!Number.isSafeInteger(n) || n < 1 || n > max) throw new TypeError('INVALID: IPC bound '+key)
  }
  if (value.maxFrameBytes < 1024 || value.maxOutputBytes < 512) throw new TypeError('INVALID: IPC minimum frame/output bound')
  if (value.maxOutputBytes > value.maxFrameBytes) throw new TypeError('INVALID: IPC output/frame bound')
  return Object.freeze(value)
}
function secretBytes(input) {
  const value = typeof input === 'string' && /^(?:[a-f0-9]{2}){32,64}$/.test(input)
    ? Buffer.from(input,'hex') : input instanceof Uint8Array ? Buffer.from(input) : null
  if (!value || value.length < 32 || value.length > 64) throw new TypeError('INVALID: host IPC secret')
  return value
}
const mac = (key,domain,value) => createHmac('sha256',key).update('aukora-prime.ipc.v1\0'+domain+'\0'+canonicalJson(value)).digest('hex')
const sessionKey = (key,binding) => Buffer.from(mac(key,'session',binding),'hex')
function validMac(key,domain,value,signature) {
  return typeof signature === 'string' && HEX.test(signature)
    && timingSafeEqual(Buffer.from(signature,'hex'),Buffer.from(mac(key,domain,value),'hex'))
}
function closed(value,keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new TypeError('INVALID: closed IPC frame')
}
const fail = (code,reason) => Object.assign(new Error(reason),{code,error_code:code})
const refusal = (error_code,reason) => ({ok:false,error_code,reason})
function parse(bytes,bounds) {
  // Preserve a BOM so the frozen strict parser rejects it; do not strip bytes
  // into a different canonical ingress on any profile.
  const text = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)
  const value = parseStrictJson(text,{maxBytes:bounds.maxFrameBytes,maxDepth:32})
  if (canonicalJson(value) !== text) throw fail('INVALID','IPC_CANONICAL_FRAME_REQUIRED')
  return value
}
function frame(socket,value,bounds) {
  const body = Buffer.from(canonicalJson(value),'utf8')
  if (!body.length || body.length > bounds.maxFrameBytes) throw fail('INVALID','IPC_FRAME_BYTE_BOUND')
  // At most one bounded frame may be retained by the socket writer. A slow
  // reader loses the channel; this never permits retrying a mutation.
  if (socket.destroyed || socket.writableLength + body.length + 4 > bounds.maxFrameBytes * 2)
    throw fail('UNAVAILABLE','IPC_OUTPUT_BACKPRESSURE')
  const header = Buffer.allocUnsafe(4);header.writeUInt32BE(body.length)
  socket.write(Buffer.concat([header,body]))
}
function framer(socket,bounds,onFrame,onFault) {
  const header = Buffer.alloc(4)
  let head = 0,body = null,used = 0,stopped = false
  socket.on('data',chunk => {
    if (stopped) return
    try {
      let offset = 0
      while (offset < chunk.length && !socket.destroyed) {
        if (!body) {
          const n = Math.min(4-head,chunk.length-offset);chunk.copy(header,head,offset,offset+n);head+=n;offset+=n
          if (head !== 4) continue
          const length = header.readUInt32BE();head=0
          if (!length || length > bounds.maxFrameBytes) throw fail('INVALID','IPC_FRAME_BYTE_BOUND')
          body = Buffer.allocUnsafe(length);used=0
        }
        const n = Math.min(body.length-used,chunk.length-offset);chunk.copy(body,used,offset,offset+n);used+=n;offset+=n
        if (used === body.length) {const complete=body;body=null;onFrame(parse(complete,bounds))}
      }
    } catch (error) {stopped=true;body=null;onFault(error)}
  })
}
async function socketPath(path,access,side) {
  if (typeof path !== 'string' || resolve(path) !== path || Buffer.byteLength(path) > 103 || path.includes('\0'))
    throw new TypeError('INVALID: absolute bounded Unix socket path')
  const parent = dirname(path),stat = await lstat(parent)
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(parent) !== parent)
    throw fail('UNAVAILABLE','IPC_PRIVATE_HOST_SOCKET_DIRECTORY_REQUIRED')
  if(access===undefined) {
    if((stat.mode&0o077)||(process.getuid&&stat.uid!==process.getuid()))throw fail('UNAVAILABLE','IPC_PRIVATE_HOST_SOCKET_DIRECTORY_REQUIRED')
    return null
  }
  const policy=JSON.parse(canonicalJson(access));closed(policy,['server_uid','client_uid','group_gid'])
  if(Object.values(policy).some(value=>!Number.isSafeInteger(value)||value<0)
    ||typeof process.getuid!=='function'||process.getuid()!==policy[side==='server'?'server_uid':'client_uid']
    ||stat.uid!==policy.server_uid||stat.gid!==policy.group_gid||(stat.mode&0o7777)!==0o710)
    throw fail('UNAVAILABLE','IPC_PROVISIONED_SOCKET_ACCESS_REQUIRED')
  if(side==='client') {
    const socket=await lstat(path)
    if(!socket.isSocket()||socket.isSymbolicLink()||socket.uid!==policy.server_uid||socket.gid!==policy.group_gid||(socket.mode&0o7777)!==0o660)
      throw fail('UNAVAILABLE','IPC_PROVISIONED_SOCKET_ACCESS_REQUIRED')
  }
  // The host must provision UID/group membership and this directory. These
  // checks create no users, groups, directories or deployment qualification.
  return Object.freeze(policy)
}

// Profiles are private constants, never constructor options. Public and private
// listeners cannot be configured to accept a union of roles or method sets.
export const createIpcServer = options => createServer(options,PUBLIC_PROFILE)
export const createAuthorityIpcServer = options => createServer(options,AUTHORITY_PROFILE)
export const createInferenceAuthorityIpcServer = options => createServer(options,INFERENCE_PROFILE)
async function createServer({socketPath:path,credentials,handlePublic,limits:inputLimits,socketAccess},profile) {
  const bounds = limits(inputLimits),access=await socketPath(path,socketAccess,'server')
  if (!Array.isArray(credentials) || !credentials.length || credentials.length > 64 || typeof handlePublic !== 'function')
    throw new TypeError('INVALID: host IPC credentials/handler')
  const pins = new Map()
  for (const credential of credentials) {
    closed(credential,['id','role','secret'])
    if (!ID.test(credential.id) || !profile.roles.includes(credential.role) || pins.has(credential.id)) throw new TypeError('INVALID: IPC credential identity/role')
    pins.set(credential.id,{role:credential.role,secret:secretBytes(credential.secret)})
  }
  try {await lstat(path);throw fail('UNAVAILABLE','IPC_SOCKET_PATH_ALREADY_EXISTS')} catch(error) {if (error.code !== 'ENOENT') throw error}
  const connections = new Set()
  let inflight=0,closedServer=false,ownedSocket=null
  const server = net.createServer(socket => {
    if (closedServer || connections.size >= bounds.maxConnections) {socket.destroy();return}
    connections.add(socket);socket.on('error',()=>{});socket.setNoDelay(true)
    // This is an absolute authentication deadline. Socket inactivity timeouts
    // reset on every byte and would allow an unauthenticated trickle to occupy
    // all connection slots indefinitely.
    const handshakeTimer=setTimeout(()=>socket.destroy(),bounds.handshakeTimeoutMs)
    const nonce=randomBytes(32).toString('hex')
    let key=null,credentialId=null,role=null,sequence=0,localInflight=0
    socket.on('close',()=>{clearTimeout(handshakeTimer);connections.delete(socket)})
    const send = (seq,result) => {
      if (socket.destroyed) return
      let value=result
      try {if (Buffer.byteLength(canonicalJson(value)) > bounds.maxOutputBytes - 256) throw new Error('bound')}
      catch {value=refusal('OUTCOME_UNKNOWN','IPC_SERVICE_OUTPUT_UNAVAILABLE')}
      const reply={version:VERSION,type:'response',seq,result:value}
      try {frame(socket,{...reply,mac:mac(key,'response',reply)},bounds)} catch {socket.destroy()}
    }
    framer(socket,bounds,value => {
      if (!key) {
        closed(value,['version','type','credential_id','client_nonce','mac'])
        if (value.version !== VERSION || value.type !== 'auth' || !ID.test(value.credential_id) || !HEX.test(value.client_nonce)) throw fail('UNAUTHORIZED','IPC_AUTH_REQUIRED')
        const pin=pins.get(value.credential_id),binding={credential_id:value.credential_id,server_nonce:nonce,client_nonce:value.client_nonce}
        if (!pin || !validMac(pin.secret,'authenticate',binding,value.mac)) throw fail('UNAUTHORIZED','IPC_AUTH_REFUSED')
        credentialId=value.credential_id;role=pin.role;key=sessionKey(pin.secret,binding)
        const answer={version:VERSION,type:'authenticated',...binding,role}
        frame(socket,{...answer,mac:mac(key,'authenticated',answer)},bounds)
        clearTimeout(handshakeTimer)
        socket.setTimeout(bounds.idleTimeoutMs,()=>socket.destroy());return
      }
      closed(value,['version','type','seq','method','input','mac'])
      const {mac:signature,...request}=value
      if (value.version !== VERSION || value.type !== 'request' || !validMac(key,'request',request,signature)
        || !Number.isSafeInteger(value.seq) || value.seq !== sequence+1 || value.seq > bounds.maxRequestsPerConnection)
        throw fail('UNAUTHORIZED','IPC_SEQUENCE_OR_AUTH_REFUSED')
      sequence=value.seq
      if (!Object.hasOwn(profile.methods,value.method) || !profile.methods[value.method].includes(role)) {
        send(value.seq,refusal('UNAUTHORIZED','IPC_METHOD_ROLE_REFUSED'));return
      }
      if (!value.input || typeof value.input !== 'object' || Array.isArray(value.input)) {send(value.seq,refusal('INVALID','IPC_REQUEST_OBJECT_REQUIRED'));return}
      if (inflight >= bounds.maxInflight || localInflight >= bounds.maxInflightPerConnection) {send(value.seq,refusal('UNAVAILABLE','IPC_INFLIGHT_BOUND'));return}
      inflight++;localInflight++
      let replied=false
      const answer=result=>{if (!replied) {replied=true;send(value.seq,result)}}
      const timer=setTimeout(()=>answer(refusal(mutation(value.method)?'OUTCOME_UNKNOWN':'UNAVAILABLE','IPC_SERVICE_REPLY_TIMEOUT')),bounds.requestTimeoutMs)
      // A timed-out handler remains charged against capacity until it actually
      // settles. There is no cancellation, retry, or authority reconstruction.
      Promise.resolve().then(()=>handlePublic(value.method,value.input,{role,request:{transport:'ipc',credential_id:credentialId}}))
        .then(answer,()=>answer(refusal(mutation(value.method)?'OUTCOME_UNKNOWN':'UNAVAILABLE','IPC_SERVICE_REPLY_UNAVAILABLE')))
        .finally(()=>{clearTimeout(timer);inflight--;localInflight--})
    },()=>socket.destroy())
    frame(socket,{version:VERSION,type:'hello',server_nonce:nonce},bounds)
  })
  // Keep an error listener after binding so late errors cannot crash the broker.
  server.on('error',()=>{})
  await new Promise((done,reject)=>{const error=e=>{server.off('listening',ready);reject(e)},ready=()=>{server.off('error',error);done()};server.once('error',error);server.once('listening',ready);server.listen(path)})
  try {
    if(access)await chown(path,access.server_uid,access.group_gid)
    await chmod(path,access?0o660:0o600);ownedSocket=await lstat(path)
    if(access&&(ownedSocket.uid!==access.server_uid||ownedSocket.gid!==access.group_gid||(ownedSocket.mode&0o7777)!==0o660))throw fail('UNAVAILABLE','IPC_PROVISIONED_SOCKET_ACCESS_REQUIRED')
  } catch(error) {server.close();for (const socket of connections)socket.destroy();throw error}
  return Object.freeze({address:path, async close() {
    if (closedServer) return
    closedServer=true;for (const socket of connections)socket.destroy()
    await new Promise(done=>server.close(done))
    // Guard any explicit cleanup against a replaced path. Node/libuv also owns
    // listener cleanup; the trusted private parent is a deployment prerequisite.
    try {const stat=await lstat(path);if (stat.isSocket() && stat.dev===ownedSocket.dev && stat.ino===ownedSocket.ino) await unlink(path)} catch(error) {if (error.code !== 'ENOENT') throw error}
    for (const pin of pins.values()) pin.secret.fill(0)
  }})
}

export const createIpcClient = options => createClient(options,PUBLIC_PROFILE)
export const createAuthorityIpcClient = options => createClient(options,AUTHORITY_PROFILE)
export const createInferenceAuthorityIpcClient = options => createClient(options,INFERENCE_PROFILE)
async function createClient({socketPath:path,credential,limits:inputLimits,socketAccess},profile) {
  const bounds=limits(inputLimits);await socketPath(path,socketAccess,'client')
  closed(credential,['id','secret'])
  if (!ID.test(credential.id)) throw new TypeError('INVALID: IPC credential identity')
  const secret=secretBytes(credential.secret),socket=net.createConnection(path),pending=new Map()
  let key=null,role=null,sequence=0,clientClosed=false,serverNonce=null
  const clientNonce=randomBytes(32).toString('hex')
  let readyResolve,readyReject
  const ready=new Promise((done,reject)=>{readyResolve=done;readyReject=reject})
  const timer=setTimeout(()=>{readyReject(fail('UNAVAILABLE','IPC_AUTH_TIMEOUT'));socket.destroy()},bounds.handshakeTimeoutMs)
  const disconnect=()=>{
    clearTimeout(timer);clientClosed=true;readyReject(fail('UNAVAILABLE','IPC_CHANNEL_UNAVAILABLE'))
    for (const item of pending.values()) {clearTimeout(item.timer);item.reject(fail(mutation(item.method)?'OUTCOME_UNKNOWN':'UNAVAILABLE','IPC_REPLY_LOST'))}
    pending.clear();secret.fill(0);key?.fill(0)
  }
  socket.on('error',()=>{});socket.on('close',disconnect);socket.setNoDelay(true)
  framer(socket,bounds,value=>{
    if (!key) {
      closed(value,['version','type','server_nonce'])
      if (value.version !== VERSION || value.type !== 'hello' || !HEX.test(value.server_nonce)) throw fail('UNAUTHORIZED','IPC_HELLO_REFUSED')
      serverNonce=value.server_nonce
      const binding={credential_id:credential.id,server_nonce:serverNonce,client_nonce:clientNonce}
      key=sessionKey(secret,binding)
      frame(socket,{version:VERSION,type:'auth',credential_id:credential.id,client_nonce:clientNonce,mac:mac(secret,'authenticate',binding)},bounds);return
    }
    if (!role) {
      closed(value,['version','type','credential_id','server_nonce','client_nonce','role','mac'])
      const {mac:signature,...answer}=value
      if (value.version !== VERSION || value.type !== 'authenticated' || value.credential_id !== credential.id
        || value.server_nonce !== serverNonce || value.client_nonce !== clientNonce || !profile.roles.includes(value.role)
        || !validMac(key,'authenticated',answer,signature)) throw fail('UNAUTHORIZED','IPC_SERVER_AUTH_REFUSED')
      role=value.role;clearTimeout(timer);readyResolve();return
    }
    closed(value,['version','type','seq','result','mac'])
    const {mac:signature,...answer}=value
    if (value.version !== VERSION || value.type !== 'response' || !Number.isSafeInteger(value.seq)
      || !validMac(key,'response',answer,signature)) throw fail('UNAUTHORIZED','IPC_RESPONSE_AUTH_REFUSED')
    const item=pending.get(value.seq)
    if (!item) throw fail('UNAUTHORIZED','IPC_RESPONSE_REPLAYED')
    pending.delete(value.seq);clearTimeout(item.timer);item.resolve(value.result)
  },()=>socket.destroy())
  try {await ready} catch(error) {socket.destroy();throw error}
  return Object.freeze({get role(){return role}, request(method,input) {
    if (clientClosed || socket.destroyed) return Promise.reject(fail('UNAVAILABLE','IPC_CHANNEL_UNAVAILABLE'))
    if (!Object.hasOwn(profile.methods,method)) return Promise.reject(fail('INVALID','IPC_METHOD_UNAVAILABLE'))
    if (pending.size >= bounds.maxInflightPerConnection || sequence >= bounds.maxRequestsPerConnection) return Promise.reject(fail('UNAVAILABLE','IPC_REQUEST_BOUND'))
    if (!input || typeof input !== 'object' || Array.isArray(input)) return Promise.reject(fail('INVALID','IPC_REQUEST_OBJECT_REQUIRED'))
    let request,signed
    try {
      request={version:VERSION,type:'request',seq:sequence+1,method,input}
      signed={...request,mac:mac(key,'request',request)}
      if (Buffer.byteLength(canonicalJson(signed)) > bounds.maxFrameBytes) throw new Error('bound')
    } catch {return Promise.reject(fail('INVALID','IPC_REQUEST_DATA_OR_BYTE_BOUND'))}
    return new Promise((done,reject)=>{
      const seq=++sequence
      const timeout=setTimeout(()=>{pending.delete(seq);reject(fail(mutation(method)?'OUTCOME_UNKNOWN':'UNAVAILABLE','IPC_REPLY_TIMEOUT'));socket.destroy()},bounds.requestTimeoutMs)
      pending.set(seq,{method,resolve:done,reject,timer:timeout})
      try {frame(socket,signed,bounds)} catch(error) {clearTimeout(timeout);pending.delete(seq);reject(fail(mutation(method)?'OUTCOME_UNKNOWN':error.code??'INVALID','IPC_SEND_UNCERTAIN'));socket.destroy()}
    })
  }, async close() {
    if (socket.destroyed) return
    await new Promise(done=>{socket.once('close',done);socket.destroy()})
  }})
}
