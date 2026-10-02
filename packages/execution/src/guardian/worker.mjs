// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer } from 'node:net'
import { chmodSync,existsSync,lstatSync,unlinkSync } from 'node:fs'
import { dirname,join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { canonicalJson } from '../../../contracts/src/runtime.mjs'
import { inspectLocalLifetime } from '../lifetime-safety.mjs'
import { refused } from '../policy.mjs'
import { closed,copy } from './registration.mjs'
import { MAX_MESSAGE_BYTES,decodeMessage } from './ipc.mjs'
import { privatePath } from './store.mjs'

const iso=()=>new Date().toISOString()
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
/** Run in the separately launched host guardian, holding its own OS lease.
 * Directly importing this into an application does not establish independence.
 * backend is constructed at trusted worker bootstrap, never from IPC/guest data.
 * It must implement independently observed, identity-conditioned idempotent
 * reclamation; pinned public SDK cannot supply that mutation primitive. */
export async function startGuardian({store,backend,socketPath,pollMs=100,controlTimeoutMs=1000}) {
  store.requireOwner();privatePath(store.root,'directory')
  if(socketPath!==join(store.root,'guardian.sock')||dirname(socketPath)!==store.root)throw refused('guardian socket must belong to its private store','INVALID')
  for(const [n,max] of [[pollMs,1000],[controlTimeoutMs,120000]])if(!Number.isSafeInteger(n)||n<1||n>max)throw refused('bounded guardian scheduling required','INVALID')
  if(typeof backend?.observe!=='function'||typeof backend?.reclaim!=='function')throw refused('guardian backend interface missing','UNAVAILABLE')
  if(existsSync(socketPath)) {
    const st=lstatSync(socketPath)
    if(!st.isSocket()||(process.getuid&&st.uid!==process.getuid())||(st.mode&0o077))throw refused('unsafe guardian socket; never remove','UNAVAILABLE')
    // Only after the exclusive process lease excludes another live guardian.
    unlinkSync(socketPath)
  }
  let closing=false,pollTimer,working=null
  const deadlines=new Map(),controllers=new Set(),sockets=new Set()
  function latch(id,reason) {
    const row=store.lookup(id)
    if(row&&row.mode!=='cleanup_requested') {row.mode='cleanup_requested';row.cleanup_reason=reason;store.save(row)}
  }
  function schedule(row) {
    if(deadlines.has(row.request_id)||row.mode==='cleanup_requested')return
    const r=row.registration,clock=inspectLocalLifetime({request:r.request,request_id:row.request_id,request_digest:r.request_digest,lifetime:r.lifetime,lifetime_digest:r.lifetime_digest})
    if(clock.status!=='active'){latch(row.request_id,clock.status==='expired'?'deadline':'clock_uncertain');return}
    deadlines.set(row.request_id,setTimeout(()=>{
      deadlines.delete(row.request_id)
      // In-process monotonic scheduling is useful, but no boot/time trust claim.
      latch(row.request_id,store.observeClock()?'deadline':'clock_uncertain')
    },clock.remaining_ms))
  }
  async function bounded(call) {
    const controller=new AbortController();controllers.add(controller);let timer
    try {return await Promise.race([Promise.resolve().then(()=>call(controller.signal)),new Promise((_,reject)=>{
      timer=setTimeout(()=>{controller.abort();reject(refused('guardian control reply uncertain','RECONCILIATION_REQUIRED'))},controlTimeoutMs)
    })])}finally{clearTimeout(timer);controllers.delete(controller)}
  }
  async function inspect(row) {
    try {
      const registration=copy(row.registration),inventory=await bounded(signal=>backend.observe(registration,{signal}))
      if(!inventory||inventory.inventory_complete!==true||!Array.isArray(inventory.sandboxes)||inventory.sandboxes.length>10000)throw refused('guardian inventory incomplete','RECONCILIATION_REQUIRED')
      row=store.lookup(row.request_id) // A deadline/cancel may have latched during RPC.
      const named=inventory.sandboxes.filter(s=>s?.name===registration.name)
      if(!named.length){row.observation={state:'api_absent',observed_at:iso()};row.last_error=null;store.save(row);return}
      const resource=named[0]
      if(named.length!==1||!UUID.test(resource.uid)||resource.workspace!==store.scope.workspace||resource.owner_token!==registration.token
        ||resource.origin_request_id!==registration.create_request_id||(row.sandbox_uid&&row.sandbox_uid!==resource.uid)) {
        row.observation={state:'identity_mismatch',observed_at:iso()};row.last_error='TARGET_MISMATCH';store.save(row);return
      }
      row.sandbox_uid??=resource.uid
      row.observation={state:'present',observed_at:iso()};row.last_error=null;store.save(row)
      if(row.mode!=='cleanup_requested')return
      row.reclaim??={request_id:randomUUID(),sandbox_uid:resource.uid,state:'attempted',reply:null}
      if(row.reclaim.sandbox_uid!==resource.uid)throw refused('guardian cleanup identity changed','TARGET_MISMATCH')
      // Every uncertain retry first corroborates the same immutable resource.
      // Reuse only this exact idempotent cleanup action, never create or exec.
      row.reclaim.state='attempted';store.save(row)
      try {
        const reply=await bounded(signal=>backend.reclaim(registration,copy(resource),{request_id:row.reclaim.request_id,signal}))
        closed(reply,['sandbox_uid','outcome'])
        if(reply.sandbox_uid!==resource.uid||!['reclaimed','already_absent'].includes(reply.outcome))throw refused('guardian cleanup reply differs','RECONCILIATION_REQUIRED')
        row=store.lookup(row.request_id);row.reclaim.state='replied';row.reclaim.reply=copy(reply);row.last_error=null;store.save(row)
      } catch(error){row=store.lookup(row.request_id);row.reclaim.state='reply_uncertain';row.last_error=error.code??'RECONCILIATION_REQUIRED';store.save(row)}
    } catch(error) {
      row=store.lookup(row.request_id);row.observation={state:'unavailable',observed_at:iso()};row.last_error=error.code??'RECONCILIATION_REQUIRED';store.save(row)
    }
  }
  async function tick() {
    if(!store.observeClock())for(const row of store.rows())latch(row.request_id,'clock_uncertain')
    for(const row of store.rows()) {if(closing)break;schedule(row);await inspect(row)}
  }
  const kick=()=>{
    if(closing||working)return
    working=Promise.resolve().then(tick)
    working.finally(()=>{working=null;if(!closing)pollTimer=setTimeout(kick,pollMs)}).catch(()=>{
      // Integrity/storage failure must not leave an apparently live enforcer.
      queueMicrotask(()=>{throw refused('guardian worker failed; durable records retained','RECONCILIATION_REQUIRED')})
    })
  }
  function bound(payload,keys) {
    closed(payload,keys);const row=store.lookup(payload.request_id)
    if(!row||row.registration_digest!==payload.registration_digest)throw refused('guardian exact registration binding required','UNAUTHORIZED')
    return row
  }
  function dispatch(request) {
    closed(request,['version','call_id','method','payload'])
    if(request.version!==1||!UUID.test(request.call_id))throw refused('guardian request binding required','INVALID')
    if(request.method==='register') {const row=store.register(request.payload);schedule(row);return store.lookup(row.request_id)}
    if(request.method==='inspect')return bound(request.payload,['request_id','registration_digest'])
    if(request.method==='cancel') {
      const row=bound(request.payload,['request_id','registration_digest','reason'])
      if(!['caller','timeout','dispose'].includes(request.payload.reason))throw refused('guardian cancellation reason required','INVALID')
      latch(row.request_id,'cancel:'+request.payload.reason);return store.lookup(row.request_id)
    }
    throw refused('guardian provides no create/exec/settlement route','UNAVAILABLE')
  }
  const server=createServer({allowHalfOpen:true},socket=>{
    sockets.add(socket);socket.once('close',()=>sockets.delete(socket));socket.on('error',()=>{});socket.setTimeout(controlTimeoutMs,()=>socket.destroy())
    let chunks=[],size=0
    socket.on('data',chunk=>{size+=chunk.length;if(size>MAX_MESSAGE_BYTES+1)socket.destroy();else chunks.push(chunk)})
    socket.on('end',()=>{
      let request,reply
      try {
        const bytes=Buffer.concat(chunks)
        if(bytes.at(-1)!==10)throw refused('guardian request incomplete','INVALID')
        request=decodeMessage(bytes.subarray(0,-1));reply={version:1,call_id:request.call_id,ok:true,value:dispatch(request)}
      } catch(error){reply={version:1,call_id:request?.call_id??null,ok:false,error_code:error.code??'INVALID',reason:'guardian request refused'}}
      socket.end(canonicalJson(reply)+'\n')
    })
  })
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,()=>{server.removeListener('error',reject);resolve()})})
  chmodSync(socketPath,0o600);kick()
  let closePromise
  return {close:()=>closePromise??=Promise.resolve().then(async()=>{
    closing=true;clearTimeout(pollTimer);for(const timer of deadlines.values())clearTimeout(timer)
    for(const controller of controllers)controller.abort();for(const socket of sockets)socket.destroy()
    await new Promise(resolve=>server.close(resolve));if(working)await working
    // Close cannot terminalize jobs or prove any external resource absent.
    unlinkSync(socketPath)
  })}
}
