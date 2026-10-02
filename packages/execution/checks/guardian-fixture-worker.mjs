// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable separate-process fixtures ONLY. The backend below is an authored
// serialized conditional-reclaim simulator, not a pinned gateway capability.
import { createServer,createConnection } from 'node:net'
import { chmodSync,closeSync,existsSync,fsyncSync,openSync,readFileSync,renameSync,writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'

const clone=value=>JSON.parse(JSON.stringify(value))
const error=(message,code='UNAVAILABLE')=>Object.assign(new Error(message),{code})
const MAX_FRAME=1024*1024

/** This protocol is private to authored fixtures; it is not the guardian wire
 * contract and supplies neither credentials nor runtime qualification. */
export function fixtureBackendCall(socketPath,method,payload={}, {timeoutMs=1000,signal}={}) {
  return new Promise((resolve,reject)=>{
    const id=randomUUID(),socket=createConnection(socketPath)
    let input='',settled=false
    const finish=(failure,result)=>{
      if(settled)return
      settled=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);socket.destroy()
      if(failure)reject(failure);else resolve(result)
    }
    const abort=()=>finish(error('fixture backend call aborted','CANCELLED'))
    const timer=setTimeout(()=>finish(error('fixture backend response timeout')),timeoutMs)
    socket.once('connect',()=>socket.write(JSON.stringify({id,method,payload})+'\n'))
    socket.on('data',chunk=>{
      input+=chunk.toString('utf8')
      if(Buffer.byteLength(input)>MAX_FRAME)return finish(error('fixture response exceeds bound','INVALID'))
      const newline=input.indexOf('\n');if(newline<0)return
      try {
        const reply=JSON.parse(input.slice(0,newline))
        if(reply.id!==id)throw error('fixture response identity differs','INVALID')
        if(reply.ok!==true)throw error(reply.message??'fixture backend refused',reply.code??'UNAVAILABLE')
        finish(null,reply.value)
      } catch(failure){finish(failure)}
    })
    socket.once('error',failure=>finish(failure))
    socket.once('end',()=>finish(error('fixture backend reply lost')))
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true})
  })
}

function durableWrite(root,file,value) {
  const next=file+'.next'
  writeFileSync(next,JSON.stringify(value),{mode:0o600})
  const fd=openSync(next,'r');try {fsyncSync(fd)}finally {closeSync(fd)}
  renameSync(next,file)
  const dir=openSync(root,'r');try {fsyncSync(dir)}finally {closeSync(dir)}
}

async function runBackend(root,socketPath) {
  const file=join(root,'fixture-backend.json')
  if(!existsSync(file))durableWrite(root,file,{version:1,resources:{},events:[],observations:0,failed_observations:0,outage:false,lost_reclaims:0,replace_on_reclaim:null})
  let queue=Promise.resolve()
  const dispatch=async(method,payload)=>{
    const state=JSON.parse(readFileSync(file,'utf8'))
    const save=()=>durableWrite(root,file,state)
    if(method==='read')return state
    if(method==='add') {
      const resource=clone(payload.resource)
      if(state.resources[resource.uid])throw error('fixture UID already exists','TARGET_MISMATCH')
      state.resources[resource.uid]=resource;state.events.push({action:'fixture_add',resource});save();return {ok:true}
    }
    if(method==='remove') {delete state.resources[payload.uid];save();return {ok:true}}
    if(method==='configure') {
      for(const key of ['outage','lost_reclaims','replace_on_reclaim'])if(Object.hasOwn(payload,key))state[key]=clone(payload[key])
      save();return {ok:true}
    }
    if(method==='observe') {
      state.observations++
      if(state.outage){state.failed_observations++;save();throw error('disposable backend outage')}
      save();return {sandboxes:Object.values(state.resources),inventory_complete:true}
    }
    if(method==='reclaim') {
      if(state.outage)throw error('disposable backend outage')
      const {registration,resource,request_id}=payload
      state.events.push({action:'reclaim_attempt',request_id,resource:clone(resource)})
      if(state.replace_on_reclaim) {
        delete state.resources[resource.uid]
        const replacement=state.replace_on_reclaim;state.resources[replacement.uid]=replacement;state.replace_on_reclaim=null
      }
      const actual=state.resources[resource.uid]
      if(!actual) {
        // A matching name rebound to another UUID must never be removed.
        if(Object.values(state.resources).some(item=>item.name===resource.name)) {
          state.events.push({action:'reclaim_refused',request_id,reason:'UID substitution'});save();throw error('fixture immutable UID no longer owns name','TARGET_MISMATCH')
        }
        save();return {sandbox_uid:resource.uid,outcome:'already_absent'}
      }
      const same=['uid','name','workspace','owner_token','origin_request_id'].every(key=>actual[key]===resource[key])
        &&actual.name===registration.name&&actual.workspace===registration.request.operation.target_identity.workspace
        &&actual.owner_token===registration.token&&actual.origin_request_id===registration.create_request_id
      if(!same) {state.events.push({action:'reclaim_refused',request_id,reason:'immutable identity differs'});save();throw error('fixture conditional reclaim refused identity substitution','TARGET_MISMATCH')}
      const earlier=state.events.filter(event=>event.action==='reclaim_attempt'&&event.resource.uid===actual.uid)
      if(earlier.some(event=>event.request_id!==request_id)) {save();throw error('fixture cleanup attempt identity changed','TARGET_MISMATCH')}
      if(state.lost_reclaims>0) {
        state.lost_reclaims--;state.events.push({action:'fixture_lost_reply',request_id,uid:actual.uid});save()
        // Leave the resource unchanged to exercise retry only after the same
        // immutable object is reobserved. No success acknowledgement is sent.
        return {fixture_drop_reply:true}
      }
      delete state.resources[actual.uid];state.events.push({action:'reclaimed',request_id,uid:actual.uid});save()
      return {sandbox_uid:actual.uid,outcome:'reclaimed'}
    }
    throw error('unknown fixture backend method','INVALID')
  }
  const server=createServer(socket=>{
    let input='',handled=false
    socket.on('error',()=>{})
    socket.on('data',chunk=>{
      input+=chunk.toString('utf8')
      if(Buffer.byteLength(input)>MAX_FRAME){socket.destroy();return}
      const newline=input.indexOf('\n');if(handled||newline<0)return;handled=true
      let frame
      try {frame=JSON.parse(input.slice(0,newline))}catch {socket.destroy();return}
      queue=queue.then(async()=>{
        try {
          const value=await dispatch(frame.method,frame.payload)
          if(value?.fixture_drop_reply)socket.end()
          else socket.end(JSON.stringify({id:frame.id,ok:true,value})+'\n')
        } catch(failure){socket.end(JSON.stringify({id:frame.id,ok:false,code:failure.code??'UNAVAILABLE',message:failure.message})+'\n')}
      })
    })
  })
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,resolve)})
  chmodSync(socketPath,0o600)
  process.send?.({type:'ready',pid:process.pid})
  await new Promise(resolve=>process.once('message',message=>{if(message?.type==='close')resolve()}))
  await queue
  await new Promise(resolve=>server.close(resolve))
}

async function runGuardian(root,socketPath,backendPath,scopeFile,initialize) {
  const { GuardianStore }=await import('../src/guardian/store.mjs')
  const { startGuardian }=await import('../src/guardian/worker.mjs')
  const scope=JSON.parse(readFileSync(scopeFile,'utf8'))
  const store=new GuardianStore(root,{initialize,scope})
  const backend={
    observe:(registration,{signal}={})=>fixtureBackendCall(backendPath,'observe',{registration},{signal}),
    reclaim:(registration,resource,{request_id,signal}={})=>fixtureBackendCall(backendPath,'reclaim',{registration,resource,request_id},{signal}),
  }
  try {
    await store.withOwner(async()=>{
      const guardian=await startGuardian({store,backend,socketPath,pollMs:15,controlTimeoutMs:150})
      process.send?.({type:'ready',pid:process.pid,guardian_id:store.identity})
      await new Promise(resolve=>process.once('message',message=>{if(message?.type==='close')resolve()}))
      await guardian.close()
    })
  } finally {store.close()}
}

async function runOwner(socketPath,registrationFile) {
  const { guardianCall }=await import('../src/guardian/ipc.mjs')
  const registration=JSON.parse(readFileSync(registrationFile,'utf8'))
  const value=await guardianCall(socketPath,'register',registration,{timeoutMs:1000})
  process.send?.({type:'registered',pid:process.pid,value})
}

const [role,...args]=process.argv.slice(2)
if(['fixture-backend','fixture-guardian','fixture-owner'].includes(role)) {
  try {
    if(role==='fixture-backend')await runBackend(...args)
    if(role==='fixture-guardian')await runGuardian(...args.slice(0,4),args[4]==='initialize')
    if(role==='fixture-owner')await runOwner(...args)
    process.disconnect?.()
  } catch(failure) {
    process.send?.({type:'error',code:failure.code??'UNAVAILABLE',message:failure.message})
    process.exitCode=1;process.disconnect?.()
  }
}
