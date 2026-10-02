// SPDX-License-Identifier: AGPL-3.0-or-later
// Keyless lifecycle check of a freshly compiled native plugin in real Cordis.
// No HTTP listener, browser, credential, inference or accepted memory record.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import {createRequire} from 'node:module'
import {resolve,join,isAbsolute} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createOwnerUiFixture} from './fixture.mjs'

const [harness,contractFile,clientFile,nativeFile]=process.argv.slice(2)
if(!harness||!contractFile||!clientFile||!isAbsolute(clientFile))
 throw new Error('native-join.mjs <pinned DSH> <browser contracts> <absolute fresh owner client.js> [guarded owned H native helper]')
const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-native-join.cjs'))
const React=require('react')
assert.equal(require('react/package.json').version,'18.3.1')
const cordisPackage=JSON.parse(await readFile(join(resolve(harness),'vendor/cordis/package.json'),'utf8'))
assert.equal(cordisPackage.version,'4.0.2')
const {Context}=await import(pathToFileURL(join(resolve(harness),'vendor/cordis/lib/index.js')).href)
const contracts=await import(pathToFileURL(resolve(contractFile)).href)
const factories={},modules={react:React,'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{}}
const loaderWindow={__ModuleLoader__:{load:({id,factory})=>{factories[id]=factory}}}
const clientBytes=await readFile(clientFile)
for(const bytes of [await readFile(new URL('../../faces/layout/lib/client.js',import.meta.url)),clientBytes])
 new Function('window',bytes.toString('utf8'))(loaderWindow)
const get=name=>Object.hasOwn(modules,name)?modules[name]:modules[name]=factories[name.replace(/\/client$/,'')](get)
get('@aukora/face-layout/client')
const ui=get('@aukora/prime-authority-ui/client')
let requests=0,assertions=0,groups=0,nativeSha256
const originals=new Map(['fetch','navigator','PublicKeyCredential'].map(name=>[name,Object.getOwnPropertyDescriptor(globalThis,name)]))
Object.defineProperty(globalThis,'fetch',{configurable:true,value:()=>{requests++;throw new Error('REFUSED: native lifecycle check cannot send requests')}})
Object.defineProperty(globalThis,'navigator',{configurable:true,value:{credentials:{get(){assertions++;throw new Error('REFUSED: native lifecycle check cannot request a credential')}}}})
Object.defineProperty(globalThis,'PublicKeyCredential',{configurable:true,value:class {}})
const ctx=new Context(),registrations=[]
const serviceRemovers=[]
const settle=async()=>{
 const fibers=[...ctx.registry.values()].flatMap(runtime=>[...runtime.fibers])
 await Promise.all(fibers.map(fiber=>fiber.await()))
}
const fixture=()=>{
 const value=createOwnerUiFixture(contracts)
 return {binding:{authority:value.authority,contracts,owner_id:'native-keyless-owner',fixture:true,requiresCapabilities:true},counts:value.counts}
}
let uiFiber,removeAuthority
try {
 for(const [name,value] of [['slots',{inject(_slot,callback){return callback()},register(descriptor,component){
   const registration={descriptor,component};registrations.push(registration)
   return ()=>{const index=registrations.indexOf(registration);if(index>=0)registrations.splice(index,1)}
 }}],['layout',{}],['locale',{}]])serviceRemovers.push(ctx.reflect.provide(name,value))
 uiFiber=ctx.plugin({name:'prime-keyless-native-check',inject:ui.inject,apply:ui.apply})
 await uiFiber
 await settle()
 const ack=ctx.primeOwnerNativeConnection,controller=ctx.primeOwnerUi
 assert(ack);assert(Object.isFrozen(ack));assert.equal(ack.controller,controller)
 assert.equal(registrations.length,4)
 const first=fixture()
 assert.equal(ack.isConnected(first.binding),false)
 assert.equal(controller.getSnapshot().authority_available,false)
 assert.equal(ctx.primeAuthority,undefined)
 groups++

 // Cordis service publication schedules the actual dependency injection.
 // Presence of the service before that fiber settles cannot acknowledge it.
 removeAuthority=ctx.reflect.provide('primeAuthority',first.binding)
 assert.equal(ctx.primeAuthority,first.binding)
 assert.equal(ack.isConnected(first.binding),false)
 await settle()
 assert.equal(ack.isConnected(first.binding),true)
 assert.equal(ack.isConnected({...first.binding}),false)
 assert.equal(controller.getSnapshot().owner_id,first.binding.owner_id)
 assert.equal(controller.getSnapshot().owner,null)
 assert.equal(controller.getSnapshot().authority_available,false)
 assert.deepEqual(first.counts,{login:0,review:0,approve:0,decline:0,logout:0})
 groups++

 // Even reconnecting the identical object creates a different generation.
 const sameObjectWitness=controller.connect(first.binding)
 assert.equal(sameObjectWitness.isCurrent(),true)
 assert.equal(ack.isConnected(first.binding),false)
 await removeAuthority();removeAuthority=undefined
 await settle()
 assert.equal(sameObjectWitness.isCurrent(),true,'stale native cleanup must preserve a same-object reconnect')
 await controller.disconnect()
 assert.equal(sameObjectWitness.isCurrent(),false)
 groups++
 const firstAgain=fixture()
 removeAuthority=ctx.reflect.provide('primeAuthority',firstAgain.binding)
 await settle()
 assert.equal(ack.isConnected(firstAgain.binding),true)
 const other=fixture()
 const replacementWitness=controller.connect(other.binding)
 assert.equal(replacementWitness.isCurrent(),true)
 assert.equal(ack.isConnected(firstAgain.binding),false)
 assert.equal(ack.isConnected(other.binding),false)
 await removeAuthority();removeAuthority=undefined
 await settle()
 assert.equal(ack.isConnected(firstAgain.binding),false)
 assert.equal(ctx.primeAuthority,undefined)
 assert.equal(replacementWitness.isCurrent(),true,'removing stale native binding must preserve a newer direct connection')
 await controller.disconnect()
 groups++

 // Real remove/provide lifecycle restores acknowledgement only for the new
 // exact service. A late call of the old owned disposer preserves it.
 const second=fixture()
 removeAuthority=ctx.reflect.provide('primeAuthority',second.binding)
 assert.equal(ack.isConnected(second.binding),false)
 await settle()
 assert.equal(ack.isConnected(second.binding),true)
 const oldRemover=removeAuthority
 await oldRemover();removeAuthority=undefined
 const third=fixture()
 removeAuthority=ctx.reflect.provide('primeAuthority',third.binding)
 await settle()
 assert.equal(ack.isConnected(third.binding),true)
 await oldRemover()
 assert.equal(ctx.primeAuthority,third.binding)
 assert.equal(ack.isConnected(third.binding),true)
 groups++

 // A binding whose transport construction fails never receives an ack.
 await removeAuthority();removeAuthority=undefined
 const invalid={contracts:{},owner_id:third.binding.owner_id,authority:{}}
 removeAuthority=ctx.reflect.provide('primeAuthority',invalid)
 await settle()
 assert.equal(ack.isConnected(invalid),false)
 assert.equal(controller.getSnapshot().authority_available,false)
 await removeAuthority();removeAuthority=undefined
 groups++

 // A synchronous connect notification may establish a direct replacement
 // before B receives its original connection witness. Its cleanup still must
 // own only the original attempt, never the newly connected generation.
 const reentrant=fixture(),direct=fixture()
 let armed=true,directWitness
 const offReentrant=controller.subscribe(()=>{
  if(!armed||controller.getSnapshot().owner_id!==reentrant.binding.owner_id)return
  armed=false;directWitness=controller.connect(direct.binding)
 })
 removeAuthority=ctx.reflect.provide('primeAuthority',reentrant.binding)
 await settle()
 offReentrant()
 assert.equal(armed,false)
 assert.equal(directWitness.isCurrent(),true)
 assert.equal(ack.isConnected(reentrant.binding),false)
 assert.equal(ack.isConnected(direct.binding),false)
 await removeAuthority();removeAuthority=undefined
 await settle()
 assert.equal(directWitness.isCurrent(),true,'native cleanup during a connect notification must preserve direct replacement')
 await controller.disconnect()
 groups++

 // Removing the service during its initial connect notification must remain
 // unacknowledged and finish unavailable when no replacement was installed.
 const closing=fixture()
 let removeOnConnect=true,pendingAcknowledgement,pendingRemoval
 const offClosing=controller.subscribe(()=>{
  if(!removeOnConnect||controller.getSnapshot().owner_id!==closing.binding.owner_id)return
  removeOnConnect=false;pendingAcknowledgement=ack.isConnected(closing.binding)
  pendingRemoval=removeAuthority()
 })
 removeAuthority=ctx.reflect.provide('primeAuthority',closing.binding)
 await settle()
 offClosing()
 await pendingRemoval
 removeAuthority=undefined
 assert.equal(removeOnConnect,false)
 assert.equal(pendingAcknowledgement,false)
 assert.equal(ack.isConnected(closing.binding),false)
 assert.equal(ctx.primeAuthority,undefined)
 assert.equal(controller.getSnapshot().authority_available,false)
 assert.equal(controller.getSnapshot().owner,null)
 groups++

 if(nativeFile){
  const source=await readFile(resolve(nativeFile),'utf8')
  nativeSha256=createHash('sha256').update(source).digest('hex')
  assert(source.includes('primeOwnerNativeConnection'),'H attachment join requires its actual guarded helper')
  const {createOwnerMemoryNativeBinding}=await import(pathToFileURL(resolve(nativeFile)).href)
  const native=createOwnerMemoryNativeBinding(ctx,{contracts,
   ownerBinding:{owner_id:'native-keyless-owner',passkeyProfile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'}},
   fetcher:()=>{requests++;throw new Error('REFUSED: native H check cannot send requests')}})
  assert.equal(ack.isConnected(ctx.primeAuthority),false)
  assert.throws(()=>native.attachAfterNativeConnection(),/UNAVAILABLE/)
  // Early attach failure may dispose its owner; do not reuse that client.
  native.dispose();await settle()
  const ready=createOwnerMemoryNativeBinding(ctx,{contracts,
   ownerBinding:{owner_id:'native-keyless-owner',passkeyProfile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'}},
   fetcher:()=>{requests++;throw new Error('REFUSED: native H check cannot send requests')}})
  await settle()
  assert.equal(ack.isConnected(ctx.primeAuthority),true)
  const attached=ready.attachAfterNativeConnection()
  assert.equal(ready.client,attached)
  assert.equal(ctx.primePilotMemory.client,attached)
  assert.equal(controller.getSnapshot().owner,null)
  assert.equal(controller.getSnapshot().authority_available,false)
  const reusedWitness=controller.connect(attached.binding)
  assert.equal(ack.isConnected(attached.binding),false)
  assert.throws(()=>ready.capabilitiesUnavailable(),/UNAVAILABLE/)
  ready.dispose();await settle()
  assert.equal(reusedWitness.isCurrent(),true,'H and B stale cleanup must preserve same-object reconnection')
  assert.equal(ctx.primeAuthority,undefined)
  assert.equal(ctx.primePilotMemory,undefined)
  assert.throws(()=>ready.attachAfterNativeConnection(),/UNAVAILABLE/)
  await controller.disconnect()
  groups++
  const changing=createOwnerMemoryNativeBinding(ctx,{contracts,
   ownerBinding:{owner_id:'native-keyless-owner',passkeyProfile:{profile:'localhost-pilot-v1',origin:'http://localhost:18731',rp_id:'localhost'}},
   fetcher:()=>{requests++;throw new Error('REFUSED: native H check cannot send requests')}})
  await settle()
  const changingBinding=ctx.primeAuthority
  let replaceOnHook=true,hookReplacement
  const offHook=controller.subscribe(()=>{
   if(!replaceOnHook)return
   replaceOnHook=false;hookReplacement=controller.connect({...changingBinding})
  })
  assert.throws(()=>changing.attachAfterNativeConnection(),/UNAVAILABLE/)
  offHook()
  await settle()
  assert.equal(hookReplacement.isCurrent(),true,'H hook-step refusal must preserve its synchronous replacement')
  assert.equal(ctx.primePilotMemory,undefined)
  changing.dispose();await settle()
  assert.equal(hookReplacement.isCurrent(),true)
  await controller.disconnect()
  groups++
 }

 const last=fixture()
 removeAuthority=ctx.reflect.provide('primeAuthority',last.binding)
 await settle()
 assert.equal(ack.isConnected(last.binding),true)
 await uiFiber.dispose()
 assert.equal(ack.isConnected(last.binding),false)
 assert.equal(ctx.primeOwnerNativeConnection,undefined)
 assert.equal(ctx.primeOwnerUi,undefined)
 // Slots here are registration-only stubs; their production service-owned
 // disposer semantics are outside the native connection lifetime question.
 groups++
 assert.equal(requests,0);assert.equal(assertions,0)
 console.log(JSON.stringify({status:'PASS',groups,cordis:cordisPackage.version,react:require('react/package.json').version,
  client_sha256:createHash('sha256').update(clientBytes).digest('hex'),requests,credential_assertions:assertions,
  ...(nativeSha256?{h_native_sha256:nativeSha256}:{}),
  h_attachment_join:nativeFile?'PASS':'UNPERFORMED: guarded H helper not supplied'}))
} finally {
 if(removeAuthority)await removeAuthority()
 if(uiFiber)await uiFiber.dispose()
 for(const remove of serviceRemovers.reverse())await remove()
 await ctx.fiber.dispose()
 for(const [name,descriptor] of originals){if(descriptor)Object.defineProperty(globalThis,name,descriptor);else delete globalThis[name]}
}
