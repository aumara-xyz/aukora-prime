// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused SSR/native join against a fresh owner build and actual pinned Cordis.
// Synthetic textarea refs and provider results exercise the registered UI click
// handler. This is not browser-event, credential, paid-call or runtime acceptance.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import {createRequire} from 'node:module'
import {resolve,join,isAbsolute} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createOwnerUiFixture} from './fixture.mjs'

const [harness,contractFile,clientFile]=process.argv.slice(2)
if(!harness||!contractFile||!clientFile||!isAbsolute(clientFile))
  throw new Error('inference-native-join.mjs <pinned DSH> <browser contracts> <absolute fresh owner client.js>')
const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-inference-native-check.cjs'))
const React=require('react'),server=require('react-dom/server'),jsx=require('react/jsx-runtime')
assert.equal(require('react/package.json').version,'18.3.1')
assert.equal(require('react-dom/package.json').version,'18.3.1')
const cordisPackage=JSON.parse(await readFile(join(resolve(harness),'vendor/cordis/package.json'),'utf8'))
assert.equal(cordisPackage.version,'4.0.2')
const {Context}=await import(pathToFileURL(join(resolve(harness),'vendor/cordis/lib/index.js')).href)
const contracts=await import(pathToFileURL(resolve(contractFile)).href)
let textareaText='  exact synthetic <message> & Ω\n\ttext  ',requestButton
const withSyntheticRef=(original)=>(type,props,...rest)=>{
  if(type==='textarea'&&props?.['aria-label']==='Message to Auma'&&props.ref) {
    // SSR never mounts an HTML textarea. Only this declared fixture assigns
    // its ref so that the production click callback reads literal test text.
    props.ref.current={value:textareaText}
  }
  return original(type,props,...rest)
}
const factories={},modules={react:React,'react/jsx-runtime':{...jsx,
  jsx:withSyntheticRef(jsx.jsx),jsxs:withSyntheticRef(jsx.jsxs)},'@deepseek-ai/dsh-client-store':{}}
const loader={__ModuleLoader__:{load:({id,factory})=>{factories[id]=factory}}}
const clientBytes=await readFile(clientFile)
for(const bytes of [await readFile(new URL('../../faces/layout/lib/client.js',import.meta.url)),clientBytes])
  new Function('window',bytes.toString('utf8'))(loader)
const get=name=>Object.hasOwn(modules,name)?modules[name]:modules[name]=factories[name.replace(/\/client$/,'')](get)
const layout=get('@aukora/face-layout/client')
modules['@aukora/face-layout/client']={...layout,ActionButton(props){
  if(props.children==='Request one Auma reply')requestButton=props
  return React.createElement(layout.ActionButton,props)
}}
const ui=get('@aukora/prime-authority-ui/client')
const clockStart=Date.parse('2030-01-01T00:00:00Z')
let clock=clockStart,networkCalls=0,credentialAssertions=0,groups=0,hostCalls=0
const originalNow=Object.getOwnPropertyDescriptor(Date,'now')
const originals=new Map(['fetch','navigator','PublicKeyCredential'].map(name=>[name,Object.getOwnPropertyDescriptor(globalThis,name)]))
Object.defineProperty(Date,'now',{configurable:true,value:()=>clock})
Object.defineProperty(globalThis,'fetch',{configurable:true,value:()=>{networkCalls++;throw new Error('REFUSED: this check has no network calls')}})
Object.defineProperty(globalThis,'navigator',{configurable:true,value:{credentials:{get(){credentialAssertions++;throw new Error('REFUSED: this check has no credential assertions')}}}})
Object.defineProperty(globalThis,'PublicKeyCredential',{configurable:true,value:class {}})
const ctx=new Context(),registrations=[],serviceRemovers=[]
let uiFiber,removeAuthority,removeInference,owner,authority
const settle=async()=>{
  const fibers=[...ctx.registry.values()].flatMap(runtime=>[...runtime.fibers])
  await Promise.all(fibers.map(fiber=>fiber.await()))
}
const tick=async()=>{for(let i=0;i<8;i++)await Promise.resolve()}
const deferred=()=>{let resolve;const promise=new Promise(done=>{resolve=done});return{promise,resolve}}
const escaped=value=>value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;'}[c]))
const render=()=>{
  requestButton=undefined
  const registration=registrations.find(value=>value.descriptor.name==='shell.surface'&&value.descriptor.id==='prime-owner')
  assert(registration,'actual native owner surface must be registered')
  const html=server.renderToStaticMarkup(React.createElement(registration.component,
    {activeSurface:'prime-owner',openSurface(){throw new Error('Unexpected navigation')},...registration.descriptor.inject()}))
  assert(requestButton,'registered native surface must render the real request control')
  return html
}
const completed=(draft,context)=>({outcome:'completed',request_uuid:draft.request_uuid,route_id:'externalDeepSeek',mode:'mock',
  proposal:{text:'  exact synthetic <reply> & 😀\n\tΩ  ',source_ids:[],grantsAuthority:false},
  usage:{input_tokens:2,output_tokens:3,cost_microusd:5},
  receipt:{sessionId:context.conversation_id,line:draft.text,turn:1,spokenAt:clock,request_uuid:draft.request_uuid,
    body_sha256:'a'.repeat(64),source_citation:{sessionId:context.conversation_id,turn:1,sha256:'a'.repeat(64),requestId:draft.request_uuid},citations:[]},omitted:[]})
const context=(suffix)=>Object.freeze({owner_id:authority.owner_id,task_id:'synthetic-task-'+suffix,conversation_id:'synthetic-conversation-'+suffix})
const publishAuthority=async()=>{
  const fixture=createOwnerUiFixture(contracts,{now:()=>clock})
  authority=Object.freeze({...fixture,requiresCapabilities:false})
  removeAuthority=ctx.reflect.provide('primeAuthority',authority)
  await settle()
  assert.equal(ctx.primeOwnerNativeConnection.isConnected(authority),true)
  return fixture
}
const publishInference=async(suffix,{ready=true,reply}={})=>{
  if(removeInference){await removeInference();removeInference=undefined;await settle()}
  const currentContext=context(suffix),listeners=new Set(),gate=deferred(),calls=[]
  let snapshot=Object.freeze(ready?{state:'ready',mode:'mock',reason:'Explicit synthetic provider fixture.'}
    :{state:'unavailable',mode:null,reason:'Owner-bound provider is unavailable in this fixture.'})
  const availability={getSnapshot:()=>snapshot,subscribe(listener){listeners.add(listener);return()=>listeners.delete(listener)}}
  const client={binding:authority,context:currentContext,availability,
    requestOne(draft,options){hostCalls++;calls.push({draft,options});return reply?Promise.resolve(reply(draft,currentContext)):gate.promise}}
  const binding={ownerController:owner,client}
  removeInference=ctx.reflect.provide('primePilotInference',binding)
  await settle()
  return{gate,calls,context:currentContext,binding,notify(){for(const listener of [...listeners])listener()},
    unavailable(){snapshot=Object.freeze({state:'unavailable',mode:null,reason:'Fixture provider disconnected.'});for(const listener of [...listeners])listener()}}
}
const click=async()=>{assert.equal(requestButton.disabled,false);requestButton.onClick();await tick()}
const login=async()=>{const result=await owner.login();assert.equal(result.owner_id,authority.owner_id);assert(owner.getSnapshot().owner)}
try{
  for(const [name,value]of [['slots',{inject(_slot,callback){return callback()},register(descriptor,component){
    const registration={descriptor,component};registrations.push(registration)
    return()=>{const index=registrations.indexOf(registration);if(index>=0)registrations.splice(index,1)}
  }}],['layout',{}],['locale',{}]])serviceRemovers.push(ctx.reflect.provide(name,value))
  uiFiber=ctx.plugin({name:'prime-keyless-inference-native-check',inject:ui.inject,apply:ui.apply})
  await uiFiber;await settle();owner=ctx.primeOwnerUi
  let html=render()
  assert.equal(requestButton.disabled,true)
  assert(html.includes('The host has not supplied an owner-bound reply client.'))
  assert(html.includes('data-auma-reply-unavailable="true"'))
  assert.equal(hostCalls,0);groups++

  await publishAuthority()
  const unavailable=await publishInference('unavailable',{ready:false})
  html=render();assert.equal(requestButton.disabled,true);assert.equal(hostCalls,0)
  await login()
  html=render();assert.equal(requestButton.disabled,true)
  assert(html.includes('Owner-bound provider is unavailable in this fixture.'))
  assert.equal(unavailable.calls.length,0);groups++

  const ready=await publishInference('completed')
  html=render();assert.equal(requestButton.disabled,false)
  assert(html.includes('data-auma-synthetic="true"'));assert(html.includes('This is not live inference.'))
  assert(html.includes(ready.context.owner_id));assert(html.includes(ready.context.task_id));assert(html.includes(ready.context.conversation_id))
  assert.equal(ready.calls.length,0,'render must not automatically request a reply')
  // Repeated real handlers share the immutable pending request identity.
  const handler=requestButton.onClick
  handler();handler();await tick()
  assert.equal(ready.calls.length,1)
  const [{draft,options}]=ready.calls
  assert(Object.isFrozen(draft));assert.deepEqual(Object.keys(draft).sort(),['request_uuid','text'])
  assert.match(draft.request_uuid,/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
  assert.equal(draft.text,textareaText);assert(options.signal instanceof AbortSignal)
  html=render();assert.equal(requestButton.disabled,true);assert(html.includes('data-auma-pilot-phase="pending"'));assert(html.includes(draft.request_uuid))
  const result=completed(draft,ready.context)
  ready.gate.resolve(result);await tick()
  html=render();assert.equal(requestButton.disabled,false)
  assert(html.includes('data-auma-pilot-phase="completed"'));assert(html.includes('data-provider-mode="mock"'))
  assert(html.includes(escaped(result.proposal.text)));assert(!html.includes('<reply>'))
  assert(html.includes(escaped(JSON.stringify(result.receipt,null,2))))
  assert(html.includes('grants no authority and has not been saved as memory'))
  assert.equal(result.proposal.text,'  exact synthetic <reply> & 😀\n\tΩ  ')
  assert.equal(ready.calls.length,1);groups++

  const unknown=await publishInference('host-unknown',{reply:(draft,context)=>({
    outcome:'outcome_unknown',request_uuid:draft.request_uuid,receipt:completed(draft,context).receipt,
    error:'Synthetic provider lost response.',reservation_retained:true})})
  html=render();await click();html=render()
  assert.equal(unknown.calls.length,1);assert.equal(requestButton.disabled,true)
  assert(html.includes('data-auma-reply-unknown="true"'));assert(html.includes('reservation remains held'))
  assert(!html.includes('data-auma-reply-text="true"'));groups++

  const loggedOut=await publishInference('logout')
  html=render();await click();assert.equal(loggedOut.calls.length,1)
  const lateLogout=completed(loggedOut.calls[0].draft,loggedOut.context)
  const logout=await owner.logout();assert.equal(logout.ok,true)
  assert.equal(loggedOut.calls[0].options.signal.aborted,true)
  loggedOut.gate.resolve(lateLogout);await tick()
  html=render();assert.equal(requestButton.disabled,true);assert(!html.includes(escaped(lateLogout.proposal.text)))
  await login();html=render()
  assert.equal(requestButton.disabled,true);assert(html.includes('data-auma-request-unconfirmed="true"'))
  assert(!html.includes('reservation remains held'),'UI cancellation has no E reservation evidence')
  assert.equal(loggedOut.calls.length,1);groups++

  const detached=await publishInference('service-disconnect')
  html=render();await click();assert.equal(detached.calls.length,1)
  const lateDetach=completed(detached.calls[0].draft,detached.context)
  const detachedBinding=detached.binding
  await removeInference();removeInference=undefined;await settle()
  assert.equal(detached.calls[0].options.signal.aborted,true)
  detached.gate.resolve(lateDetach);await tick()
  html=render();assert.equal(requestButton.disabled,true);assert(!html.includes(escaped(lateDetach.proposal.text)))
  removeInference=ctx.reflect.provide('primePilotInference',detachedBinding);await settle()
  html=render();assert.equal(requestButton.disabled,true);assert(html.includes('data-auma-request-unconfirmed="true"'))
  assert(!html.includes('reservation remains held'));assert.equal(detached.calls.length,1);groups++

  const expiring=await publishInference('expiry')
  html=render();await click();assert.equal(expiring.calls.length,1)
  const lateExpiry=completed(expiring.calls[0].draft,expiring.context)
  clock=clockStart+300001;expiring.notify()
  assert.equal(expiring.calls[0].options.signal.aborted,true)
  expiring.gate.resolve(lateExpiry);await tick()
  html=render();assert.equal(requestButton.disabled,true);assert(!html.includes(escaped(lateExpiry.proposal.text)))
  assert(html.includes('current configured owner and native connection'))
  assert.equal(expiring.calls.length,1);groups++

  // A fresh exact authority lifetime is a different native connection. Removal
  // of that connection fences a pending response even if its reply client stays.
  clock=clockStart
  await removeAuthority();removeAuthority=undefined;await settle()
  await publishAuthority();await login()
  const disconnected=await publishInference('authority-disconnect')
  html=render();await click();assert.equal(disconnected.calls.length,1)
  const lateConnection=completed(disconnected.calls[0].draft,disconnected.context)
  await removeAuthority();removeAuthority=undefined;await settle()
  assert.equal(ctx.primeOwnerNativeConnection.isConnected(disconnected.binding.client.binding),false)
  assert.equal(disconnected.calls[0].options.signal.aborted,true)
  disconnected.gate.resolve(lateConnection);await tick()
  html=render();assert.equal(requestButton.disabled,true);assert(!html.includes(escaped(lateConnection.proposal.text)))
  assert.equal(disconnected.calls.length,1);groups++

  assert.equal(networkCalls,0);assert.equal(credentialAssertions,0)
  console.log(JSON.stringify({status:'PASS',groups,cordis:cordisPackage.version,pinned_react:'18.3.1',
    client_sha256:createHash('sha256').update(clientBytes).digest('hex'),native_registered_surface:true,
    real_production_click_handler:true,synthetic_textarea_ref:true,synthetic_host_calls:hostCalls,
    network_calls:networkCalls,credential_assertions:credentialAssertions,browser_events:'UNPERFORMED',
    paid_provider_calls:'UNPERFORMED',protected_runtime:'UNPERFORMED'}))
}finally{
  if(removeInference)await removeInference()
  if(removeAuthority)await removeAuthority()
  if(uiFiber)await uiFiber.dispose()
  for(const remove of serviceRemovers.reverse())await remove()
  await ctx.fiber.dispose()
  Object.defineProperty(Date,'now',originalNow)
  for(const[name,descriptor]of originals){if(descriptor)Object.defineProperty(globalThis,name,descriptor);else delete globalThis[name]}
}
