// SPDX-License-Identifier: AGPL-3.0-or-later
// Ordinary positive fixture lifecycle only. No enrolled credential or effect.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {join,resolve} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createPrimeOwnerController} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'

const [harness,contractFile]=process.argv.slice(2)
if(!harness)throw new Error('ordinary-lifecycle.mjs <pinned Prime DSH> [browser contract helper]')
const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-owner-ordinary.cjs'))
const reactMeta=require('react/package.json')
assert.equal(reactMeta.version,'18.3.1','ordinary built factory uses pinned React')
const contracts=await import(contractFile?pathToFileURL(resolve(contractFile)).href:new URL('../../../contracts/src/browser.mjs',import.meta.url).href)
const modules={react:require('react'),'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{}}
const factories={},loaderWindow={__ModuleLoader__:{load:({id,factory})=>{factories[id]=factory}}}
// Existing render-fixture factory loader: owned bundles and injected fixtures
// stay in one JSON realm. No browser, host hook or credential API is installed.
for(const name of ['../../faces/layout/lib/client.js','../lib/client.js'])new Function('window',await readFile(new URL(name,import.meta.url),'utf8'))(loaderWindow)
const get=name=>{if(name in modules)return modules[name];return modules[name]=factories[name.replace(/\/client$/,'')](get)}
get('@aukora/face-layout/client')
const built=get('@aukora/prime-authority-ui/client')
assert.equal(typeof built.createPrimeOwnerController,'function')

const clock=Date.parse('2030-01-01T00:00:00Z'),results=[],failures=[]
let assertions=2
const eq=(actual,expected,message)=>{assertions++;assert.deepEqual(actual,expected,message)}
const ok=(value,message)=>{assertions++;assert.ok(value,message)}
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done});return{promise,resolve}}
const turns=async()=>{for(let i=0;i<12;i++)await Promise.resolve()}
function make(factory,options={}){
  const binding=createOwnerUiFixture(contracts,{now:()=>clock,...options})
  const timers=new Set(),controller=factory({now:()=>clock,schedule(fn){const timer={fn};timers.add(timer);return timer},unschedule(timer){timers.delete(timer)}})
  controller.connect(binding)
  return{binding,controller,timers}
}
function snapshot(controller){const state=controller.getSnapshot();return{
  phase:state.phase,owner:state.owner,operation_available:state.operation_available,expired:state.expired,
  logout_status:state.logout_status,logout_error_code:state.logout_error_code,presentation:state.presentation,
  approval_action_pending:state.approval_action_pending,error_code:state.error_code,
}}
async function scenario(label,factory,name,run){
  try{results.push({implementation:label,scenario:name,observed:await run(factory)})}
  catch(error){failures.push({implementation:label,scenario:name,error:error?.message??String(error)})}
}
for(const [label,factory]of [['source',createPrimeOwnerController],['built',built.createPrimeOwnerController]]){
  await scenario(label,factory,'login-review-repeat-approval',async factory=>{
    const login=deferred(),approval=deferred(),f=make(factory,{loginGate:login.promise,approvalGate:approval.promise})
    try{
      const pending=f.controller.login();eq(f.controller.getSnapshot().phase,'login_pending');eq(f.controller.getSnapshot().owner,null)
      login.resolve();await pending;eq(f.controller.getSnapshot().phase,'authenticated');eq(f.binding.counts.login,1)
      ok(!Object.hasOwn(f.controller.getSnapshot().owner,'session_token'),'owner presentation excludes session token')
      await f.controller.prepare();const view=f.controller.getSnapshot().presentation
      eq(f.controller.getSnapshot().phase,'review_ready');eq(f.binding.counts.review,1)
      eq(view.canonical_operation,contracts.canonicalJson(f.binding.operation));eq(view.operation_digest,await contracts.operationDigest(f.binding.operation))
      eq(view.rows.map(row=>row.key).sort(),Object.keys(f.binding.operation).sort());ok(Object.isFrozen(view.operation.canonical_parameters))
      const first=f.controller.submitApproval(),second=f.controller.submitApproval();eq(f.controller.getSnapshot().phase,'approval_pending')
      await turns();eq(f.binding.counts.approve,1,'ordinary repeated clicks dispatch one approval')
      approval.resolve();await Promise.all([first,second]);eq(f.controller.getSnapshot().phase,'approved');eq(f.binding.counts.approve,1)
      ok(f.controller.getSnapshot().reason.includes('Execution has not been confirmed'),'approval does not claim an effect')
      eq(await f.controller.submitApproval(),null);eq(f.binding.counts.approve,1)
      return snapshot(f.controller)
    }finally{login.resolve();approval.resolve();f.controller.dispose();await turns()}
  })
  await scenario(label,factory,'login-logout-repeat-logout-relogin',async factory=>{
    const logout=deferred(),f=make(factory,{logoutGate:logout.promise})
    try{
      await f.controller.login();await f.controller.prepare();eq(f.controller.getSnapshot().phase,'review_ready')
      const first=f.controller.logout(),second=f.controller.logout();eq(first,second,'pending logout clicks coalesce')
      eq(f.controller.getSnapshot().owner,null,'local owner removed immediately');eq(f.controller.getSnapshot().presentation,null)
      eq(f.controller.getSnapshot().logout_status,'pending');eq(f.binding.counts.logout,1,'one synthetic server logout call')
      logout.resolve();eq(await first,{ok:true,status:'LOGGED_OUT'});eq(await second,{ok:true,status:'LOGGED_OUT'})
      eq(f.controller.getSnapshot().phase,'logged_out');eq(f.controller.getSnapshot().logout_status,'confirmed')
      eq(await f.controller.logout(),{ok:true,status:'LOGGED_OUT'});eq(f.binding.counts.logout,1,'completed repeated logout makes no extra host call')
      await f.controller.login();eq(f.controller.getSnapshot().phase,'authenticated');eq(f.binding.counts.login,2)
      await f.controller.prepare();eq(f.controller.getSnapshot().phase,'review_ready');eq(f.binding.counts.review,2)
      return snapshot(f.controller)
    }finally{logout.resolve();f.controller.dispose();await turns()}
  })
  await scenario(label,factory,'dispose-publishes-owner-loss',async factory=>{
    const f=make(factory),observed=[]
    try{
      await f.controller.login();await f.controller.prepare();const off=f.controller.subscribe(()=>observed.push(snapshot(f.controller)))
      f.controller.dispose();eq(f.controller.getSnapshot().owner,null);eq(f.controller.getSnapshot().presentation,null)
      eq(f.controller.getSnapshot().phase,'unavailable');eq(f.controller.getSnapshot().operation_available,false)
      ok(observed.some(state=>state.owner===null&&state.presentation===null),'owner loss published before subscribers are removed')
      eq(f.binding.counts.logout,1);eq(f.timers.size,0,'dispose clears only its own synthetic timer')
      await turns();eq(f.controller.getSnapshot().logout_status,'confirmed');eq(observed.length,1,'removed subscribers receive no late server acknowledgement')
      off();return snapshot(f.controller)
    }finally{f.controller.dispose();await turns()}
  })
}
if(!failures.length){for(const name of ['login-review-repeat-approval','login-logout-repeat-logout-relogin','dispose-publishes-owner-loss']){
  const source=results.find(result=>result.implementation==='source'&&result.scenario===name),compiled=results.find(result=>result.implementation==='built'&&result.scenario===name)
  eq(compiled.observed,source.observed,'source and built ordinary lifecycle agree: '+name)
}}
console.log(JSON.stringify({result:failures.length?'FAIL':'PASS',ordinary_scenarios_per_implementation:3,implementations:['source','built'],assertions,
  source_built_agreement:!failures.length,react_version:reactMeta.version,real_enrollment:false,real_authentication:false,effects:false,network_calls:0,
  failures},null,2))
if(failures.length)process.exitCode=1
