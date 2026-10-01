import assert from 'node:assert/strict'
import {pathToFileURL} from 'node:url'
import {createPrimeOwnerController,createHttpAuthority} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'
const contracts = await import(process.argv[2] ? pathToFileURL(process.argv[2]).href : '@aukora-prime/contracts')
let clock = Date.parse('2030-01-01T00:00:00Z')
const make = options => {const binding=createOwnerUiFixture(contracts,{now:()=>clock,...options});const controller=createPrimeOwnerController({now:()=>clock});controller.connect(binding);return {binding,controller}}
let cases=0
{
  let release
  const loginGate=new Promise(r=>{release=r})
  const f=make({loginGate}); const pending=f.controller.login()
  assert.equal(f.controller.getSnapshot().phase,'login_pending');assert.equal(f.controller.getSnapshot().owner,null)
  release();await pending;assert.equal(f.controller.getSnapshot().phase,'authenticated')
  assert.equal(Object.hasOwn(f.controller.getSnapshot().owner,'session_token'),false)
  await f.controller.prepare();const view=f.controller.getSnapshot().presentation
  assert.equal(view.rows.length,Object.keys(f.binding.operation).length);assert.deepEqual(view.rows.map(row=>row.key).sort(),Object.keys(f.binding.operation).sort());assert.equal(view.canonical_operation,contracts.canonicalJson(f.binding.operation))
  assert(Object.isFrozen(view.operation.canonical_parameters));assert.equal(view.review_challenge.challenge,'1'.padStart(64,'0'))
  await Promise.all([f.controller.approve(),f.controller.approve()]);assert.equal(f.binding.counts.approve,1)
  assert.equal(f.controller.getSnapshot().phase,'approved');assert(f.controller.getSnapshot().reason.includes('Execution has not been confirmed'))
  f.controller.dispose();cases++
}
{
  const f=make({outcome:'unknown'});await f.controller.login();await f.controller.prepare();await f.controller.approve()
  assert.equal(f.controller.getSnapshot().phase,'outcome_unknown');await f.controller.approve();assert.equal(f.binding.counts.approve,1)
  f.controller.dispose();cases++
}
{
  const f=make();await f.controller.login();await f.controller.prepare();await f.controller.decline()
  assert.equal(f.controller.getSnapshot().phase,'denied');assert.equal(f.binding.counts.approve,0);assert.equal(f.binding.counts.decline,1)
  f.controller.dispose();cases++
}
{
  let expire
  const binding=createOwnerUiFixture(contracts,{now:()=>clock});const controller=createPrimeOwnerController({now:()=>clock,schedule:fn=>{expire=fn;return 1},unschedule:()=>{}})
  controller.connect(binding);await controller.login();await controller.prepare();clock+=121000;expire()
  assert.equal(controller.getSnapshot().phase,'expired');await controller.approve();assert.equal(binding.counts.approve,0)
  controller.dispose();clock-=121000;cases++
}
{
  let release;const gate=new Promise(r=>{release=r});const f=make({loginGate:gate});const pending=f.controller.login();f.controller.logout();release();await pending
  assert.equal(f.controller.getSnapshot().owner,null);assert.equal(f.controller.getSnapshot().phase,'logged_out');f.controller.dispose();cases++
}
{
  const f=make();f.controller.connect({...f.binding,authority:{...f.binding.authority,loginChallenge:async()=>({ok:false,error_code:'UNAVAILABLE',reason:'No enrolled credential.'})}})
  await f.controller.login();assert.equal(f.controller.getSnapshot().phase,'unavailable');assert.equal(f.controller.getSnapshot().owner,null)
  assert.equal(f.binding.counts.login,0);f.controller.dispose();cases++
}
{
  const requests=[];const authority=createHttpAuthority(async(url,options)=>{requests.push({url,options});return {ok:false,json:async()=>({ok:false,error_code:'UNAVAILABLE'})}})
  const input={owner_id:'public-fixture',kind:'passkey'};await authority.loginChallenge(input)
  assert.equal(requests[0].url,'/api/prime/authority/loginChallenge');assert.equal(requests[0].options.redirect,'error')
  assert.equal(requests[0].options.credentials,'same-origin');assert.deepEqual(JSON.parse(requests[0].options.body),input);cases++
}
console.log(JSON.stringify({result:'PASS',cases,real_enrollment:false,real_authentication:false,effects:false}))
