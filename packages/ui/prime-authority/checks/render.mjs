import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {runInNewContext} from 'node:vm'
import {resolve,join} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createPrimeOwnerController} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'

// This is server-render evidence of the actual native component, separate from browser observation.
const [harness,contractFile]=process.argv.slice(2)
if(!harness||!contractFile)throw new Error('render.mjs <pinned Prime DSH> <browser contract helper>')
const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-owner-render.cjs'))
const React=require('react'),server=require('react-dom/server'),contracts=await import(pathToFileURL(resolve(contractFile)).href)
const modules={'react':React,'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{}}
const factories={}
const sandbox={window:{__ModuleLoader__:{load:({id,factory})=>{factories[id]=factory}}},AbortController,setTimeout,clearTimeout,Date,console}
for(const name of ['../../faces/layout/lib/client.js','../lib/client.js'])runInNewContext(await readFile(new URL(name,import.meta.url),'utf8'),sandbox)
const get=name=>{if(name in modules)return modules[name];return modules[name]=factories[name.replace(/\/client$/,'')](get)}
get('@aukora/face-layout/client')
const ui=get('@aukora/prime-authority-ui/client')
const render=controller=>server.renderToStaticMarkup(React.createElement(ui.OwnerSurface,{activeSurface:'prime-owner',controller}))
let count=0,clock=Date.parse('2030-01-01T00:00:00Z')
const make=options=>{const binding=createOwnerUiFixture(contracts,{now:()=>clock,...options});const controller=createPrimeOwnerController({now:()=>clock});controller.connect(binding);return {binding,controller}}
{
  const f=make();let html=render(f.controller)
  assert(html.includes('Disposable UI fixture.'));assert(html.includes('Sign in with passkey'));assert(!html.includes('Host-confirmed owner:'))
  await f.controller.login();await f.controller.prepare();html=render(f.controller)
  for(const key of Object.keys(f.binding.operation))assert(html.includes(`data-operation-field="${key}"`))
  assert(html.includes('data-review-challenge'));assert(html.includes('data-operation-digest'));assert(html.includes('data-canonical-operation'))
  assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;must remain literal text&lt;/script&gt;'))
  assert(!html.includes('synthetic-in-memory-only'));assert(!html.includes('client_data_json'))
  await f.controller.approve();html=render(f.controller)
  assert(html.includes('data-phase="approved"'));assert(html.includes('Execution has not been confirmed'))
  assert(/disabled=""[^>]*>Approve exact operation/.test(html));f.controller.dispose();count++
}
{
  const f=make();await f.controller.login();await f.controller.prepare();await f.controller.decline()
  const html=render(f.controller);assert(html.includes('data-phase="denied"'));assert(html.includes('confirmed that this operation was declined'))
  f.controller.dispose();count++
}
{
  const f=make({outcome:'unknown'});await f.controller.login();await f.controller.prepare();await f.controller.approve()
  const html=render(f.controller);assert(html.includes('data-phase="outcome_unknown"'));assert(html.includes('do not retry'))
  assert(/disabled=""[^>]*>Request fresh review/.test(html));f.controller.dispose();count++
}
{
  let release;const gate=new Promise(r=>{release=r}),f=make({loginGate:gate}),pending=f.controller.login()
  const html=render(f.controller);assert(html.includes('data-phase="login_pending"'));assert(!html.includes('Host-confirmed owner:'))
  assert(/disabled=""[^>]*>Sign in with passkey/.test(html));release();await pending;f.controller.dispose();count++
}
{
  let expire;const binding=createOwnerUiFixture(contracts,{now:()=>clock});const controller=createPrimeOwnerController({now:()=>clock,schedule:fn=>{expire=fn;return 1},unschedule:()=>{}})
  controller.connect(binding);await controller.login();await controller.prepare();clock+=121000;expire()
  const html=render(controller);assert(html.includes('data-phase="expired"'));assert(/disabled=""[^>]*>Approve exact operation/.test(html))
  controller.dispose();count++
}
console.log(JSON.stringify({result:'PASS',native_component_render_groups:count,browser_observation:'PENDING',real_authentication:false,effects:false}))
