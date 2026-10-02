import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {resolve,join,isAbsolute} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createPrimeOwnerController} from '../src/client/controller.mjs'
import {createOwnerUiFixture} from './fixture.mjs'

// This is server-render evidence of the actual native component, separate from browser observation.
const [harness,contractFile,clientFile]=process.argv.slice(2)
if(!harness||!contractFile)throw new Error('render.mjs <pinned Prime DSH> <browser contract helper> [owned built client.js]')
if(clientFile&&!isAbsolute(clientFile))throw new Error('render.mjs owned client must be an absolute local file path')
const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-owner-render.cjs'))
const React=require('react'),server=require('react-dom/server'),contracts=await import(pathToFileURL(resolve(contractFile)).href)
const modules={'react':React,'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{}}
const factories={}
// Keep JSON prototypes in the same realm as the injected controller/contracts,
// as in the browser. The inert loader receives only these verified owned bundles;
// no global window, native apply hook, credential API, or host is installed.
const loaderWindow={__ModuleLoader__:{load:({id,factory})=>{factories[id]=factory}}}
for(const name of ['../../faces/layout/lib/client.js','../lib/client.js']) {
  const file=name==='../lib/client.js'&&clientFile?resolve(clientFile):new URL(name,import.meta.url)
  new Function('window',await readFile(file,'utf8'))(loaderWindow)
}
const get=name=>{if(name in modules)return modules[name];return modules[name]=factories[name.replace(/\/client$/,'')](get)}
get('@aukora/face-layout/client')
const ui=get('@aukora/prime-authority-ui/client')
const render=controller=>server.renderToStaticMarkup(React.createElement(ui.OwnerSurface,{activeSurface:'prime-owner',controller}))
const badge=controller=>server.renderToStaticMarkup(React.createElement(ui.CapabilityBadge,{controller}))
let count=0,clock=Date.parse('2030-01-01T00:00:00Z')
const make=options=>{const binding=createOwnerUiFixture(contracts,{now:()=>clock,...options});const controller=createPrimeOwnerController({now:()=>clock});controller.connect(binding);return {binding,controller}}
{
  const f=make();await f.controller.login()
  const captureMetadata={profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:'2030-01-01',
    observed_at:'2030-01-01T00:00:00Z',confidence_percent:70,sensitivity:'none'}
  const memoryCapture={statement:'  <img src=x onerror=alert(1)>\n<script>exact memory</script> 😀  ',attributed_to:'owner-voice',
    capture_metadata:captureMetadata,evidence_quote:'  Selected source <mark>quote differs from statement</mark>\n& remains exact 😀  '}
  const operation={...f.binding.operation,action_type:'memory.save',canonical_parameters:{capture_sha256:'a'.repeat(64),
    idempotency_key_sha256:'b'.repeat(64),heads:{},...memoryCapture}}
  f.controller.setOperation(operation,{memoryCapture});await f.controller.prepare()
  const unavailable=render(f.controller)
  assert(unavailable.includes('data-memory-action-unavailable'));assert(/disabled=""[^>]*>Approve exact operation/.test(unavailable))
  f.controller.setApprovalAction(async()=>{throw new Error('Render fixture never invokes a workflow')})
  const html=render(f.controller)
  assert(html.includes('data-memory-statement'));assert(html.includes('data-memory-attribution'));assert(html.includes('data-memory-capture-hash'))
  assert(html.includes('owner-voice'));assert(!html.includes('<img src=x'));assert(!html.includes('<script>exact memory'))
  assert(html.includes('  &lt;img src=x onerror=alert(1)&gt;\n&lt;script&gt;exact memory&lt;/script&gt; 😀  '))
  assert(html.includes('data-memory-evidence-quote'))
  assert(html.includes('  Selected source &lt;mark&gt;quote differs from statement&lt;/mark&gt;\n&amp; remains exact 😀  '))
  assert(!html.includes('<mark>quote differs from statement</mark>'))
  assert(html.includes(await contracts.operationDigest(operation)));assert(!/disabled=""[^>]*>Approve exact operation/.test(html))
  for(const review of [null,{...f.controller.getSnapshot().presentation.memory_review,statement:'Different'},
    {...f.controller.getSnapshot().presentation.memory_review,attributed_to:'agent'},
    {...f.controller.getSnapshot().presentation.memory_review,capture_sha256:'b'.repeat(64)},
    {...f.controller.getSnapshot().presentation.memory_review,capture_metadata:null},
    {...f.controller.getSnapshot().presentation.memory_review,evidence_quote:'Different quotation'}]) {
    const snapshot={...f.controller.getSnapshot(),presentation:{...f.controller.getSnapshot().presentation,memory_review:review}}
    const guarded=render({...f.controller,getSnapshot:()=>snapshot})
    assert(guarded.includes('data-memory-review-refused'));assert(/disabled=""[^>]*>Approve exact operation/.test(guarded))
  }
  const noMetadata={...f.controller.getSnapshot(),presentation:{...f.controller.getSnapshot().presentation,capture_metadata:null}}
  const guarded=render({...f.controller,getSnapshot:()=>noMetadata})
  assert(guarded.includes('data-memory-review-refused'));assert(/disabled=""[^>]*>Approve exact operation/.test(guarded))
  f.controller.dispose();count++
}
{
  const f=make();await f.controller.login();await f.controller.prepare()
  const result={phase:'saved',operation:f.binding.operation,memory_capture:null,operation_digest:null,
    approval:'approved',save:'saved',saved:true,record:null,receipt:{literal:'<script>receipt remains text</script>'},
    receipt_digest:'sha256:'+'a'.repeat(64),citation:{verdict:'UNVERIFIED',literal:'<b>citation remains text</b>'},
    citation_status:'unverified',index:{status:'pending',indexed:false,searchable:false},authority_settlement:'pending',
    reconciliation_required:true,error_code:'RECONCILIATION_REQUIRED',read_error_code:null}
  // Presentation-only report fixture. Actual receipt/proof validation is checked
  // by approval-action.mjs using the real bridge workflow and controller.
  const snapshot={...f.controller.getSnapshot(),approval_action_result:result}
  const html=render({...f.controller,getSnapshot:()=>snapshot})
  for(const [field,value] of [['approval','approved'],['save','saved'],['index','pending'],['citation','unverified'],['settlement','pending']]) {
    assert(new RegExp(`data-memory-${field}-status="[^"]*">${value}`).test(html))
  }
  assert(html.includes('Reconciliation is required'));assert(html.includes('data-memory-effect-receipt'));assert(html.includes('data-memory-citation'))
  assert(!html.includes('<script>receipt'));assert(html.includes('&lt;script&gt;receipt remains text&lt;/script&gt;'))
  assert(!html.includes('<b>citation'));assert(html.includes('&lt;b&gt;citation remains text&lt;/b&gt;'))
  const pending=render({...f.controller,getSnapshot:()=>({...snapshot,approval_action_pending:true})})
  assert(/disabled=""[^>]*>Approve exact operation/.test(pending));assert(/disabled=""[^>]*>Sign out/.test(pending))
  f.controller.dispose();count++
}
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
{
  const f=make();f.controller.connect({...f.binding,fixture:false,requiresCapabilities:true})
  const caps={version:1,source_commit:'a'.repeat(40),runtime_pid:123,release_digest:'sha256:'+'b'.repeat(64),phase:'disposable-preview',qualification:'PENDING',
    unavailable_capabilities:['owner-passkey','approved-shell','sdk-child-launchers','model-inference','durable-memory','messaging','media-generation']}
  f.controller.setCapabilities(caps)
  const html=render(f.controller),summary=badge(f.controller)
  assert(html.includes('qualification pending'));assert(html.includes('does not prove that memory is loaded'))
  for(const id of caps.unavailable_capabilities)assert(html.includes(`data-capability="${id}"`))
  assert(html.includes(caps.source_commit));assert(html.includes(caps.release_digest));assert(/disabled=""[^>]*>Sign in with passkey/.test(html))
  assert(summary.includes('<details'));assert(summary.includes('data-reserves-hot-corners'));assert(summary.includes('data-prime-capability-badge'))
  f.controller.dispose();count++
}
console.log(JSON.stringify({result:'PASS',native_component_render_groups:count,owner_build_input:clientFile?'explicit-owned-build':'tracked-lib',
  browser_observation:'PENDING',real_authentication:false,effects:false}))
