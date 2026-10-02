// SPDX-License-Identifier: AGPL-3.0-or-later
// Focused SSR of a fresh owner build with pinned React. Synthetic workflow
// facts only; no browser, owner credential, request, memory effect or receipt claim.
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {resolve,join,isAbsolute} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createOwnerUiFixture} from './fixture.mjs'

const [harness,contractFile,clientFile] = process.argv.slice(2)
if (!harness || !contractFile || !clientFile || !isAbsolute(clientFile)) {
  throw new Error('pilot-render.mjs <pinned-dsh> <browser-contracts> <absolute-fresh-client>')
}
const require = createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-pilot-render.cjs'))
const React = require('react'), server = require('react-dom/server')
assert.equal(require('react/package.json').version,'18.3.1')
assert.equal(require('react-dom/package.json').version,'18.3.1')
const contracts = await import(pathToFileURL(resolve(contractFile)).href)
const modules = {react:React,'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{}}
const factories = {}
const loader = {__ModuleLoader__:{load:({id,factory}) => {factories[id]=factory}}}
for (const file of [new URL('../../faces/layout/lib/client.js',import.meta.url),clientFile]) {
  new Function('window',await readFile(file,'utf8'))(loader)
}
const get = name => Object.hasOwn(modules,name) ? modules[name]
  : modules[name] = factories[name.replace(/\/client$/,'')](get)
const ui = get('@aukora/prime-authority-ui/client')
const render = (component,props) => server.renderToStaticMarkup(React.createElement(component,props))
const clock = Date.parse('2030-01-01T00:00:00Z')
const controller = ui.createPrimeOwnerController({now:()=>clock,schedule:()=>null,unschedule:()=>{}})
const fixture = createOwnerUiFixture(contracts,{now:()=>clock})
const statement = '  exact <script>literal</script> & 😀\n\ttext  '
const evidenceQuote = '  different <source> quotation & é  '
const canonicalBytes = ' {"exact":"saved bytes <tag> & 😀"}\n'
let calls = 0, privateReads = 0, groups = 0
const memory = Object.freeze({phase:'saved',operation:{operation_id:'synthetic-save'},memory_capture:null,
  operation_digest:'sha256:'+'a'.repeat(64),approval:'approved',save:'saved',saved:true,
  record:{canonical_bytes:canonicalBytes,storage_status:'stored',evidence:[{quote:evidenceQuote}]},
  receipt:{fixture:'synthetic receipt'},receipt_digest:'sha256:'+'b'.repeat(64),citation:{fixture:'synthetic citation'},
  citation_status:'verified',index:{status:'indexed',indexed:true,searchable:false},authority_settlement:'pending',
  reconciliation_required:false,error_code:null,read_error_code:null})
const forget = Object.freeze({phase:'idle',operation:null,record_summary:null,operation_digest:null,
  approval:'not_requested',forget:'not_attempted',forgotten:null,result:null,receipt:null,receipt_digest:null,
  authority_settlement:null,reconciliation_required:false,error_code:null,recovery_status:'not_requested',
  recovery_operation_id:null,recovery_operation_digest:null})
const store = value => ({getSnapshot(){privateReads++;return value},subscribe(){return()=>{}}})
const client = {binding:{owner_id:fixture.owner_id},workflow:store(memory),forgetWorkflow:store(forget),
  async proposeSave(){calls++;throw Error('unexpected SSR proposal')},async refresh(){calls++;throw Error('unexpected SSR refresh')},
  async recover(){calls++;throw Error('unexpected SSR recovery')},async recoverForget(){calls++;throw Error('unexpected SSR forget recovery')}}
const binding = {ownerController:controller,client}
const escaped = text => text.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;'}[c]))
try {
  const initial = render(ui.OwnerSurface,{activeSurface:'prime-owner',openSurface(){calls++},controller})
  assert(initial.includes('data-prime-pilot-path="true"'))
  assert(initial.includes('Open Models settings'))
  assert(initial.includes('data-auma-reply-unavailable="true"'))
  assert(/<button[^>]*disabled=""[^>]*>Request one Auma reply<\/button>/.test(initial))
  assert(initial.includes('data-memory-pilot-unavailable="true"'))
  assert.equal(calls,0);assert.equal(privateReads,0);groups++

  controller.connect(fixture)
  let html = render(ui.PilotMemoryPanel,{controller,binding})
  assert(html.includes('data-memory-pilot-unavailable="true"'))
  assert.equal(privateReads,0,'unauthenticated panel must not read private stores')
  await controller.login()
  assert.equal(controller.getSnapshot().approval_action_result,null)
  html = render(ui.PilotMemoryPanel,{controller,binding})
  assert(html.includes('data-memory-pilot-facts="true"'))
  assert(html.includes(escaped(canonicalBytes)))
  assert(html.includes(escaped(evidenceQuote)))
  assert(html.includes('searchable: No'))
  assert(html.includes('<dt>Authority settlement</dt><dd>pending</dd>'))
  assert.equal(controller.getSnapshot().approval_action_result,null,'fresh-session facts do not need a retained action')
  assert.equal(calls,0,'render does not recover/propose/refresh automatically');groups++

  const privateReadsBefore = privateReads
  for (const rejected of [{...binding,ownerController:ui.createPrimeOwnerController()},
    {...binding,client:{...client,binding:{owner_id:'different-owner'}}},
    {...binding,client:{...client,workflow:undefined}}]) {
    html=render(ui.PilotMemoryPanel,{controller,binding:rejected})
    assert(html.includes('data-memory-pilot-unavailable="true"'));assert(!html.includes(escaped(canonicalBytes)))
    if (rejected.ownerController !== controller) rejected.ownerController.dispose()
  }
  assert.equal(privateReads,privateReadsBefore,'mismatched/unattached stores remain unread')
  controller.capabilitiesUnavailable()
  controller.disconnect()
  html=render(ui.PilotMemoryPanel,{controller,binding})
  assert(html.includes('data-memory-pilot-unavailable="true"'));assert(!html.includes(escaped(canonicalBytes)))
  assert.equal(privateReads,privateReadsBefore);assert.equal(calls,0);groups++

  const receipt={sessionId:'synthetic-session',line:'synthetic body',turn:1,spokenAt:clock,
    request_uuid:'synthetic-request',body_sha256:'a'.repeat(64),
    source_citation:{sessionId:'synthetic-session',turn:1,sha256:'a'.repeat(64),requestId:'synthetic-request'},citations:[]}
  const completed={outcome:'completed',request_uuid:'synthetic-request',route_id:'externalDeepSeek',mode:'mock',
    proposal:{text:statement,source_ids:[],grantsAuthority:false},usage:{input_tokens:1,output_tokens:2,cost_microusd:3},receipt,omitted:[]}
  html=render(ui.AumaReplyView,{result:completed})
  assert(html.includes('synthetic provider'));assert(html.includes(escaped(statement)))
  assert(!html.includes('<script>literal</script>'));assert(html.includes('grants no authority and has not been saved as memory'))
  for (const invalid of [{...completed,usage:{...completed.usage,cost_microusd:NaN}},
    {...completed,receipt:null},{outcome:'outcome_unknown',request_uuid:'synthetic-request',reservation_retained:false},
    {aukora_prime:{request_uuid:'synthetic-request',grants_authority:false}}]) {
    html=render(ui.AumaReplyView,{result:invalid})
    assert(html.includes('data-auma-reply-invalid="true"'));assert(!html.includes('reservation remains held'))
  }
  html=render(ui.AumaReplyView,{result:{outcome:'outcome_unknown',request_uuid:'synthetic-request',receipt,error:'fixture',reservation_retained:true}})
  assert(html.includes('data-auma-reply-unknown="true"'));assert(html.includes('do not retry'))
  assert.equal(calls,0);groups++
} finally {controller.dispose()}
console.log(JSON.stringify({result:'PASS',groups,pinned_react:'18.3.1',fresh_client:clientFile,
  synthetic_stores:true,browser:false,network_calls:calls,real_credentials:false,memory_effects:false}))
