// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { resolve, join, isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createOwnerUiFixture } from './fixture.mjs'
import { providerCatalog, providerNamespace, mountDshCatalog } from '../../../inference/src/provider-settings.mjs'
import { providerNamespaceView } from '../../adapters/provider-settings.mjs'

// Ordinary SSR acceptance only. Uses the tracked or explicitly supplied owned
// native UI build and pinned React; no compilation, service or browser.
const [harness, contractFile, clientFile] = process.argv.slice(2)
if (!harness || !contractFile) throw new Error('ordinary-render.mjs <pinned Prime DSH> <browser contracts> [owned built client.js]')
if (clientFile && !isAbsolute(clientFile)) throw new Error('ordinary-render.mjs owned client must be an absolute local file path')
const require = createRequire(join(resolve(harness), 'node_modules/.pnpm/node_modules/prime-ordinary-render.cjs'))
const React = require('react'), server = require('react-dom/server')
assert.equal(require('react/package.json').version, '18.3.1')
assert.equal(require('react-dom/package.json').version, '18.3.1')
const contracts = await import(pathToFileURL(resolve(contractFile)).href)
const modules = { react:React,'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{} }
const factories = {}, bundleHashes = {}
const loaderWindow = { __ModuleLoader__:{ load:({id,factory}) => { factories[id] = factory } } }
for (const [name, relative] of [['layout','../../faces/layout/lib/client.js'],['prime_owner','../lib/client.js']]) {
  const bytes = await readFile(name === 'prime_owner' && clientFile ? resolve(clientFile) : new URL(relative, import.meta.url))
  bundleHashes[name] = createHash('sha256').update(bytes).digest('hex')
  new Function('window', bytes.toString('utf8'))(loaderWindow)
}
const get = name => {
  if (Object.hasOwn(modules, name)) return modules[name]
  return modules[name] = factories[name.replace(/\/client$/, '')](get)
}
get('@aukora/face-layout/client')
const ui = get('@aukora/prime-authority-ui/client')
const render = controller => server.renderToStaticMarkup(React.createElement(ui.OwnerSurface, {activeSurface:'prime-owner',controller}))
const escaped = text => text.replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;'}[character]))
const preText = (html, attribute) => html.match(new RegExp(`<pre[^>]*\\b${attribute}="(?:true)?"[^>]*>([\\s\\S]*?)<\\/pre>`))?.[1]
const nodeDigest = (domain, value) => 'sha256:' + createHash('sha256').update(domain).update('\0').update(contracts.canonicalJson(value)).digest('hex')
let groups = 0, protocolGroups = 0

// Capture the actual non-exported companion through its production Cordis slot
// registration. Effects and service injections are recorded, never executed.
const registrations = [], effects = [], injections = []
ui.apply({
  effect(callback, name) { effects.push({callback,name}) },
  inject(names, callback) { injections.push({names,callback}) },
  slots:{ inject(_name, callback) { return callback() },register(descriptor, component) {
    registrations.push({descriptor,component}); return () => {}
  } },
})
const providerSlot = registrations.find(({descriptor}) => descriptor.name === 'settings.models.provider-card')
assert(providerSlot)
assert.equal(providerSlot.descriptor.key, 'prime-inference')
assert(effects.length > 0); assert.equal(injections.length, 2)
const providers = providerSlot.descriptor.inject().controller
try {
  const provider = {provider:'externalDeepSeek',displayName:'DeepSeek',settingsNs:'prime-inference',
    settingsPath:['providers','externalDeepSeek'],active:true,declared:true}
  const before = providers.getSnapshot()
  const html = server.renderToStaticMarkup(React.createElement(providerSlot.component, {
    provider,configured:false,keyConfigured:false,controller:providers,
  }))
  assert(html.includes('data-prime-provider-editor="true"')); assert(html.includes('data-provider="externalDeepSeek"'))
  assert(html.includes('DeepSeek')); assert(html.includes('externalDeepSeek'))
  assert(/<input[^>]*aria-label="Endpoint"[^>]*value="https:\/\/api\.deepseek\.com"/.test(html))
  assert(/<input[^>]*readonly=""[^>]*aria-label="Configured model"[^>]*value="Unconfirmed"/.test(html))
  assert(html.includes('DeepSeek V4.1 Flash (deepseek-flash)'))
  assert(/<option value="deepseek-flash" selected="">/.test(html))
  assert(html.includes('This selection is a local draft. Configuration changes require separate owner approval.'))
  assert(html.includes('Catalog: pending. Owner status: unavailable. Key entry: unavailable.'))
  assert(html.includes('Not confirmed configured'))
  assert(/<input[^>]*type="password"[^>]*aria-label="DeepSeek API key"[^>]*disabled=""/.test(html))
  assert(/<button[^>]*type="submit"[^>]*disabled=""[^>]*>Store key with approved handoff<\/button>/.test(html))
  assert(html.includes('Owner configuration and secure key entry are unavailable.'))
  assert.equal(providers.getSnapshot(), before)
  assert.equal(before.row.enabled, false); assert.equal(before.row.credentialConfigured, false)
  groups++
} finally { providers.dispose() }

// Pure catalog data is injected directly into the actual built controller. No
// public HTTP route, owner-status method or credential handoff is installed.
const publicCatalog = providerCatalog(), publicNamespace = providerNamespace()
const publicDirectory = publicCatalog.providers[0]
assert.equal(publicDirectory.provider, 'externalDeepSeek'); assert.equal(publicDirectory.displayName, 'DeepSeek')
assert.equal(publicDirectory.settingsNs, 'prime-inference')
assert.deepEqual(publicDirectory.settingsPath, ['providers','externalDeepSeek'])
assert.equal(publicDirectory.active, false); assert.equal(publicDirectory.paid_requests_enabled, false)
assert.deepEqual(publicCatalog.namespace, publicNamespace)
const unauthenticatedOwner = ui.createPrimeOwnerController()
const loadedProviders = ui.createPrimeProviderController()
let catalogReads = 0
try {
  assert.equal(unauthenticatedOwner.getSnapshot().owner, null)
  loadedProviders.connect({ownerController:unauthenticatedOwner,contracts,api:{catalog() { catalogReads++; return providerCatalog() }}})
  await loadedProviders.load()
  const state = loadedProviders.getSnapshot()
  assert.equal(catalogReads, 1); assert.equal(state.catalog_status, 'loaded')
  assert.equal(state.owner_status, 'unavailable'); assert.equal(state.entry_status, 'unavailable')
  assert.deepEqual(state.row, publicNamespace.section.providers.externalDeepSeek)
  const html = server.renderToStaticMarkup(React.createElement(providerSlot.component, {
    provider:publicDirectory,configured:false,keyConfigured:false,controller:loadedProviders,
  }))
  assert(html.includes('data-prime-provider-editor="true"'))
  assert(html.includes('Catalog: loaded. Owner status: unavailable. Key entry: unavailable.'))
  assert(/<input[^>]*readonly=""[^>]*aria-label="Endpoint"[^>]*value="https:\/\/api\.deepseek\.com"/.test(html))
  assert(/<option value="deepseek-flash" selected="">/.test(html))
  assert(html.includes('This selection is a local draft. Configuration changes require separate owner approval.'))
  for (const label of ['Maximum input tokens','Maximum output tokens','Maximum requests']) {
    assert(new RegExp(`<input[^>]*readonly=""[^>]*aria-label="${label}"[^>]*value="0"`).test(html))
  }
  assert(/<input[^>]*readonly=""[^>]*aria-label="Task spend ceiling"[^>]*value="Not configured"/.test(html))
  assert(/<input[^>]*readonly=""[^>]*aria-label="Configured model"[^>]*value="Unconfirmed"/.test(html))
  assert(/<input[^>]*type="password"[^>]*aria-label="DeepSeek API key"[^>]*disabled=""/.test(html))
  assert(/<button[^>]*type="submit"[^>]*disabled=""[^>]*>Store key with approved handoff<\/button>/.test(html))
  assert.equal(state.row.taskSpendCeiling, null); assert.equal(state.row.enabled, false)
  assert.equal(state.row.credentialConfigured, false); assert.equal(catalogReads, 1)
  groups++
} finally { loadedProviders.dispose(); unauthenticatedOwner.dispose() }

// Positive nonsecret settings-protocol conversion through the actual pinned
// Schemastery implementation, plus a mocked directory registration only.
const Schema = require('@deepseek-ai/schemastery')
assert.equal(require('@deepseek-ai/schemastery/package.json').version, '3.18.2')
const namespaceView = providerNamespaceView(publicNamespace, {Schema,contracts})
const rehydratedSchema = new Schema(namespaceView.schema)
assert.equal(namespaceView.ns, publicDirectory.settingsNs)
assert.deepEqual(rehydratedSchema(namespaceView.value), publicNamespace.section)
assert.deepEqual(namespaceView.value, namespaceView.base); assert.deepEqual(namespaceView.secrets, [])
const serializedRoot = namespaceView.schema.refs[namespaceView.schema.uid]
const serializedProviders = namespaceView.schema.refs[serializedRoot.dict.providers]
const serializedProvider = namespaceView.schema.refs[serializedProviders.dict.externalDeepSeek]
for (const field of Object.keys(publicNamespace.section.providers.externalDeepSeek)) {
  assert.equal(namespaceView.schema.refs[serializedProvider.dict[field]].meta.role, 'readonly')
}
let registeredDirectory
const directoryDisposer = () => {}
assert.equal(mountDshCatalog({llm:{registerConfigurableProviders(entries) { registeredDirectory = entries; return directoryDisposer }}}), directoryDisposer)
assert.deepEqual(registeredDirectory, [{provider:'externalDeepSeek',displayName:'DeepSeek',settingsNs:'prime-inference',
  settingsPath:['providers','externalDeepSeek'],declared:false}])
groups++; protocolGroups++

const clock = Date.parse('2030-01-01T00:00:00Z')
const binding = createOwnerUiFixture(contracts, {now:() => clock})
const controller = ui.createPrimeOwnerController({now:() => clock,schedule:() => 1,unschedule() {}})
controller.connect(binding)
try {
  await controller.login()
  // Independently chosen ordinary original-record summary, never derived from
  // operation parameters. The original synthetic bytes remain unchanged.
  const recordSummary = {record_id:'ordinary-ssr-record',revision:'ordinary-ssr-revision',
    statement:'  Keep cafe\u0301 & tea\nLine two 😀 Русский  ',attributed_to:'owner-edit'}
  const originalBytes = contracts.canonicalJson({statement:recordSummary.statement,attributedTo:recordSummary.attributed_to})
  const canonicalHash = createHash('sha256').update(originalBytes).digest('hex')
  const ownerSubject = 'aukora:1:' + '1'.repeat(64)
  const operation = {...binding.operation,action_type:'memory.forget',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:ownerSubject},expected_state_version:'sha256:' + '2'.repeat(64),
    canonical_parameters:{profile:'prime-logical-forget/v1',record_id:recordSummary.record_id,revision:recordSummary.revision,
      statement:recordSummary.statement,attributed_to:recordSummary.attributed_to,canonical_sha256:canonicalHash,
      at:'2030-01-01T00:00:00Z',heads:{remembered:'aukora:aura-record:v1'}}}
  controller.setOperation(operation, {recordSummary})
  const operationDigest = await contracts.operationDigest(operation)
  let handlerCalls = 0
  controller.setForgetAction(async (_presentation, options) => {
    handlerCalls++
    const approved = await options.approve()
    assert.equal(approved.status, 'APPROVED')
    const result = {record_id:recordSummary.record_id,state:'tombstoned',canonical_payload_retained:true,physical_media_erasure:false,
      authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false}
    const request = {version:1,action_type:'memory.forget',owner_subject:ownerSubject,operation_id:operation.operation_id,
      operation_digest:operationDigest,parameters:operation.canonical_parameters}
    const receipt = {version:1,kind:'prime-memory-effect/v1',operation_id:operation.operation_id,operation_digest:operationDigest,
      grant_id:'grant:' + approved.approval_proof.nonce,request_id:'12345678-1234-4123-8123-123456789abc',
      request_digest:nodeDigest('aukora-prime.memory.effect.v1', request),owner_subject:ownerSubject,action_type:'memory.forget',status:'applied',
      result_digest:nodeDigest('aukora-prime.memory-result.v1', result),result}
    return {phase:'forgotten',operation,record_summary:recordSummary,operation_digest:operationDigest,approval:'approved',forget:'forgotten',
      forgotten:true,result,receipt,receipt_digest:nodeDigest('aukora-prime.memory-receipt.v1', receipt),authority_settlement:'completed',
      reconciliation_required:false,error_code:null,recovery_status:'not_requested',recovery_operation_id:null,recovery_operation_digest:null}
  })
  await controller.prepare()
  const review = controller.getSnapshot().presentation
  const html = render(controller)
  assert(html.includes('data-memory-forget-review="true"'))
  for (const [attribute, value] of [['data-forget-record-id',recordSummary.record_id],['data-forget-revision',recordSummary.revision],
    ['data-forget-statement',recordSummary.statement],['data-forget-attribution',recordSummary.attributed_to],['data-forget-canonical-hash',canonicalHash]]) {
    assert.equal(preText(html, attribute), escaped(value))
  }
  for (const field of Object.keys(operation)) assert(html.includes(`data-operation-field="${field}"`))
  assert.equal(preText(html, 'data-operation-digest'), operationDigest)
  assert.equal(preText(html, 'data-canonical-operation'), escaped(contracts.canonicalJson(operation)))
  assert(html.includes('data-review-challenge="true"'))
  assert(html.includes('Logical forget removes visibility. Canonical payloads, backups, WAL, authority history and physical media are retained.'))
  assert(!/disabled=""[^>]*>Approve exact operation/.test(html))
  assert.equal(review.forget_review.statement, recordSummary.statement)
  assert(!html.includes('synthetic-in-memory-only')); assert(!html.includes('client_data_json'))
  groups++

  const reported = await controller.submitApproval()
  assert(reported); assert.equal(handlerCalls, 1); assert.equal(binding.counts.approve, 1)
  const completed = render(controller)
  assert(completed.includes('data-memory-forget-result="true"')); assert(completed.includes('data-phase="approved"'))
  assert(/data-forget-status="true">forgotten<\/dd>/.test(completed))
  assert(/data-forget-settlement="true">completed<\/dd>/.test(completed))
  assert(completed.includes(reported.receipt_digest))
  assert.equal(preText(completed, 'data-forget-receipt'), escaped(JSON.stringify(reported.receipt, null, 2)))
  assert(completed.includes('Visibility was removed. Canonical payloads, external backups, WAL and physical media were not erased.'))
  assert(!completed.includes('data-memory-workflow-result'))
  assert(!completed.includes('synthetic-in-memory-only')); assert(!completed.includes('client_data_json'))
  assert.equal(preText(completed, 'data-forget-statement'), escaped(recordSummary.statement))
  assert.equal(originalBytes, contracts.canonicalJson({statement:recordSummary.statement,attributedTo:recordSummary.attributed_to}))
  assert.notEqual(recordSummary.statement.normalize('NFC'),recordSummary.statement)
  groups++
} finally { controller.dispose() }

// A paired ordinary capture passes through the actual built controller. The
// fixed metadata and saved record below are explicitly synthetic host reports.
const captureBinding = createOwnerUiFixture(contracts, {now:() => clock})
const captureController = ui.createPrimeOwnerController({now:() => clock,schedule:() => 1,unschedule() {}})
captureController.connect(captureBinding)
try {
  await captureController.login()
  const statement = '  Original <b>café & tea</b>\nLine two 😀 аa  '
  const captureMetadata = Object.freeze({profile:'prime-pilot-memory-capture/v1',category:'fact',
    valid_from:'2030-01-01',observed_at:'2030-01-01T00:00:00Z',confidence_percent:70,sensitivity:'none'})
  const quote = 'Selected source: <mark>café & tea</mark>\n"Original" source 😀 а'
  const memoryCapture = Object.freeze({statement,attributed_to:'owner-edit',capture_metadata:captureMetadata,evidence_quote:quote})
  const ownerSubject = 'aukora:1:' + '1'.repeat(64)
  const captureOperation = {...captureBinding.operation,operation_id:'ordinary-ssr-capture',action_type:'memory.save',audience:'aukora-prime.memory',
    target_identity:{kind:'prime-memory',owner_subject:ownerSubject},
    canonical_parameters:{capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),
      heads:{remembered:'aukora:aura-record:v1'},...memoryCapture}}
  const operationDigest = await contracts.operationDigest(captureOperation)
  const source = {sessionId:'ordinary-source-session',seq:3,sha256:'e'.repeat(64)}
  const evidence = [{log:source.sessionId,turn:source.seq,turnDigest:source.sha256,quote}]
  const canonicalBytes = JSON.stringify({statement,attributedTo:memoryCapture.attributed_to,
    category:captureMetadata.category,validFrom:captureMetadata.valid_from,observedAt:captureMetadata.observed_at,
    confidence:0.7,sensitivity:captureMetadata.sensitivity,source,evidence}, null, 2)
  let saveReports = 0
  captureController.setApprovalAction(async (_presentation, options) => {
    const approved = await options.approve()
    assert.equal(approved.status, 'APPROVED')
    saveReports++
    const record = {version:1,record_id:'ordinary-saved-record',owner_subject:ownerSubject,task_id:captureOperation.task_id,
      scope:'owner',privacy:'local',record_format:'ordinary-synthetic-original',canonicalizer:'fixture-original-json',
      canonical_bytes:canonicalBytes,revision:'ordinary-saved-revision',grants_authority:false,
      source_event_digest:'sha256:' + source.sha256,evidence,chain_domain:'remembered',
      source_span:{event_id:'ordinary-source-event',start:0,end:quote.length},storage_status:'saved',index_status:'pending'}
    contracts.validateContract('MemoryRecord', record)
    const request = {version:1,action_type:'memory.save',owner_subject:ownerSubject,operation_id:captureOperation.operation_id,
      operation_digest:operationDigest,parameters:captureOperation.canonical_parameters}
    const receipt = {version:1,kind:'prime-memory-effect/v1',operation_id:captureOperation.operation_id,operation_digest:operationDigest,
      grant_id:'grant:' + approved.approval_proof.nonce,request_id:'12345678-1234-4123-8123-123456789abd',
      request_digest:nodeDigest('aukora-prime.memory.effect.v1', request),owner_subject:ownerSubject,action_type:'memory.save',status:'applied',
      result_digest:nodeDigest('aukora-prime.memory-result.v1', record),result:record}
    return {phase:'saved',operation:captureOperation,memory_capture:memoryCapture,operation_digest:operationDigest,approval:'approved',
      save:'saved',saved:true,record,receipt,receipt_digest:nodeDigest('aukora-prime.memory-receipt.v1', receipt),citation:null,
      citation_status:'unavailable',index:{status:'pending',indexed:false,searchable:false},authority_settlement:'completed',
      reconciliation_required:false,error_code:null,read_error_code:'UNAVAILABLE'}
  })
  captureController.setOperation(captureOperation, {memoryCapture,captureMetadata})
  await captureController.prepare()
  const review = captureController.getSnapshot().presentation
  const html = render(captureController)
  assert.equal(preText(html, 'data-memory-statement'), escaped(statement))
  assert.equal(preText(html, 'data-memory-attribution'), memoryCapture.attributed_to)
  assert.equal(preText(html, 'data-memory-evidence-quote'), escaped(quote))
  assert.equal(review.memory_review.evidence_quote, quote)
  assert.deepEqual(review.memory_review.capture_metadata, captureMetadata)
  assert.deepEqual(review.capture_metadata, captureMetadata)
  assert(html.includes('data-memory-fixed-capture-policy="true"'))
  for (const [label, value] of [['Profile',captureMetadata.profile],['Category',captureMetadata.category],
    ['Confidence percent',String(captureMetadata.confidence_percent)],['Sensitivity',captureMetadata.sensitivity],
    ['Observed at',captureMetadata.observed_at],['Valid from',captureMetadata.valid_from]]) {
    assert(html.includes(`<dt>${escaped(label)}</dt><dd>${escaped(value)}</dd>`))
  }
  // The independently chosen values were compared above. The retained draft is
  // detached through canonical JSON, so its display has canonical key order.
  assert.equal(preText(html, 'data-fixed-capture-metadata'), escaped(JSON.stringify(review.capture_metadata, null, 2)))
  assert(html.includes(`<time>${captureMetadata.observed_at}</time>`)); assert(html.includes(`<time>${captureMetadata.valid_from}</time>`))
  assert(html.includes('data-memory-unicode-hint="ascii-lookalikes"'))
  assert(html.includes('data-memory-unicode-hint="mixed-scripts"'))
  assert(html.includes(`<code>UTF-16 index ${statement.indexOf('а')}: U+0430, Cyrillic letter resembling a</code>`))
  assert(html.includes('Hints aid review and preserve the exact text.'))
  assert(!html.includes('data-capture-source-evidence-unavailable="true"'))
  assert(!html.includes('<mark>café & tea</mark>'))
  assert(!html.includes('<b>café & tea</b>'))
  assert.equal(review.memory_review.statement, statement)
  assert.equal(saveReports, 0); assert.equal(captureBinding.counts.approve, 0)
  groups++

  const reported = await captureController.submitApproval()
  assert(reported); assert.equal(saveReports, 1); assert.equal(captureBinding.counts.approve, 1)
  assert.equal(reported.record.canonical_bytes, canonicalBytes)
  assert.deepEqual(reported.record.evidence, evidence)
  const saved = render(captureController)
  assert(saved.includes('data-memory-saved-capture-content="true"'))
  assert.equal(preText(saved, 'data-memory-saved-canonical-bytes'), escaped(canonicalBytes))
  assert.equal(preText(saved, 'data-memory-saved-evidence-quote'), escaped(quote))
  assert.equal(preText(saved, 'data-memory-saved-evidence-fields'), escaped(JSON.stringify(reported.record.evidence[0], null, 2)))
  assert(saved.includes('Source quotations describe the selected source event and can differ from the captured statement.'))
  assert(/data-memory-save-status="true">saved<\/dd>/.test(saved))
  assert(/data-memory-index-status="true">pending<\/dd>/.test(saved))
  assert(/data-memory-citation-status="true">unavailable<\/dd>/.test(saved))
  assert(/data-memory-settlement-status="true">completed<\/dd>/.test(saved))
  assert.equal(preText(saved, 'data-memory-effect-receipt'), escaped(JSON.stringify(reported.receipt, null, 2)))
  assert(!saved.includes('<mark>café & tea</mark>'))
  assert(!saved.includes('synthetic-in-memory-only')); assert(!saved.includes('client_data_json'))
  assert.notEqual(quote, statement)
  groups++

  // A fresh NEW-capture proposal without independently prepared metadata is
  // refused; it cannot retain a ready review or expose an approval path.
  const withoutMetadata = {...captureOperation,operation_id:'ordinary-ssr-capture-no-metadata'}
  const missingMetadata = {statement,attributed_to:memoryCapture.attributed_to,evidence_quote:quote}
  assert.throws(() => captureController.setOperation(withoutMetadata, {memoryCapture:missingMetadata}),error => error.code==='TARGET_MISMATCH')
  const absent = render(captureController)
  assert.equal(captureController.getSnapshot().presentation, null)
  assert.equal(captureController.getSnapshot().operation_available, false)
  assert(absent.includes('No operation has been supplied by the host.'))
  assert(!absent.includes('data-memory-statement'))
  assert(!absent.includes('data-memory-evidence-quote'))
  assert(!absent.includes('>Approve exact operation'))
  assert(!absent.includes('data-memory-fixed-capture-policy'))
  assert(!absent.includes('data-fixed-capture-metadata="true"'))
  assert(!absent.includes('The host supplied this exact fixed-pilot metadata.'))
  assert(!absent.includes('Confidence percent'))
  assert.equal(saveReports, 1); assert.equal(captureBinding.counts.approve, 1)
  groups++
} finally { captureController.dispose() }

console.log(JSON.stringify({result:'PASS',evidence:'RAN',scope:'ordinary native SSR and nonsecret provider protocol',
  ordinary_acceptance_groups:groups,native_render_groups:groups-protocolGroups,provider_protocol_groups:protocolGroups,
  base_checkpoint:'1b7bd3d7909996c8d515a5c588059e5b2257e39a',react:'18.3.1',react_dom:'18.3.1',schemastery:'3.18.2',
  catalog_reads:catalogReads,bundle_sha256:bundleHashes,owner_build_input:clientFile ? 'explicit-owned-build' : 'tracked-lib',
  browser_observation:'UNPERFORMED',runtime:false,network:false,real_authentication:false,real_credentials:false,
  real_memory_effects:false,real_provider_effects:false,compile:false,adversarial_cases:false}))
