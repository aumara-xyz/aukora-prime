// SPDX-License-Identifier: AGPL-3.0-or-later
// Closed ordinary source profile. Expected check-source pins were reviewed from
// H's clean 284a16250474214d14d5012594fed69341fe4a46 checkout; never derive-and-pass.
// The publication reviewer checked the explicit UI comment-adaptation source
// and four metadata-refusal checks; current pins match that sealed source.
// Original H review preceded privacy redactions.
// Check-source pins remain the independently reviewed bytes; this is no new runtime receipt.
// No authority audit, wildcard, shell, package manager, live service or guest call.
export const NODE_VERSION = 'v24.11.1'
export const SOURCE_REVIEW_COMMIT = '284a16250474214d14d5012594fed69341fe4a46'
const frozen = row => Object.freeze({...row, args: Object.freeze(row.args ?? []),
  nodeArgs: Object.freeze(row.unsupportedReason ? [] : ['--max-old-space-size=512', ...(row.nodeArgs ?? [])]),
  pins: Object.freeze((row.pins ?? []).map(Object.freeze))})
const memoryTitle = 'synthetic historical byte forms retain envelope IDs, salt, opaque aura and separate byte hashes'
export const CASES = Object.freeze([
  frozen({id:'contracts-v1', property:'Frozen operation vectors and transport envelopes',
    entry:'packages/contracts/check.mjs',
    expectedSha256:'75f3b3119b8e55000986cf59da9e98e09c37a35d7b4f4f56d198727b162c00f2',
    pins:[{path:'packages/contracts/golden-v1.json', sha256:'ffc6655e603b1d01af54304742b73393a510910d34ad942fd0042cdd1f006875'}],
    protocol:'assert-script', timeoutMs:15000}),
  frozen({id:'memory-original-bytes', property:'Historical record bytes and IDs survive original byte forms',
    entry:'packages/memory/test/codecs-hardening.test.mjs',
    expectedSha256:'f11e4592b33f80112ceed7b091292d1f513c2577cd38c0102c9cc0c2ea456737',
    nodeArgs:['--test','--test-isolation=none','--test-reporter=tap','--test-name-pattern','^'+memoryTitle+'$'],
    protocol:'tap', expectedTitle:memoryTitle, minTests:1, timeoutMs:15000}),
  frozen({id:'inference-mock-accounting', property:'Mock-only body, data scope and durable accounting',
    entry:'packages/inference/check.mjs',
    expectedSha256:'d20bb25f5152137431575ba96049f31d721669968ad20528e3fe5f66fc22d1b2',
    nodeArgs:['--test','--test-isolation=none','--test-reporter=tap'], protocol:'tap',
    expectedTitle:'Lane E disposable mock acceptance: exact body, scope, durable caps, uncertainty and DSH stream',
    minTests:1, timeoutMs:20000}),
  frozen({id:'ui-static-boundary', property:'Local native assets and static route boundaries',
    entry:'packages/ui/scripts/check-static.mjs',
    expectedSha256:'bd7797da793dfafc352250e445f06b8be4c9e17f6fc52005b6a721dc3c0858cf',
    pins:[{path:'packages/ui/baseline-manifest.json', sha256:'a3e519151fce2e2280a1ed921f94f2bf358a96db3f3e6e4d87016eee5b0677c9'}],
    protocol:'assert-script', timeoutMs:15000}),
  frozen({id:'ui-owner-presentation', property:'Injected owner review and signing presentation boundaries',
    entry:'packages/ui/scripts/check-transport.mjs',
    expectedSha256:'00efe464cd365865b0f5cb56d66a0a3cbd18d92962a61f67870dae4e5d67bac0',
    protocol:'assert-script', timeoutMs:15000}),
  frozen({id:'ops-release-metadata', property:'Release digest, ordinary archive bytes and metadata refusal',
    entry:'packages/ops/check-digest-controls.mjs',
    expectedSha256:'f7b8fe1f6b1e80301f3f8a9c52113ea91c04b1c9bb85ee7486adaf9c478e6b5d',
    requiresPython:true, protocol:'assert-script', timeoutMs:15000}),
  frozen({id:'authority-review-renewal', property:'Ordinary authenticated review TTL renewal',
    entry:'packages/authority/check-admission.mjs', args:['admission-probe','session-renewal'],
    expectedSha256:'54b51ea7401e4c4e01674edec553c0738731a58500b10366dbe27e73ece8a35c',
    protocol:'assert-script', timeoutMs:15000}),
  frozen({id:'execution-ordinary-binding', property:'Ordinary executor qualification/binding regression',
    entry:'packages/execution/checks/mechanisms.mjs', args:['bash_parameters'],
    expectedSha256:'dee9796d61f751ccde7eca94afebbabcb867878bfbed6206bd52ad13bed36f70',
    protocol:'assert-script', timeoutMs:15000})
])

// These are received historical owner/operator reports, not fresh observations or
// independently verified receipts. They never affect an ordinary case result.
export const HISTORY = Object.freeze([
  Object.freeze({id:'pg-storage-record', status:'HISTORICAL_ONLY', reported_result:'PASS',
    scope:'Operator-reported synthetic PG prepare/restart/verify/cleanup; toy authority storage-only',
    source_record_id:'historical-owner-operator-relay',
    provenance:'OWNER_RELAY_ONLY', receipt_file:null, receipt_sha256:null,
    current_verification:'UNPERFORMED', authority_or_product_qualification:'UNPERFORMED'}),
  Object.freeze({id:'uid-parent-record', status:'HISTORICAL_ONLY', reported_result:'SETUP_COMPLETED',
    scope:'H-reported protected-parent/UID setup at parents8c20',
    reported_uids:Object.freeze({app:997, authority:995, memory:994, postgres:113}),
    source_record_id:'historical-owner-operator-relay',
    provenance:'OWNER_RELAY_ONLY', receipt_file:null, receipt_sha256:null,
    current_verification:'UNPERFORMED', acl_or_cross_uid_qualification:'UNPERFORMED'})
])
export const UNPERFORMED = Object.freeze([
  Object.freeze({id:'owner-ceremony', status:'UNPERFORMED', reason:'KEYLESS_SOURCE_PROFILE'}),
  Object.freeze({id:'live-pg', status:'UNPERFORMED', reason:'HISTORICAL_RECORD_ONLY_NO_CONNECTION'}),
  Object.freeze({id:'current-cross-uid', status:'UNPERFORMED', reason:'NO_HOST_PERMISSION_OBSERVATION'}),
  Object.freeze({id:'qualified-guest', status:'UNPERFORMED', reason:'NO_GUEST_OR_HELD_OPENSHELL_FIXTURE'}),
  Object.freeze({id:'paid-inference', status:'UNPERFORMED', reason:'NO_CREDENTIALS_OR_EXTERNAL_REQUEST'}),
  Object.freeze({id:'composed-pixels', status:'UNPERFORMED', reason:'NO_GUI_OR_RUNNING_APP_TARGET'}),
  Object.freeze({id:'extended-authority-save', status:'UNPERFORMED', reason:'EXTENDED_SUITE_ONLY_NO_265_SAVE_RUN'})
])
