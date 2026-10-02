// SPDX-License-Identifier: AGPL-3.0-or-later
// TEST ONLY. Required ordinary source/build fixture helpers; those checks use
// the native controller directly. The retained legacy port below is only for
// an older standalone check. Never imported by a production client or host.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {readFile} from 'node:fs/promises'
import {createRequire} from 'node:module'
import {isAbsolute,join,resolve} from 'node:path'
import {pathToFileURL} from 'node:url'
import {createPrimeOwnerController} from '../src/client/controller.mjs'

/** Required actual source join. An explicit detached consumer root permits a
 * reviewed C/D/bridge checkpoint to be checked before H imports it. This is not
 * a deployment fallback: missing imports/methods fail and never skip a node. */
export async function loadOwnerJoinFixture(root){
  if(root&&!isAbsolute(root))throw new TypeError('TEST_ONLY_ABSOLUTE_OWNER_JOIN_ROOT_REQUIRED')
  const fixtureUrl=root?pathToFileURL(join(resolve(root),'packages/runtime-bridge/test/owner-memory-fixture.mjs')):
    new URL('../../../runtime-bridge/test/owner-memory-fixture.mjs',import.meta.url)
  const forgetUrl=root?pathToFileURL(join(resolve(root),'packages/runtime-bridge/src/owner-forget-workflow.mjs')):
    new URL('../../../runtime-bridge/src/owner-forget-workflow.mjs',import.meta.url)
  const [fixture,forget]=await Promise.all([import(fixtureUrl.href),import(forgetUrl.href)])
  for(const name of ['fixture','draft','assertSaved','assertUnknown','ok'])assert.equal(typeof fixture[name],'function','required actual owner join export '+name)
  assert.equal(typeof forget.createOwnerForgetWorkflow,'function','required actual logical-forget workflow')
  return Object.freeze({...fixture,createOwnerForgetWorkflow:forget.createOwnerForgetWorkflow})
}

/** Independent expectation comes from this fixture's detached input and trusted
 * selected event bytes, never the proposed operation parameters or UI reply. */
export function assertExpandedCapture(f,input){
  const selected=f.host.events.map(value=>Buffer.from(value)).find(bytes=>createHash('sha256').update(bytes).digest('hex')===f.host.source.sha256)
  assert.ok(selected,'the fixture retains the actual selected immutable source event')
  const event=JSON.parse(selected.toString('utf8')),at=f.host.source.at
  const expected={statement:JSON.parse(input.extraction_json).statement,attributed_to:f.host.attributedTo,
    capture_metadata:{profile:'prime-pilot-memory-capture/v1',category:'fact',valid_from:at.slice(0,10),observed_at:at,confidence_percent:70,sensitivity:'none'},
    evidence_quote:event.text}
  const snapshot=f.controller.getSnapshot(),view=snapshot.presentation,operation=view.operation
  assert.deepEqual(Object.keys(operation.canonical_parameters).sort(),['capture_sha256','idempotency_key_sha256','heads','statement','attributed_to','capture_metadata','evidence_quote'].sort(),'new operation has exact seven parameters')
  assert.deepEqual(f.workflow.getSnapshot().memory_capture,expected,'bridge independently prepared and retained all four capture fields')
  assert.deepEqual(Object.keys(view.memory_review).sort(),['statement','attributed_to','capture_metadata','evidence_quote','capture_sha256'].sort(),'native review has the complete draft and original private capture hash')
  for(const key of ['statement','attributed_to','capture_metadata','evidence_quote']){
    assert.deepEqual(view.memory_review[key],expected[key],'native review exact '+key)
    assert.deepEqual(operation.canonical_parameters[key],expected[key],'signed parameters exact '+key)
  }
  assert.deepEqual(view.capture_metadata,expected.capture_metadata,'optional metadata sibling matches the bound independent draft')
  assert.equal(view.memory_review.capture_sha256,operation.canonical_parameters.capture_sha256)
  assert.notEqual(expected.evidence_quote,expected.statement,'source quotation is separately selected and is not reconstructed from statement')
  return expected
}

export function assertExpandedSaved(saved,expected){
  const original=JSON.parse(saved.record.canonical_bytes)
  assert.equal(original.statement,expected.statement)
  assert.equal(original.attributedTo,expected.attributed_to)
  assert.equal(original.category,expected.capture_metadata.category)
  assert.equal(original.validFrom,expected.capture_metadata.valid_from)
  assert.equal(original.observedAt,expected.capture_metadata.observed_at)
  assert.equal(original.confidence,expected.capture_metadata.confidence_percent/100)
  assert.equal(original.sensitivity,expected.capture_metadata.sensitivity)
  assert.deepEqual(saved.record.evidence.map(value=>value.quote),[expected.evidence_quote],'actual D saved the exact selected source quote')
  assert.deepEqual(original.evidence.map(value=>value.quote),[expected.evidence_quote],'original canonical bytes retain the same exact quote')
}

export function createApprovalHookPort(native){
  assert.equal(typeof native?.getSnapshot,'function','an actual native owner controller is required')
  assert.equal(typeof native?.setApprovalAction,'function','the native approval hook is required')
  let active=null
  const clear=()=>{active=null}
  const wrap=handler=>{
    if(handler===null){clear();return null}
    if(typeof handler!=='function')throw new TypeError('TEST_ONLY_APPROVAL_HANDLER_REQUIRED')
    return(presentation,options)=>{
      if(typeof options?.approve!=='function')throw new TypeError('TEST_ONLY_SCOPED_APPROVAL_CALLBACK_REQUIRED')
      const scope={approve:options.approve};active=scope
      let result
      try{result=handler(presentation,options)}catch(error){if(active===scope)clear();throw error}
      return Promise.resolve(result).finally(()=>{if(active===scope)clear()})
    }
  }
  return Object.freeze({...native,native,
    // An unscoped old-workflow call gets no proof. There is no public raw
    // native.approve fallback, synthetic signer, grant or receipt here.
    approve:()=>active?active.approve():Promise.resolve(null),
    setApprovalAction:handler=>native.setApprovalAction(wrap(handler)),
    setForgetAction:handler=>native.setForgetAction(wrap(handler)),
    connect(binding){clear();return native.connect(binding)},
    logout(){clear();return native.logout()},
    disconnect(){clear();return native.disconnect()},
    dispose(){clear();return native.dispose()},
  })
}

/** Exact existing ordinary/render factory loader; an explicit read-only DSH
 * witness supplies pinned React. Missing inputs fail and never skip a check. */
export async function loadApprovalHookController(harness,clientFile){
  if(clientFile&&!harness)throw new TypeError('TEST_ONLY_CLIENT_OVERRIDE_REQUIRES_PINNED_DSH')
  if(clientFile&&!isAbsolute(clientFile))throw new TypeError('TEST_ONLY_ABSOLUTE_CLIENT_OVERRIDE_REQUIRED')
  if(!harness)return createPrimeOwnerController
  if(!isAbsolute(harness))throw new TypeError('TEST_ONLY_ABSOLUTE_PINNED_DSH_REQUIRED')
  const require=createRequire(join(resolve(harness),'node_modules/.pnpm/node_modules/prime-owner-hook.cjs'))
  assert.equal(require('react/package.json').version,'18.3.1','compiled hook fixture uses pinned React')
  const modules={react:require('react'),'react/jsx-runtime':require('react/jsx-runtime'),'@deepseek-ai/dsh-client-store':{}}
  const factories={},loaderWindow={__ModuleLoader__:{load:({id,factory})=>{factories[id]=factory}}}
  for(const file of [new URL('../../faces/layout/lib/client.js',import.meta.url),clientFile||new URL('../lib/client.js',import.meta.url)])new Function('window',await readFile(file,'utf8'))(loaderWindow)
  const get=name=>{if(name in modules)return modules[name];return modules[name]=factories[name.replace(/\/client$/,'')](get)}
  get('@aukora/face-layout/client')
  const factory=get('@aukora/prime-authority-ui/client').createPrimeOwnerController
  assert.equal(typeof factory,'function','the actual built native controller export is required')
  return factory
}
