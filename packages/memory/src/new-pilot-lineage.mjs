// SPDX-License-Identifier: AGPL-3.0-or-later
// Explicit local operator setup only. Never mount this adapter on a guest route.
import { types } from 'node:util'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MemoryRefusal, requireMemory } from './codecs.mjs'
import { createMemoryOwnerSerializer } from './owner-serialization.mjs'
import { assertPrivateHost, assertPrivateProfile, detachPrivateData } from './private-v2-control.mjs'
import { isPrivateV2FileRetentionReader, makePrivateV2GenesisEnvelope } from './private-v2-retention.mjs'
import { privateV2Fields } from './private-v2-coordinator.mjs'
import { verifyNewPilotMemoryStore } from './new-pilot-memory-store.mjs'
import { REDUCED_PILOT_SCOPE } from './reduced-pilot-scope.mjs'

const check=(condition,code)=>requireMemory(condition,'memory:new-pilot-lineage-'+code)
const same=(left,right)=>canonicalJSON(left)===canonicalJSON(right)
const HOST_OWNER=['owner_id','owner_subject','authorization_epoch']
const RECEIPT=['version','kind','host','profile','control_sha256','checkpoint_sha256','new_lineage_only']
const SCHEMA=/^prime_pilot_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/

function contractsFrom(input) {
  check(input && typeof input==='object' && !types.isProxy(input),'contracts-required')
  const ds=Object.getOwnPropertyDescriptors(input), names=['validateContract','operationDigest','canonicalJson']
  check(names.every(name=>ds[name] && Object.hasOwn(ds[name],'value') && typeof ds[name].value==='function'
    && !types.isProxy(ds[name].value)),'contracts-required')
  return Object.freeze(Object.fromEntries(names.map(name=>[name,ds[name].value.bind(input)])))
}
function publisherFrom(input,profile) {
  check(input && typeof input==='object' && !types.isProxy(input),'bootstrap-publisher-required')
  const ds=Object.getOwnPropertyDescriptors(input)
  check(Reflect.ownKeys(ds).every(name=>name==='bootstrap'||name==='status') && ds.bootstrap
    && Object.hasOwn(ds.bootstrap,'value') && typeof ds.bootstrap.value==='function'
    && !types.isProxy(ds.bootstrap.value),'bootstrap-publisher-required')
  if(ds.status) {
    check(Object.hasOwn(ds.status,'value'),'bootstrap-publisher-required')
    const status=detachPrivateData(ds.status.value)
    check(status.kind==='private-v2-new-lineage-bootstrap-publisher'
      && status.expected_authority_store_id===profile.expected_authority_store_id
      && status.expected_memory_store_id===profile.expected_memory_store_id,'bootstrap-publisher-profile-mismatch')
  }
  return ds.bootstrap.value.bind(input)
}
function unknown(cause,host,envelope) {
  const error=new MemoryRefusal('memory:new-pilot-lineage-outcome-unknown')
  error.cause=cause; error.cause_code=cause?.code ?? null
  error.reconciliation_required=true; error.automatic_retry=false
  error.owner_id=host.owner_id; error.owner_subject=host.owner_subject
  if(envelope) {error.checkpoint_sha256=envelope.checkpoint_sha256;error.control_sha256=envelope.control_state.control_sha256}
  return error
}

/**
 * Compose the NEW-only protected handshake on an already committed, separately
 * authorized fresh pilot PG schema. Constructor performs no setup, SQL or IO.
 * H/C supplies the independently observed NEW authority store ID in profile;
 * neither a scalar ID nor this setup receipt qualifies C identity/enrollment.
 */
export function createNewPilotLineageSetup(input) {
  const config=privateV2Fields(input,['pool','reader','publisher','profile','contracts','expected_schema'],
    'new-pilot-configuration-required')
  const profile=detachPrivateData(assertPrivateProfile(config.profile)), contracts=contractsFrom(config.contracts)
  check(typeof config.expected_schema==='string' && SCHEMA.test(config.expected_schema),'fresh-schema-required')
  check(isPrivateV2FileRetentionReader(config.reader),'owned-reader-required')
  check(config.reader.status.expected_authority_store_id===profile.expected_authority_store_id
    && config.reader.status.expected_memory_store_id===profile.expected_memory_store_id,'reader-profile-mismatch')
  const reader=config.reader, publish=publisherFrom(config.publisher,profile)
  const serializer=createMemoryOwnerSerializer({pool:config.pool})
  let attempted=false
  async function bootstrap(inputHost) {
    const host=detachPrivateData(assertPrivateHost(inputHost))
    check(!attempted,'attempt-already-made')
    attempted=true
    let publisherAttempted=false, envelope=null
    try {
      return await serializer.run(Object.fromEntries(HOST_OWNER.map(key=>[key,host[key]])),async scope=>{
        let begun=false
        try {
          await scope.client.query('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');begun=true
          await scope.client.query('SET LOCAL synchronous_commit = on')
          await serializer.inspect(scope)
          const settings={host,profile,contracts,expected_schema:config.expected_schema}
          const actual=await verifyNewPilotMemoryStore(scope.client,settings)
          envelope=makePrivateV2GenesisEnvelope(host,actual.control,{profile,contracts})
          // Once the protected publisher may have observed the request this
          // setup instance is permanently one-use, even if its reply is lost.
          publisherAttempted=true
          const reply=detachPrivateData(await publish({host,control_state:actual.control,
            expected_checkpoint_sha256:envelope.checkpoint_sha256}))
          privateV2Fields(reply,RECEIPT,'new-pilot-bootstrap-receipt-fields')
          check(reply.version===1 && reply.kind==='prime-memory-new-lineage-bootstrap/v1'
            && same(reply.host,host) && same(reply.profile,profile)
            && reply.control_sha256===actual.control.control_sha256
            && reply.checkpoint_sha256===envelope.checkpoint_sha256
            && reply.new_lineage_only===true,'bootstrap-reply-binding')
          // Transport acknowledgement is insufficient. The distinct configured
          // protected reader independently verifies inode/UID/bytes/full lineage.
          const published=await reader.readCurrent(host)
          const lineage=await reader.readPublishedLineage(host,{checkpoint_sha256:null})
          check(same(published,envelope) && Array.isArray(lineage) && lineage.length===1
            && same(lineage[0],envelope),'protected-readback-conflict')
          const repeated=await verifyNewPilotMemoryStore(scope.client,settings)
          check(same(repeated.control,actual.control) && same(repeated.physical_scope,actual.physical_scope),
            'actual-pg-scope-changed')
          await serializer.inspect(scope)
          check(same(await reader.readCurrent(host),envelope),'protected-current-changed')
          await scope.client.query('COMMIT');begun=false
          return Object.freeze({version:1,kind:'prime-new-pilot-lineage-setup/v1',host,profile,
            guarantee_scope:REDUCED_PILOT_SCOPE,physical_scope:actual.physical_scope,
            control_sha256:actual.control.control_sha256,checkpoint_sha256:envelope.checkpoint_sha256,
            new_lineage_only:true,authority_identity_verified:false,grants_authority:false})
        } catch(error) {
          if(begun) await scope.client.query('ROLLBACK').catch(()=>{})
          throw error
        }
      })
    } catch(cause) {
      if(publisherAttempted || cause?.code?.startsWith('memory:owner-session-')) throw unknown(cause,host,envelope)
      throw cause
    }
  }
  return Object.freeze({bootstrap,status:Object.freeze({configured:true,kind:'new-pilot-lineage-setup-source',
    guarantee:'REDUCED-GUARANTEE',qualified_runtime:false,grants_authority:false})})
}
