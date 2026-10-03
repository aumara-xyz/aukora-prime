// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { buildRememberedNote, RECALL_CEILINGS } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { contentFreeTombstone } from '../genesis/plugins/aukora-kira/lib/memory-law.mjs'
import { CONTROLS, ownerControlIn } from '../genesis/plugins/aukora-kira/lib/memory-forget.mjs'
import { SECRET_PATTERNS } from './capture-policy.mjs'
import { AURA_RECORD_DOMAIN, sha256, parseOriginal, validateOriginal, auraEntryHash,
  requireMemory, MemoryRefusal, verifyChain, verifyMembership, verifySources } from './codecs.mjs'
import { makeSnapshot, inspectSnapshot, recordCommitment } from './snapshot.mjs'
import { memoryAuthorization, memoryTarget, memoryStateVersion, memoryEffectDigest, memoryResultDigest, memoryReceiptDigest } from './authorization.mjs'
import { requireRedactableChain } from './codecs.mjs'
import { validateCaptureDraft, validateCaptureReview } from './capture-review.mjs'
import { validatePilotCaptureMetadata } from './pilot-capture.mjs'
import { validateCaptureOrigin, captureProfileForOrigin, validateCaptureScopeParity } from './reduced-pilot-scope.mjs'
import { makeMemoryControlState, inspectMemoryControlState, MEMORY_CONTROL_TABLES, MEMORY_WRITER_CLOSURE_TABLE } from './control-state.mjs'
import { createUnavailableControlRetention, isControlRetentionReader, MEMORY_RETENTION_SCHEMA } from './control-retention.mjs'
import { isControlRetentionCoordinator } from './control-retention-coordinator.mjs'
import { createMemoryOwnerSerializer } from './owner-serialization.mjs'
import { createRetainedMemoryParticipant, createPrivateV2RetainedMemoryParticipant } from './retained-memory-participant.mjs'
import { isMemoryOwnerSerializer } from './owner-serialization.mjs'
import { isPrivateV2Coordinator } from './private-v2-coordinator.mjs'
import { assertPrivateHost, assertPrivateProfile, readControlV3, assertRestoreEffectParameters, detachPrivateData } from './private-v2-control.mjs'
import { isPrivateV2Restore, inspectPrivateV2ColdBundle } from './private-v2-restore.mjs'
import { requirePrivateV2Guards } from './private-v2-guards.mjs'
import { writerClosureBinding, makeWriterClosureRow, inspectWriterClosureRow } from './writer-closure.mjs'
import { installWriterClosureGuards, requireWriterClosureGuards } from './writer-closure-guards.mjs'

const ALL_CONTROL_TABLES = {...MEMORY_CONTROL_TABLES, unsent_closures: MEMORY_WRITER_CLOSURE_TABLE}

const rows = async (db, sql, values = []) => (await db.query(sql, values)).rows
const ownerOf = host => {
  requireMemory(typeof host?.owner_subject === 'string' && host.owner_subject.length > 0, 'memory:host-owner-required')
  return host.owner_subject
}
const bytesOf = value => Buffer.from(value)
const checkReadPolicy = (host,privacy,scope) => {
  requireMemory((host.permittedPrivacy ?? ['local']).includes(privacy), 'memory:privacy-not-permitted')
  requireMemory((host.permittedScopes ?? [host.scope ?? 'owner']).includes(scope), 'memory:scope-not-permitted')
}
const eventEntries = host => (host.events ?? []).map(bytes => ({ bytes: bytesOf(bytes), sha256: sha256(bytesOf(bytes)) }))
const chainBytes = entries => Buffer.concat(entries.map(e => bytesOf(e.bytes)))

/** Caller supplies a Prime-owned PostgreSQL Pool. This module never discovers credentials or a sibling repository. */
export function createPostgresMemory({ pool, indexTarget = 'postgres:fts:simple:v1', indexGeneration = '1',
  verifyApprovedEvidence, authority, contracts, restoreAnchorProvider, controlRetention, controlRetentionCoordinator, privateV2 } = {}) {
  requireMemory(typeof pool?.connect === 'function' && typeof pool?.query === 'function', 'memory:postgres-pool-required')
  requireMemory(typeof indexTarget === 'string' && indexTarget && typeof indexGeneration === 'string'
    && indexGeneration, 'memory:index-target-required')
  requireMemory(restoreAnchorProvider===undefined || typeof restoreAnchorProvider==='function','memory:restore-anchor-provider-invalid')
  requireMemory(controlRetentionCoordinator===undefined || isControlRetentionCoordinator(controlRetentionCoordinator),
    'memory:owned-control-retention-coordinator-required')
  requireMemory(restoreAnchorProvider===undefined || (controlRetention===undefined && controlRetentionCoordinator===undefined),
    'memory:restore-provider-ambiguous')
  const v3=privateV2!==undefined
  requireMemory(!v3 || (isPrivateV2Coordinator(privateV2.coordinator) && isMemoryOwnerSerializer(privateV2.serializer)
    && canonicalJSON(assertPrivateProfile(privateV2.profile))===canonicalJSON(privateV2.coordinator.profile)
    && controlRetention===undefined && controlRetentionCoordinator===undefined && restoreAnchorProvider===undefined),
  'memory:private-v2-configuration-required')
  const restoreSource=v3?privateV2.restoreSource:undefined
  requireMemory(restoreSource===undefined || isPrivateV2Restore(restoreSource),'memory:private-v2-owned-restore-source-required')
  const retainedReader=v3?privateV2.coordinator.reader:controlRetention ?? controlRetentionCoordinator?.reader ?? createUnavailableControlRetention()
  requireMemory(v3 || isControlRetentionReader(retainedReader),'memory:owned-control-retention-reader-required')
  requireMemory(controlRetentionCoordinator===undefined || controlRetentionCoordinator.reader===retainedReader,
    'memory:control-retention-reader-mismatch')
  const retentionContexts=new Map(),retentionHost=host=>({owner_id:host.owner_id,owner_subject:host.owner_subject,
    authorization_epoch:host.authorization_epoch})
  // Retained writers and closures hold the owner session. Legacy writers take the same
  // key in their SQL transactions; installed database guards also fence old client code.
  const ownerSerializer=v3?privateV2.serializer:createMemoryOwnerSerializer({pool})
  const v3Hosts=new WeakMap()
  const participantController=v3?createPrivateV2RetainedMemoryParticipant({coordinator:privateV2.coordinator,
    serializer:ownerSerializer,contracts,profile:privateV2.profile}):controlRetentionCoordinator?createRetainedMemoryParticipant({coordinator:controlRetentionCoordinator,
    serializer:ownerSerializer,contracts}):null
  const legacyAnchorProvider=typeof restoreAnchorProvider==='function'
  const loadRestoreAnchor=restoreAnchorProvider ?? (host=>retainedReader.restoreAnchorProvider({
    owner_id:host.owner_id,owner_subject:host.owner_subject,authorization_epoch:host.authorization_epoch}))

  async function transaction(owner, work, { readOnly = false, privateV2Phase = null, restoreCompletion = null } = {}) {
    const ownedScope=ownerSerializer?.current()
    requireMemory(!ownedScope || ownedScope.host.owner_subject===owner,'memory:owner-session-mismatch')
    const client = ownedScope?.client ?? await pool.connect()
    try {
      requireMemory(!v3 || (ownedScope && v3Hosts.has(ownedScope)), 'memory:private-v2-trusted-host-required')
      await client.query(v3?'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE':readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN')
      if (!readOnly || v3) {
        await client.query('SET LOCAL synchronous_commit = on')
        // Serialize per owner without global locks; capture, forget, import and rebuild share this lock.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [owner])
      }
      if(v3) {
        const host=v3Hosts.get(ownedScope)
        await requirePrivateV2Guards(client,{owner_subject:host.owner_subject,owner_id:host.owner_id,
          expected_store_id:privateV2.profile.expected_memory_store_id,profile:privateV2.profile})
        if(privateV2Phase===null || privateV2Phase==='intent') await participantController.assertCurrent(client,host)
      }
      if(restoreCompletion && privateV2Phase!=='effect') restoreCompletion()
      const result = await work(client)
      if(restoreCompletion) restoreCompletion()
      if(v3 && privateV2Phase==='intent' && result===null) await participantController.prepareIntent(client)
      if(v3 && privateV2Phase==='effect') await participantController.prepareEffect(client,result)
      if(v3 && privateV2Phase===null) await participantController.assertCurrent(client,v3Hosts.get(ownedScope))
      if(restoreCompletion) restoreCompletion()
      await client.query('COMMIT')
      if(restoreCompletion) restoreCompletion()
      return result
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error }
    finally { if(!ownedScope) client.release() }
  }
  async function migrate() {
    const [settings] = await rows(pool,"SELECT current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes")
    requireMemory(settings?.fsync === 'on' && settings.full_page_writes === 'on', 'memory:postgres-durability-unavailable')
    await pool.query(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'))
  }
  // Explicit schema migration, supplied pool only. Missing genuine PostgreSQL remains unavailable.
  async function migrateWriterClosureGuards() { return installWriterClosureGuards(pool) }
  async function assertWriterOpen(db,owner,operation_id) {
    const [closure]=await rows(db,'SELECT operation_id FROM prime_memory_unsent_closures WHERE owner_subject=$1 AND operation_id=$2',
      [owner,operation_id])
    requireMemory(!closure,'memory:operation-writer-closed')
  }

  async function storeEvents(db, owner, events) {
    for (const event of events) {
      requireMemory(sha256(event.bytes) === event.sha256, 'memory:event-changed')
      parseOriginal(event.bytes)
      await db.query(`INSERT INTO prime_memory_events(owner_subject,sha256,bytes) VALUES($1,$2,$3)
        ON CONFLICT(owner_subject,sha256) DO NOTHING`, [owner,event.sha256,event.bytes])
      const [stored] = await rows(db, 'SELECT bytes FROM prime_memory_events WHERE owner_subject=$1 AND sha256=$2', [owner,event.sha256])
      requireMemory(stored && bytesOf(stored.bytes).equals(event.bytes), 'memory:event-conflict')
    }
  }
  async function enqueue(db, owner, id, revision, operation = 'index') {
    await db.query(`INSERT INTO prime_memory_outbox(owner_subject,record_id,revision,target,generation,operation)
      VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, [owner,id,revision,indexTarget,indexGeneration,operation])
  }
  async function persistRecord(db, owner, meta, bytes, { taskId, revision, chainDomain, chainSequence }) {
    const [prior] = await rows(db, `SELECT canonical_bytes,original_sha256 FROM prime_memory_records
      WHERE owner_subject=$1 AND record_id=$2 AND revision=$3`, [owner,meta.id,revision])
    if (prior) {
      requireMemory(prior.original_sha256 === meta.digest && bytesOf(prior.canonical_bytes).equals(bytes), 'memory:revision-conflict')
      return false
    }
    await db.query(`INSERT INTO prime_memory_records(owner_subject,record_id,revision,canonical_bytes,original_sha256,
      record_format,canonicalizer,task_id,scope,privacy,tier,statement,chain_domain,chain_sequence,source_digest)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    [owner,meta.id,revision,bytes,meta.digest,meta.format,meta.canon,taskId,meta.scope,meta.privacy,meta.tier,
      meta.statement,chainDomain,chainSequence,meta.record.source?.sha256 ?? null])
    await enqueue(db, owner, meta.id, revision)
    return true
  }
  async function appendEntry(db, owner, domain, body) {
    const [head] = await rows(db, 'SELECT sequence,hash FROM prime_memory_heads WHERE owner_subject=$1 AND chain_domain=$2', [owner,domain])
    const priorRows = await rows(db, 'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence', [owner,domain])
    const prior = verifyChain(chainBytes(priorRows), head?.hash ?? AURA_RECORD_DOMAIN)
    requireMemory(prior.sequence === (head?.sequence ?? 0), 'memory:chain-head-sequence-changed')
    const fields = { ...body, sequence: (head?.sequence ?? 0) + 1 }, prev = head?.hash ?? AURA_RECORD_DOMAIN
    const entry = { ...fields, prev, hash: auraEntryHash(prev, fields) }
    const bytes = Buffer.from(canonicalJSON(entry) + '\n')
    await db.query(`INSERT INTO prime_memory_chain(owner_subject,chain_domain,sequence,bytes,hash,prev)
      VALUES($1,$2,$3,$4,$5,$6)`, [owner,domain,entry.sequence,bytes,entry.hash,entry.prev])
    await db.query(`INSERT INTO prime_memory_heads(owner_subject,chain_domain,sequence,hash) VALUES($1,$2,$3,$4)
      ON CONFLICT(owner_subject,chain_domain) DO UPDATE SET sequence=EXCLUDED.sequence,hash=EXCLUDED.hash`,
    [owner,domain,entry.sequence,entry.hash])
    return entry
  }
  async function rawStatus(db, owner, id, revision) {
    const [row] = await rows(db, `SELECT o.state, EXISTS(SELECT 1 FROM prime_memory_fts f WHERE f.owner_subject=o.owner_subject
      AND f.record_id=o.record_id AND f.revision=o.revision AND f.target=o.target AND f.generation=o.generation) AS searchable
      FROM prime_memory_outbox o WHERE o.owner_subject=$1 AND o.record_id=$2 AND o.revision=$3
      AND o.target=$4 AND o.generation=$5 AND o.operation='index'`, [owner,id,revision,indexTarget,indexGeneration])
    const [hidden] = await rows(db, 'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2', [owner,id])
    return { saved: true, indexed: row?.state === 'indexed', searchable: !hidden && row?.state === 'indexed' && row.searchable === true,
      index_status: row?.state === 'failed' ? 'failed' : (!hidden && row?.state === 'indexed' && row.searchable === true ? 'searchable'
        : (row?.state === 'indexed' ? 'indexed' : 'pending')) }
  }
  async function contractOf(db, row) {
    const status = await rawStatus(db, row.owner_subject, row.record_id, row.revision)
    const meta = validateOriginal(row.canonical_bytes,row.owner_subject)
    requireMemory(meta.digest === row.original_sha256, 'memory:stored-bytes-changed')
    const record = meta.record
    // Closed frozen MemoryRecord v1. Decimal-bearing historical JSON remains inside the UTF-8 string.
    return { version: 1, record_id: row.record_id, owner_subject: row.owner_subject, task_id: row.task_id,
      scope: row.scope, privacy: row.privacy, record_format: row.record_format, canonicalizer: row.canonicalizer,
      canonical_bytes: bytesOf(row.canonical_bytes).toString('utf8'), revision: String(row.revision), grants_authority: false,
      source_event_digest: row.source_digest ? 'sha256:' + row.source_digest : null,
      evidence: record.evidence ?? record.source ?? [], chain_domain: row.chain_domain, source_span: record.source?.span ?? null,
      storage_status: 'saved', index_status: status.index_status }
  }
  async function loadRecord(db, owner, id, revision) {
    const selected = await rows(db, `SELECT * FROM prime_memory_records WHERE owner_subject=$1 AND record_id=$2
      AND ($3::integer IS NULL OR revision=$3) ORDER BY revision DESC LIMIT 1`, [owner,id,revision ?? null])
    requireMemory(selected.length > 0, 'memory:record-missing')
    return selected[0]
  }

  function captureContext(host,input,idempotencyKey) {
    const allowed=['category','statement','validFrom','observedAt','confidence','sensitivity','links']
    requireMemory(input && Object.keys(input).every(k=>allowed.includes(k)),'memory:extraction-fields-invalid')
    validatePilotCaptureMetadata(host,input)
    host=structuredClone(host);input=structuredClone(input)
    const owner=ownerOf(host)
    requireMemory(typeof host.task_id==='string' && host.task_id,'memory:host-task-required')
    requireMemory(typeof idempotencyKey==='string' && idempotencyKey.length>0 && idempotencyKey.length<=1024,'memory:idempotency-key-required')
    requireMemory(host.offTheRecord!==true && host.paused!==true && host.privacy==='local'
      && !Object.entries(CONTROLS).some(([key,value])=>value.stopsCapture && host.controls?.[key]),'memory:capture-policy-blocked')
    requireMemory(['owner','owner-voice','owner-edit','backfill','lane-requester','dream','agent'].includes(host.attributedTo),'memory:host-attribution-required')
    const events=eventEntries(host),selected=events.find(event=>event.sha256===host.source.sha256)
    requireMemory(selected,'memory:capture-source-missing')
    const event=parseOriginal(selected.bytes)
    requireMemory(typeof event.text==='string' && event.text.length>0,'memory:capture-source-text-missing')
    const origin=validateCaptureOrigin(host.origin ?? {by:'prime.capture/v1'})
    const captureProfile=captureProfileForOrigin(origin)
    let reviewDraft
    try {reviewDraft=validateCaptureDraft({statement:input.statement,attributed_to:host.attributedTo,
      capture_metadata:{profile:captureProfile,category:input.category,valid_from:input.validFrom,
        observed_at:input.observedAt,confidence_percent:70,sensitivity:input.sensitivity},evidence_quote:event.text})}
    catch {requireMemory(false,'memory:capture-review-invalid')}
    const capture={input,subject:owner,task:host.task_id,source:host.source,
      evidence:host.evidence ?? null,attribution:host.attributedTo,scope:host.scope ?? 'owner',privacy:host.privacy,
      origin,bodyAtCapture:host.bodyAtCapture ?? null,events:events.map(e=>e.sha256)}
    return {host,input,owner,events,idempotencyKey,reviewDraft,requestDigest:sha256(Buffer.from(canonicalJSON(capture)))}
  }
  async function currentHeads(db,owner) {
    const heads={}
    for(const head of await rows(db,'SELECT * FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain',[owner])) {
      const entries=await rows(db,'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',[owner,head.chain_domain])
      const verified=verifyChain(chainBytes(entries),head.hash)
      requireMemory(verified.sequence===head.sequence,'memory:chain-head-sequence-changed');heads[head.chain_domain]=head.hash
    }
    return heads
  }
  async function prepareCaptureWrite(db,context) {
    const {host,input,owner,events,idempotencyKey,requestDigest}=context
    validatePilotCaptureMetadata(host,input)
    const origin=validateCaptureScopeParity(host.origin ?? {by:'prime.capture/v1'},context.reviewDraft.capture_metadata.profile)
    const purges=await rows(db,'SELECT bytes FROM prime_memory_purges WHERE owner_subject=$1',[owner])
    const purgedSources=new Set(purges.flatMap(row=>parseOriginal(row.bytes).source_digests ?? []))
    requireMemory(!events.some(event=>purgedSources.has(event.sha256)), 'memory:purged-source-recapture')
    const [controls]=await rows(db,'SELECT bytes FROM prime_memory_controls WHERE owner_subject=$1 AND scope=$2',[owner,host.scope ?? 'owner'])
    const policy=controls?parseOriginal(controls.bytes):{}
    requireMemory(policy.paused!==true && policy.offTheRecord!==true
      && !Object.entries(CONTROLS).some(([key,value])=>value.stopsCapture && policy.controls?.[key]),'memory:capture-control-blocked')
    const [previous]=await rows(db,'SELECT * FROM prime_memory_requests WHERE owner_subject=$1 AND idempotency_key=$2',[owner,idempotencyKey])
    if(previous) {
      requireMemory(previous.request_digest===requestDigest,'memory:idempotency-conflict')
      const [hidden]=await rows(db,'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2',[owner,previous.record_id])
      requireMemory(!hidden,'memory:record-tombstoned')
      return async()=>contractOf(db,await loadRecord(db,owner,previous.record_id,previous.revision))
    }
    const completed=new Set((await rows(db,'SELECT operation_id FROM prime_memory_effects WHERE owner_subject=$1',[owner])).map(effect=>effect.operation_id))
    const keyDigest=sha256(Buffer.from(idempotencyKey))
    for(const intent of await rows(db,'SELECT operation_id,operation_bytes FROM prime_memory_intents WHERE owner_subject=$1',[owner])) {
      const operation=parseOriginal(intent.operation_bytes)
      requireMemory(intent.operation_id===context.operationId || completed.has(intent.operation_id)
        || operation.action_type!=='memory.save' || operation.canonical_parameters?.idempotency_key_sha256!==keyDigest,
        'memory:unresolved-idempotency-reconciliation-required')
    }
    const sourceEvent=events.find(e=>e.sha256===host.source?.sha256)
    requireMemory(sourceEvent,'memory:capture-source-missing')
    const event=parseOriginal(sourceEvent.bytes)
    requireMemory(typeof event.text==='string' && event.text.length>0,'memory:capture-source-text-missing')
    requireMemory(event.text===context.reviewDraft.evidence_quote,'memory:capture-review-invalid')
    requireMemory(!SECRET_PATTERNS.some(pattern=>pattern.test(event.text)||pattern.test(input.statement)),'memory:capture-secret-shape')
    requireMemory(host.attributedTo==='agent' || ownerControlIn(event.text)===null,'memory:capture-owner-control')
    const note=buildRememberedNote({...input,attributedTo:host.attributedTo,subject:owner,scope:host.scope ?? 'owner',
      privacy:host.privacy,source:host.source,origin,
      evidence:host.evidence ?? [{log:host.source.sessionId,turn:host.source.seq,turnDigest:host.source.sha256,quote:event.text}]})
    const digest=sha256(Buffer.from(note.statement)),marker=sha256(Buffer.from(`${note.id}\0${digest}`))
    // Validate the complete byte/evidence closure before consuming any authority.
    const candidate={...note,contentHash:digest,aura:{index:0,entryHash:marker},bodyAtCapture:host.bodyAtCapture ?? null}
    requireMemory(canonicalJSON(candidate.origin)===canonicalJSON(origin),'memory:capture-scope-changed')
    validateCaptureScopeParity(candidate.origin,context.reviewDraft.capture_metadata.profile)
    const verdict=verifySources(validateOriginal(Buffer.from(JSON.stringify(candidate)),owner),new Map(events.map(e=>[e.sha256,e.bytes])))
    requireMemory(verdict.verdict==='VERIFIED','memory:capture-evidence-missing')
    return async()=>{
      const entry=await appendEntry(db,owner,'remembered',{op:'remember',id:note.id,at:note.observedAt,tier:'remembered',
        by:'prime.capture/v1',contentHash:digest,entryHash:marker,originKey:sha256(Buffer.from(idempotencyKey)),bodyAtCapture:host.bodyAtCapture ?? null})
      const stored={...candidate,aura:{index:entry.sequence-1,entryHash:marker}},bytes=Buffer.from(JSON.stringify(stored)+'\n'),meta=validateOriginal(bytes,owner)
      requireMemory(canonicalJSON(meta.record.origin)===canonicalJSON(origin),'memory:capture-scope-changed')
      validateCaptureScopeParity(meta.record.origin,context.reviewDraft.capture_metadata.profile)
      const required=new Set([note.source.sha256,...note.evidence.map(e=>e.turnDigest)])
      await storeEvents(db,owner,events.filter(e=>required.has(e.sha256)))
      await persistRecord(db,owner,meta,bytes,{taskId:host.task_id,revision:1,chainDomain:'remembered',chainSequence:entry.sequence})
      await db.query(`INSERT INTO prime_memory_requests(owner_subject,idempotency_key,request_digest,record_id,revision)
        VALUES($1,$2,$3,$4,1)`,[owner,idempotencyKey,requestDigest,note.id])
      return contractOf(db,await loadRecord(db,owner,note.id,1))
    }
  }
  async function prepareCaptureBinding(host,input,key) {
    const context=captureContext(host,input,key)
    return transaction(context.owner,async db=>{
      await prepareCaptureWrite(db,context)
      const heads=await currentHeads(db,context.owner)
      return {target_identity:memoryTarget(context.owner),state_version:memoryStateVersion(heads),
        canonical_parameters:{capture_sha256:context.requestDigest,idempotency_key_sha256:sha256(Buffer.from(key)),heads,
          ...context.reviewDraft},
        memory_capture:context.reviewDraft}
    },{readOnly:true})
  }
  async function captureAuthorizedRemembered(host,input,key,options={}) {
    const context=captureContext(host,input,key);options=structuredClone(options)
    context.operationId=options.operation?.operation_id
    const parameters=options.operation?.canonical_parameters
    requireMemory(parameters?.capture_sha256===context.requestDigest
      && parameters.idempotency_key_sha256===sha256(Buffer.from(key)) && parameters.heads,'memory:capture-operation-mismatch')
    try {validateCaptureReview(parameters,context.reviewDraft)}
    catch {requireMemory(false,'memory:capture-review-invalid')}
    return authorizedEffect(context.host,'memory.save',{capture_sha256:context.requestDigest,
      idempotency_key_sha256:sha256(Buffer.from(key)),heads:parameters.heads,
      ...context.reviewDraft},options,
      async db=>{
        const actual=await currentHeads(db,context.owner)
        requireMemory(canonicalJSON(actual)===canonicalJSON(parameters.heads),'memory:target-state-changed')
        return prepareCaptureWrite(db,context)
      },{includeReceipt:true})
  }
  const activeTargets=new Map()
  function authorityTargetObservation(operation) {
    const active=activeTargets.get(operation?.operation_id)
    requireMemory(active && canonicalJSON(operation)===active.operation_json,'memory:target-observation-outside-lock')
    return structuredClone(active.observation)
  }
  async function withAuthorityTargetObservation(host,operation,fn) {
    host=structuredClone(host);operation=structuredClone(operation)
    requireMemory(typeof fn==='function' && typeof host.owner_id==='string' && operation.owner_id===host.owner_id && ownerOf(host) && operation.task_id===host.task_id
      && canonicalJSON(operation.target_identity)===canonicalJSON(memoryTarget(host.owner_subject)),'memory:target-binding-mismatch')
    const restoreReview=v3 && operation.action_type==='memory.restore'
    requireMemory(!restoreReview || restoreSource,'memory:private-v2-restore-source-required')
    return transaction(host.owner_subject,async db=>{
      if(restoreReview) {
        const bound=assertPrivateHost({...retentionHost(host),task_id:host.task_id})
        const actual=await readControlV3(db,{owner_subject:bound.owner_subject,owner_id:bound.owner_id,
          profile:privateV2.profile},{contracts})
        const retained=await privateV2.coordinator.readVerifiedRestoreCurrent(bound,actual)
        const parameters=assertRestoreEffectParameters(operation.canonical_parameters)
        requireMemory(parameters.retention_checkpoint_sha256===retained.current.checkpoint_sha256
          && parameters.control_anchor_sha256===retained.current.control_state.control_sha256
          && parameters.retention_epoch===retained.current.authorization_epoch
          && operation.authorization_epoch===bound.authorization_epoch
          && parameters.retention_epoch===bound.authorization_epoch
          && canonicalJSON(parameters.heads)===canonicalJSON(retained.current.control_state.heads),
        'memory:private-v2-restore-review-binding-mismatch')
      }
      const heads=await currentHeads(db,host.owner_subject)
      requireMemory(operation.expected_state_version===memoryStateVersion(heads),'memory:target-state-changed')
      requireMemory(!activeTargets.has(operation.operation_id),'memory:target-observation-reentrant')
      activeTargets.set(operation.operation_id,{operation_json:canonicalJSON(operation),
        observation:{target_identity:memoryTarget(host.owner_subject),state_version:memoryStateVersion(heads)}})
      try {return await fn()} finally {activeTargets.delete(operation.operation_id)}
    },{privateV2Phase:restoreReview?'restore-review':null})
  }

  /** FTS is a rebuildable projection. Its ACK never changes the authoritative bytes or chain membership. */
  async function drainOutbox(host, limit = 100) {
    const owner = ownerOf(host)
    requireMemory(Number.isSafeInteger(limit) && limit > 0 && limit <= 1000, 'memory:outbox-limit-invalid')
    return transaction(owner, async db => {
      const jobs = await rows(db, `SELECT * FROM prime_memory_outbox WHERE owner_subject=$1 AND target=$2 AND generation=$3
        AND state IN ('pending','failed') ORDER BY record_id,revision LIMIT $4 FOR UPDATE SKIP LOCKED`, [owner,indexTarget,indexGeneration,limit])
      let indexed = 0
      for (const job of jobs) {
        await db.query('SAVEPOINT prime_memory_index_job')
        try {
          const [hidden] = await rows(db, 'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2', [owner,job.record_id])
          if (job.operation === 'remove' || hidden) {
            await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2', [owner,job.record_id])
          } else {
            const row = await loadRecord(db, owner, job.record_id, job.revision)
            const meta = validateOriginal(row.canonical_bytes, owner)
            requireMemory(meta.digest === row.original_sha256, 'memory:stored-bytes-changed')
            await db.query(`INSERT INTO prime_memory_fts(owner_subject,record_id,revision,target,generation,scope,privacy,statement)
              VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
            [owner,job.record_id,job.revision,indexTarget,indexGeneration,row.scope,row.privacy,meta.statement])
          }
          await db.query(`UPDATE prime_memory_outbox SET state='indexed',attempts=attempts+1,last_error=NULL
            WHERE owner_subject=$1 AND record_id=$2 AND revision=$3 AND target=$4 AND generation=$5 AND operation=$6`,
          [owner,job.record_id,job.revision,indexTarget,indexGeneration,job.operation])
          indexed++
        } catch (error) {
          await db.query('ROLLBACK TO SAVEPOINT prime_memory_index_job')
          await db.query(`UPDATE prime_memory_outbox SET state='failed',attempts=attempts+1,last_error=$7
            WHERE owner_subject=$1 AND record_id=$2 AND revision=$3 AND target=$4 AND generation=$5 AND operation=$6`,
          [owner,job.record_id,job.revision,indexTarget,indexGeneration,job.operation,error.code ?? 'memory:index-unavailable'])
        }
        await db.query('RELEASE SAVEPOINT prime_memory_index_job')
      }
      return { processed: jobs.length, indexed, failed: jobs.length - indexed, target: indexTarget, generation: indexGeneration }
    })
  }
  async function repairIndex(host) {
    const owner = ownerOf(host)
    return transaction(owner, async db => {
      const records = await rows(db, `SELECT r.* FROM prime_memory_records r WHERE r.owner_subject=$1
        AND NOT EXISTS(SELECT 1 FROM prime_memory_tombstones t WHERE t.owner_subject=r.owner_subject AND t.record_id=r.record_id)
        AND NOT EXISTS(SELECT 1 FROM prime_memory_fts f WHERE f.owner_subject=r.owner_subject AND f.record_id=r.record_id
          AND f.revision=r.revision AND f.target=$2 AND f.generation=$3)`, [owner,indexTarget,indexGeneration])
      for (const row of records) {
        await enqueue(db, owner, row.record_id, row.revision)
        await db.query(`UPDATE prime_memory_outbox SET state='pending',last_error=NULL WHERE owner_subject=$1 AND record_id=$2
          AND revision=$3 AND target=$4 AND generation=$5 AND operation='index'`, [owner,row.record_id,row.revision,indexTarget,indexGeneration])
      }
      return { pending: records.length }
    })
  }

  async function citeIn(db, owner, row, expectedHead) {
    const [hidden] = await rows(db, 'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2', [owner,row.record_id])
    requireMemory(!hidden, 'memory:record-tombstoned')
    const meta = validateOriginal(row.canonical_bytes, owner)
    requireMemory(meta.digest === row.original_sha256, 'memory:stored-bytes-changed')
    const entries = await rows(db, 'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence', [owner,row.chain_domain])
    const [head] = await rows(db, 'SELECT sequence,hash FROM prime_memory_heads WHERE owner_subject=$1 AND chain_domain=$2', [owner,row.chain_domain])
    requireMemory(head, 'memory:chain-head-missing')
    const chain = verifyChain(chainBytes(entries), head.hash)
    requireMemory(chain.sequence === head.sequence, 'memory:chain-head-sequence-changed')
    if (expectedHead) verifyChain(chainBytes(entries), expectedHead)
    const entry = verifyMembership(meta, chain.entries, row.chain_sequence)
    const events = await rows(db, 'SELECT sha256,bytes FROM prime_memory_events WHERE owner_subject=$1', [owner])
    let source = verifySources(meta, new Map(events.map(e => [e.sha256, bytesOf(e.bytes)])))
    if (meta.tier === 'approved' && verifyApprovedEvidence) {
      // C/host injects its approved proof consumer; ordinary note capture never enters this path.
      source = await verifyApprovedEvidence({ owner_subject: owner, record_bytes: bytesOf(row.canonical_bytes), entry, db })
      requireMemory(['VERIFIED','UNVERIFIED','MISSING'].includes(source?.verdict), 'memory:approved-verifier-result-invalid')
    }
    return { record_id: row.record_id, revision: String(row.revision), chain_domain: row.chain_domain,
      chain_sequence: row.chain_sequence, aura_entry_hash: entry.hash, verified_head: chain.head,
      ...source, grants_authority: false }
  }
  async function cite(host, id, revision, expectedHead) {
    const owner = ownerOf(host)
    return transaction(owner, async db => {
      const [hidden] = await rows(db, 'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2', [owner,id])
      requireMemory(!hidden, 'memory:record-tombstoned')
      const row = await loadRecord(db, owner, id, revision); checkReadPolicy(host,row.privacy,row.scope)
      return citeIn(db,owner,row,expectedHead)
    }, { readOnly: true })
  }
  async function status(host, id, revision) {
    const owner = ownerOf(host)
    return transaction(owner, async db => {
      const [hidden] = await rows(db, 'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2', [owner,id])
      requireMemory(!hidden, 'memory:record-tombstoned')
      const row = await loadRecord(db, owner, id, revision)
      checkReadPolicy(host,row.privacy,row.scope)
      return { record: await contractOf(db,row), ...await rawStatus(db,owner,id,row.revision) }
    }, { readOnly: true })
  }
  async function recall(host, { query, scope = 'owner', permittedPrivacy = ['local'], limit = 20 } = {}) {
    const owner = ownerOf(host)
    requireMemory(typeof query === 'string' && query.length > 0 && query.length <= 4096
      && typeof scope === 'string' && Array.isArray(permittedPrivacy) && permittedPrivacy.length > 0
      && permittedPrivacy.every(p => ['local','private','exportable'].includes(p))
      && Number.isSafeInteger(limit) && limit > 0 && limit <= 100, 'memory:recall-arguments-invalid')
    requireMemory(host.offTheRecord !== true && host.paused !== true
      && !Object.entries(CONTROLS).some(([key,value]) => (value.stopsRecall || (value.stopsRecallPersonal && scope==='owner'))
        && host.controls?.[key]), 'memory:recall-policy-blocked')
    for (const privacy of permittedPrivacy) checkReadPolicy(host,privacy,scope)
    // Owner AND privacy AND scope are in the SQL predicate before ranking/retrieval, never post-filtered.
    return transaction(owner, async db => {
      const [controls] = await rows(db, 'SELECT bytes FROM prime_memory_controls WHERE owner_subject=$1 AND scope=$2', [owner,scope])
      const policy = controls ? parseOriginal(controls.bytes) : {}
      requireMemory(policy.paused !== true && policy.offTheRecord !== true
        && !Object.entries(CONTROLS).some(([key,value]) => (value.stopsRecall || (value.stopsRecallPersonal && scope==='owner'))
          && policy.controls?.[key]), 'memory:recall-control-blocked')
      const found = await rows(db, `SELECT r.* FROM prime_memory_fts f JOIN prime_memory_records r
        ON r.owner_subject=f.owner_subject AND r.record_id=f.record_id AND r.revision=f.revision
        WHERE f.owner_subject=$1 AND r.owner_subject=$1 AND f.scope=$2 AND r.scope=$2
        AND f.privacy=ANY($3::text[]) AND r.privacy=ANY($3::text[])
        AND f.target=$4 AND f.generation=$5 AND f.document @@ plainto_tsquery('simple',$6)
        AND EXISTS(SELECT 1 FROM prime_memory_outbox o WHERE o.owner_subject=$1 AND o.record_id=f.record_id
          AND o.revision=f.revision AND o.target=f.target AND o.generation=f.generation AND o.operation='index' AND o.state='indexed')
        AND NOT EXISTS(SELECT 1 FROM prime_memory_tombstones t WHERE t.owner_subject=$1 AND t.record_id=f.record_id)
        AND r.revision=(SELECT max(v.revision) FROM prime_memory_records v WHERE v.owner_subject=$1 AND v.record_id=r.record_id)
        ORDER BY ts_rank(f.document,plainto_tsquery('simple',$6)) DESC,r.record_id LIMIT $7`,
      [owner,scope,permittedPrivacy,indexTarget,indexGeneration,query,limit])
      const records = []
      for (const row of found) records.push({ record: await contractOf(db,row), citation: await citeIn(db,owner,row) })
      return { availability: 'found', records, ceilings: RECALL_CEILINGS, grants_authority: false }
    }, { readOnly: true }).catch(error => {
      if (error instanceof MemoryRefusal) throw error
      return { availability: 'undetermined', reason: 'memory:store-unavailable', records: null, grants_authority: false }
    })
  }

  function mutationTime(at) {
    const time=new Date(at)
    requireMemory(typeof at==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(at)
      && Number.isFinite(time.valueOf()) && time.toISOString().slice(0,19)+'Z'===at,'memory:tombstone-time-invalid')
  }
  async function recordMutationState(db,host,id,action,at) {
    mutationTime(at);const owner=ownerOf(host),row=await loadRecord(db,owner,id)
    checkReadPolicy(host,row.privacy,row.scope)
    const meta=validateOriginal(row.canonical_bytes,owner)
    requireMemory(meta.digest===row.original_sha256,'memory:stored-bytes-changed')
    const heads=await currentHeads(db,owner),entries=await rows(db,
      'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',[owner,row.chain_domain])
    verifyMembership(meta,verifyChain(chainBytes(entries),heads[row.chain_domain]).entries,row.chain_sequence)
    const profile=action==='memory.forget'?'prime-logical-forget/v1':'prime-active-record-payloads/v1'
    const parameters={profile,record_id:id,revision:String(row.revision),canonical_sha256:meta.digest,at,heads,
      statement:meta.statement,attributed_to:meta.record.attributedTo ?? null}
    if(action==='memory.purge') {
      const originals=await rows(db,'SELECT * FROM prime_memory_originals WHERE owner_subject=$1 ORDER BY snapshot_digest,logical_path',[owner])
      const snapshots=await rows(db,'SELECT * FROM prime_memory_snapshots WHERE owner_subject=$1 ORDER BY digest',[owner])
      const quarantine=await rows(db,'SELECT * FROM prime_memory_quarantine WHERE owner_subject=$1 ORDER BY snapshot_digest,logical_path',[owner])
      const backups=(await rows(db,'SELECT * FROM prime_memory_effects WHERE owner_subject=$1 ORDER BY operation_id',[owner]))
        .filter(effect=>effect.action==='memory.backup')
      const forest={originals:originals.map(r=>({snapshot_digest:r.snapshot_digest,logical_path:r.logical_path,
        sha256:r.sha256,metadata_sha256:sha256(bytesOf(r.metadata_bytes))})),
        snapshots:snapshots.map(r=>({digest:r.digest,manifest_sha256:sha256(bytesOf(r.manifest_bytes))})),
        quarantine:quarantine.map(r=>({snapshot_digest:r.snapshot_digest,logical_path:r.logical_path,reason:r.reason}))}
      parameters.collateral_scope={discard_owner_imported_source_forest:true,discard_owner_full_backup_effects:true,
        imported_source_forest_sha256:sha256(Buffer.from(canonicalJSON(forest))),
        full_backup_effects_sha256:sha256(Buffer.from(canonicalJSON(backups.map(r=>({operation_id:r.operation_id,
          request_digest:r.request_digest,result_sha256:sha256(bytesOf(r.result_bytes))}))))),
        imported_original_count:originals.length,imported_snapshot_count:snapshots.length,
        quarantine_count:quarantine.length,full_backup_effect_count:backups.length}
    }
    return {row,meta,heads,parameters}
  }
  async function prepareRecordMutationBinding(host,id,{action,at}={}) {
    host=structuredClone(host);requireMemory(['memory.forget','memory.purge'].includes(action),'memory:mutation-action-invalid')
    return transaction(ownerOf(host),async db=>{
      const state=await recordMutationState(db,host,id,action,at)
      return {target_identity:memoryTarget(host.owner_subject),state_version:memoryStateVersion(state.heads),
        canonical_parameters:state.parameters,record_summary:{record_id:id,revision:String(state.row.revision),
          statement:state.meta.statement,attributed_to:state.meta.record.attributedTo ?? null}}
    },{readOnly:true})
  }
  async function writeTombstone(db,owner,row,at) {
    const [existing]=await rows(db,'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2',[owner,row.record_id])
    if(!existing) {
      const {tombstone}=contentFreeTombstone({id:row.record_id,at}),bytes=Buffer.from(canonicalJSON(tombstone)+'\n')
      await db.query('INSERT INTO prime_memory_tombstones(owner_subject,record_id,bytes,sha256) VALUES($1,$2,$3,$4)',[owner,row.record_id,bytes,sha256(bytes)])
      await appendEntry(db,owner,row.chain_domain,{op:'forget',id:row.record_id,at,by:'prime.forget/v1'})
    }
    await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2',[owner,row.record_id])
  }
  async function forgetRecord(host,id,options={}) {
    host=structuredClone(host);options=structuredClone(options)
    const owner=ownerOf(host),at=options.operation?.canonical_parameters?.at
    return authorizedEffect(host,'memory.forget',options.operation?.canonical_parameters,options,async db=>{
      const state=await recordMutationState(db,host,id,'memory.forget',at)
      requireMemory(canonicalJSON(state.parameters)===canonicalJSON(options.operation.canonical_parameters),'memory:record-operation-mismatch')
      return async()=>{
        await writeTombstone(db,owner,state.row,at);await enqueue(db,owner,id,state.row.revision,'remove')
        return {record_id:id,state:'tombstoned',canonical_payload_retained:true,physical_media_erasure:false,
          authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false}
      }
    },{includeReceipt:options.include_receipt===true,receiptResultKey:'result'})
  }
  async function purgeRecordPayload(host,id,options={}) {
    host=structuredClone(host);options=structuredClone(options)
    const owner=ownerOf(host),at=options.operation?.canonical_parameters?.at
    return authorizedEffect(host,'memory.purge',options.operation?.canonical_parameters,options,async db=>{
      const state=await recordMutationState(db,host,id,'memory.purge',at)
      requireMemory(canonicalJSON(state.parameters)===canonicalJSON(options.operation.canonical_parameters),'memory:record-operation-mismatch')
      const all=await rows(db,'SELECT * FROM prime_memory_records WHERE owner_subject=$1 ORDER BY record_id,revision',[owner])
      const effects=await rows(db,'SELECT * FROM prime_memory_effects WHERE owner_subject=$1',[owner])
      const completed=new Set(effects.map(effect=>effect.operation_id))
      // Unresolved save/backup intent bytes can retain the target plaintext without a proven result association.
      for(const intent of await rows(db,'SELECT * FROM prime_memory_intents WHERE owner_subject=$1',[owner])) {
        const op=parseOriginal(intent.operation_bytes)
        requireMemory(!['memory.save','memory.backup'].includes(op.action_type) || completed.has(intent.operation_id),
          'memory:purge-unresolved-payload-intent')
      }
      const selected=all.filter(r=>r.record_id===id),sourceDigests=new Set()
      const commitments=selected.map(row=>recordCommitment(row,bytesOf(row.canonical_bytes)))
      for(const commitment of commitments) for(const digest of commitment.source_digests) sourceDigests.add(digest)
      // Shared evidence cannot be deleted under a single-record grant. Owner-wide erase is explicit.
      for(const row of all.filter(r=>r.record_id!==id)) {
        const references=recordCommitment(row,bytesOf(row.canonical_bytes)).source_digests
        requireMemory(!references.some(d=>sourceDigests.has(d)),'memory:purge-shared-evidence-closure')
      }
      for(const chain of inspectSnapshot(await buildExport(db,owner),owner).chains.values()) requireRedactableChain(chain.entries)
      return async()=>{
        await writeTombstone(db,owner,state.row,at)
        for(const commitment of commitments) await db.query(`INSERT INTO prime_memory_redactions(owner_subject,record_id,revision,bytes)
          VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,[owner,id,commitment.revision,Buffer.from(canonicalJSON(commitment)+'\n')])
        for(const digest of sourceDigests) await db.query('DELETE FROM prime_memory_events WHERE owner_subject=$1 AND sha256=$2',[owner,digest])
        // Content-free idempotency rows remain a replay fence even after payload removal.
        for(const table of ['records','fts','outbox']) await db.query('DELETE FROM prime_memory_'+table+' WHERE owner_subject=$1 AND record_id=$2',[owner,id])
        // Imported source forests and full-backup results may include the selected plaintext without a separable byte boundary.
        for(const table of ['originals','snapshots','quarantine']) await db.query('DELETE FROM prime_memory_'+table+' WHERE owner_subject=$1',[owner])
        for(const effect of effects) {
          const result=parseOriginal(effect.result_bytes)
          if(effect.action==='memory.backup' || (effect.action==='memory.save' && result.record_id===id)) {
            await writeReplayFence(db,owner,effect)
            await db.query('DELETE FROM prime_memory_effects WHERE owner_subject=$1 AND operation_id=$2',[owner,effect.operation_id])
            await db.query('DELETE FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2',[owner,effect.operation_id])
          }
        }
        const purge={kind:'prime-active-record-purge/v1',record_ids:[id],source_digests:[...sourceDigests].sort(),at}
        await db.query('INSERT INTO prime_memory_purges(owner_subject,operation_id,bytes) VALUES($1,$2,$3)',
          [owner,options.operation.operation_id,Buffer.from(canonicalJSON(purge))])
        return {record_id:id,state:'active-record-payloads-purged',revisions_purged:selected.length,source_events_purged:sourceDigests.size,
          imported_source_forest_discarded:true,physical_media_erasure:false,backups_erased:false,wal_erased:false,
          authority_approval_history_erased:false,grants_authority:false}
      }
    },{includeReceipt:options.include_receipt===true,receiptResultKey:'result'})
  }

  async function buildExport(db, owner, { full = false } = {}) {
    const files=[],heads={},tombstones=await rows(db,'SELECT * FROM prime_memory_tombstones WHERE owner_subject=$1',[owner])
    const hidden=new Set(tombstones.map(t=>t.record_id)),redactions=[],removedEvents=new Set(),liveEvents=new Set()
    requireMemory(!full || hidden.size===0,'memory:full-backup-forgotten-payload-forbidden')
    for (const row of await rows(db,'SELECT * FROM prime_memory_records WHERE owner_subject=$1 ORDER BY record_id,revision',[owner])) {
      if (!full && hidden.has(row.record_id)) redactions.push(recordCommitment(row,bytesOf(row.canonical_bytes)))
      else {
        for(const hash of recordCommitment(row,bytesOf(row.canonical_bytes)).source_digests) liveEvents.add(hash)
        files.push({path:`records/${row.record_id}/${row.revision}.json`,role:'record',record_id:row.record_id,
          task_id:row.task_id,revision:row.revision,chain_domain:row.chain_domain,chain_sequence:row.chain_sequence,bytes:bytesOf(row.canonical_bytes)})
      }
    }
    const retained=await rows(db,'SELECT bytes FROM prime_memory_redactions WHERE owner_subject=$1',[owner])
    requireMemory(!full || retained.length===0,'memory:full-backup-payload-unavailable')
    for (const row of retained) {
      const value=parseOriginal(row.bytes)
      if (!redactions.some(r=>r.record_id===value.record_id && r.revision===value.revision)) redactions.push(value)
    }
    for (const r of redactions) {
      for(const hash of r.source_digests) removedEvents.add(hash)
      files.push({path:`redactions/${r.record_id}/${r.revision}.json`,role:'redaction',bytes:Buffer.from(canonicalJSON(r)+'\n')})
    }
    for (const head of await rows(db,'SELECT * FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain',[owner])) {
      const entries=await rows(db,'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',[owner,head.chain_domain])
      heads[head.chain_domain]=head.hash
      files.push({path:`chains/${head.chain_domain}.jsonl`,role:'chain',chain_domain:head.chain_domain,bytes:chainBytes(entries)})
    }
    for (const event of await rows(db,'SELECT sha256,bytes FROM prime_memory_events WHERE owner_subject=$1',[owner])) {
      if (!removedEvents.has(event.sha256) && (full || liveEvents.has(event.sha256))) files.push({path:`events/${event.sha256}.json`,role:'event',bytes:bytesOf(event.bytes)})
    }
    for (const t of tombstones) {
      const original=parseOriginal(t.bytes),bare=original.tombstone ?? original
      // v2 emits the content-free commitment, while full v1 backups preserve the original wrapper bytes.
      const bytes=full?bytesOf(t.bytes):Buffer.from(canonicalJSON({kind:'tombstone',recordId:t.record_id,at:bare.at})+'\n')
      files.push({path:`tombstones/${t.record_id}.json`,role:'tombstone',bytes})
    }
    for (const control of await rows(db,'SELECT * FROM prime_memory_controls WHERE owner_subject=$1',[owner])) {
      files.push({path:`controls/${sha256(Buffer.from(control.scope))}.json`,role:'control',scope:control.scope,bytes:bytesOf(control.bytes)})
    }
    const opaque=new Set()
    for (const original of await rows(db,'SELECT * FROM prime_memory_originals WHERE owner_subject=$1',[owner])) {
      const metadata=parseOriginal(original.metadata_bytes)
      if(full) files.push({path:`originals/${original.snapshot_digest}/${original.logical_path}`,
        role:metadata.role==='approved-evidence'?'approved-evidence':'original',original_metadata:metadata,bytes:bytesOf(original.bytes)})
      else if(metadata.role==='opaque-original') opaque.add(parseOriginal(original.bytes).sha256)
      else opaque.add(original.sha256)
    }
    for (const source of await rows(db,'SELECT * FROM prime_memory_snapshots WHERE owner_subject=$1',[owner])) {
      if(full) files.push({path:`original-manifests/${source.digest}.json`,role:'original',bytes:bytesOf(source.manifest_bytes)})
      else opaque.add(sha256(source.manifest_bytes))
    }
    for (const hash of opaque) files.push({path:`opaque-originals/${hash}.json`,role:'opaque-original',
      bytes:Buffer.from(canonicalJSON({kind:'opaque-original/v1',sha256:hash})+'\n')})
    const snapshot=makeSnapshot(owner,files,heads,{redacted:!full});inspectSnapshot(snapshot,owner)
    return snapshot
  }
  async function exportSnapshot(host) {
    const owner=ownerOf(host)
    return transaction(owner,db=>buildExport(db,owner),{readOnly:true})
  }
  async function controlContracts() {
    const runtime=contracts ?? await import('@aukora-prime/contracts').catch(()=>null)
    requireMemory(typeof runtime?.validateContract==='function' && typeof runtime?.operationDigest==='function',
      'memory:contracts-unavailable')
    return runtime
  }
  async function controlTables(db,owner) {
    const tables={}
    for(const [name,definition] of Object.entries(ALL_CONTROL_TABLES))
      tables[name]=await rows(db,'SELECT * FROM '+definition.table+' WHERE owner_subject=$1',[owner])
    return tables
  }
  // Sensitive trusted-host backup seam. Data snapshots do not carry this control authority.
  async function exportControlState(host) {
    host=structuredClone(host);const runtime=await controlContracts(),owner=ownerOf(host)
    return transaction(owner,async db=>makeMemoryControlState(host,
      {heads:await currentHeads(db,owner),tables:await controlTables(db,owner)},{contracts:runtime}),{readOnly:true})
  }
  async function writeReplayFence(db,owner,effect) {
    const fence={owner_subject:owner,operation_id:effect.operation_id,operation_digest:effect.operation_digest,
      grant_id:effect.grant_id,action:effect.action,request_id:effect.request_id,
      request_digest:effect.request_digest,status:'payload-purged'}
    await db.query(`INSERT INTO prime_memory_replay_fences(owner_subject,operation_id,operation_digest,grant_id,
      action,request_id,request_digest,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,Object.values(fence))
    const [stored]=await rows(db,'SELECT * FROM prime_memory_replay_fences WHERE owner_subject=$1 AND operation_id=$2',[owner,effect.operation_id])
    requireMemory(stored && canonicalJSON(stored)===canonicalJSON(fence),'memory:replay-fence-conflict')
  }
  async function settleCommitted(effect) {
    const {operation,grant,receipt}=effect
    const settleMethod=participantController?'settleMemoryRetained':'settleMemory'
    if(typeof authority?.[settleMethod]!=='function') return {authority_settlement:'pending',reconciliation_required:true,
      settlement_reason:participantController?'memory:retained-authority-unavailable':'memory:authority-unavailable'}
    try {
      const settled=await authority[settleMethod]({operation,consumed_grant:grant,request_id:receipt.request_id,
        request_digest:receipt.request_digest,receipt})
      requireMemory(settled?.ok===true && settled.status==='COMPLETED' && settled.request_id===receipt.request_id
        && settled.request_digest===receipt.request_digest && settled.receipt_digest===memoryReceiptDigest(receipt)
        && settled.reconciliation_required===false,'memory:settlement-unconfirmed')
      return {authority_settlement:'completed',receipt_digest:settled.receipt_digest,reconciliation_required:false}
    } catch(error) {return {authority_settlement:'pending',reconciliation_required:true,settlement_reason:error.code ?? 'memory:settlement-unavailable'}}
  }
  async function readEffect(db,owner,id) {
    const [row]=await rows(db,'SELECT * FROM prime_memory_effects WHERE owner_subject=$1 AND operation_id=$2',[owner,id])
    if(!row) return null
    const effect={result:parseOriginal(row.result_bytes),receipt:parseOriginal(row.receipt_bytes),
      operation:parseOriginal(row.operation_bytes),grant:parseOriginal(row.grant_bytes)}
    requireMemory(effect.receipt.result_digest===memoryResultDigest(effect.result)
      && canonicalJSON(effect.receipt.result)===canonicalJSON(effect.result)
      && row.request_digest===memoryEffectDigest(parseOriginal(row.request_bytes)), 'memory:effect-ledger-changed')
    if(effect.operation.action_type==='memory.save') {
      const [hidden]=await rows(db,'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2',[owner,effect.result.record_id])
      requireMemory(!hidden,'memory:record-tombstoned')
    }
    if(effect.operation.action_type==='memory.backup') {
      const hidden=await rows(db,'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1',[owner])
      requireMemory(hidden.length===0,'memory:full-backup-forgotten-payload-forbidden')
    }
    return effect
  }
  async function reconcileEffect(host,operation_id) {
    requireMemory(v3 || retainedReader.status.kind!=='file-reader' || controlRetentionCoordinator,
      'memory:control-retention-coordinator-required')
    host=structuredClone(host);const owner=ownerOf(host)
    const effect=await transaction(owner,async db=>{
      const [fenced]=await rows(db,'SELECT operation_id FROM prime_memory_replay_fences WHERE owner_subject=$1 AND operation_id=$2',[owner,operation_id])
      requireMemory(!fenced,'memory:effect-payload-purged-replay-forbidden')
      return readEffect(db,owner,operation_id)
    },{readOnly:true,privateV2Phase:v3?'recovery':null})
    if(!effect) {
      const [intent]=await transaction(owner,db=>rows(db,'SELECT * FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2',
        [owner,operation_id]),{readOnly:true,privateV2Phase:v3?'recovery':null})
      requireMemory(intent,'memory:effect-missing-outcome-unknown')
      const op=parseOriginal(intent.operation_bytes)
      requireMemory(op.owner_id===host.owner_id && op.task_id===host.task_id,'memory:effect-owner-mismatch')
      return {status:'unresolved',operation_id,request_id:intent.request_id,request_digest:intent.request_digest,
        reconciliation_required:true,automatic_retry:false,grants_authority:false}
    }
    requireMemory(effect.operation.owner_id===host.owner_id && effect.operation.task_id===host.task_id,'memory:effect-owner-mismatch')
    const finish=async()=>{
      await finalizeRetainedEffect(host,effect)
      const settlement=v3?await transaction(owner,()=>settleCommitted(effect)):await settleCommitted(effect)
      return {result:effect.result,receipt:effect.receipt,...settlement}
    }
    const plan={host:v3?assertPrivateHost({ ...retentionHost(host),task_id:host.task_id }):retentionHost(host),operation:effect.operation,
      request_id:effect.receipt.request_id,request_digest:effect.receipt.request_digest}
    return participantController?(v3 && effect.operation.action_type==='memory.restore'
      ?participantController.runRecoveredOperation(plan,finish):participantController.runOperation(plan,finish)):finish()
  }
  // Trusted worker-only recovery primitive. This closes the exact D writer; it grants no
  // permission, consumes no proof and cannot establish C's independently durable non-consumption.
  async function closeUnsentOperation(host,inputReference) {
    requireMemory(retainedReader.status.kind!=='file-reader' || controlRetentionCoordinator,
      'memory:control-retention-coordinator-required')
    const binding=writerClosureBinding(host,inputReference),owner=binding.host.owner_subject
    const retentionOwner={owner_id:binding.host.owner_id,owner_subject:owner,authorization_epoch:binding.host.authorization_epoch}
    let closureAttempted=false
    try {
      // Await the complete owner session, including its final inspection and cleanup.
      // A committed closure cannot become an ordinary retryable error during unlock.
      return await ownerSerializer.run(retentionOwner,async()=>{
        let prior,closureRow,context
        const absent=async db=>{
          for(const table of ['intents','effects','replay_fences']) {
            const [existing]=await rows(db,'SELECT operation_id FROM '+MEMORY_CONTROL_TABLES[table].table
              +' WHERE owner_subject=$1 AND operation_id=$2',[owner,binding.reference.operation_id])
            requireMemory(!existing,'memory:writer-closure-durable-operation-present')
          }
        }
        await transaction(owner,async db=>{
          await requireWriterClosureGuards(db)
          await absent(db)
          const [row]=await rows(db,'SELECT * FROM prime_memory_unsent_closures WHERE owner_subject=$1 AND operation_id=$2',
            [owner,binding.reference.operation_id])
          if(row) {inspectWriterClosureRow(row,binding);prior=row;closureAttempted=true}
          closureRow=prior ?? makeWriterClosureRow(binding,randomUUID())
        })
        closureAttempted=Boolean(prior)
        let checked=inspectWriterClosureRow(closureRow,binding)
        if(controlRetentionCoordinator) {
          let pending
          try {pending=await controlRetentionCoordinator.inspect(retentionOwner)}
          catch(error) {if(error.code!=='memory:control-retention-pending-missing')throw error}
          if(pending) {
            requireMemory(pending.marker.operation_id===binding.reference.operation_id
              && pending.marker.operation_digest===binding.digest,'memory:writer-closure-retention-unresolved')
            // A lost begin reply can leave the exact closing marker with no SQL row.
            // Recover only its original negative-fence identity; never replace it with
            // a fresh request or treat a prepared checkpoint as a database restore.
            if(!prior) {
              requireMemory(pending.prepared===null,'memory:writer-closure-retention-unresolved')
              closureRow=makeWriterClosureRow(binding,pending.marker.request_id)
              checked=inspectWriterClosureRow(closureRow,binding)
            }
            requireMemory(pending.marker.request_id===checked.closure.closure_id
              && pending.marker.request_digest===checked.closure_digest,'memory:writer-closure-retention-unresolved')
            closureAttempted=true
            context=await controlRetentionCoordinator.recoverClosure({host:retentionOwner,
              operation_id:binding.reference.operation_id,operation_digest:binding.digest,
              request_id:checked.closure.closure_id,request_digest:checked.closure_digest})
          } else if(!prior) {
            const current=await retainedReader.readCurrent(retentionOwner)
            const live=await transaction(owner,async db=>makeMemoryControlState(binding.host,
              {heads:await currentHeads(db,owner),tables:await controlTables(db,owner)},{contracts:await controlContracts()}))
            requireMemory(current.control_state.control_sha256===live.control_sha256,'memory:retention-current-state-mismatch')
            closureAttempted=true
            context=await controlRetentionCoordinator.beginClosure({host:retentionOwner,
              operation_id:binding.reference.operation_id,operation_digest:binding.digest,
              request_id:checked.closure.closure_id,request_digest:checked.closure_digest})
          }
        }
        if(!prior) await transaction(owner,async db=>{
          await requireWriterClosureGuards(db)
          await absent(db)
          closureAttempted=true
          const columns=MEMORY_WRITER_CLOSURE_TABLE.columns
          await db.query('INSERT INTO prime_memory_unsent_closures('+columns.join(',')+') VALUES('
            +columns.map((_,i)=>'$'+(i+1)).join(',')+')',columns.map(key=>closureRow[key]))
        })
        let retained=null
        await transaction(owner,async db=>{
          await requireWriterClosureGuards(db)
          await absent(db)
          const [stored]=await rows(db,'SELECT * FROM prime_memory_unsent_closures WHERE owner_subject=$1 AND operation_id=$2',
            [owner,binding.reference.operation_id])
          inspectWriterClosureRow(stored,binding)
          if(controlRetentionCoordinator) {
            const control=makeMemoryControlState(binding.host,{heads:await currentHeads(db,owner),
              tables:await controlTables(db,owner)},{contracts:await controlContracts()})
            if(context) {
              const pending=await controlRetentionCoordinator.inspect(retentionOwner)
              if(!pending.prepared) await controlRetentionCoordinator.prepared(context,control)
              await controlRetentionCoordinator.complete(context,control)
            }
            const current=await retainedReader.readCurrent(retentionOwner)
            requireMemory(current.control_state.control_sha256===control.control_sha256,'memory:writer-closure-retention-unresolved')
            retained={checkpoint_sha256:current.checkpoint_sha256,control_sha256:control.control_sha256,
              authorization_epoch:current.authorization_epoch}
          }
        })
        await ownerSerializer.inspect()
        return {status:'closed-unsent',...checked,retention:retained,idempotent:Boolean(prior),grants_authority:false}
      })
    } catch(error) {
      if(!closureAttempted)throw error
      const unknown=new MemoryRefusal('memory:writer-closure-outcome-unknown')
      unknown.cause=error;unknown.cause_code=error.cause_code ?? error.code ?? 'memory:store-unavailable'
      unknown.reconciliation_required=true;unknown.automatic_retry=false
      unknown.operation_id=binding.reference.operation_id;unknown.operation_digest=binding.digest
      throw unknown
    }
  }
  const inFlightEffects=new Map()
  async function retentionControlState(db,host,context,{restorePrepared=false}={}) {
    const owner=ownerOf(host),retained=inspectMemoryControlState(context.predecessor.control_state,host,
      {contracts:await controlContracts()})
    const tables=restorePrepared?await mergeRestoreControl(db,host,retained):await controlTables(db,owner)
    const heads=restorePrepared?retained.heads:await currentHeads(db,owner)
    return makeMemoryControlState(host,{heads,tables},{contracts:await controlContracts()})
  }
  async function finalizeRetainedEffect(host,effect,context,restoreCompletion=null) {
    if(v3) return transaction(ownerOf(host),db=>participantController.completeEffect(db),{privateV2Phase:'completion',restoreCompletion})
    if(!controlRetentionCoordinator) return
    await transaction(ownerOf(host),async db=>{
      const [intent]=await rows(db,'SELECT * FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2',
        [ownerOf(host),effect.operation.operation_id])
      requireMemory(intent && intent.operation_digest===effect.receipt.operation_digest
        && intent.request_id===effect.receipt.request_id && intent.request_digest===effect.receipt.request_digest,
        'memory:retention-durable-intent-required')
      if(!context) {
        let pending
        try {pending=await controlRetentionCoordinator.inspect(retentionHost(host))}
        catch(error) {
          if(error.code!=='memory:control-retention-pending-missing') throw error
          const current=await retainedReader.readCurrent(retentionHost(host))
          const live=makeMemoryControlState(host,{heads:await currentHeads(db,ownerOf(host)),
            tables:await controlTables(db,ownerOf(host))},{contracts:await controlContracts()})
          requireMemory(live.control_sha256===current.control_state.control_sha256,'memory:retention-current-state-mismatch')
          return
        }
        requireMemory(pending.marker.operation_id===effect.operation.operation_id,'memory:retention-other-operation-held')
        context=await controlRetentionCoordinator.recover({host:retentionHost(host),operation:effect.operation,
          request_id:intent.request_id,request_digest:intent.request_digest})
        await participantController.bindRecovered(context)
        if(!pending.prepared) await controlRetentionCoordinator.prepared(context,
          await retentionControlState(db,host,context))
      }
      await controlRetentionCoordinator.complete(context,await retentionControlState(db,host,context))
    })
  }
  async function authorizedEffect(host,action,parameters,options,work,{includeReceipt=false,receiptResultKey='record',restoreBundle}={}) {
    requireMemory(!v3 || ['memory.save','memory.forget'].includes(action)
      || (action==='memory.restore' && restoreSource && restoreBundle),'memory:private-v2-action-unavailable')
    requireMemory(v3 || retainedReader.status.kind!=='file-reader' || controlRetentionCoordinator,
      'memory:control-retention-coordinator-required')
    const owner=ownerOf(host),binding=await memoryAuthorization({authority,contracts,retainedMemory:!!participantController},host,action,parameters,options)
    const key=owner+'\0'+binding.operation.operation_id,proof_json=canonicalJSON(options.approval_proof)
    const running=inFlightEffects.get(key)
    if(running) {
      requireMemory(running.digest===binding.digest && running.proof_json===proof_json,'memory:concurrent-operation-conflict')
      return running.promise
    }
    const promise=(async()=>{
      const committed=participantController?await transaction(owner,db=>readEffect(db,owner,binding.operation.operation_id),
        {readOnly:true,privateV2Phase:v3?'recovery':null}):null
      if(committed) requireMemory(committed.receipt.operation_digest===binding.digest,'memory:operation-replay-conflict')
      const request_id=committed?.receipt.request_id ?? randomUUID(),request={version:1,action_type:action,owner_subject:owner,
        operation_id:binding.operation.operation_id,operation_digest:binding.digest,parameters}
      const effectPlan={request_id,request,request_digest:memoryEffectDigest(request),committed}
      requireMemory(!committed || committed.receipt.request_digest===effectPlan.request_digest,'memory:request-replay-conflict')
      const execute=()=>executeAuthorizedEffect(host,action,parameters,options,work,{includeReceipt,receiptResultKey},binding,effectPlan)
      const plan={host:v3?assertPrivateHost({ ...retentionHost(host),task_id:host.task_id }):retentionHost(host),operation:binding.operation,
        request_id,request_digest:effectPlan.request_digest}
      if(v3 && action==='memory.restore') return committed
        ?participantController.runRecoveredOperation(plan,execute)
        :participantController.runRestoreOperation({...plan,bundle:restoreBundle},execute)
      return participantController?participantController.runOperation(plan,execute):execute()

    })().finally(()=>inFlightEffects.delete(key))
    inFlightEffects.set(key,{digest:binding.digest,proof_json,promise})
    return promise
  }
  async function executeAuthorizedEffect(host,action,parameters,options,work,{includeReceipt,receiptResultKey},binding,effectPlan) {
    const owner=ownerOf(host),{request_id,request,request_digest}=effectPlan
    let preparedGrant,dispatched=false,dispatchAttempted=false,effect,retentionContext,retentionAttempted=false
    let restoreCheck=null
    const restoreCompletion=v3 && action==='memory.restore' && !effectPlan.committed ?()=>{
      requireMemory(typeof restoreCheck==='function','memory:private-v2-restore-completion-missing')
      restoreCheck()
    }:null
    const targetScope=async(db,fn)=>{
      const heads=await currentHeads(db,owner)
      requireMemory(binding.operation.expected_state_version===memoryStateVersion(heads),'memory:target-state-changed')
      requireMemory(!activeTargets.has(binding.operation.operation_id),'memory:target-observation-reentrant')
      activeTargets.set(binding.operation.operation_id,{operation_json:canonicalJSON(binding.operation),
        observation:{target_identity:memoryTarget(owner),state_version:memoryStateVersion(heads)}})
      try {return await fn()} finally {activeTargets.delete(binding.operation.operation_id)}
    }
    try {
      effect=await transaction(owner,async db=>{
        await assertWriterOpen(db,owner,binding.operation.operation_id)
        const [fenced]=await rows(db,'SELECT operation_id FROM prime_memory_replay_fences WHERE owner_subject=$1 AND operation_id=$2',[owner,binding.operation.operation_id])
        requireMemory(!fenced,'memory:effect-payload-purged-replay-forbidden')
        const prior=await readEffect(db,owner,binding.operation.operation_id)
        if(prior) {
          requireMemory(prior.receipt.operation_digest===binding.digest && prior.operation.action_type===action,'memory:operation-replay-conflict')
          return prior
        }
        requireMemory(!effectPlan.committed,'memory:committed-effect-disappeared')
        const [intent]=await rows(db,'SELECT request_id FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2',[owner,binding.operation.operation_id])
        requireMemory(!intent,'memory:effect-unresolved-reconciliation-required')
        await work(db,{preflight:true})
        if(controlRetentionCoordinator || v3) {
          requireMemory(host.authorization_epoch===binding.operation.authorization_epoch,'memory:retention-epoch-binding-mismatch')
          if(v3) await participantController.assertCurrent(db,assertPrivateHost({...retentionHost(host),task_id:host.task_id}))
          else if(action!=='memory.restore') {
            const current=await retainedReader.readCurrent(retentionHost(host))
            const live=makeMemoryControlState(host,{heads:await currentHeads(db,owner),tables:await controlTables(db,owner)},
              {contracts:await controlContracts()})
            requireMemory(live.control_sha256===current.control_state.control_sha256,'memory:retention-current-state-mismatch')
          }
          // C validates approval first, then calls the private participant before kernel consumption.
          retentionAttempted=true
        }
        preparedGrant=await targetScope(db,()=>binding.reserve())
        if(participantController) {
          retentionContext=participantController.context()
          requireMemory(retentionContext,'memory:retained-prepare-participant-required')
          retentionContexts.set(binding.operation.operation_id,retentionContext)
        }
        // Durable intent precedes dispatch; its opaque request survives rollback or restart.
        await db.query(`INSERT INTO prime_memory_intents(owner_subject,operation_id,operation_digest,grant_bytes,operation_bytes,
          request_id,request_digest,request_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
          [owner,binding.operation.operation_id,binding.digest,Buffer.from(canonicalJSON(preparedGrant)),
            Buffer.from(canonicalJSON(binding.operation)),request_id,request_digest,Buffer.from(canonicalJSON(request))])
        return null
      },{privateV2Phase:v3?(effectPlan.committed?'recovery':'intent'):null})
      if(!effect && v3) await transaction(owner,db=>participantController.completeIntent(db),{privateV2Phase:'completion'})
      if(!effect && retentionContext && !v3) await transaction(owner,async db=>{
        // Actual committed intent is retained; current stays predecessor and marker stays held.
        await controlRetentionCoordinator.prepared(retentionContext,await retentionControlState(db,host,retentionContext,
          {restorePrepared:action==='memory.restore'}))
      })
      if(!effect) effect=await transaction(owner,async db=>{
        await assertWriterOpen(db,owner,binding.operation.operation_id)
        // Any race after PREPARED is refused under the reacquired owner lock; no grant is unconsumed.
        const execute=await work(db,{preflight:true}),grant=preparedGrant
        if(retentionContext && !v3) await controlRetentionCoordinator.observe(retentionContext)
        await targetScope(db,async()=>{dispatchAttempted=true;await binding.dispatch({grant,request_id,request_digest});dispatched=true})
        const result=await execute(),result_digest=memoryResultDigest(result)
        if(restoreCompletion) {
          const descriptor=Object.getOwnPropertyDescriptor(execute,'assertComplete')
          requireMemory(descriptor && Object.hasOwn(descriptor,'value') && typeof descriptor.value==='function',
            'memory:private-v2-restore-completion-missing')
          restoreCheck=descriptor.value;restoreCompletion()
        }
        const receipt={version:1,kind:'prime-memory-effect/v1',operation_id:binding.operation.operation_id,
          operation_digest:binding.digest,grant_id:grant.grant_id,request_id,request_digest,owner_subject:owner,
          action_type:action,status:'applied',result_digest,result}
        await db.query(`INSERT INTO prime_memory_effects(owner_subject,operation_id,operation_digest,grant_id,action,result_bytes,
          request_id,request_digest,request_bytes,receipt_bytes,operation_bytes,grant_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [owner,binding.operation.operation_id,binding.digest,grant.grant_id,action,Buffer.from(canonicalJSON(result)),
            request_id,request_digest,Buffer.from(canonicalJSON(request)),Buffer.from(canonicalJSON(receipt)),
            Buffer.from(canonicalJSON(binding.operation)),Buffer.from(canonicalJSON(grant))])
        return {result,receipt,operation:binding.operation,grant}
      },{privateV2Phase:v3?'effect':null,restoreCompletion})
      // Independent final checkpoint commits before C receives an applied settlement.
      await finalizeRetainedEffect(host,effect,retentionContext,restoreCompletion)
    } catch(error) {
      if(!v3 && participantController && retentionAttempted && !preparedGrant && !participantController.context()) {
        try {await controlRetentionCoordinator.inspect(retentionHost(host))}
        catch(observationError) {if(observationError.code==='memory:control-retention-pending-missing') throw error}
      }
      if(!preparedGrant && !dispatched && !retentionAttempted) throw error
      if(dispatchAttempted && preparedGrant && typeof authority?.markOutcomeUnknown==='function')
        await Promise.resolve(authority.markOutcomeUnknown({operation:binding.operation,consumed_grant:preparedGrant,request_id,request_digest})).catch(()=>{})
      const held=participantController?.context()?.request
      const unknown=new MemoryRefusal('memory:authority-effect-outcome-unknown')
      unknown.cause=error
      unknown.cause_code=error.code ?? 'memory:store-unavailable';unknown.reconciliation_required=true
      unknown.automatic_retry=false
      unknown.operation_id=binding.operation.operation_id;unknown.request_id=request_id;unknown.request_digest=request_digest
      if(v3 && held) {unknown.transition_id=held.transition_id;unknown.transition_digest=held.transition_digest}
      throw unknown
    } finally {retentionContexts.delete(binding.operation.operation_id)}
    // Only the committed, locally derived receipt can settle C. No guest receipt is accepted.
    const settlement=v3?await transaction(owner,()=>settleCommitted(effect),{restoreCompletion}):await settleCommitted(effect)
    return includeReceipt?{[receiptResultKey]:effect.result,receipt:effect.receipt,...settlement}:effect.result
  }
  async function exportBackup(host,options) {
    host=structuredClone(host);options=structuredClone(options)
    const owner=ownerOf(host),snapshot=await transaction(owner,db=>buildExport(db,owner,{full:true}),{readOnly:true})
    return authorizedEffect(host,'memory.backup',{manifest_sha256:snapshot.manifest_sha256,heads:snapshot.heads},options,
      async db=>{
        const current=await buildExport(db,owner,{full:true})
        requireMemory(current.manifest_sha256===snapshot.manifest_sha256,'memory:export-state-changed')
        return async()=>current
      })
  }
  async function prepareBackupBinding(host) {
    host=structuredClone(host);const owner=ownerOf(host)
    return transaction(owner,async db=>{
      const snapshot=await buildExport(db,owner,{full:true}),heads=await currentHeads(db,owner)
      return {target_identity:memoryTarget(owner),state_version:memoryStateVersion(heads),
        canonical_parameters:{manifest_sha256:snapshot.manifest_sha256,heads:snapshot.heads}}
    },{readOnly:true})
  }

  async function trustedRestoreControl(host,operation) {
    let retained
    const context=operation && retentionContexts.get(operation.operation_id)
    try {retained=structuredClone(context
      ? await controlRetentionCoordinator.observe(context)
      : await loadRestoreAnchor(structuredClone(host)))}
    catch {requireMemory(false,'memory:trusted-restore-anchor-unavailable')}
    let retentionBinding={}
    if(!legacyAnchorProvider) {
      requireMemory(retained?.schema===MEMORY_RETENTION_SCHEMA && retained.owner_id===host.owner_id
        && retained.owner_subject===ownerOf(host) && retained.authorization_epoch===host.authorization_epoch,
        'memory:retention-owner-epoch-mismatch')
      retentionBinding={retention_checkpoint_sha256:retained.checkpoint_sha256,retention_epoch:retained.authorization_epoch}
      retained=retained.control_state
    }
    requireMemory(['aukora-prime-memory-control-state/v1','aukora-prime-memory-control-state/v2'].includes(retained?.schema),
      'memory:trusted-control-anchor-required')
    const checked=inspectMemoryControlState(retained,host,{contracts:await controlContracts()})
    requireMemory(Object.keys(checked.heads).length>0 && Object.values(checked.heads).some(h=>/^[0-9a-f]{64}$/.test(h)),
      'memory:trusted-restore-anchor-invalid')
    return {...checked,...retentionBinding}
  }
  const retentionParameters=retained=>retained.retention_checkpoint_sha256===undefined?{}:{
    retention_checkpoint_sha256:retained.retention_checkpoint_sha256,retention_epoch:retained.retention_epoch}
  async function mergeRestoreControl(db,host,retained,{write=false}={}) {
    const owner=ownerOf(host),local=await controlTables(db,owner),merged={}
    // Closures are permanent writer fences, not inert snapshot rows. Qualify their
    // actual writable PostgreSQL transaction before preflight or importing them.
    // Read-only preparation fails closed for this profile; historical v1 without
    // any local or retained closure continues through the original path.
    if(local.unsent_closures.length || retained.tables.unsent_closures.length)
      await requireWriterClosureGuards(db)
    for(const [name,definition] of Object.entries(ALL_CONTROL_TABLES)) {
      const keyed=new Map(),key=row=>canonicalJSON(definition.key.map(field=>row[field]))
      for(const row of [...local[name],...retained.tables[name]]) {
        const prior=keyed.get(key(row))
        requireMemory(!prior || definition.columns.every(field=>definition.byteColumns.includes(field)
          ? bytesOf(prior[field]).equals(bytesOf(row[field])) : prior[field]===row[field]),'memory:restore-control-conflict')
        if(!prior) keyed.set(key(row),row)
      }
      merged[name]=[...keyed.values()]
    }
    // Validate the union, including global grant/request collisions and unresolved effect joins.
    const runtime=await controlContracts()
    inspectMemoryControlState(makeMemoryControlState(host,{heads:retained.heads,tables:merged},{contracts:runtime}),host,{contracts:runtime})
    for(const name of ['intents','effects','replay_fences']) for(const row of retained.tables[name]) {
      const grantId=row.grant_id ?? parseOriginal(row.grant_bytes).grant_id
      for(const other of ['intents','effects','replay_fences']) {
        const [request]=await rows(db,'SELECT owner_subject,operation_id FROM '+MEMORY_CONTROL_TABLES[other].table+' WHERE request_id=$1',[row.request_id])
        requireMemory(!request || (request.owner_subject===owner && request.operation_id===row.operation_id),
          'memory:restore-control-replay-conflict')
        if(other!=='intents') {
          const [grant]=await rows(db,'SELECT owner_subject,operation_id FROM '+MEMORY_CONTROL_TABLES[other].table+' WHERE grant_id=$1',[grantId])
          requireMemory(!grant || (grant.owner_subject===owner && grant.operation_id===row.operation_id),
            'memory:restore-control-replay-conflict')
        }
      }
    }
    if(write) for(const [name,definition] of Object.entries(ALL_CONTROL_TABLES)) for(const row of retained.tables[name]) {
      const columns=definition.columns
      await db.query('INSERT INTO '+definition.table+'('+columns.join(',')+') VALUES('
        +columns.map((_,i)=>'$'+(i+1)).join(',')+') ON CONFLICT DO NOTHING',columns.map(field=>row[field]))
      const keyColumns=['owner_subject',...definition.key]
      const [stored]=await rows(db,'SELECT * FROM '+definition.table+' WHERE '
        +keyColumns.map((field,i)=>field+'=$'+(i+1)).join(' AND '),keyColumns.map(field=>row[field]))
      requireMemory(stored && columns.every(field=>definition.byteColumns.includes(field)
        ? bytesOf(stored[field]).equals(bytesOf(row[field])) : stored[field]===row[field]),'memory:restore-control-conflict')
    }
    return merged
  }
  async function prepareRestoreBinding(host,snapshot) {
    requireMemory(!participantController,'memory:retained-restore-lineage-unqualified')
    host=structuredClone(host);const retained=await trustedRestoreControl(host),owner=ownerOf(host)
    const frozen=JSON.parse(JSON.stringify(snapshot)),checked=inspectSnapshot(frozen,owner,{expectedHeads:retained.heads,quarantineInvalid:true})
    requireMemory(checked.anchored,'memory:restore-unanchored')
    return transaction(owner,async db=>{
      const controls=await mergeRestoreControl(db,host,retained)
      await importPreflight(db,owner,checked,frozen,controls)
      const heads=await currentHeads(db,owner)
      return {target_identity:memoryTarget(owner),state_version:memoryStateVersion(heads),canonical_parameters:{
        manifest_sha256:checked.digest,mode:'prime-restore',heads:frozen.heads,retained_heads:retained.heads,
        control_anchor_sha256:retained.digest,...retentionParameters(retained)}}
    },{readOnly:true})
  }
  async function importPreflight(db,owner,checked,frozen,retainedTables) {
    const purges=retainedTables?.purges ?? await rows(db,'SELECT bytes FROM prime_memory_purges WHERE owner_subject=$1',[owner])
    const purgedIds=new Set(purges.flatMap(row=>parseOriginal(row.bytes).record_ids)),purgedSources=new Set(
      purges.flatMap(row=>parseOriginal(row.bytes).source_digests ?? []))
    requireMemory(!purges.length || checked.quarantine.length===0,'memory:purged-quarantine-reimport')
    requireMemory(!checked.files.some(f=>f.role==='record' && purgedIds.has(f.record_id)), 'memory:purged-payload-reimport')
    requireMemory(![...checked.events.keys()].some(h=>purgedSources.has(h)), 'memory:purged-source-reimport')
    for(const file of checked.files.filter(f=>f.role==='record')) {
      const record=parseOriginal(file.bytes)
      const referenced=[record.source?.sha256,...(Array.isArray(record.evidence) ? record.evidence.map(e=>e?.turnDigest) : [])]
      requireMemory(!referenced.some(h=>purgedSources.has(h)),'memory:purged-source-reference-reimport')
    }
    requireMemory(!purges.length || (frozen.schema==='aukora-prime-memory-snapshot/v2'
      && !checked.files.some(f=>['original','approved-evidence'].includes(f.role))), 'memory:purged-source-forest-reimport')
    for(const head of await rows(db,'SELECT * FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain',[owner])) {
      const incoming=checked.chains.get(head.chain_domain)
      requireMemory(incoming,'memory:import-local-chain-omitted')
      const oldRows=await rows(db,'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',[owner,head.chain_domain])
      const old=verifyChain(chainBytes(oldRows),head.hash)
      requireMemory(incoming.sequence>=old.sequence && (old.sequence===0 || incoming.entries[old.sequence-1].hash===old.head),'memory:import-chain-fork')
    }
    for(const item of checked.records) {
      const [prior]=await rows(db,'SELECT canonical_bytes,original_sha256 FROM prime_memory_records WHERE owner_subject=$1 AND record_id=$2 AND revision=$3',
        [owner,item.meta.id,item.file.revision])
      requireMemory(!prior || (prior.original_sha256===item.meta.digest && bytesOf(prior.canonical_bytes).equals(item.file.bytes)),'memory:revision-conflict')
    }
    if(retainedTables) {
      for(const row of retainedTables.tombstones) {
        const value=parseOriginal(row.bytes),bare=value.tombstone ?? value
        requireMemory(checked.tombstones.some(t=>t.id===row.record_id && t.at===bare.at),'memory:restore-control-tombstone-omitted')
      }
      for(const row of retainedTables.redactions) requireMemory(checked.redactions.some(r=>r.value.record_id===row.record_id
        && r.value.revision===row.revision && canonicalJSON(r.value)===canonicalJSON(parseOriginal(row.bytes))),
        'memory:restore-control-redaction-omitted')
      requireMemory(checked.controls.length===retainedTables.controls.length && retainedTables.controls.every(row=>
        checked.controls.some(c=>c.scope===row.scope && c.file.bytes.equals(bytesOf(row.bytes)))),
        'memory:restore-control-policy-mismatch')
    }
  }
  async function importSnapshot(host, snapshot, options = {}) {
    host=structuredClone(host);options=structuredClone(options)
    const { mode = 'kira-import' } = options
    let expectedHeads=options.expectedHeads,retained
    const owner = ownerOf(host)
    const frozen = JSON.parse(JSON.stringify(snapshot))
    requireMemory(['kira-import','prime-restore'].includes(mode),'memory:import-mode-invalid')
    // Caller-provided head files are cross-checks, never a restore trust root.
    if(mode==='prime-restore') {
      retained=await trustedRestoreControl(host)
      requireMemory(retained.retention_epoch===undefined || options.operation?.authorization_epoch===retained.retention_epoch,
        'memory:retention-epoch-binding-mismatch')
      requireMemory(expectedHeads===undefined || canonicalJSON(expectedHeads)===canonicalJSON(retained.heads),'memory:restore-anchor-mismatch')
      expectedHeads=retained.heads
    }
    const checked = inspectSnapshot(frozen,owner,{expectedHeads,quarantineInvalid:true})
    if(mode==='prime-restore') requireMemory(checked.anchored,'memory:restore-unanchored')
    requireMemory(mode!=='prime-restore' || !checked.records.some(r=>checked.tombstones.some(t=>t.id===r.meta.id)),
      'memory:restore-forgotten-payload-forbidden')
    requireMemory(!participantController || mode!=='prime-restore','memory:retained-restore-lineage-unqualified')
    return authorizedEffect(host,mode==='prime-restore'?'memory.restore':'memory.import',
      {manifest_sha256:checked.digest,mode,heads:frozen.heads,retained_heads:expectedHeads ?? null,
        ...(retained?{control_anchor_sha256:retained.digest,...retentionParameters(retained)}:{})},options,async db=>{
      if(retained) {
        const current=await trustedRestoreControl(host,options.operation)
        requireMemory(current.digest===retained.digest && canonicalJSON(retentionParameters(current))===canonicalJSON(retentionParameters(retained)),
          'memory:restore-anchor-changed')
      }
      const controlRows=retained?await mergeRestoreControl(db,host,retained):undefined
      await importPreflight(db,owner,checked,frozen,controlRows)
      if(!retained) requireMemory(frozen.schema!=='aukora-prime-memory-snapshot/v2'
        && !checked.records.some(r=>r.meta.record.origin?.by==='prime.capture/v1')
        && ![...checked.chains.values()].some(chain=>chain.entries.some(entry=>typeof entry.by==='string' && entry.by.startsWith('prime.'))),
        'memory:prime-data-import-requires-control-restore')
      return async()=>{
      await importPreflight(db,owner,checked,frozen,controlRows)
      if(retained) await mergeRestoreControl(db,host,retained,{write:true})
      const [prior] = await rows(db,'SELECT digest FROM prime_memory_snapshots WHERE owner_subject=$1 AND digest=$2',[owner,checked.digest])
      if (prior) return { imported: 0, already_imported: true, quarantined: checked.quarantine.length }
      await db.query('INSERT INTO prime_memory_snapshots(owner_subject,digest,manifest_bytes) VALUES($1,$2,$3)',[owner,checked.digest,checked.manifestBytes])
      for (const file of checked.files) {
        const { bytes, bytes_base64, ...metadata } = file
        await db.query(`INSERT INTO prime_memory_originals(owner_subject,snapshot_digest,logical_path,bytes,sha256,metadata_bytes)
          VALUES($1,$2,$3,$4,$5,$6)`,[owner,checked.digest,file.path,file.bytes,file.sha256,Buffer.from(canonicalJSON(metadata))])
      }
      await storeEvents(db,owner,[...checked.events].map(([sha256,bytes]) => ({ sha256,bytes })))
      for (const [domain,chain] of checked.chains) {
        const [existing] = await rows(db,'SELECT sequence,hash FROM prime_memory_heads WHERE owner_subject=$1 AND chain_domain=$2',[owner,domain])
        if (existing) {
          const oldRows = await rows(db,'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',[owner,domain])
          const old = verifyChain(chainBytes(oldRows),existing.hash)
          requireMemory(chain.entries.length >= old.sequence && (old.sequence === 0 || chain.entries[old.sequence-1].hash === old.head), 'memory:import-chain-fork')
        }
        const start = existing?.sequence ?? 0
        // Retain exact original entry lines; never serialize imported entries into new canonical bytes.
        const lines = chain.file.bytes.toString('utf8').slice(0,-1).split('\n')
        for (const entry of chain.entries.slice(start)) {
          await db.query(`INSERT INTO prime_memory_chain(owner_subject,chain_domain,sequence,bytes,hash,prev)
            VALUES($1,$2,$3,$4,$5,$6)`,[owner,domain,entry.sequence,Buffer.from(lines[entry.sequence-1]+'\n'),entry.hash,entry.prev])
        }
        await db.query(`INSERT INTO prime_memory_heads(owner_subject,chain_domain,sequence,hash) VALUES($1,$2,$3,$4)
          ON CONFLICT(owner_subject,chain_domain) DO UPDATE SET sequence=EXCLUDED.sequence,hash=EXCLUDED.hash`,[owner,domain,chain.sequence,chain.head])
      }
      let imported = 0
      for (const item of checked.records) {
        try {
          if (await persistRecord(db,owner,item.meta,item.file.bytes,{ taskId: item.file.task_id ?? host.task_id ?? 'snapshot-import',
            revision: item.file.revision,chainDomain:item.file.chain_domain,chainSequence:item.file.chain_sequence })) imported++
        } catch(error) {
          if (error.code !== 'memory:revision-conflict') throw error
          checked.quarantine.push({ path:item.file.path,reason:error.code })
        }
      }
      for (const item of checked.redactions) {
        await db.query(`INSERT INTO prime_memory_redactions(owner_subject,record_id,revision,bytes) VALUES($1,$2,$3,$4)
          ON CONFLICT DO NOTHING`,[owner,item.value.record_id,item.value.revision,item.file.bytes])
      }
      for (const item of checked.tombstones) {
        await db.query(`INSERT INTO prime_memory_tombstones(owner_subject,record_id,bytes,sha256) VALUES($1,$2,$3,$4)
          ON CONFLICT DO NOTHING`,[owner,item.id,item.file.bytes,item.file.sha256])
        await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2',[owner,item.id])
      }
      for (const control of checked.controls) {
        await db.query(`INSERT INTO prime_memory_controls(owner_subject,scope,bytes) VALUES($1,$2,$3)
          ON CONFLICT(owner_subject,scope) DO UPDATE SET bytes=EXCLUDED.bytes`,[owner,control.scope,control.file.bytes])
      }
      for (const refused of checked.quarantine) {
        await db.query(`INSERT INTO prime_memory_quarantine(owner_subject,snapshot_digest,logical_path,reason)
          VALUES($1,$2,$3,$4)`,[owner,checked.digest,refused.path,refused.reason])
      }
      return { imported, already_imported: false, quarantined: checked.quarantine.length, snapshot_digest: checked.digest,
        control_state_restored:Boolean(retained),...(retained?{control_anchor_sha256:retained.digest,...retentionParameters(retained)}:{}) }
      }
    })
  }
  // Explicit owner-wide active-table purge. Backups/WAL/filesystem snapshots are outside this operation.
  async function eraseOwnerPayloads(host,options={}) {
    host=structuredClone(host);options=structuredClone(options)
    const owner=ownerOf(host),at=options.at
    requireMemory(typeof at==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(at),'memory:tombstone-time-invalid')
    const prior=await exportSnapshot(host)
    return authorizedEffect(host,'memory.erase-owner',
      {profile:'prime-active-owner-payloads/v1',manifest_sha256:prior.manifest_sha256,heads:prior.heads,at},options,
      async db=>{
        const current=await buildExport(db,owner)
        requireMemory(current.manifest_sha256===prior.manifest_sha256,'memory:erase-state-changed')
        for(const chain of inspectSnapshot(current,owner).chains.values()) requireRedactableChain(chain.entries)
        const records=await rows(db,'SELECT * FROM prime_memory_records WHERE owner_subject=$1 ORDER BY record_id,revision',[owner])
        const effects=await rows(db,'SELECT * FROM prime_memory_effects WHERE owner_subject=$1',[owner])
        const completed=new Set(effects.map(effect=>effect.operation_id))
        const intents=await rows(db,'SELECT * FROM prime_memory_intents WHERE owner_subject=$1',[owner])
        requireMemory(intents.every(intent=>intent.operation_id===options.operation.operation_id || completed.has(intent.operation_id)),
          'memory:purge-unresolved-payload-intent')
        return async()=>{
          const existing=await rows(db,'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1',[owner])
          const hidden=new Set(existing.map(t=>t.record_id))
          for(const row of records) {
            const commitment=recordCommitment(row,bytesOf(row.canonical_bytes))
            await db.query(`INSERT INTO prime_memory_redactions(owner_subject,record_id,revision,bytes) VALUES($1,$2,$3,$4)
              ON CONFLICT DO NOTHING`,[owner,row.record_id,row.revision,Buffer.from(canonicalJSON(commitment)+'\n')])
            if(!hidden.has(row.record_id)) {
              const {tombstone}=contentFreeTombstone({id:row.record_id,at}),bytes=Buffer.from(canonicalJSON(tombstone)+'\n')
              await db.query('INSERT INTO prime_memory_tombstones(owner_subject,record_id,bytes,sha256) VALUES($1,$2,$3,$4)',[owner,row.record_id,bytes,sha256(bytes)])
              await appendEntry(db,owner,row.chain_domain,{op:'forget',id:row.record_id,at,by:'prime.erase/v1'})
              hidden.add(row.record_id)
            }
          }
          const source_digests=new Set(records.flatMap(row=>recordCommitment(row,bytesOf(row.canonical_bytes)).source_digests))
          for(const source of await rows(db,'SELECT sha256,bytes FROM prime_memory_events WHERE owner_subject=$1',[owner])) source_digests.add(source.sha256)
          const purge={kind:'prime-active-owner-purge/v1',record_ids:[...hidden].sort(),source_digests:[...source_digests].sort(),at}
          await db.query('INSERT INTO prime_memory_purges(owner_subject,operation_id,bytes) VALUES($1,$2,$3)',
            [owner,options.operation.operation_id,Buffer.from(canonicalJSON(purge))])
          for(const effect of effects) {
            await writeReplayFence(db,owner,effect)
            await db.query('DELETE FROM prime_memory_intents WHERE owner_subject=$1 AND operation_id=$2',[owner,effect.operation_id])
          }
          for(const table of ['fts','outbox','records','events','originals','snapshots','quarantine'])
            await db.query('DELETE FROM prime_memory_'+table+' WHERE owner_subject=$1',[owner])
          // Previous full-backup effect results may contain plaintext, and must be removed too.
          await db.query('DELETE FROM prime_memory_effects WHERE owner_subject=$1',[owner])
          return {state:'active-table-payloads-purged',owner_subject:owner,records_purged:records.length,
            retained:'historical-chain-tombstones-purges-idempotency-and-replay-fences',physical_media_erasure:false,
            authority_approval_history_erased:false,backups_erased:false,wal_erased:false,grants_authority:false}
        }
      })
  }
  async function restoreSnapshot(host,snapshot,options) {
    if(v3) {
      requireMemory(restoreSource,'memory:private-v2-restore-source-required')
      const bound=assertPrivateHost({...retentionHost(host),task_id:host.task_id})
      const bundle=detachPrivateData(snapshot)
      const checked=inspectPrivateV2ColdBundle(bundle,bound,{profile:privateV2.profile,contracts})
      const anchor=checked.published_lineage[0]
      const parameters={manifest_sha256:checked.bundle.snapshot.manifest_sha256,mode:'prime-restore',
        heads:checked.bundle.snapshot.heads,retained_heads:anchor.control_state.heads,
        control_anchor_sha256:anchor.control_state.control_sha256,
        retention_checkpoint_sha256:anchor.checkpoint_sha256,retention_epoch:anchor.authorization_epoch}
      return authorizedEffect(host,'memory.restore',parameters,options,
        db=>restoreSource.prepareRestoreEffectWork(db,bound,participantController),
        {includeReceipt:true,receiptResultKey:'result',restoreBundle:bundle})
    }
    requireMemory(!participantController,'memory:retained-restore-lineage-unqualified')
    requireMemory(options?.mode===undefined || options.mode==='prime-restore','memory:restore-mode-invalid')
    return importSnapshot(host,snapshot,{...options,mode:'prime-restore'})
  }
  if(v3) {
    // Source-owned private composition only. Every async call derives the full owner
    // context before acquiring its genuine held session; unsigned writers/setup are absent.
    const allowed={captureAuthorizedRemembered,prepareCaptureBinding,withAuthorityTargetObservation,reconcileEffect,
      drainOutbox,repairIndex,status,recall,cite,prepareRecordMutationBinding,forgetRecord,
      ...(restoreSource?{restoreSnapshot}:{}),
      exportControlState:host=>transaction(ownerOf(host),db=>readControlV3(db,
        {owner_subject:host.owner_subject,owner_id:host.owner_id,profile:privateV2.profile},{contracts}))}
    const wrapped=Object.fromEntries(Object.entries(allowed).map(([name,fn])=>[name,async(host,...args)=>{
      host=structuredClone(host)
      const bound=assertPrivateHost({owner_id:host.owner_id,owner_subject:host.owner_subject,
        task_id:host.task_id,authorization_epoch:host.authorization_epoch})
      return participantController.withOwnerLifetime(bound,async scope=>{
        const previous=v3Hosts.get(scope)
        requireMemory(!previous || canonicalJSON(previous)===canonicalJSON(bound),'memory:private-v2-owner-context-conflict')
        v3Hosts.set(scope,bound)
        try {return await fn(host,...args)} finally {if(previous)v3Hosts.set(scope,previous);else v3Hosts.delete(scope)}
      })
    }]))
    return Object.freeze({...wrapped,authorityTargetObservation,retainedMemoryParticipant:participantController.participant,
      controlRetentionStatus:()=>Object.freeze({configured:true,kind:'private-v2-retained-effects-source',qualified_runtime:false})})
  }
  return Object.freeze({ retainedMemoryParticipant:participantController?.participant, migrate,migrateWriterClosureGuards,closeUnsentOperation,captureAuthorizedRemembered,prepareCaptureBinding,authorityTargetObservation,withAuthorityTargetObservation,reconcileEffect,drainOutbox,repairIndex,status,recall,cite,prepareRecordMutationBinding,forgetRecord,purgeRecordPayload,eraseOwnerPayloads,exportSnapshot,exportControlState,exportBackup,prepareBackupBinding,prepareRestoreBinding,importSnapshot,restoreSnapshot,
    controlRetentionStatus:()=>legacyAnchorProvider?{configured:true,kind:'explicit-host-control-provider',file_backed:false}:retainedReader.status })
}

export { MemoryRefusal } from './codecs.mjs'
export { makeSnapshot, inspectSnapshot } from './snapshot.mjs'
export { verifyDiamondEvidence } from './diamond.mjs'
export { snapshotReadOnlyKiraFiles } from './read-only-snapshot.mjs'

export { memoryStateVersion, memoryEffectDigest, memoryTarget, MEMORY_AUDIENCE } from './authorization.mjs'
// Private successor source is explicitly unavailable without the reviewed host qualification join.
export { createPrivateV2Memory } from './private-v2-memory.mjs'
