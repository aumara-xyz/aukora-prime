// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs'
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { buildRememberedNote, RECALL_CEILINGS } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { contentFreeTombstone } from '../genesis/plugins/aukora-kira/lib/memory-law.mjs'
import { CONTROLS, ownerControlIn } from '../genesis/plugins/aukora-kira/lib/memory-forget.mjs'
import { SECRET_PATTERNS } from './capture-policy.mjs'
import { AURA_RECORD_DOMAIN, sha256, parseOriginal, validateOriginal, auraEntryHash,
  requireMemory, MemoryRefusal, verifyChain, verifyMembership, verifySources } from './codecs.mjs'
import { makeSnapshot, inspectSnapshot } from './snapshot.mjs'

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
  verifyApprovedEvidence, authorizeImport, allowSyntheticImport = false } = {}) {
  requireMemory(typeof pool?.connect === 'function' && typeof pool?.query === 'function', 'memory:postgres-pool-required')
  requireMemory(typeof indexTarget === 'string' && indexTarget && typeof indexGeneration === 'string'
    && indexGeneration, 'memory:index-target-required')

  async function transaction(owner, work, { readOnly = false } = {}) {
    const client = await pool.connect()
    try {
      await client.query(readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN')
      if (!readOnly) {
        await client.query('SET LOCAL synchronous_commit = on')
        // Serialize per owner without global locks; capture, forget, import and rebuild share this lock.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [owner])
      }
      const result = await work(client)
      await client.query('COMMIT')
      return result
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error }
    finally { client.release() }
  }
  async function migrate() {
    const [settings] = await rows(pool,"SELECT current_setting('fsync') AS fsync, current_setting('full_page_writes') AS full_page_writes")
    requireMemory(settings?.fsync === 'on' && settings.full_page_writes === 'on', 'memory:postgres-durability-unavailable')
    await pool.query(readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'))
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

  /** Ordinary automatic remembered capture. Host attribution/source/policy are separate from untrusted extraction. */
  async function captureRemembered(host, input, idempotencyKey) {
    host = structuredClone(host); input = structuredClone(input)
    const owner = ownerOf(host)
    requireMemory(typeof host.task_id === 'string' && host.task_id, 'memory:host-task-required')
    requireMemory(typeof idempotencyKey === 'string' && idempotencyKey.length > 0 && idempotencyKey.length <= 1024, 'memory:idempotency-key-required')
    const allowed = ['category','statement','validFrom','observedAt','confidence','sensitivity','links']
    requireMemory(input && Object.keys(input).every(k => allowed.includes(k)), 'memory:extraction-fields-invalid')
    requireMemory(host.offTheRecord !== true && host.paused !== true && host.privacy === 'local'
      && !Object.entries(CONTROLS).some(([key,value]) => value.stopsCapture && host.controls?.[key]), 'memory:capture-policy-blocked')
    requireMemory(['owner','owner-voice','owner-edit','backfill','lane-requester','dream','agent'].includes(host.attributedTo), 'memory:host-attribution-required')
    const events = eventEntries(host), requestDigest = sha256(Buffer.from(canonicalJSON({ input,
      subject: owner, task: host.task_id, source: host.source, attribution: host.attributedTo,
      scope: host.scope ?? 'owner', origin: host.origin ?? {by:'prime.capture/v1'}, events: events.map(e => e.sha256) })))
    return transaction(owner, async db => {
      const [controls] = await rows(db, 'SELECT bytes FROM prime_memory_controls WHERE owner_subject=$1 AND scope=$2', [owner,host.scope ?? 'owner'])
      const policy = controls ? parseOriginal(controls.bytes) : {}
      requireMemory(policy.paused !== true && policy.offTheRecord !== true
        && !Object.entries(CONTROLS).some(([key,value]) => value.stopsCapture && policy.controls?.[key]), 'memory:capture-control-blocked')
      const [previous] = await rows(db, 'SELECT * FROM prime_memory_requests WHERE owner_subject=$1 AND idempotency_key=$2', [owner,idempotencyKey])
      if (previous) {
        requireMemory(previous.request_digest === requestDigest, 'memory:idempotency-conflict')
        return contractOf(db, await loadRecord(db, owner, previous.record_id, previous.revision))
      }
      const sourceEvent = events.find(e => e.sha256 === host.source?.sha256)
      requireMemory(sourceEvent, 'memory:capture-source-missing')
      const event = parseOriginal(sourceEvent.bytes)
      requireMemory(typeof event.text === 'string' && event.text.length > 0, 'memory:capture-source-text-missing')
      requireMemory(!SECRET_PATTERNS.some(pattern => pattern.test(event.text) || pattern.test(input.statement)), 'memory:capture-secret-shape')
      requireMemory(host.attributedTo === 'agent' || ownerControlIn(event.text) === null, 'memory:capture-owner-control')
      const note = buildRememberedNote({ ...input, attributedTo: host.attributedTo, subject: owner,
        scope: host.scope ?? 'owner', privacy: host.privacy, source: host.source,
        origin: host.origin ?? {by:'prime.capture/v1'},
        evidence: host.evidence ?? [{ log: host.source.sessionId, turn: host.source.seq,
          turnDigest: host.source.sha256, quote: event.text }] })
      const digest = sha256(Buffer.from(note.statement)), marker = sha256(Buffer.from(`${note.id}\0${digest}`))
      const entry = await appendEntry(db, owner, 'remembered', { op: 'remember', id: note.id, at: note.observedAt,
        tier: 'remembered', by: 'prime.capture/v1', contentHash: digest, entryHash: marker,
        originKey: idempotencyKey, bodyAtCapture: host.bodyAtCapture ?? null })
      const stored = { ...note, contentHash: digest, aura: { index: entry.sequence - 1, entryHash: marker },
        bodyAtCapture: host.bodyAtCapture ?? null }
      const bytes = Buffer.from(JSON.stringify(stored) + '\n'), meta = validateOriginal(bytes, owner)
      const sourceVerdict = verifySources(meta, new Map(events.map(e => [e.sha256,e.bytes])))
      requireMemory(sourceVerdict.verdict === 'VERIFIED', 'memory:capture-evidence-missing')
      const requiredEvents = new Set([note.source.sha256,...note.evidence.map(e => e.turnDigest)])
      await storeEvents(db, owner, events.filter(e => requiredEvents.has(e.sha256)))
      await persistRecord(db, owner, meta, bytes, { taskId: host.task_id, revision: 1, chainDomain: 'remembered', chainSequence: entry.sequence })
      await db.query(`INSERT INTO prime_memory_requests(owner_subject,idempotency_key,request_digest,record_id,revision)
        VALUES($1,$2,$3,$4,1)`, [owner,idempotencyKey,requestDigest,note.id])
      return contractOf(db, await loadRecord(db, owner, note.id, 1))
    })
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
      const row = await loadRecord(db, owner, id, revision); checkReadPolicy(host,row.privacy,row.scope)
      return citeIn(db,owner,row,expectedHead)
    }, { readOnly: true })
  }
  async function status(host, id, revision) {
    const owner = ownerOf(host)
    return transaction(owner, async db => {
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

  // A content-free visibility tombstone. Full physical erasure is a separate owner-authorized operation.
  async function tombstoneRecord(host, id, at) {
    const owner = ownerOf(host)
    requireMemory(typeof at === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(at), 'memory:tombstone-time-invalid')
    return transaction(owner, async db => {
      const row = await loadRecord(db, owner, id)
      const [existing] = await rows(db, 'SELECT record_id FROM prime_memory_tombstones WHERE owner_subject=$1 AND record_id=$2', [owner,id])
      if (existing) return { record_id: id, state: 'tombstoned', grants_authority: false }
      const { tombstone } = contentFreeTombstone({ id, at }), bytes = Buffer.from(canonicalJSON(tombstone) + '\n')
      await db.query('INSERT INTO prime_memory_tombstones(owner_subject,record_id,bytes,sha256) VALUES($1,$2,$3,$4)', [owner,id,bytes,sha256(bytes)])
      await appendEntry(db, owner, row.tier === 'remembered' ? 'remembered' : 'approved', { op: 'forget', id, at, by: 'prime.forget/v1' })
      await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2', [owner,id])
      await enqueue(db,owner,id,row.revision,'remove')
      return { record_id: id, state: 'tombstoned', grants_authority: false }
    })
  }

  async function exportSnapshot(host) {
    const owner = ownerOf(host)
    return transaction(owner, async db => {
      const files = [], heads = {}
      for (const row of await rows(db,'SELECT * FROM prime_memory_records WHERE owner_subject=$1 ORDER BY record_id,revision',[owner])) {
        files.push({ path: `records/${row.record_id}/${row.revision}.json`, role: 'record', record_id: row.record_id,
          task_id: row.task_id, revision: row.revision, chain_domain: row.chain_domain, chain_sequence: row.chain_sequence, bytes: bytesOf(row.canonical_bytes) })
      }
      for (const head of await rows(db,'SELECT * FROM prime_memory_heads WHERE owner_subject=$1 ORDER BY chain_domain',[owner])) {
        const entries = await rows(db,'SELECT bytes FROM prime_memory_chain WHERE owner_subject=$1 AND chain_domain=$2 ORDER BY sequence',[owner,head.chain_domain])
        heads[head.chain_domain] = head.hash
        files.push({ path: `chains/${head.chain_domain}.jsonl`, role: 'chain', chain_domain: head.chain_domain, bytes: chainBytes(entries) })
      }
      for (const event of await rows(db,'SELECT sha256,bytes FROM prime_memory_events WHERE owner_subject=$1',[owner])) {
        files.push({ path: `events/${event.sha256}.json`, role: 'event', bytes: bytesOf(event.bytes) })
      }
      for (const t of await rows(db,'SELECT * FROM prime_memory_tombstones WHERE owner_subject=$1',[owner])) {
        files.push({ path: `tombstones/${t.record_id}.json`, role: 'tombstone', bytes: bytesOf(t.bytes) })
      }
      for (const control of await rows(db,'SELECT * FROM prime_memory_controls WHERE owner_subject=$1',[owner])) {
        files.push({ path: `controls/${sha256(Buffer.from(control.scope))}.json`, role: 'control', scope: control.scope, bytes: bytesOf(control.bytes) })
      }
      for (const original of await rows(db,'SELECT * FROM prime_memory_originals WHERE owner_subject=$1',[owner])) {
        const metadata = parseOriginal(original.metadata_bytes)
        files.push({ path: `originals/${original.snapshot_digest}/${original.logical_path}`,
          role: metadata.role === 'approved-evidence' ? 'approved-evidence' : 'original',
          original_metadata: metadata, bytes: bytesOf(original.bytes) })
      }
      for (const source of await rows(db,'SELECT * FROM prime_memory_snapshots WHERE owner_subject=$1',[owner])) {
        files.push({ path: `original-manifests/${source.digest}.json`, role: 'original', bytes: bytesOf(source.manifest_bytes) })
      }
      const snapshot = makeSnapshot(owner,files,heads)
      inspectSnapshot(snapshot,owner)
      return snapshot
    }, { readOnly: true })
  }

  async function importSnapshot(host, snapshot, { mode, expectedHeads, proof } = {}) {
    const owner = ownerOf(host)
    const frozen = JSON.parse(JSON.stringify(snapshot))
    const synthetic = mode === 'synthetic-fixture' && allowSyntheticImport === true
    const authorized = synthetic || (typeof authorizeImport === 'function'
      && await authorizeImport({ owner_subject: owner, manifest_digest: frozen?.manifest_sha256, mode, proof }) === true)
    requireMemory(authorized, 'memory:real-data-import-not-authorized')
    // Detach once: asynchronous authority checks and SQL waits must never re-read a caller-mutated snapshot.
    const checked = inspectSnapshot(frozen,owner,{ expectedHeads, quarantineInvalid: true })
    return transaction(owner, async db => {
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
      for (const item of checked.tombstones) {
        await db.query(`INSERT INTO prime_memory_tombstones(owner_subject,record_id,bytes,sha256) VALUES($1,$2,$3,$4)
          ON CONFLICT DO NOTHING`,[owner,item.id,item.file.bytes,item.file.sha256])
        await db.query('DELETE FROM prime_memory_fts WHERE owner_subject=$1 AND record_id=$2',[owner,item.id])
      }
      for (const control of checked.controls) {
        await db.query(`INSERT INTO prime_memory_controls(owner_subject,scope,bytes) VALUES($1,$2,$3)
          ON CONFLICT(owner_subject,scope) DO NOTHING`,[owner,control.scope,control.file.bytes])
      }
      for (const refused of checked.quarantine) {
        await db.query(`INSERT INTO prime_memory_quarantine(owner_subject,snapshot_digest,logical_path,reason)
          VALUES($1,$2,$3,$4)`,[owner,checked.digest,refused.path,refused.reason])
      }
      return { imported, already_imported: false, quarantined: checked.quarantine.length, snapshot_digest: checked.digest }
    })
  }
  const restoreSnapshot = (host,snapshot,options) => importSnapshot(host,snapshot,{...options,mode: options?.mode ?? 'prime-restore'})
  return Object.freeze({ migrate,captureRemembered,drainOutbox,repairIndex,status,recall,cite,tombstoneRecord,exportSnapshot,importSnapshot,restoreSnapshot })
}

export { MemoryRefusal } from './codecs.mjs'
export { makeSnapshot, inspectSnapshot } from './snapshot.mjs'
export { verifyDiamondEvidence } from './diamond.mjs'
export { snapshotReadOnlyKiraFiles } from './read-only-snapshot.mjs'
