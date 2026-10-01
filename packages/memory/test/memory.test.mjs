// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import { mkdtempSync, rmSync, writeFileSync, cpSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync, sign } from 'node:crypto'
import { createPostgresMemory } from '../src/index.mjs'
import { makeSnapshot, inspectSnapshot } from '../src/snapshot.mjs'
import { sha256, parseOriginal, validateOriginal, AURA_RECORD_DOMAIN, auraEntryHash } from '../src/codecs.mjs'
import { buildRememberedNote } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { stageKiraMemoryRecord } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { canonicalJSON, kiraRecordContentSha256 } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { verifyDiamondEvidence } from '../src/diamond.mjs'
import { snapshotReadOnlyKiraFiles } from '../src/read-only-snapshot.mjs'

// A disposable SQLite-backed SQL fixture, not PostgreSQL acceptance. Translation is limited to the
// dialect differences below; all records, transactions, bytea and restart storage are real file bytes.
class FixturePool {
  constructor(path) { this.db = new DatabaseSync(path); this.failIndex = false; this.failOutbox = false; this.unavailable = false }
  async connect() { if (this.unavailable) throw new Error('synthetic store unavailable'); return { query: this.query.bind(this), release() {} } }
  close() { this.db.close() }
  async query(sql, values = []) {
    if (this.unavailable) throw new Error('synthetic store unavailable')
    if(sql.startsWith('SELECT current_setting')) return {rows:[{fsync:'on',full_page_writes:'on'}]}
    if (this.failIndex && sql.startsWith('INSERT INTO prime_memory_fts')) throw new Error('synthetic index unavailable')
    if (this.failOutbox && sql.startsWith('INSERT INTO prime_memory_outbox')) throw new Error('synthetic outbox unavailable')
    if (/^SET LOCAL|^SELECT pg_advisory_xact_lock/.test(sql)) return { rows: [] }
    sql = sql.replace('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY','BEGIN')
      .replace("document tsvector GENERATED ALWAYS AS (to_tsvector('simple',statement)) STORED",'document text GENERATED ALWAYS AS (statement) STORED')
      .replace('USING gin(document)','(document)').replace(/::integer/g,'')
      .replace(/=ANY\((\$\d+)::text\[\]\)/g,' IN (SELECT value FROM json_each($1))')
      .replace("f.document @@ plainto_tsquery('simple',$6)","f.statement LIKE '%' || $6 || '%'")
      .replace("ts_rank(f.document,plainto_tsquery('simple',$6))",'length(f.statement)')
      .replace(' FOR UPDATE SKIP LOCKED','')
    if (!values.length) { this.db.exec(sql); return { rows: [] } }
    const ordered = []
    sql = sql.replace(/\$(\d+)/g,(_,n) => { const value = values[Number(n)-1]; ordered.push(Array.isArray(value) ? JSON.stringify(value) : value); return '?' })
    const result = this.db.prepare(sql).all(...ordered)
    return { rows: result.map(r => ({ ...r, ...(r.searchable !== undefined ? { searchable: Boolean(r.searchable) } : {}) })) }
  }
}
const at = '2026-10-01T11:03:00Z'
const owner = 'aukora:1:' + 'a'.repeat(64)
const other = 'aukora:1:' + 'b'.repeat(64)
const event = text => Buffer.from(JSON.stringify({ type:'turn', text, seq:0, at })+'\n')
function host(subject = owner, text = 'Synthetic owner likes banana.') {
  const bytes = event(text)
  return { owner_subject:subject,task_id:'synthetic-task',privacy:'local',scope:'owner',attributedTo:'owner',
    source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(bytes)},events:[bytes] }
}
const input = {category:'fact',statement:'banana',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
const service = (pool,options={}) => createPostgresMemory({pool,allowSyntheticImport:true,...options})

test('synthetic durable capture, honest ACKs, owner filters, restart, import and Prime-only cold restore',async () => {
  const dir = mkdtempSync(join(tmpdir(),'prime-memory-'))
  let pool = new FixturePool(join(dir,'storage.sqlite')),memory = service(pool)
  try {
    await memory.migrate()
    const captureHost = host()
    pool.failOutbox = true
    await assert.rejects(memory.captureRemembered(captureHost,input,'rollback'),/synthetic outbox/)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_chain').get().n,0)
    pool.failOutbox = false
    const saved = await memory.captureRemembered(captureHost,input,'turn-1')
    assert.equal(saved.storage_status,'saved'); assert.equal(saved.index_status,'pending')
    const initial = await memory.status(captureHost,saved.record_id)
    assert.equal(initial.saved,true); assert.equal(initial.indexed,false); assert.equal(initial.searchable,false)
    assert.equal((await memory.recall(captureHost,{query:'banana'})).records.length,0)
    assert.equal((await memory.cite(captureHost,saved.record_id,'1')).verdict,'VERIFIED')
    assert.deepEqual(await memory.captureRemembered(captureHost,input,'turn-1'),saved)
    await assert.rejects(memory.captureRemembered(captureHost,{...input,statement:'changed'},'turn-1'),{code:'memory:idempotency-conflict'})
    await assert.rejects(memory.captureRemembered(captureHost,{...input,attributedTo:'owner'},'spoof'),{code:'memory:extraction-fields-invalid'})
    await assert.rejects(memory.captureRemembered({...captureHost,offTheRecord:true},input,'off'),{code:'memory:capture-policy-blocked'})
    await assert.rejects(memory.captureRemembered(host(owner,'This is off the record.'),input,'off-words'),{code:'memory:capture-owner-control'})
    await assert.rejects(memory.captureRemembered(host(owner,'-----BEGIN PRIVATE KEY----- synthetic'),input,'secret'),{code:'memory:capture-secret-shape'})
    pool.failIndex = true
    assert.equal((await memory.drainOutbox(captureHost)).failed,1)
    assert.equal((await memory.status(captureHost,saved.record_id)).record.index_status,'failed')
    pool.failIndex = false; await memory.drainOutbox(captureHost)
    assert.equal((await memory.status(captureHost,saved.record_id)).searchable,true)
    assert.equal((await memory.recall(captureHost,{query:'banana'})).records[0].record.canonical_bytes,saved.canonical_bytes)
    await assert.rejects(memory.cite(host(other),saved.record_id),{code:'memory:record-missing'})
    assert.equal((await memory.recall(host(other),{query:'banana'})).records.length,0)
    await assert.rejects(memory.recall(captureHost,{query:'banana',permittedPrivacy:['private']}),{code:'memory:privacy-not-permitted'})
    const otherSaved = await memory.captureRemembered(host(other),input,'other-1'); await memory.drainOutbox(host(other))
    assert.notEqual(otherSaved.record_id,saved.record_id)
    pool.close(); pool = new FixturePool(join(dir,'storage.sqlite')); memory = service(pool)
    assert.equal((await memory.cite(captureHost,saved.record_id)).verdict,'VERIFIED')
    assert.equal((await memory.recall(captureHost,{query:'banana'})).records.length,1)
    assert.equal((await memory.captureRemembered(captureHost,input,'turn-1')).record_id,saved.record_id)
    const retarget = service(pool,{indexGeneration:'2'})
    assert.equal((await retarget.status(captureHost,saved.record_id)).indexed,false)
    await retarget.repairIndex(captureHost); await retarget.drainOutbox(captureHost)
    assert.equal((await retarget.status(captureHost,saved.record_id)).searchable,true)
    pool.db.prepare('DELETE FROM prime_memory_fts WHERE owner_subject=?').run(owner)
    const lost = await retarget.status(captureHost,saved.record_id)
    assert.equal(lost.indexed,true); assert.equal(lost.searchable,false)
    await retarget.repairIndex(captureHost); await retarget.drainOutbox(captureHost)
    const snapshot = await memory.exportSnapshot(captureHost)
    assert.equal(snapshot.owner_subject,owner)
    assert.equal(inspectSnapshot(snapshot,owner).records.length,1)
    const packageRoot = fileURLToPath(new URL('../',import.meta.url)),copied = join(dir,'empty-prime-memory')
    cpSync(packageRoot,copied,{recursive:true}); writeFileSync(join(dir,'snapshot.json'),JSON.stringify(snapshot)); writeFileSync(join(dir,'heads.json'),JSON.stringify(snapshot.heads))
    const cold = spawnSync(process.execPath,[join(copied,'bin/cold-verify.mjs'),join(dir,'snapshot.json'),owner,join(dir,'heads.json')],{cwd:dir,encoding:'utf8'})
    assert.equal(cold.status,0,cold.stderr); assert.equal(JSON.parse(cold.stdout).citations[0].verdict,'VERIFIED')
    assert.equal(JSON.parse(cold.stdout).independent_trust_anchor_supplied,true)
    const restoredPool = new FixturePool(join(dir,'restore.sqlite'))
    try {
      const restored = service(restoredPool); await restored.migrate()
      const noImportPermission = createPostgresMemory({pool:restoredPool})
      await assert.rejects(noImportPermission.importSnapshot(captureHost,snapshot,{mode:'synthetic-fixture'}),{code:'memory:real-data-import-not-authorized'})
      assert.equal((await restored.restoreSnapshot(captureHost,snapshot,{mode:'synthetic-fixture',expectedHeads:snapshot.heads})).imported,1)
      assert.equal((await restored.importSnapshot(captureHost,snapshot,{mode:'synthetic-fixture'})).already_imported,true)
      assert.equal((await restored.status(captureHost,saved.record_id)).record.canonical_bytes,saved.canonical_bytes)
      assert.equal((await restored.status(captureHost,saved.record_id)).indexed,false)
      await restored.drainOutbox(captureHost)
      assert.equal((await restored.recall(captureHost,{query:'banana'})).records[0].citation.verdict,'VERIFIED')
      const backup = await restored.exportSnapshot(captureHost)
      assert.ok(backup.files.some(f => f.role==='original' && f.bytes_base64===snapshot.files.find(r=>r.role==='record').bytes_base64))
      await restored.tombstoneRecord(captureHost,saved.record_id,at)
      assert.equal((await restored.recall(captureHost,{query:'banana'})).records.length,0)
      await assert.rejects(restored.cite(captureHost,saved.record_id),{code:'memory:record-tombstoned'})
      assert.equal(inspectSnapshot(await restored.exportSnapshot(captureHost),owner).tombstones.length,1)
    } finally { restoredPool.close() }
    pool.unavailable = true
    assert.equal((await memory.recall(captureHost,{query:'banana'})).availability,'undetermined')
    pool.unavailable = false
    const corrupted = JSON.parse(JSON.stringify(snapshot)); corrupted.files[0].bytes_base64 = Buffer.from('changed').toString('base64')
    assert.throws(()=>inspectSnapshot(corrupted,owner),{code:'memory:snapshot-file-changed'})
    assert.throws(()=>inspectSnapshot(snapshot,owner,{expectedHeads:{remembered:'f'.repeat(64)}}),{code:'memory:retained-head-mismatch'})
    const liveSource = pool.db.prepare('SELECT bytes FROM prime_memory_events WHERE owner_subject=? LIMIT 1').get(owner)
    pool.db.prepare('UPDATE prime_memory_events SET bytes=? WHERE owner_subject=?').run(Buffer.from('{"text":"changed"}'),owner)
    await assert.rejects(memory.cite(captureHost,saved.record_id),{code:'memory:source-event-changed'})
    pool.db.prepare('UPDATE prime_memory_events SET bytes=? WHERE owner_subject=?').run(liveSource.bytes,owner)
    // The entire selected closure has exact donor hashes; Diamond's held license notice stays present.
    const provenance = JSON.parse(readFileSync(join(packageRoot,'PROVENANCE.json')))
    for (const file of provenance.files) assert.equal(sha256(readFileSync(join(packageRoot,file.path))),file.sha256)
    const diamond = JSON.parse(readFileSync(join(packageRoot,'genesis/vendor/kira-export/upstream-diamond.json')))
    for (const file of diamond.files) assert.equal(sha256(readFileSync(join(packageRoot,'genesis/vendor/kira-export',file.path))),file.sha256)
    assert.ok(diamond.license.includes('HELD at 7400473825'))
  } finally { pool.close(); rmSync(dir,{recursive:true,force:true}) }
})

test('Diamond separate-process consumer checks synthetic signed evidence and retains its numeric/profile limits',async () => {
  const candidate={subject:owner,kind:'observation',source:[],content:{synthetic:1},links:[],privacy:'local',createdAt:at}
  const record=stageKiraMemoryRecord(candidate).record,content=kiraRecordContentSha256(record)
  const fields={verdict:'accepted',key:record.recordId,contentSha256:content,operation:'memory.put',sequence:1}
  const entry={...fields,prev:AURA_RECORD_DOMAIN,hash:auraEntryHash(AURA_RECORD_DOMAIN,fields)}
  const {privateKey,publicKey}=generateKeyPairSync('ed25519')
  const pub=publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex')
  const body={kind:'aukora-kira-memory-receipt/v1',operation:'memory.put',recordId:record.recordId,effectDigest:content,
    nonce:'synthetic-nonce',issuedAt:1,aura:{entryHash:entry.hash,head:entry.hash,seq:1,priorHead:null}}
  const receipt={...body,sig:sign(null,Buffer.from(body.kind+'\n'+canonicalJSON(body)),privateKey).toString('hex'),issuerPk:pub}
  const args={recordBytes:Buffer.from(JSON.stringify(record)),receiptBytes:Buffer.from(JSON.stringify(receipt)),
    logBytes:Buffer.from(JSON.stringify(entry)+'\n'),issuerAnchor:pub}
  const valid=await verifyDiamondEvidence(args)
  assert.equal(valid.verdict,'VERIFIED',valid.reason)
  assert.equal(valid.report.approval.status,'OWNER_APPROVAL_UNCHECKED')
  assert.equal(valid.grants_authority,false)
  const altered={...receipt,sig:'00'.repeat(64)}
  assert.equal((await verifyDiamondEvidence({...args,receiptBytes:Buffer.from(JSON.stringify(altered))})).verdict,'UNVERIFIED')
  const decimal=stageKiraMemoryRecord({...candidate,content:{synthetic:1.5}}).record
  assert.equal((await verifyDiamondEvidence({...args,recordBytes:Buffer.from(JSON.stringify(decimal))})).reason,'UNSUPPORTED_NUMBER')
  const v1=stageKiraMemoryRecord(candidate,{format:'v1'}).record
  assert.equal((await verifyDiamondEvidence({...args,recordBytes:Buffer.from(JSON.stringify(v1))})).verdict,'UNVERIFIED')
})

// Run only against a caller-designated disposable loopback database. No DB is discovered or started.
test('PostgreSQL acceptance on an explicitly supplied disposable database',{
  skip:!process.env.PRIME_MEMORY_DISPOSABLE_DATABASE_URL ? 'UNPERFORMED: no disposable PostgreSQL runtime supplied' : false
},async () => {
  const url = new URL(process.env.PRIME_MEMORY_DISPOSABLE_DATABASE_URL)
  assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname),'Only disposable loopback PostgreSQL acceptance is permitted')
  const {Pool} = await import('pg')
  const bootstrap=new Pool({connectionString:url.href}),schema='prime_memory_synthetic_'+Date.now().toString(36)
  let pg
  try {
    await bootstrap.query('CREATE SCHEMA '+schema)
    pg=new Pool({connectionString:url.href,options:'-c search_path='+schema})
    let memory=service(pg); await memory.migrate()
    const saved=await memory.captureRemembered(host(),input,'pg-turn-1')
    assert.equal((await memory.status(host(),saved.record_id)).indexed,false)
    await memory.drainOutbox(host())
    assert.equal((await memory.recall(host(),{query:'banana'})).records[0].record.canonical_bytes,saved.canonical_bytes)
    await pg.end(); pg=new Pool({connectionString:url.href,options:'-c search_path='+schema}); memory=service(pg)
    assert.equal((await memory.cite(host(),saved.record_id)).verdict,'VERIFIED')
    assert.equal((await memory.captureRemembered(host(),input,'pg-turn-1')).record_id,saved.record_id)
    assert.equal(inspectSnapshot(await memory.exportSnapshot(host()),owner).records.length,1)
  } finally {
    if(pg) await pg.end()
    await bootstrap.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE'); await bootstrap.end()
  }
})

test('preserved decimal v0, safe-integer v1, UNLINKED, pre-split chains and quarantine never mint new IDs',async () => {
  const dir = mkdtempSync(join(tmpdir(),'prime-memory-import-')),pool = new FixturePool(join(dir,'storage.sqlite'))
  try {
    const memory = service(pool); await memory.migrate()
    const sourceHost = host(),data = event('Synthetic owner likes banana.'),digest = sha256(data)
    const note = buildRememberedNote({...input,subject:owner,privacy:'local',attributedTo:'owner',source:{state:'UNLINKED',cited:true,sessionId:'missing-synthetic',citedTurn:0,because:'Synthetic event absent'},evidence:[{log:'missing-synthetic',turn:0,turnDigest:digest,quote:'banana'}]})
    const marker = sha256(Buffer.from(`${note.id}\0${sha256(Buffer.from(note.statement))}`))
    const stored = {...note,aura:{index:0,entryHash:marker}},body={op:'remember',id:note.id,entryHash:marker,sequence:1,at}
    const entry = {...body,prev:AURA_RECORD_DOMAIN,hash:auraEntryHash(AURA_RECORD_DOMAIN,body)}
    const bytes = Buffer.from(JSON.stringify(stored,null,2)+'\n')
    const snapshot = makeSnapshot(owner,[{path:'remembered.json',role:'record',record_id:note.id,revision:1,chain_domain:'legacy-presplit',chain_sequence:1,bytes},
      {path:'presplit.jsonl',role:'chain',chain_domain:'legacy-presplit',bytes:Buffer.from(JSON.stringify(entry)+'\n')}],{'legacy-presplit':entry.hash})
    await memory.importSnapshot(sourceHost,snapshot,{mode:'synthetic-fixture'})
    const restored = await memory.status(sourceHost,note.id)
    assert.equal(restored.record.canonical_bytes,bytes.toString('utf8'))
    assert.equal(parseOriginal(Buffer.from(restored.record.canonical_bytes)).salt,note.salt)
    assert.equal((await memory.cite(sourceHost,note.id)).verdict,'MISSING')
    const invalid = {...stored,statement:'tampered'}
    const bad = makeSnapshot(owner,[{...snapshot.files[0],path:'invalid.json',bytes:Buffer.from(JSON.stringify(invalid))},
      {path:'presplit.jsonl',role:'chain',chain_domain:'legacy-presplit',bytes:Buffer.from(JSON.stringify(entry)+'\n')}],{'legacy-presplit':entry.hash})
    assert.equal((await memory.importSnapshot(sourceHost,bad,{mode:'synthetic-fixture'})).quarantined,1)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_originals').get().n,4)
    const candidate = {subject:owner,kind:'observation',source:[],content:{decimal:1.5},links:[],privacy:'local',createdAt:at}
    const v0 = stageKiraMemoryRecord(candidate).record
    const v0Bytes = Buffer.from(JSON.stringify(v0,null,2)+'\n')
    assert.equal(validateOriginal(v0Bytes,owner).id,v0.recordId)
    assert.equal(validateOriginal(v0Bytes,owner).canon,'aukora:canon-json:v0-ecmascript-number')
    assert.throws(()=>stageKiraMemoryRecord(candidate,{format:'v1'}))
    const v1 = stageKiraMemoryRecord({...candidate,content:{decimal:'1.5'}},{format:'v1'}).record
    assert.equal(validateOriginal(Buffer.from(JSON.stringify(v1)),owner).format,'v1')
    const approvedBody={op:'memory.put',recordId:v0.recordId,sequence:1,at}
    const approvedEntry={...approvedBody,prev:AURA_RECORD_DOMAIN,hash:auraEntryHash(AURA_RECORD_DOMAIN,approvedBody)}
    const approved=makeSnapshot(owner,[{path:'approved-v0.json',role:'record',record_id:v0.recordId,revision:1,chain_domain:'approved',chain_sequence:1,bytes:v0Bytes},
      {path:'approved.jsonl',role:'chain',chain_domain:'approved',bytes:Buffer.from(JSON.stringify(approvedEntry)+'\n')}],{approved:approvedEntry.hash})
    await memory.importSnapshot(sourceHost,approved,{mode:'synthetic-fixture'})
    assert.equal((await memory.status(sourceHost,v0.recordId)).record.canonical_bytes,v0Bytes.toString('utf8'))
    assert.equal((await memory.cite(sourceHost,v0.recordId)).verdict,'UNVERIFIED')
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_heads').get().n,2)
    // Real source adapter, operated only on explicitly inventoried synthetic files.
    writeFileSync(join(dir,'note.json'),bytes);writeFileSync(join(dir,'presplit.jsonl'),JSON.stringify(entry)+'\n')
    const manifestBytes=Buffer.from(JSON.stringify({owner_subject:owner,heads:{'legacy-presplit':entry.hash},files:[
      {path:'note.json',role:'record',chain_domain:'legacy-presplit'},
      {path:'presplit.jsonl',role:'chain',chain_domain:'legacy-presplit'}]})+'\n')
    const readOnly=snapshotReadOnlyKiraFiles({directory:dir,manifestBytes,owner_subject:owner})
    assert.equal(inspectSnapshot(readOnly,owner).records[0].file.bytes.toString(),bytes.toString())
    assert.equal(readFileSync(join(dir,'note.json')).toString(),bytes.toString())
    assert.equal((await memory.importSnapshot(sourceHost,readOnly,{mode:'synthetic-fixture'})).imported,0)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})
