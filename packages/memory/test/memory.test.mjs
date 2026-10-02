// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import { mkdtempSync, rmSync, writeFileSync, cpSync, readFileSync, realpathSync, chmodSync, statSync } from 'node:fs'
import retentionFiles from 'node:fs/promises'
import { tmpdir, userInfo } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync, execFileSync } from 'node:child_process'
import { generateKeyPairSync, sign } from 'node:crypto'
import { createPostgresMemory } from '../src/index.mjs'
import { makeSnapshot, inspectSnapshot } from '../src/snapshot.mjs'
import { sha256, parseOriginal, validateOriginal, AURA_RECORD_DOMAIN, auraEntryHash } from '../src/codecs.mjs'
import { buildRememberedNote } from '../genesis/plugins/aukora-kira/lib/memory-tiers.mjs'
import { stageKiraMemoryRecord } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { canonicalJSON, kiraRecordContentSha256 } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { verifyDiamondEvidence } from '../src/diamond.mjs'
import { snapshotReadOnlyKiraFiles } from '../src/read-only-snapshot.mjs'
import { runMemoryCommand } from '../src/cli.mjs'
import { validateCaptureReview, validateCaptureDraft } from '../src/capture-review.mjs'
import { memoryTarget, MEMORY_AUDIENCE, memoryStateVersion, memoryReceiptDigest, memoryResultDigest } from '../src/authorization.mjs'
import { createFileControlRetentionPublisher, createFileControlRetentionReader } from '../src/control-retention.mjs'
import { createControlRetentionCoordinator } from '../src/control-retention-coordinator.mjs'

// A disposable SQLite-backed SQL fixture, not PostgreSQL acceptance. Translation is limited to the
// dialect differences below; all records, transactions, bytea and restart storage are real file bytes.
// Session lock/PID observations below are modeled per fixture client, not actual PostgreSQL locks.
let nextFixtureBackendPid=40000
const fixtureSessionInspection=`SELECT pg_backend_pid() AS backend_pid, EXISTS (
  SELECT 1 FROM pg_locks
  WHERE locktype = 'advisory' AND mode = 'ExclusiveLock' AND granted = true
    AND pid = pg_backend_pid()
    AND classid = ((hashtextextended($1, 0) >> 32) & 4294967295)::oid
    AND objid = (hashtextextended($1, 0) & 4294967295)::oid
    AND objsubid = 1
) AS held`
class FixturePool {
  constructor(path) { this.db = new DatabaseSync(path); this.queue=Promise.resolve(); this.sessions=new Map(); this.failIndex = false; this.failOutbox = false; this.unavailable = false }
  async connect() {
    if(this.unavailable) throw new Error('synthetic store unavailable')
    const previous=this.queue;let releaseQueue
    this.queue=new Promise(resolve=>{releaseQueue=resolve});await previous
    const session={backend_pid:++nextFixtureBackendPid,locks:new Map(),active:true}
    this.sessions.set(session.backend_pid,session)
    return {query:(sql,values)=>this.query(sql,values,session),release:()=>{
      assert.equal(session.active,true,'fixture client released only once')
      session.active=false;session.locks.clear();this.sessions.delete(session.backend_pid);releaseQueue()
    }}
  }
  close() { this.db.close() }
  async query(sql, values = [], session) {
    if (this.unavailable) throw new Error('synthetic store unavailable')
    if(sql==='SELECT pg_advisory_lock(hashtextextended($1, 0)), pg_backend_pid() AS backend_pid'
      || sql===fixtureSessionInspection || sql==='SELECT pg_advisory_unlock(hashtextextended($1, 0)) AS unlocked') {
      assert.equal(session?.active,true,'fixture session observation requires active owned client')
      assert.equal(values.length,1);assert.equal(typeof values[0],'string')
      const held=session.locks.get(values[0]) ?? 0
      if(sql===fixtureSessionInspection) return {rows:[{backend_pid:session.backend_pid,held:held>0}]}
      if(sql.startsWith('SELECT pg_advisory_lock(')) {
        session.locks.set(values[0],held+1);return {rows:[{backend_pid:session.backend_pid}]}
      }
      if(held>0) session.locks.set(values[0],held-1)
      return {rows:[{unlocked:held>0}]}
    }
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
  return { owner_subject:subject,owner_id:subject,task_id:'synthetic-task',privacy:'local',scope:'owner',attributedTo:'owner',
    source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(bytes)},events:[bytes] }
}
const input = {category:'fact',statement:'banana',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
const captureMetadata = extraction => ({profile:'prime-pilot-memory-capture/v1',category:extraction.category,
  valid_from:extraction.validFrom,observed_at:extraction.observedAt,
  confidence_percent:extraction.confidence*100,sensitivity:extraction.sensitivity})
const captureDraft = (h,extraction=input) => ({statement:extraction.statement,attributed_to:h.attributedTo,
  capture_metadata:captureMetadata(extraction),evidence_quote:parseOriginal(h.events.find(bytes=>sha256(bytes)===h.source.sha256)).text})
// Private test-only authority. Only explicitly registered toy operation digests can reach the SQL fixture.
// It is not exported by the package and does not verify production proofs; C owns that integration check.
let operationNumber=0
const permittedOperations=new Map(),preparedOperations=new Map(),dispatchedOperations=new Set()
const toyContracts={
  operationDigest:operation=>'sha256:'+sha256(Buffer.from('aukora-prime.operation.v1\0'+canonicalJSON(operation))),
  validateContract(kind,value) {assert.equal(value?.version,1);assert.equal(typeof value,'object');return value}
}
const toyAuthority={
  reserve({operation,approval_proof}) {
    const digest=toyContracts.operationDigest(operation)
    if(!permittedOperations.has(digest) || dispatchedOperations.has(digest) || approval_proof.operation_digest!==digest)
      return {ok:false,error_code:'UNAUTHORIZED'}
    const grant={version:1,grant_id:'toy-grant:'+operation.operation_id,operation_id:operation.operation_id,
      operation_digest:digest,owner_id:operation.owner_id,audience:operation.audience,
      authorization_epoch:operation.authorization_epoch,prepared_at:at,reservation_id:'toy-reservation:'+operation.nonce}
    preparedOperations.set(digest,grant);return {ok:true,status:'PREPARED',consumed_grant:grant}
  },
  claimDispatch({operation,consumed_grant,request_id,request_digest}) {
    assert.match(request_id,/^[0-9a-f-]{36}$/);assert.match(request_digest,/^sha256:[0-9a-f]{64}$/)
    const digest=toyContracts.operationDigest(operation)
    assert.deepEqual(consumed_grant,preparedOperations.get(digest));dispatchedOperations.add(digest)
    return {ok:true,status:'DISPATCHED',consumed_grant}
  },
  settleMemory({request_id,request_digest,receipt}) {
    return {ok:true,status:'COMPLETED',request_id,request_digest,receipt_digest:memoryReceiptDigest(receipt),idempotent:false,reconciliation_required:false}
  }
}
function toyAuthorization(subject,action,parameters,stateHeads={}) {
  assert.ok([owner,other].includes(subject))
  const operation={version:1,operation_id:'toy-operation:'+ ++operationNumber,task_id:'synthetic-task',owner_id:subject,
    agent_id:'synthetic-agent',audience:MEMORY_AUDIENCE,action_type:action,target_identity:memoryTarget(subject),
    canonical_parameters:parameters,data_scope:['synthetic'],expected_state_version:memoryStateVersion(stateHeads),
    provider_and_region:{provider:'local',region:'local'},maximum_cost:{currency:'USD',amount:'0'},
    expiry:'2099-10-01T11:03:00Z',nonce:'toy-nonce:'+operationNumber,policy_version:'synthetic-policy',authorization_epoch:0}
  const digest=toyContracts.operationDigest(operation);permittedOperations.set(digest,parameters.manifest_sha256)
  return {operation,approval_proof:{version:1,operation_id:operation.operation_id,operation_digest:digest,
    owner_id:subject,audience:operation.audience,authorization_epoch:0,expiry:operation.expiry,nonce:operation.nonce,
    material:{kind:'owner_key',synthetic:true}}}
}
async function toyImport(pool,snapshot,{mode='kira-import',expectedHeads}={}) {
  // Exact manifest allowlist is registered here, only for byte snapshots constructed by this focused fixture.
  const stateHeads=Object.fromEntries((await pool.query('SELECT * FROM prime_memory_heads WHERE owner_subject=$1',[snapshot.owner_subject])).rows.map(r=>[r.chain_domain,r.hash]))
  const boundHost={owner_subject:snapshot.owner_subject,owner_id:mode==='prime-restore'
    ? trustedFixtureAnchors.get(snapshot.owner_subject)?.owner_id ?? snapshot.owner_subject :snapshot.owner_subject,task_id:'synthetic-task'}
  return {mode,expectedHeads,...toyBoundOperation(boundHost,mode==='prime-restore'?'memory.restore':'memory.import',
    {manifest_sha256:snapshot.manifest_sha256,mode,heads:snapshot.heads,
      retained_heads:mode==='prime-restore' ? trustedFixtureAnchors.get(snapshot.owner_subject)?.heads : expectedHeads ?? null,
      ...(mode==='prime-restore'?{control_anchor_sha256:trustedFixtureAnchors.get(snapshot.owner_subject)?.control_sha256}:{})},stateHeads)}
}
const trustedFixtureAnchors=new Map()
const fixtureAnchorProvider=async h=>trustedFixtureAnchors.get(h.owner_subject)
async function retainFixtureAnchor(memory,h) {
  trustedFixtureAnchors.set(h.owner_subject,await memory.exportControlState(h))
}
const service=(pool,options={})=>createPostgresMemory({pool,authority:toyAuthority,contracts:toyContracts,restoreAnchorProvider:fixtureAnchorProvider,...options})
function toyBoundOperation(h,action,parameters,heads={}) {
  const options=toyAuthorization(h.owner_subject,action,parameters,heads)
  options.operation.owner_id=h.owner_id;options.approval_proof.owner_id=h.owner_id
  options.approval_proof.operation_digest=toyContracts.operationDigest(options.operation)
  permittedOperations.set(options.approval_proof.operation_digest,parameters.manifest_sha256 ?? parameters.capture_sha256)
  return options
}

async function fixtureCapture(memory,h,extraction,key) {
  const binding=await memory.prepareCaptureBinding(h,extraction,key)
  const options=toyBoundOperation(h,'memory.save',binding.canonical_parameters,binding.canonical_parameters.heads)
  return (await memory.captureAuthorizedRemembered(h,extraction,key,options)).record
}
async function fixtureForget(memory,h,id,at) {
  const binding=await memory.prepareRecordMutationBinding(h,id,{action:'memory.forget',at})
  return memory.forgetRecord(h,id,toyBoundOperation(h,'memory.forget',binding.canonical_parameters,binding.canonical_parameters.heads))
}

test('synthetic durable capture, honest ACKs, owner filters, restart, import and Prime-only cold restore',async () => {
  const dir = mkdtempSync(join(tmpdir(),'prime-memory-'))
  let pool = new FixturePool(join(dir,'storage.sqlite')),memory = service(pool)
  try {
    await memory.migrate()
    const captureHost = host()
    pool.failOutbox = true
    await assert.rejects(fixtureCapture(memory,captureHost,input,'rollback'),{code:'memory:authority-effect-outcome-unknown'})
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_chain').get().n,0)
    pool.failOutbox = false
    const saved = await fixtureCapture(memory,captureHost,input,'turn-1')
    assert.equal(saved.storage_status,'saved'); assert.equal(saved.index_status,'pending')
    const initial = await memory.status(captureHost,saved.record_id)
    assert.equal(initial.saved,true); assert.equal(initial.indexed,false); assert.equal(initial.searchable,false)
    assert.equal((await memory.recall(captureHost,{query:'banana'})).records.length,0)
    assert.equal((await memory.cite(captureHost,saved.record_id,'1')).verdict,'VERIFIED')
    assert.deepEqual(await fixtureCapture(memory,captureHost,input,'turn-1'),saved)
    await assert.rejects(fixtureCapture(memory,captureHost,{...input,statement:'changed'},'turn-1'),{code:'memory:idempotency-conflict'})
    await assert.rejects(fixtureCapture(memory,captureHost,{...input,attributedTo:'owner'},'spoof'),{code:'memory:extraction-fields-invalid'})
    await assert.rejects(fixtureCapture(memory,{...captureHost,offTheRecord:true},input,'off'),{code:'memory:capture-policy-blocked'})
    await assert.rejects(fixtureCapture(memory,host(owner,'This is off the record.'),input,'off-words'),{code:'memory:capture-owner-control'})
    await assert.rejects(fixtureCapture(memory,host(owner,'-----BEGIN PRIVATE KEY----- synthetic'),input,'secret'),{code:'memory:capture-secret-shape'})
    pool.failIndex = true
    assert.equal((await memory.drainOutbox(captureHost)).failed,1)
    assert.equal((await memory.status(captureHost,saved.record_id)).record.index_status,'failed')
    pool.failIndex = false; await memory.drainOutbox(captureHost)
    assert.equal((await memory.status(captureHost,saved.record_id)).searchable,true)
    assert.equal((await memory.recall(captureHost,{query:'banana'})).records[0].record.canonical_bytes,saved.canonical_bytes)
    await assert.rejects(memory.cite(host(other),saved.record_id),{code:'memory:record-missing'})
    assert.equal((await memory.recall(host(other),{query:'banana'})).records.length,0)
    await assert.rejects(memory.recall(captureHost,{query:'banana',permittedPrivacy:['private']}),{code:'memory:privacy-not-permitted'})
    const otherSaved = await fixtureCapture(memory,host(other),input,'other-1'); await memory.drainOutbox(host(other))
    assert.notEqual(otherSaved.record_id,saved.record_id)
    pool.close(); pool = new FixturePool(join(dir,'storage.sqlite')); memory = service(pool)
    assert.equal((await memory.cite(captureHost,saved.record_id)).verdict,'VERIFIED')
    assert.equal((await memory.recall(captureHost,{query:'banana'})).records.length,1)
    assert.equal((await fixtureCapture(memory,captureHost,input,'turn-1')).record_id,saved.record_id)
    const retarget = service(pool,{indexGeneration:'2'})
    assert.equal((await retarget.status(captureHost,saved.record_id)).indexed,false)
    await retarget.repairIndex(captureHost); await retarget.drainOutbox(captureHost)
    assert.equal((await retarget.status(captureHost,saved.record_id)).searchable,true)
    pool.db.prepare('DELETE FROM prime_memory_fts WHERE owner_subject=?').run(owner)
    const lost = await retarget.status(captureHost,saved.record_id)
    assert.equal(lost.indexed,true); assert.equal(lost.searchable,false)
    await retarget.repairIndex(captureHost); await retarget.drainOutbox(captureHost)
    await retainFixtureAnchor(memory,captureHost)
    const snapshot = await memory.exportSnapshot(captureHost)
    assert.equal(snapshot.owner_subject,owner)
    assert.equal(inspectSnapshot(snapshot,owner).records.length,1)
    const packageRoot = fileURLToPath(new URL('../',import.meta.url)),copied = join(dir,'empty-prime-memory')
    cpSync(packageRoot,copied,{recursive:true}); writeFileSync(join(dir,'snapshot.json'),JSON.stringify(snapshot)); writeFileSync(join(dir,'heads.json'),JSON.stringify(snapshot.heads))
    const cold = spawnSync(process.execPath,[join(copied,'bin/cold-verify.mjs'),join(dir,'snapshot.json'),owner,join(dir,'heads.json')],{cwd:dir,encoding:'utf8'})
    assert.equal(cold.status,0,cold.stderr); assert.equal(JSON.parse(cold.stdout).citations[0].verdict,'VERIFIED')
    assert.equal(JSON.parse(cold.stdout).independent_trust_anchor_supplied,true)
    assert.equal((await runMemoryCommand(['verify',join(dir,'snapshot.json'),owner,join(dir,'heads.json')])).snapshot_integrity,'VERIFIED')
    const cliExport = join(dir,'cli-export.json')
    assert.equal((await runMemoryCommand(['export',owner,cliExport],{pool})).snapshot_integrity,'UNANCHORED')
    const restoredPool = new FixturePool(join(dir,'restore.sqlite'))
    try {
      const restored = service(restoredPool); await restored.migrate()
      const noImportPermission = createPostgresMemory({pool:restoredPool})
      await assert.rejects(noImportPermission.importSnapshot(captureHost,snapshot,await toyImport(restoredPool,snapshot)),{code:'memory:authority-unavailable'})
      assert.equal((await restored.restoreSnapshot(captureHost,snapshot,await toyImport(restoredPool,snapshot,{mode:'prime-restore',expectedHeads:snapshot.heads}))).imported,1)
      assert.equal((await restored.restoreSnapshot(captureHost,snapshot,await toyImport(restoredPool,snapshot,{mode:'prime-restore'}))).already_imported,true)
      await assert.rejects(runMemoryCommand(['restore',join(dir,'snapshot.json'),owner,'--synthetic-fixture'],{pool:restoredPool}),{code:'memory:authority-unavailable'})
      const cliAuth=await toyImport(restoredPool,snapshot,{mode:'prime-restore',expectedHeads:snapshot.heads})
      const cliAuthFile=join(dir,'authorization.json')
      writeFileSync(join(dir,'heads.json'),JSON.stringify(snapshot.heads))
      writeFileSync(cliAuthFile,JSON.stringify({operation:cliAuth.operation,approval_proof:cliAuth.approval_proof}))
      assert.equal((await runMemoryCommand(['restore',join(dir,'snapshot.json'),owner,cliAuthFile,join(dir,'heads.json')],
        {pool:restoredPool,authority:toyAuthority,contracts:toyContracts,host:captureHost,restoreAnchorProvider:fixtureAnchorProvider})).already_imported,true)
      assert.equal((await restored.status(captureHost,saved.record_id)).record.canonical_bytes,saved.canonical_bytes)
      assert.equal((await restored.status(captureHost,saved.record_id)).indexed,false)
      await restored.drainOutbox(captureHost)
      assert.equal((await restored.recall(captureHost,{query:'banana'})).records[0].citation.verdict,'VERIFIED')
      const backup = await restored.exportSnapshot(captureHost)
      assert.ok(backup.files.some(f=>f.role==='opaque-original'));assert.equal(backup.files.some(f=>f.role==='original'),false)
      await fixtureForget(restored,captureHost,saved.record_id,at)
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

// The G5 runner supplies its own task-owned socket/cluster. Never connect to a discovered/system DB.
test('PostgreSQL acceptance on an explicitly supplied disposable database',{
  skip:!process.env.PRIME_MEMORY_DISPOSABLE_SOCKET_DIR ? 'UNPERFORMED: no disposable PostgreSQL runtime supplied' : false
},async () => {
  const dataDir=realpathSync(process.env.PRIME_MEMORY_DISPOSABLE_DATA_DIR)
  assert.match(dataDir,/^\/(?:private\/)?tmp\/prime-memory-pg\.[^/]+\/data$/)
  assert.equal(readFileSync(join(dataDir,'../.prime-memory-owned-synthetic'),'utf8'),'prime-memory-synthetic-v1\n')
  const config={host:process.env.PRIME_MEMORY_DISPOSABLE_SOCKET_DIR,port:55434,database:'postgres',user:userInfo().username}
  const {Pool} = await import('pg')
  const schema='prime_memory_synthetic_'+Date.now().toString(36),restoreSchema=schema+'_restore'
  let bootstrap=new Pool(config),pg,restoredPool
  try {
    await bootstrap.query('CREATE SCHEMA '+schema)
    pg=new Pool({...config,options:'-c search_path='+schema})
    let memory=service(pg); await memory.migrate()
    const saved=await fixtureCapture(memory,host(),input,'pg-turn-1')
    assert.equal((await memory.status(host(),saved.record_id)).indexed,false)
    await memory.drainOutbox(host())
    assert.equal((await memory.recall(host(),{query:'banana'})).records[0].record.canonical_bytes,saved.canonical_bytes)
    await pg.end(); pg=null;await bootstrap.end();bootstrap=null
    execFileSync(join(process.env.PRIME_MEMORY_POSTGRES_BINDIR,'pg_ctl'),['-D',dataDir,'-m','fast','-w','-t','30','restart'],{stdio:'pipe'})
    bootstrap=new Pool(config);pg=new Pool({...config,options:'-c search_path='+schema}); memory=service(pg)
    assert.equal((await memory.cite(host(),saved.record_id)).verdict,'VERIFIED')
    assert.equal((await fixtureCapture(memory,host(),input,'pg-turn-1')).record_id,saved.record_id)
    const second=await fixtureCapture(memory,host(owner,'Synthetic source for second banana only.'),{...input,statement:'second banana'},'pg-turn-2')
    await memory.drainOutbox(host());await fixtureForget(memory,host(),second.record_id,at)
    assert.equal((await memory.recall(host(),{query:'banana'})).records.length,1)
    await retainFixtureAnchor(memory,host())
    const snapshot=await memory.exportSnapshot(host())
    assert.equal(inspectSnapshot(snapshot,owner).records.length,1);assert.equal(inspectSnapshot(snapshot,owner).redactions.length,1)
    const standalone=join(dataDir,'../empty-prime-memory')
    cpSync(fileURLToPath(new URL('../',import.meta.url)),standalone,{recursive:true})
    const backupFile=join(dataDir,'../backup.json'),headsFile=join(dataDir,'../heads.json')
    writeFileSync(backupFile,JSON.stringify(snapshot));writeFileSync(headsFile,JSON.stringify(snapshot.heads))
    const cold=spawnSync(process.execPath,[join(standalone,'bin/cold-verify.mjs'),backupFile,owner,headsFile],{cwd:standalone,encoding:'utf8'})
    assert.equal(cold.status,0,cold.stderr)
    assert.equal(JSON.parse(cold.stdout).redacted_records,1)
    await bootstrap.query('CREATE SCHEMA '+restoreSchema)
    restoredPool=new Pool({...config,options:'-c search_path='+restoreSchema})
    const restored=service(restoredPool);await restored.migrate()
    assert.equal((await restored.restoreSnapshot(host(),snapshot,await toyImport(restoredPool,snapshot,{mode:'prime-restore',expectedHeads:snapshot.heads}))).imported,1)
    assert.equal((await restored.status(host(),saved.record_id)).record.canonical_bytes,saved.canonical_bytes)
    assert.equal((await restored.status(host(),saved.record_id)).indexed,false)
    await restored.drainOutbox(host())
    assert.equal((await restored.recall(host(),{query:'banana'})).records.length,1)
    assert.equal((await restored.cite(host(),saved.record_id)).verdict,'VERIFIED')
    await assert.rejects(restored.cite(host(),second.record_id),{code:'memory:record-tombstoned'})
    const retarget=service(restoredPool,{indexGeneration:'postgres-restart-2'})
    assert.equal((await retarget.status(host(),saved.record_id)).indexed,false)
    await retarget.repairIndex(host());await retarget.drainOutbox(host())
    assert.equal((await retarget.status(host(),saved.record_id)).searchable,true)
  } finally {
    if(pg) await pg.end()
    if(restoredPool) await restoredPool.end()
    if(bootstrap) {
      await bootstrap.query('DROP SCHEMA IF EXISTS '+restoreSchema+' CASCADE')
      await bootstrap.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE');await bootstrap.end()
    }
  }
})

test('preserved decimal v0, safe-integer v1, UNLINKED, pre-split chains and quarantine never mint new IDs',async () => {
  const dir = mkdtempSync(join(tmpdir(),'prime-memory-import-')),pool = new FixturePool(join(dir,'storage.sqlite'))
  try {
    const memory = service(pool); await memory.migrate()
    const sourceHost = host(),data = event('Synthetic owner likes banana.'),digest = sha256(data)
    const historicalStatement='Historical cafe\u0301 remains byte exact.'
    assert.notEqual(historicalStatement.normalize('NFC'),historicalStatement)
    const note = buildRememberedNote({...input,statement:historicalStatement,subject:owner,privacy:'local',attributedTo:'owner',source:{state:'UNLINKED',cited:true,sessionId:'missing-synthetic',citedTurn:0,because:'Synthetic event absent'},evidence:[{log:'missing-synthetic',turn:0,turnDigest:digest,quote:historicalStatement}]})
    const marker = sha256(Buffer.from(`${note.id}\0${sha256(Buffer.from(note.statement))}`))
    const stored = {...note,aura:{index:0,entryHash:marker}},body={op:'remember',id:note.id,entryHash:marker,sequence:1,at}
    const entry = {...body,prev:AURA_RECORD_DOMAIN,hash:auraEntryHash(AURA_RECORD_DOMAIN,body)}
    const bytes = Buffer.from(JSON.stringify(stored,null,2)+'\n')
    const snapshot = makeSnapshot(owner,[{path:'remembered.json',role:'record',record_id:note.id,revision:1,chain_domain:'legacy-presplit',chain_sequence:1,bytes},
      {path:'presplit.jsonl',role:'chain',chain_domain:'legacy-presplit',bytes:Buffer.from(JSON.stringify(entry)+'\n')}],{'legacy-presplit':entry.hash})
    await memory.importSnapshot(sourceHost,snapshot,await toyImport(pool,snapshot))
    const restored = await memory.status(sourceHost,note.id)
    assert.equal(restored.record.canonical_bytes,bytes.toString('utf8'))
    assert.equal(parseOriginal(Buffer.from(restored.record.canonical_bytes)).salt,note.salt)
    assert.equal(parseOriginal(Buffer.from(restored.record.canonical_bytes)).statement,historicalStatement)
    assert.equal(parseOriginal(Buffer.from(restored.record.canonical_bytes)).evidence[0].quote,historicalStatement)
    assert.equal((await memory.cite(sourceHost,note.id)).verdict,'MISSING')
    const invalid = {...stored,statement:'tampered'}
    const bad = makeSnapshot(owner,[{...snapshot.files.find(f=>f.role==='record'),path:'invalid.json',bytes:Buffer.from(JSON.stringify(invalid))},
      {path:'presplit.jsonl',role:'chain',chain_domain:'legacy-presplit',bytes:Buffer.from(JSON.stringify(entry)+'\n')}],{'legacy-presplit':entry.hash})
    assert.equal((await memory.importSnapshot(sourceHost,bad,await toyImport(pool,bad))).quarantined,1)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_originals').get().n,4)
    const candidate = {subject:owner,kind:'observation',source:[],content:{decimal:1.5},links:[],privacy:'local',createdAt:at}
    const v0 = stageKiraMemoryRecord(candidate).record
    const v0Bytes = Buffer.from(JSON.stringify(v0,null,2)+'\n')
    assert.equal(validateOriginal(v0Bytes,owner).id,v0.recordId)
    assert.equal(validateOriginal(v0Bytes,owner).canon,'aukora:canon-json:v0-ecmascript-number')
    assert.throws(()=>stageKiraMemoryRecord(candidate,{format:'v1'}))
    const v1 = stageKiraMemoryRecord({...candidate,content:{decimal:'1.5'}},{format:'v1'}).record
    assert.equal(validateOriginal(Buffer.from(JSON.stringify(v1)),owner).format,'v1')
    const approvedBody={verdict:'settled',operation:'memory.put',key:v0.recordId,sequence:1,contentSha256:kiraRecordContentSha256(v0)}
    const approvedEntry={...approvedBody,prev:AURA_RECORD_DOMAIN,hash:auraEntryHash(AURA_RECORD_DOMAIN,approvedBody)}
    const approved=makeSnapshot(owner,[...snapshot.files.map(f=>({...f,bytes:Buffer.from(f.bytes_base64,'base64')})),
      {path:'approved-v0.json',role:'record',record_id:v0.recordId,revision:1,chain_domain:'approved',chain_sequence:1,bytes:v0Bytes},
      {path:'approved.jsonl',role:'chain',chain_domain:'approved',bytes:Buffer.from(JSON.stringify(approvedEntry)+'\n')}],
      {'legacy-presplit':entry.hash,approved:approvedEntry.hash})
    await memory.importSnapshot(sourceHost,approved,await toyImport(pool,approved))
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
    const omitted=await toyImport(pool,readOnly)
    await assert.rejects(memory.importSnapshot(sourceHost,readOnly,omitted),{code:'memory:import-local-chain-omitted'})
    assert.equal(dispatchedOperations.has(omitted.approval_proof.operation_digest),false)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})

test('authorized save settlement/restart, omission mutations, redacted restore and explicit active-table purge',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-boundaries-'))
  let pool=new FixturePool(join(dir,'storage.sqlite')),memory=service(pool)
  const h={...host(),owner_id:'synthetic-owner-id-distinct-from-subject'}
  try {
    await memory.migrate()
    const binding=await memory.prepareCaptureBinding(h,input,'approved-turn')
    const options=toyAuthorization(owner,'memory.save',binding.canonical_parameters)
    options.operation.owner_id=h.owner_id
    options.operation.expected_state_version=binding.state_version
    options.approval_proof.owner_id=h.owner_id
    options.approval_proof.nonce='fresh-review-challenge'
    options.approval_proof.expiry='2098-01-01T00:00:00Z'
    options.approval_proof.operation_digest=toyContracts.operationDigest(options.operation)
    permittedOperations.set(options.approval_proof.operation_digest,binding.canonical_parameters.capture_sha256)
    assert.throws(()=>memory.authorityTargetObservation(options.operation),{code:'memory:target-observation-outside-lock'})
    assert.deepEqual(await memory.withAuthorityTargetObservation(h,options.operation,()=>memory.authorityTargetObservation(options.operation)),
      {target_identity:binding.target_identity,state_version:binding.state_version})
    let count=0
    const checkingAuthority={...toyAuthority,
      reserve(args) {assert.equal(memory.authorityTargetObservation(args.operation).state_version,binding.state_version);count++;return toyAuthority.reserve(args)},
      claimDispatch(args) {assert.equal(memory.authorityTargetObservation(args.operation).state_version,binding.state_version);return toyAuthority.claimDispatch(args)},
      settleMemory(args) {
        // Settlement may occur only after the effect and receipt are committed and readable on the store.
        assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_effects').get().n,1)
        return toyAuthority.settleMemory(args)
      }
    }
    memory=service(pool,{authority:checkingAuthority})
    const approved=await memory.captureAuthorizedRemembered(h,input,'approved-turn',options)
    assert.equal(approved.record.storage_status,'saved');assert.equal(approved.record.index_status,'pending')
    assert.equal(approved.authority_settlement,'completed');assert.equal(approved.reconciliation_required,false)
    assert.equal(count,1)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,1)
    assert.equal((await memory.captureAuthorizedRemembered(h,input,'approved-turn',options)).record.record_id,approved.record.record_id)
    assert.equal(count,1)
    await assert.rejects(memory.captureAuthorizedRemembered(h,{...input,statement:'injected'},'approved-turn',options),{code:'memory:capture-operation-mismatch'})
    await memory.drainOutbox(h)
    assert.equal((await memory.status(h,approved.record.record_id)).searchable,true)
    pool.close();pool=new FixturePool(join(dir,'storage.sqlite'));memory=service(pool)
    assert.equal((await memory.reconcileEffect(h,options.operation.operation_id)).authority_settlement,'completed')
    assert.equal((await memory.cite(h,approved.record.record_id)).verdict,'VERIFIED')
    await retainFixtureAnchor(memory,h)
    const before=await memory.exportSnapshot(h)
    const rec=before.files.find(f=>f.role==='record')
    const injected={...parseOriginal(Buffer.from(rec.bytes_base64,'base64')),instructions:'injected instruction'}
    assert.throws(()=>validateOriginal(Buffer.from(JSON.stringify(injected)),owner),{code:'memory:note-fields-invalid'})
    const remanifest=(snapshot,files)=>makeSnapshot(owner,files.map(f=>({...f,bytes:Buffer.from(f.bytes_base64,'base64')})),snapshot.heads,{redacted:snapshot.schema.endsWith('/v2')})
    const emptyRecords=remanifest(before,before.files.filter(f=>f.role!=='record'))
    assert.throws(()=>inspectSnapshot(emptyRecords,owner,{expectedHeads:before.heads}),{code:'memory:chain-record-omitted'})
    const omittedEvents=remanifest(before,before.files.filter(f=>f.role!=='event'))
    assert.throws(()=>inspectSnapshot(omittedEvents,owner,{quarantineInvalid:true}),{code:'memory:snapshot-evidence-omitted'})
    const noAuthority=createPostgresMemory({pool,allowSyntheticImport:true,authorizeImport:()=>true})
    await assert.rejects(noAuthority.importSnapshot(h,before),{code:'memory:authority-unavailable'})
    await assert.rejects(noAuthority.importSnapshot(h,before,{mode:'synthetic-fixture'}),{code:'memory:import-mode-invalid'})
    const snapshotFile=join(dir,'snapshot.json');writeFileSync(snapshotFile,JSON.stringify(before))
    assert.equal((await runMemoryCommand(['verify',snapshotFile,owner])).snapshot_integrity,'UNANCHORED')
    const cold=spawnSync(process.execPath,[fileURLToPath(new URL('../bin/cold-verify.mjs',import.meta.url)),snapshotFile,owner],{encoding:'utf8'})
    assert.equal(cold.status,0,cold.stderr);assert.equal(JSON.parse(cold.stdout).verdict,'UNANCHORED')
    const changedField=remanifest(before,before.files.map((f,i)=>i===0?{...f,untrusted_metadata:'injected'}:f))
    assert.throws(()=>inspectSnapshot(changedField,owner),{code:'memory:snapshot-file-fields-invalid'})

    // Seed a complete imported original so normal export has a plaintext source forest to exclude.
    const restorePool=new FixturePool(join(dir,'restore.sqlite'))
    try {
      const restore=service(restorePool);await restore.migrate()
      await restore.restoreSnapshot(h,before,await toyImport(restorePool,before,{mode:'prime-restore'}))
      await fixtureForget(restore,h,approved.record.record_id,at)
      await retainFixtureAnchor(restore,h)
      const redacted=await restore.exportSnapshot(h)
      assert.equal(inspectSnapshot(redacted,owner).redactions.length,1)
      assert.equal(redacted.files.some(f=>f.role==='record'||f.role==='event'||f.role==='original'),false)
      for(const file of redacted.files) assert.equal(Buffer.from(file.bytes_base64,'base64').toString().includes('banana'),false)
      const missingTombstone=remanifest(redacted,redacted.files.filter(f=>f.role!=='tombstone'))
      assert.throws(()=>inspectSnapshot(missingTombstone,owner,{expectedHeads:redacted.heads}),{code:'memory:redaction-invalid'})
      // Original v1 profile also rejects tombstone omission despite unchanged independently retained chain heads.
      const fullFiles=before.files.map(f=>({...f,bytes:Buffer.from(f.bytes_base64,'base64')}))
        .filter(f=>!['chain','opaque-original'].includes(f.role))
        .concat(redacted.files.filter(f=>f.role==='chain').map(f=>({...f,bytes:Buffer.from(f.bytes_base64,'base64')})))
      const v1Omission=makeSnapshot(owner,fullFiles,redacted.heads)
      assert.throws(()=>inspectSnapshot(v1Omission,owner,{expectedHeads:redacted.heads}),{code:'memory:chain-tombstone-omitted'})
      const redactedPool=new FixturePool(join(dir,'redacted.sqlite'))
      try {
        const r=service(redactedPool);await r.migrate()
        await r.restoreSnapshot(h,redacted,await toyImport(redactedPool,redacted,{mode:'prime-restore',expectedHeads:redacted.heads}))
        await r.drainOutbox(h);assert.equal((await r.recall(h,{query:'banana'})).records.length,0)
        await assert.rejects(r.cite(h,approved.record.record_id),{code:'memory:record-tombstoned'})
        assert.equal(inspectSnapshot(await r.exportSnapshot(h),owner,{expectedHeads:redacted.heads}).redactions.length,1)
      } finally {redactedPool.close()}
    } finally {restorePool.close()}

    await assert.rejects(memory.eraseOwnerPayloads(h,{at}),{code:'memory:validated-operation-required'})
    const otherRecord=await fixtureCapture(memory,host(other),input,'unrelated-owner')
    const backupBinding=await memory.prepareBackupBinding(h)
    const full=await memory.exportBackup(h,toyBoundOperation(h,'memory.backup',backupBinding.canonical_parameters,before.heads))
    assert.equal(full.schema,'aukora-prime-memory-snapshot/v1')
    const current=await memory.exportSnapshot(h)
    const eraseOptions={at,...toyBoundOperation(h,'memory.erase-owner',
      {profile:'prime-active-owner-payloads/v1',manifest_sha256:current.manifest_sha256,heads:current.heads,at},current.heads)}
    const purged=await memory.eraseOwnerPayloads(h,eraseOptions)
    assert.equal(purged.state,'active-table-payloads-purged');assert.equal(purged.physical_media_erasure,false)
    for(const table of ['records','events','originals','snapshots','fts'])
      assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+table+' WHERE owner_subject=?').get(owner).n,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_requests WHERE owner_subject=?').get(owner).n,1)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents WHERE owner_subject=?').get(owner).n,1)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_replay_fences WHERE owner_subject=?').get(owner).n,2)
    assert.equal((await memory.status(host(other),otherRecord.record_id)).saved,true)
    const purgedExport=await memory.exportSnapshot(h)
    assert.equal(inspectSnapshot(purgedExport,owner).redactions.length,1)
    assert.equal(purgedExport.files.some(f=>['record','event','original'].includes(f.role)),false)
    await assert.rejects(memory.cite(h,approved.record.record_id),{code:'memory:record-tombstoned'})
    const reimport=await toyImport(pool,full);reimport.operation.owner_id=h.owner_id;reimport.approval_proof.owner_id=h.owner_id
    reimport.approval_proof.operation_digest=toyContracts.operationDigest(reimport.operation)
    permittedOperations.set(reimport.approval_proof.operation_digest,full.manifest_sha256)
    await assert.rejects(memory.importSnapshot(h,full,reimport),{code:'memory:purged-payload-reimport'})

    // Dispatch plus SQL failure retains its durable intent and never automatically replays the grant.
    const failedHost={...host(owner,'Synthetic new evidence after purge.'),owner_id:h.owner_id}
    const failedBinding=await memory.prepareCaptureBinding(failedHost,input,'failed-approved-turn')
    const failureOptions=toyBoundOperation(h,'memory.save',failedBinding.canonical_parameters,purgedExport.heads)
    pool.failOutbox=true
    await assert.rejects(memory.captureAuthorizedRemembered(failedHost,input,'failed-approved-turn',failureOptions),error=>
      error.code==='memory:authority-effect-outcome-unknown' && error.reconciliation_required && typeof error.request_id==='string')
    pool.failOutbox=false
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records WHERE owner_subject=?').get(owner).n,0)
    pool.close();pool=new FixturePool(join(dir,'storage.sqlite'));memory=service(pool)
    const uncertain=await memory.reconcileEffect(h,failureOptions.operation.operation_id)
    assert.equal(uncertain.status,'unresolved');assert.equal(uncertain.automatic_retry,false)
    await assert.rejects(memory.captureAuthorizedRemembered(failedHost,input,'failed-approved-turn',failureOptions),{code:'memory:effect-unresolved-reconciliation-required'})
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})

test('literal capture review refuses coercion and invisible controls without changing the independent draft',()=>{
  const draft={statement:'Exact <banana>\n\t🙂',attributed_to:'owner',capture_metadata:captureMetadata(input),
    evidence_quote:'The exact selected event can differ from the note.'}
  const params={capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),heads:{remembered:'c'.repeat(64)},...draft}
  assert.deepEqual(validateCaptureReview(params,draft),draft)
  for(const unit of ['\u061c','\u200e','\u200f','\u202a','\u202e','\u2066','\u2069','\u200b','\u00ad','\u2028','\u2029',
    '\u034f','\u115f','\u1160','\u17b4','\u17b5','\u3164','\uffa0','\u2800','\r','\u0000','\u0085','\ud800']) {
    assert.throws(()=>validateCaptureDraft({...draft,statement:'banana'+unit}),/memory:capture-review-invalid/)
    assert.throws(()=>validateCaptureDraft({...draft,evidence_quote:'selected event'+unit}),/memory:capture-review-invalid/)
  }
  for(const text of ['\t\n ','cafe\u0301','\u200c','\u200d']) {
    assert.throws(()=>validateCaptureDraft({...draft,statement:text}),/memory:capture-review-invalid/)
    assert.throws(()=>validateCaptureDraft({...draft,evidence_quote:text}),/memory:capture-review-invalid/)
  }
  for(const text of ['می\u200cروم','क्\u200dष','café','Exact Cyrillic а and Latin a']) {
    assert.equal(validateCaptureDraft({...draft,statement:text}).statement,text)
    assert.equal(validateCaptureDraft({...draft,evidence_quote:text}).evidence_quote,text)
  }
  for(const key of ['capture_sha256','idempotency_key_sha256'])
    assert.throws(()=>validateCaptureReview({...params,[key]:[params[key]]},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,heads:{remembered:['c'.repeat(64)]}},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,statement:'different'},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,attributed_to:'agent'},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,evidence_quote:'different selected event'},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureDraft({statement:draft.statement,attributed_to:draft.attributed_to}),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({capture_sha256:params.capture_sha256,idempotency_key_sha256:params.idempotency_key_sha256,
    heads:params.heads,statement:params.statement,attributed_to:params.attributed_to},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,capture_metadata:{...draft.capture_metadata,valid_from:'2026-09-30'}},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,capture_metadata:{...draft.capture_metadata,confidence_percent:69}},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureDraft({...draft,capture_metadata:{...draft.capture_metadata,confidence_percent:'70'}}),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureDraft({...draft,capture_metadata:{...draft.capture_metadata,extra:true}}),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureDraft({...draft,statement:'x'.repeat(4097)}),/memory:capture-review-invalid/)
})

test('three concurrent identical approved saves coalesce exactly once; signed literal tampering refuses before reserve',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-concurrent-')),pool=new FixturePool(join(dir,'storage.sqlite'))
  let reserves=0,dispatches=0
  const authority={...toyAuthority,reserve(args){reserves++;return toyAuthority.reserve(args)},claimDispatch(args){dispatches++;return toyAuthority.claimDispatch(args)}}
  try {
    const memory=service(pool,{authority});await memory.migrate()
    assert.equal(memory.captureRemembered,undefined);assert.equal(memory.tombstoneRecord,undefined)
    const h=host(),binding=await memory.prepareCaptureBinding(h,input,'concurrent-approved')
    assert.deepEqual(Object.keys(binding).sort(),['canonical_parameters','memory_capture','state_version','target_identity'])
    assert.deepEqual(binding.memory_capture,captureDraft(h))
    assert.notEqual(binding.memory_capture.evidence_quote,binding.memory_capture.statement)
    for(const changed of [{statement:'forged literal'},{attributed_to:'agent'},
      {evidence_quote:'forged selected source quote'},
      {capture_metadata:{...binding.memory_capture.capture_metadata,profile:'forged-profile'}},
      {capture_metadata:{...binding.memory_capture.capture_metadata,category:'preference'}},
      {capture_metadata:{...binding.memory_capture.capture_metadata,valid_from:'2026-09-30'}},
      {capture_metadata:{...binding.memory_capture.capture_metadata,observed_at:'2026-10-01T11:02:00Z'}},
      {capture_metadata:{...binding.memory_capture.capture_metadata,confidence_percent:69}},
      {capture_metadata:{...binding.memory_capture.capture_metadata,sensitivity:'private'}}]) {
      const rejected=toyBoundOperation(h,'memory.save',{...binding.canonical_parameters,...changed})
      await assert.rejects(memory.captureAuthorizedRemembered(h,input,'concurrent-approved',rejected),{code:'memory:capture-review-invalid'})
      assert.equal(reserves,0)
      assert.equal(dispatches,0)
      assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,0)
    }
    const options=toyBoundOperation(h,'memory.save',binding.canonical_parameters)
    const saved=await Promise.all(Array.from({length:3},()=>memory.captureAuthorizedRemembered(h,input,'concurrent-approved',options)))
    assert.equal(new Set(saved.map(r=>r.receipt.request_id)).size,1)
    assert.equal(new Set(saved.map(r=>r.record.record_id)).size,1)
    assert.equal(reserves,1);assert.equal(dispatches,1)
    const stored=parseOriginal(Buffer.from(saved[0].record.canonical_bytes))
    assert.equal(stored.statement,binding.memory_capture.statement)
    assert.equal(stored.attributedTo,binding.memory_capture.attributed_to)
    assert.equal(stored.evidence[0].quote,binding.memory_capture.evidence_quote)
    assert.deepEqual(captureMetadata(stored),binding.memory_capture.capture_metadata)
    for(const table of ['records','requests','outbox','intents','effects']) assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+table).get().n,1)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})

test('unsafe or non-NFC new statement and selected quote refuse before SQL or authority consumption',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-new-text-policy-')),pool=new FixturePool(join(dir,'storage.sqlite'))
  let reserves=0,dispatches=0,queries=0
  const authority={...toyAuthority,reserve(args){reserves++;return toyAuthority.reserve(args)},claimDispatch(args){dispatches++;return toyAuthority.claimDispatch(args)}}
  try {
    const memory=service(pool,{authority});await memory.migrate()
    const h=host(),key='new-text-approved',binding=await memory.prepareCaptureBinding(h,input,key)
    const options=toyBoundOperation(h,'memory.save',binding.canonical_parameters)
    const query=pool.query.bind(pool);pool.query=(...args)=>{queries++;return query(...args)}
    for(const literal of ['cafe\u0301','unsafe\u200btext','unsafe\u2028text','unsafe\u2029text','unsafe\u034ftext']) {
      await assert.rejects(memory.prepareCaptureBinding(h,{...input,statement:literal},'unsafe-draft'),{code:'memory:pilot-capture-profile-refused'})
      await assert.rejects(memory.prepareCaptureBinding(host(owner,literal),input,'unsafe-quote'),{code:'memory:capture-review-invalid'})
      await assert.rejects(memory.captureAuthorizedRemembered(h,{...input,statement:literal},key,options),{code:'memory:pilot-capture-profile-refused'})
      await assert.rejects(memory.captureAuthorizedRemembered(host(owner,literal),input,key,options),{code:'memory:capture-review-invalid'})
    }
    assert.equal(queries,0);assert.equal(reserves,0);assert.equal(dispatches,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})

test('approved logical forget forbids new or replayed full backups; exact per-record purge retains unrelated memory',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-record-purge-')),pool=new FixturePool(join(dir,'storage.sqlite'))
  try {
    const memory=service(pool);await memory.migrate();const h=host()
    const selected=await fixtureCapture(memory,h,input,'selected')
    const retained=await fixtureCapture(memory,host(owner,'Independent synthetic second source.'),{...input,statement:'retained apple'},'retained')
    const backupBinding=await memory.prepareBackupBinding(h)
    const backupOptions=toyBoundOperation(h,'memory.backup',backupBinding.canonical_parameters,backupBinding.canonical_parameters.heads)
    await memory.exportBackup(h,backupOptions)
    await assert.rejects(memory.forgetRecord(h,selected.record_id),{code:'memory:validated-operation-required'})
    await fixtureForget(memory,h,selected.record_id,at)
    await assert.rejects(memory.prepareBackupBinding(h),{code:'memory:full-backup-forgotten-payload-forbidden'})
    await assert.rejects(memory.reconcileEffect(h,backupOptions.operation.operation_id),{code:'memory:full-backup-forgotten-payload-forbidden'})
    const binding=await memory.prepareRecordMutationBinding(h,selected.record_id,{action:'memory.purge',at})
    assert.equal(binding.canonical_parameters.collateral_scope.discard_owner_full_backup_effects,true)
    assert.equal(binding.canonical_parameters.collateral_scope.full_backup_effect_count,1)
    const options=toyBoundOperation(h,'memory.purge',binding.canonical_parameters,binding.canonical_parameters.heads)
    const purged=await memory.purgeRecordPayload(h,selected.record_id,options)
    assert.equal(purged.state,'active-record-payloads-purged');assert.equal(purged.physical_media_erasure,false)
    assert.equal(purged.authority_approval_history_erased,false)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records WHERE record_id=?').get(selected.record_id).n,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_events WHERE sha256=?').get(h.source.sha256).n,0)
    assert.equal((await memory.cite(h,retained.record_id)).verdict,'VERIFIED')
    const snapshot=await memory.exportSnapshot(h)
    assert.equal(inspectSnapshot(snapshot,owner).records.length,1)
    assert.equal(inspectSnapshot(snapshot,owner).redactions.length,1)
    await assert.rejects(memory.prepareCaptureBinding(h,input,'revive-purged-source'),{code:'memory:purged-source-recapture'})
    const decoded=snapshot.files.map(f=>({...f,bytes:Buffer.from(f.bytes_base64,'base64')}))
    const old=parseOriginal(Buffer.from(selected.canonical_bytes)),note=buildRememberedNote({...input,statement:'revived quote',
      subject:owner,scope:'owner',privacy:'local',attributedTo:'owner',source:old.source,evidence:old.evidence,origin:old.origin})
    const chain=decoded.find(f=>f.role==='chain'),entries=chain.bytes.toString().trimEnd().split('\n').map(JSON.parse)
    const marker=sha256(Buffer.from(note.id+'\0'+sha256(Buffer.from(note.statement))))
    const body={op:'remember',id:note.id,at,tier:'remembered',by:'prime.capture/v1',sequence:entries.length+1,
      contentHash:sha256(Buffer.from(note.statement)),entryHash:marker,bodyAtCapture:null}
    const entry={...body,prev:entries.at(-1).hash,hash:auraEntryHash(entries.at(-1).hash,body)}
    const revivedFiles=decoded.map(f=>f===chain ? {...f,bytes:Buffer.concat([chain.bytes,Buffer.from(canonicalJSON(entry)+'\n')])} : f)
    revivedFiles.push({path:'revived.json',role:'record',record_id:note.id,revision:1,chain_domain:'remembered',chain_sequence:entry.sequence,
      bytes:Buffer.from(JSON.stringify({...note,contentHash:body.contentHash,aura:{index:entry.sequence-1,entryHash:marker},bodyAtCapture:null})+'\n')})
    const revived=makeSnapshot(owner,revivedFiles,{remembered:entry.hash},{redacted:true})
    assert.equal(inspectSnapshot(revived,owner).records.find(r=>r.meta.id===note.id).citation.verdict,'MISSING')
    const revivalOptions=await toyImport(pool,revived)
    await assert.rejects(memory.importSnapshot(h,revived,revivalOptions),{code:'memory:purged-source-reference-reimport'})
    assert.equal(preparedOperations.has(revivalOptions.approval_proof.operation_digest),false)
    const quarantined=makeSnapshot(owner,[...decoded,{path:'invalid-payload.json',role:'record',record_id:retained.record_id,
      revision:2,chain_domain:'remembered',chain_sequence:2,bytes:Buffer.from(JSON.stringify({old_plaintext:'banana'}))}],snapshot.heads,{redacted:true})
    assert.equal(inspectSnapshot(quarantined,owner,{quarantineInvalid:true}).quarantine.length,1)
    const quarantineOptions=await toyImport(pool,quarantined)
    await assert.rejects(memory.importSnapshot(h,quarantined,quarantineOptions),{code:'memory:purged-quarantine-reimport'})
    assert.equal(preparedOperations.has(quarantineOptions.approval_proof.operation_digest),false)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})

test('purge refuses shared evidence or unresolved payload intents before reserving a grant',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-purge-preflight-')),pool=new FixturePool(join(dir,'storage.sqlite'))
  try {
    const memory=service(pool);await memory.migrate();const h=host()
    const one=await fixtureCapture(memory,h,input,'shared-one')
    await fixtureCapture(memory,h,{...input,statement:'same event second statement'},'shared-two')
    let binding=await memory.prepareRecordMutationBinding(h,one.record_id,{action:'memory.purge',at})
    let options=toyBoundOperation(h,'memory.purge',binding.canonical_parameters,binding.canonical_parameters.heads)
    await assert.rejects(memory.purgeRecordPayload(h,one.record_id,options),{code:'memory:purge-shared-evidence-closure'})
    assert.equal(preparedOperations.has(options.approval_proof.operation_digest),false)
    const independent=await fixtureCapture(memory,host(owner,'Independent unique source for purge.'),{...input,statement:'unique'},'unique')
    const failedHost=host(owner,'Uncertain synthetic pending source.')
    const failedBinding=await memory.prepareCaptureBinding(failedHost,input,'uncertain')
    const failedOptions=toyBoundOperation(h,'memory.save',failedBinding.canonical_parameters,failedBinding.canonical_parameters.heads)
    pool.failOutbox=true
    await assert.rejects(memory.captureAuthorizedRemembered(failedHost,input,'uncertain',failedOptions),{code:'memory:authority-effect-outcome-unknown'})
    pool.failOutbox=false
    binding=await memory.prepareRecordMutationBinding(h,independent.record_id,{action:'memory.purge',at})
    options=toyBoundOperation(h,'memory.purge',binding.canonical_parameters,binding.canonical_parameters.heads)
    await assert.rejects(memory.purgeRecordPayload(h,independent.record_id,options),{code:'memory:purge-unresolved-payload-intent'})
    assert.equal(preparedOperations.has(options.approval_proof.operation_digest),false)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})

test('restore uses independent current anchors and preflights local forks before consumption',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-restore-preflight-')),pool=new FixturePool(join(dir,'storage.sqlite'))
  const emptyPool=new FixturePool(join(dir,'empty.sqlite'))
  try {
    const memory=service(pool);await memory.migrate();const h=host(),saved=await fixtureCapture(memory,h,input,'anchor-note')
    const before=await memory.exportSnapshot(h)
    const noAnchor=service(emptyPool,{restoreAnchorProvider:undefined});await noAnchor.migrate()
    await retainFixtureAnchor(memory,h)
    const selfAnchored=await toyImport(emptyPool,before,{mode:'prime-restore',expectedHeads:before.heads})
    await assert.rejects(noAnchor.restoreSnapshot(h,before,selfAnchored),{code:'memory:trusted-restore-anchor-unavailable'})
    await assert.rejects(noAnchor.restoreSnapshot(h,before,{...selfAnchored,mode:'kira-import'}),{code:'memory:restore-mode-invalid'})
    assert.equal(preparedOperations.has(selfAnchored.approval_proof.operation_digest),false)
    await fixtureForget(memory,h,saved.record_id,at)
    await retainFixtureAnchor(memory,h)
    const current=await memory.exportSnapshot(h)
    const stale=await toyImport(emptyPool,before,{mode:'prime-restore',expectedHeads:before.heads})
    await assert.rejects(service(emptyPool).restoreSnapshot(h,before,stale),{code:'memory:restore-anchor-mismatch'})
    assert.equal(preparedOperations.has(stale.approval_proof.operation_digest),false)
    const files=current.files.map(f=>({...f,bytes:Buffer.from(f.bytes_base64,'base64')}))
    const chain=files.find(f=>f.role==='chain'),entries=chain.bytes.toString().trimEnd().split('\n').map(JSON.parse)
    const body={...entries[0],at:'2026-10-01T11:04:00Z'};delete body.hash;delete body.prev
    entries[0]={...body,prev:AURA_RECORD_DOMAIN,hash:auraEntryHash(AURA_RECORD_DOMAIN,body)}
    const forget={...entries[1]};delete forget.hash;delete forget.prev
    entries[1]={...forget,prev:entries[0].hash,hash:auraEntryHash(entries[0].hash,forget)}
    chain.bytes=Buffer.from(entries.map(e=>canonicalJSON(e)+'\n').join(''))
    const fork=makeSnapshot(owner,files,{remembered:entries[1].hash},{redacted:true})
    const forkOptions=await toyImport(pool,fork)
    await assert.rejects(memory.importSnapshot(h,fork,forkOptions),{code:'memory:import-chain-fork'})
    assert.equal(preparedOperations.has(forkOptions.approval_proof.operation_digest),false)
  } finally {pool.close();emptyPool.close();rmSync(dir,{recursive:true,force:true})}
})

test('cold restore retains owner-bound idempotency, committed receipts and unresolved intents without dispatch retry',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-control-restore-'))
  const sourcePool=new FixturePool(join(dir,'source.sqlite'))
  let targetPool=new FixturePool(join(dir,'target.sqlite'))
  try {
    const memory=service(sourcePool);await memory.migrate()
    const h={...host(),owner_id:'distinct-control-owner'}
    const binding=await memory.prepareCaptureBinding(h,input,'retained-key')
    const saveOptions=toyBoundOperation(h,'memory.save',binding.canonical_parameters,binding.canonical_parameters.heads)
    const saved=await memory.captureAuthorizedRemembered(h,input,'retained-key',saveOptions)
    const uncertainHost={...host(owner,'Synthetic unresolved event.'),owner_id:h.owner_id}
    const uncertainBinding=await memory.prepareCaptureBinding(uncertainHost,input,'unresolved-key')
    const uncertainOptions=toyBoundOperation(uncertainHost,'memory.save',uncertainBinding.canonical_parameters,uncertainBinding.canonical_parameters.heads)
    sourcePool.failOutbox=true
    await assert.rejects(memory.captureAuthorizedRemembered(uncertainHost,input,'unresolved-key',uncertainOptions),
      {code:'memory:authority-effect-outcome-unknown'})
    sourcePool.failOutbox=false
    await retainFixtureAnchor(memory,h)
    const independentlyRetained=trustedFixtureAnchors.get(owner),snapshot=await memory.exportSnapshot(h)
    assert.equal(independentlyRetained.tables.requests.length,1)
    assert.equal(independentlyRetained.tables.intents.length,2)
    assert.equal(independentlyRetained.tables.effects.length,1)
    let restored=service(targetPool);await restored.migrate()
    const headsOnly=service(targetPool,{restoreAnchorProvider:async()=>({owner_subject:owner,heads:snapshot.heads})})
    const restoration=await toyImport(targetPool,snapshot,{mode:'prime-restore'})
    await assert.rejects(headsOnly.restoreSnapshot(h,snapshot,restoration),{code:'memory:trusted-control-anchor-required'})
    const wrongOwner=service(targetPool,{restoreAnchorProvider:async()=>({...independentlyRetained,owner_id:'different-owner'})})
    await assert.rejects(wrongOwner.restoreSnapshot(h,snapshot,restoration),{code:'memory:control-state-owner-schema'})
    const proposed=await restored.prepareRestoreBinding(h,snapshot)
    assert.equal(proposed.canonical_parameters.control_anchor_sha256,independentlyRetained.control_sha256)
    const changed=toyBoundOperation(h,'memory.restore',{...proposed.canonical_parameters,control_anchor_sha256:'0'.repeat(64)})
    await assert.rejects(restored.restoreSnapshot(h,snapshot,changed),{code:'memory:operation-binding-mismatch'})
    assert.equal(preparedOperations.has(changed.approval_proof.operation_digest),false)
    const result=await restored.restoreSnapshot(h,snapshot,restoration)
    assert.equal(result.control_state_restored,true)
    assert.equal(result.control_anchor_sha256,independentlyRetained.control_sha256)
    assert.equal(targetPool.db.prepare('SELECT count(*) AS n FROM prime_memory_requests').get().n,1)
    for(const table of ['intents','effects']) {
      const original=sourcePool.db.prepare('SELECT * FROM prime_memory_'+table+' ORDER BY operation_id').all()
      for(const row of original) {
        const retained=targetPool.db.prepare('SELECT * FROM prime_memory_'+table+' WHERE operation_id=?').get(row.operation_id)
        assert.deepEqual(retained,row)
      }
    }
    targetPool.close();targetPool=new FixturePool(join(dir,'target.sqlite'));restored=service(targetPool)
    const uncertain=await restored.reconcileEffect(uncertainHost,uncertainOptions.operation.operation_id)
    assert.equal(uncertain.status,'unresolved');assert.equal(uncertain.automatic_retry,false)
    assert.equal(uncertain.request_id,sourcePool.db.prepare('SELECT request_id FROM prime_memory_intents WHERE operation_id=?').get(uncertainOptions.operation.operation_id).request_id)
    const before=preparedOperations.size
    await assert.rejects(restored.captureAuthorizedRemembered(uncertainHost,input,'unresolved-key',uncertainOptions),
      {code:'memory:effect-unresolved-reconciliation-required'})
    assert.equal(preparedOperations.size,before)
    await assert.rejects(restored.prepareCaptureBinding(uncertainHost,input,'unresolved-key'),
      {code:'memory:unresolved-idempotency-reconciliation-required'})
    const attemptedNewGrant=toyBoundOperation(uncertainHost,'memory.save',uncertainBinding.canonical_parameters,uncertainBinding.canonical_parameters.heads)
    await assert.rejects(restored.captureAuthorizedRemembered(uncertainHost,input,'unresolved-key',attemptedNewGrant),
      {code:'memory:unresolved-idempotency-reconciliation-required'})
    assert.equal(preparedOperations.size,before)
    assert.equal((await restored.captureAuthorizedRemembered(h,input,'retained-key',saveOptions)).record.canonical_bytes,saved.record.canonical_bytes)
    assert.equal(preparedOperations.size,before)
    assert.equal((await restored.prepareCaptureBinding(h,input,'retained-key')).canonical_parameters.capture_sha256,binding.canonical_parameters.capture_sha256)
    await assert.rejects(restored.prepareCaptureBinding(h,{...input,statement:'changed'},'retained-key'),{code:'memory:idempotency-conflict'})
  } finally {sourcePool.close();targetPool.close();rmSync(dir,{recursive:true,force:true})}
})

async function atomicRetentionFixture(t) {
  // Ordinary SQLite + same actual UID fixture; mock identity and Mac-stripped setgid only.
  const dir=mkdtempSync(join(realpathSync('/tmp'),'prime-memory-atomic-retention-'))
  const directory=mkdtempSync(join(dir,'independent-control-'));chmodSync(directory,0o2750)
  const actualUid=process.getuid(),readerUid=actualUid+100000,gid=statSync(directory).gid
  const uid=t.mock.method(process,'getuid',()=>actualUid),euid=t.mock.method(process,'geteuid',()=>actualUid)
  t.mock.method(process,'getgroups',()=>[gid])
  const role=value=>{uid.mock.mockImplementation(()=>value);euid.mock.mockImplementation(()=>value)}
  if(process.platform==='darwin' && (statSync(directory).mode & 0o2000)===0) {
    const setgid=stat=>Object.assign(Object.create(Object.getPrototypeOf(stat)),stat,
      {mode:typeof stat.mode==='bigint'?stat.mode|0o2000n:stat.mode|0o2000})
    const lstat=retentionFiles.lstat,open=retentionFiles.open
    t.mock.method(retentionFiles,'lstat',async(filename,...args)=>{
      const stat=await lstat(filename,...args);return filename===directory && stat.isDirectory()?setgid(stat):stat
    })
    t.mock.method(retentionFiles,'open',async(filename,...args)=>{
      const handle=await open(filename,...args)
      if(filename===directory) {const stat=handle.stat.bind(handle)
        t.mock.method(handle,'stat',async(...statArgs)=>setgid(await stat(...statArgs)))}
      return handle
    })
  }
  const h={...host(),owner_id:'distinct-atomic-retention-owner',authorization_epoch:0}
  const retainedHost={owner_id:h.owner_id,owner_subject:h.owner_subject,authorization_epoch:0}
  const config={directory,publisher_uid:actualUid,reader_uid:readerUid,retention_gid:gid,contracts:toyContracts}
  let publisher=createFileControlRetentionPublisher(config),pool=new FixturePool(join(dir,'source.sqlite')),memory,activePool=pool
  const unconfigured=service(pool);await unconfigured.migrate()
  await publisher.publish({host:retainedHost,control_state:await unconfigured.exportControlState(h),expected_checkpoint_sha256:null})
  role(readerUid)
  const reader=createFileControlRetentionReader(config),events=[],fault={mode:null}
  const privatePublisher=Object.fromEntries(['beginMutation','retainPrepared','publishMutation'].map(method=>[method,async args=>{
    if(fault.mode==='truthy-'+method) return true
    const previous=process.getuid();role(actualUid)
    try {
      if(method==='publishMutation' && fault.mode==='publication-before') throw new Error('synthetic publication transport lost')
      const actual=await publisher[method](args);events.push(method)
      if(method==='retainPrepared' && fault.mode==='prepared-reply') throw new Error('synthetic prepared reply lost')
      if(method==='publishMutation' && fault.mode==='publication-reply') throw new Error('synthetic final reply lost')
      return actual
    } finally {role(previous)}
  }]))
  const calls={reserve:0,dispatch:0,settle:0,unknown:0},permitSessions=new Map()
  async function assertPermit(phase,args,permit) {
    const fields=['version','kind','phase','owner_id','owner_subject','authorization_epoch','operation_id','operation_digest',
      'request_id','request_digest','owner_session','predecessor_checkpoint_sha256','checkpoint_sha256','control_sha256',
      'marker_sha256','grant_digest','receipt_digest','result_digest']
    assert.deepEqual(Object.keys(permit).sort(),fields.sort());assert.equal(Object.isFrozen(permit),true)
    assert.equal(permit.version,1);assert.equal(permit.kind,'prime-retained-memory-permit/v1');assert.equal(permit.phase,phase)
    for(const key of Object.keys(retainedHost)) assert.equal(permit[key],retainedHost[key])
    assert.equal(permit.operation_id,args.operation.operation_id)
    assert.equal(permit.operation_digest,toyContracts.operationDigest(args.operation))
    assert.match(permit.request_id,/^[0-9a-f-]{36}$/);assert.match(permit.request_digest,/^sha256:[0-9a-f]{64}$/)
    const session=permit.owner_session
    assert.deepEqual(Object.keys(session).sort(),['kind',...Object.keys(retainedHost),'session_id','backend_pid','lock_key_sha256'].sort())
    assert.equal(Object.isFrozen(session),true);assert.equal(session.kind,'postgres-owner-session/v1')
    for(const key of Object.keys(retainedHost)) assert.equal(session[key],retainedHost[key])
    assert.match(session.session_id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    assert.equal(session.lock_key_sha256,sha256(Buffer.from('aukora-prime.memory-owner-lock.v1\0'+retainedHost.owner_subject)))
    const heldSession=activePool.sessions.get(session.backend_pid)
    assert.equal(heldSession?.active,true);assert.equal(heldSession.locks.get(retainedHost.owner_subject),1)
    const prior=permitSessions.get(args.operation.operation_id)
    if(prior) {
      assert.deepEqual(session,prior.owner_session)
      assert.equal(permit.request_id,prior.request_id);assert.equal(permit.request_digest,prior.request_digest)
      assert.equal(permit.predecessor_checkpoint_sha256,prior.predecessor_checkpoint_sha256)
    }
    if(phase==='prepare') {
      assert.equal(prior,undefined);permitSessions.set(args.operation.operation_id,permit)
      assert.equal(permit.grant_digest,null);assert.equal(permit.receipt_digest,null);assert.equal(permit.result_digest,null)
    } else {
      assert.equal(permit.request_id,args.request_id);assert.equal(permit.request_digest,args.request_digest)
      assert.equal(permit.grant_digest,'sha256:'+sha256(Buffer.from('aukora-prime.consumed-grant.v1\0'+canonicalJSON(args.consumed_grant))))
    }
    if(phase==='settle') {
      const current=await reader.readCurrent(retainedHost)
      assert.equal(permit.checkpoint_sha256,current.checkpoint_sha256)
      assert.equal(permit.predecessor_checkpoint_sha256,current.previous_checkpoint_sha256)
      assert.equal(permit.control_sha256,current.control_state.control_sha256)
      assert.equal(permit.marker_sha256,null)
      assert.equal(permit.receipt_digest,memoryReceiptDigest(args.receipt))
      assert.equal(permit.result_digest,memoryResultDigest(args.receipt.result))
      permitSessions.delete(args.operation.operation_id)
    } else {
      const observed=await reader.inspectPending(retainedHost),checkpoint=phase==='prepare'?observed.predecessor:observed.prepared
      assert.ok(checkpoint)
      assert.equal(permit.checkpoint_sha256,checkpoint.checkpoint_sha256)
      assert.equal(permit.predecessor_checkpoint_sha256,observed.predecessor.checkpoint_sha256)
      assert.equal(permit.control_sha256,checkpoint.control_state.control_sha256)
      assert.equal(permit.marker_sha256,sha256(Buffer.from('aukora-prime.memory-retention-marker.v2\0'+canonicalJSON(observed.marker))))
      assert.equal(permit.receipt_digest,null);assert.equal(permit.result_digest,null)
    }
  }
  const authority={...toyAuthority,async reserve(args) {
    calls.reserve++;events.push('reserve')
    const observed=await reader.inspectPending(retainedHost)
    assert.equal(observed.marker.operation_id,args.operation.operation_id);assert.equal(observed.prepared,null)
    assert.equal(activePool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents WHERE operation_id=?').get(args.operation.operation_id).n,0)
    const actual=toyAuthority.reserve(args)
    if(fault.mode==='reserve-reply') throw new Error('synthetic reserve reply lost')
    return actual
  },async claimDispatch(args) {
    calls.dispatch++;events.push('dispatch')
    const observed=await reader.inspectPending(retainedHost)
    assert.ok(observed.prepared);assert.equal(observed.current.checkpoint_sha256,observed.predecessor.checkpoint_sha256)
    assert.equal(observed.prepared.control_state.tables.intents.some(row=>row.operation_id===args.operation.operation_id),true)
    const actual=toyAuthority.claimDispatch(args)
    if(fault.mode==='dispatch-reply') throw new Error('synthetic dispatch reply lost')
    return actual
  },async settleMemory(args) {
    calls.settle++;events.push('settle')
    const current=await reader.readCurrent(retainedHost)
    assert.equal(current.control_state.tables.effects.some(row=>row.operation_id===args.operation.operation_id),true)
    return toyAuthority.settleMemory(args)
  },markOutcomeUnknown(args) {calls.unknown++;assert.equal(dispatchedOperations.has(toyContracts.operationDigest(args.operation)),true)
    return {ok:true,status:'OUTCOME_UNKNOWN',reconciliation_required:true}},
    async reserveRetained(args) {
      await assertPermit('prepare',args,await memory.retainedMemoryParticipant.prepare({operation:args.operation}))
      return authority.reserve(args)
    },async claimDispatchRetained(args) {
      await assertPermit('dispatch',args,await memory.retainedMemoryParticipant.dispatch(args))
      return authority.claimDispatch(args)
    },async settleMemoryRetained(args) {
      await assertPermit('settle',args,await memory.retainedMemoryParticipant.settle(args))
      return authority.settleMemory(args)
    }}
  const makeMemory=(selectedPool,{omitRetainedMethod}={})=>{
    activePool=selectedPool
    const selectedAuthority=omitRetainedMethod?{...authority,[omitRetainedMethod]:undefined}:authority
    memory=createPostgresMemory({pool:selectedPool,authority:selectedAuthority,contracts:toyContracts,
      controlRetentionCoordinator:createControlRetentionCoordinator({reader,publisher:privatePublisher,contracts:toyContracts})})
    return memory
  }
  makeMemory(pool)
  t.after(()=>{role(actualUid);pool.close();rmSync(dir,{recursive:true,force:true})})
  return {h,retainedHost,reader,events,fault,calls,makeMemory,get pool(){return pool},
    reopen(){pool.close();pool=new FixturePool(join(dir,'source.sqlite'));permitSessions.clear();return makeMemory(pool)},
    freshPublisher(){const previous=process.getuid();role(actualUid);publisher=createFileControlRetentionPublisher(config);role(previous)},
    dir,privatePublisher,get memory(){return memory}}
}

test('atomic retained participant orders reservation, dispatch and settlement; cold read works while restore is disabled',async t=>{
  const f=await atomicRetentionFixture(t),binding=await f.memory.prepareCaptureBinding(f.h,input,'atomic-key')
  const options=toyBoundOperation(f.h,'memory.save',binding.canonical_parameters)
  const [saved,coalesced]=await Promise.all([
    f.memory.captureAuthorizedRemembered(f.h,input,'atomic-key',options),
    f.memory.captureAuthorizedRemembered(f.h,input,'atomic-key',options)])
  assert.deepEqual(coalesced,saved)
  assert.deepEqual(f.events,['beginMutation','reserve','retainPrepared','dispatch','publishMutation','settle'])
  assert.equal(saved.authority_settlement,'completed')
  const checkpoint=await f.reader.readCurrent(f.retainedHost),snapshot=await f.memory.exportSnapshot(f.h)
  const targetPool=new FixturePool(join(f.dir,'target.sqlite'));t.after(()=>targetPool.close())
  const readonly=createPostgresMemory({pool:targetPool,authority:toyAuthority,contracts:toyContracts,controlRetention:f.reader})
  await readonly.migrate()
  const prepared=await readonly.prepareRestoreBinding(f.h,snapshot)
  const changed=toyBoundOperation(f.h,'memory.restore',{...prepared.canonical_parameters,retention_checkpoint_sha256:'0'.repeat(64)})
  await assert.rejects(readonly.restoreSnapshot(f.h,snapshot,changed),{code:'memory:control-retention-coordinator-required'})
  // The retained private participant and row observations now select the cold target memory service.
  const restored=f.makeMemory(targetPool)
  const before={...f.calls}
  await assert.rejects(restored.restoreSnapshot(f.h,snapshot,changed),{code:'memory:retained-restore-lineage-unqualified'})
  assert.equal(preparedOperations.has(changed.approval_proof.operation_digest),false)
  await assert.rejects(restored.prepareRestoreBinding(f.h,snapshot),{code:'memory:retained-restore-lineage-unqualified'})
  await assert.rejects(restored.prepareRestoreBinding({...f.h,authorization_epoch:1},snapshot),{code:'memory:retained-restore-lineage-unqualified'})
  const restoreOptions=toyBoundOperation(f.h,'memory.restore',prepared.canonical_parameters)
  await assert.rejects(restored.restoreSnapshot(f.h,snapshot,restoreOptions),{code:'memory:retained-restore-lineage-unqualified'})
  await assert.rejects(restored.importSnapshot(f.h,snapshot,{...restoreOptions,mode:'prime-restore'}),
    {code:'memory:retained-restore-lineage-unqualified'})
  assert.deepEqual(f.calls,before)
  assert.equal(targetPool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,0)
  assert.equal(targetPool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
  assert.equal((await f.reader.readCurrent(f.retainedHost)).checkpoint_sha256,checkpoint.checkpoint_sha256)
  const cold=f.reopen()
  assert.equal((await cold.cite(f.h,saved.record.record_id)).verdict,'VERIFIED')
  assert.equal((await cold.status(f.h,saved.record.record_id)).record.canonical_bytes,saved.record.canonical_bytes)
  const reconciled=await cold.reconcileEffect(f.h,options.operation.operation_id)
  assert.equal(reconciled.authority_settlement,'completed')
  assert.equal(reconciled.receipt.request_id,saved.receipt.request_id)
})

test('atomic retained profile refuses each missing retained authority method before marker or legacy reservation',async t=>{
  const f=await atomicRetentionFixture(t),initial=await f.reader.readCurrent(f.retainedHost)
  for(const method of ['reserveRetained','claimDispatchRetained','settleMemoryRetained']) {
    const memory=f.makeMemory(f.pool,{omitRetainedMethod:method})
    const binding=await memory.prepareCaptureBinding(f.h,input,'missing-'+method)
    const options=toyBoundOperation(f.h,'memory.save',binding.canonical_parameters)
    await assert.rejects(memory.captureAuthorizedRemembered(f.h,input,'missing-'+method,options),
      {code:'memory:retained-authority-unavailable'})
    assert.equal(preparedOperations.has(options.approval_proof.operation_digest),false)
    assert.deepEqual(f.calls,{reserve:0,dispatch:0,settle:0,unknown:0});assert.deepEqual(f.events,[])
    assert.equal((await f.reader.readCurrent(f.retainedHost)).checkpoint_sha256,initial.checkpoint_sha256)
    await assert.rejects(f.reader.inspectPending(f.retainedHost),{code:'memory:control-retention-pending-missing'})
    assert.equal(f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n,0)
  }
})

for(const mode of ['reserve-reply','prepared-commit','prepared-reply','dispatch-reply','effect-commit','publication-before','publication-reply',
  'truthy-beginMutation','truthy-retainPrepared','truthy-publishMutation'])
  test('atomic retention keeps '+mode+' uncertainty fenced without effect retry',async t=>{
    const f=await atomicRetentionFixture(t),binding=await f.memory.prepareCaptureBinding(f.h,input,'uncertain-atomic-key')
    const options=toyBoundOperation(f.h,'memory.save',binding.canonical_parameters)
    f.fault.mode=mode
    if(mode.endsWith('-commit')) {
      const query=f.pool.query.bind(f.pool);let injected=false
      t.mock.method(f.pool,'query',async(sql,...args)=>{
        const actual=await query(sql,...args)
        if(sql==='COMMIT' && !injected) {
          const intentCount=f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_intents').get().n
          const effectCount=f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_effects').get().n
          if(intentCount && (mode==='prepared-commit'?effectCount===0:effectCount===1)) {
            injected=true;throw new Error('synthetic committed transaction reply lost')
          }
        }
        return actual
      })
    }
    await assert.rejects(f.memory.captureAuthorizedRemembered(f.h,input,'uncertain-atomic-key',options),error=>{
      if(mode==='truthy-beginMutation') {
        // The private prepare participant refuses a missing durable marker before kernel reservation.
        assert.equal(error.code,'memory:control-retention-pending-missing')
      } else {
        assert.equal(error.code,'memory:authority-effect-outcome-unknown');assert.equal(error.automatic_retry,false)
      }
      return true
    })
    assert.equal(f.calls.reserve,mode==='truthy-beginMutation'?0:1);assert.equal(f.calls.settle,0)
    const facts=f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_effects').get().n
    const counts={...f.calls};f.fault.mode=null;f.freshPublisher()
    const cold=f.reopen()
    if(facts) {
      const reconciled=await cold.reconcileEffect(f.h,options.operation.operation_id)
      assert.equal(reconciled.authority_settlement,'completed')
      assert.equal((await f.reader.readCurrent(f.retainedHost)).control_state.tables.effects.length,1)
    } else {
      if(mode==='truthy-beginMutation') assert.equal((await f.reader.readCurrent(f.retainedHost)).control_state.tables.intents.length,0)
      else await assert.rejects(f.reader.readCurrent(f.retainedHost),{code:'memory:control-retention-update-pending'})
      if(mode==='reserve-reply' || mode==='truthy-beginMutation') await assert.rejects(cold.reconcileEffect(f.h,options.operation.operation_id),{code:'memory:effect-missing-outcome-unknown'})
      else {const held=await cold.reconcileEffect(f.h,options.operation.operation_id);assert.equal(held.status,'unresolved');assert.equal(held.automatic_retry,false)}
    }
    assert.equal(f.calls.reserve,counts.reserve);assert.equal(f.calls.dispatch,counts.dispatch)
    assert.equal(f.pool.db.prepare('SELECT count(*) AS n FROM prime_memory_effects').get().n,facts)
  })

test('independent purge control anchor blocks old data in an empty store and retains content-free replay fences',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-purge-cold-restore-'))
  const sourcePool=new FixturePool(join(dir,'source.sqlite')),targetPool=new FixturePool(join(dir,'target.sqlite'))
  try {
    const memory=service(sourcePool);await memory.migrate();const h=host()
    const selectedBinding=await memory.prepareCaptureBinding(h,input,'selected-key')
    const selectedOptions=toyBoundOperation(h,'memory.save',selectedBinding.canonical_parameters)
    const selected=await memory.captureAuthorizedRemembered(h,input,'selected-key',selectedOptions)
    const retainedHost=host(owner,'Independent retained synthetic quote.')
    const retained=await fixtureCapture(memory,retainedHost,{...input,statement:'retained'},'retained-key')
    const oldSnapshot=await memory.exportSnapshot(h)
    const mutation=await memory.prepareRecordMutationBinding(h,selected.record.record_id,{action:'memory.purge',at})
    await memory.purgeRecordPayload(h,selected.record.record_id,toyBoundOperation(h,'memory.purge',mutation.canonical_parameters,mutation.canonical_parameters.heads))
    await retainFixtureAnchor(memory,h)
    const anchor=trustedFixtureAnchors.get(owner),current=await memory.exportSnapshot(h)
    assert.equal(anchor.tables.purges.length,1);assert.equal(anchor.tables.requests.length,2)
    assert.equal(anchor.tables.replay_fences.length,1)
    const fenced=anchor.tables.replay_fences[0]
    assert.equal(fenced.operation_id,selectedOptions.operation.operation_id)
    assert.equal(JSON.stringify(fenced).includes('banana'),false)
    const restored=service(targetPool);await restored.migrate()
    const stale=await toyImport(targetPool,oldSnapshot,{mode:'prime-restore',expectedHeads:oldSnapshot.heads})
    await assert.rejects(restored.restoreSnapshot(h,oldSnapshot,stale),{code:'memory:restore-anchor-mismatch'})
    assert.equal(preparedOperations.has(stale.approval_proof.operation_digest),false)
    const dataOnly=await toyImport(targetPool,oldSnapshot)
    await assert.rejects(restored.importSnapshot(h,oldSnapshot,dataOnly),{code:'memory:prime-data-import-requires-control-restore'})
    assert.equal(preparedOperations.has(dataOnly.approval_proof.operation_digest),false)
    assert.equal(targetPool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,0)
    const imported=await restored.restoreSnapshot(h,current,await toyImport(targetPool,current,{mode:'prime-restore'}))
    assert.equal(imported.imported,1);assert.equal(imported.control_state_restored,true)
    assert.equal(targetPool.db.prepare('SELECT count(*) AS n FROM prime_memory_purges').get().n,1)
    assert.equal(targetPool.db.prepare('SELECT count(*) AS n FROM prime_memory_replay_fences').get().n,1)
    assert.equal((await restored.cite(retainedHost,retained.record_id)).verdict,'VERIFIED')
    await assert.rejects(restored.prepareCaptureBinding(h,{...input,statement:'new ID same erased source'},'fresh-key'),{code:'memory:purged-source-recapture'})
    await assert.rejects(restored.reconcileEffect(h,selectedOptions.operation.operation_id),{code:'memory:effect-payload-purged-replay-forbidden'})
    await assert.rejects(restored.captureAuthorizedRemembered(h,input,'selected-key',selectedOptions),{code:'memory:effect-payload-purged-replay-forbidden'})
  } finally {sourcePool.close();targetPool.close();rmSync(dir,{recursive:true,force:true})}
})

test('new capture defaults refuse invisible policy changes before reserve and approved forget exposes its actual settlement',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'prime-memory-pilot-forget-')),pool=new FixturePool(join(dir,'storage.sqlite'))
  try {
    const memory=service(pool);await memory.migrate();const h=host()
    const binding=await memory.prepareCaptureBinding(h,input,'fixed-profile')
    const options=toyBoundOperation(h,'memory.save',binding.canonical_parameters)
    for(const change of [{category:'decision'},{confidence:0.9},{sensitivity:'high'},{links:[{relation:'about',id:'hidden'}]},
      {observedAt:'2026-10-01T11:04:00Z'},{validFrom:'2026-09-30'}]) {
      await assert.rejects(memory.captureAuthorizedRemembered(h,{...input,...change},'fixed-profile',options),
        {code:'memory:pilot-capture-profile-refused'})
      assert.equal(preparedOperations.has(options.approval_proof.operation_digest),false)
    }
    for(const change of [{scope:'workspace'},{evidence:[]},{bodyAtCapture:'hidden'},{origin:{by:'different-profile'}}])
      await assert.rejects(memory.prepareCaptureBinding({...h,...change},input,'fixed-profile'),{code:'memory:pilot-capture-profile-refused'})
    const saved=await memory.captureAuthorizedRemembered(h,input,'fixed-profile',options)
    const mutation=await memory.prepareRecordMutationBinding(h,saved.record.record_id,{action:'memory.forget',at})
    const forged=toyBoundOperation(h,'memory.forget',{...mutation.canonical_parameters,statement:'different reviewed target'},mutation.canonical_parameters.heads)
    await assert.rejects(memory.forgetRecord(h,saved.record.record_id,{include_receipt:true,...forged}),{code:'memory:record-operation-mismatch'})
    assert.equal(preparedOperations.has(forged.approval_proof.operation_digest),false)
    const forgotten=await memory.forgetRecord(h,saved.record.record_id,{include_receipt:true,
      ...toyBoundOperation(h,'memory.forget',mutation.canonical_parameters,mutation.canonical_parameters.heads)})
    assert.equal(forgotten.result.state,'tombstoned');assert.equal(forgotten.result.canonical_payload_retained,true)
    assert.equal(forgotten.result.authority_approval_history_erased,false)
    assert.equal(forgotten.authority_settlement,'completed');assert.equal(forgotten.reconciliation_required,false)
    assert.equal(forgotten.receipt.action_type,'memory.forget')
    assert.equal(forgotten.receipt_digest,memoryReceiptDigest(forgotten.receipt))
    assert.equal((await memory.recall(h,{query:'banana'})).records.length,0)
    assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_records').get().n,1)
  } finally {pool.close();rmSync(dir,{recursive:true,force:true})}
})
