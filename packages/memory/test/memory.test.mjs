// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DatabaseSync } from 'node:sqlite'
import { mkdtempSync, rmSync, writeFileSync, cpSync, readFileSync, realpathSync } from 'node:fs'
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
import { memoryTarget, MEMORY_AUDIENCE, memoryStateVersion, memoryReceiptDigest } from '../src/authorization.mjs'

// A disposable SQLite-backed SQL fixture, not PostgreSQL acceptance. Translation is limited to the
// dialect differences below; all records, transactions, bytea and restart storage are real file bytes.
class FixturePool {
  constructor(path) { this.db = new DatabaseSync(path); this.queue=Promise.resolve(); this.failIndex = false; this.failOutbox = false; this.unavailable = false }
  async connect() {
    if(this.unavailable) throw new Error('synthetic store unavailable')
    const previous=this.queue;let release
    this.queue=new Promise(resolve=>{release=resolve});await previous
    return {query:this.query.bind(this),release}
  }
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
  return { owner_subject:subject,owner_id:subject,task_id:'synthetic-task',privacy:'local',scope:'owner',attributedTo:'owner',
    source:{sessionId:'synthetic-session',seq:0,at,sha256:sha256(bytes)},events:[bytes] }
}
const input = {category:'fact',statement:'banana',validFrom:'2026-10-01',observedAt:at,confidence:0.7,sensitivity:'none'}
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
  return {mode,expectedHeads,...toyAuthorization(snapshot.owner_subject,mode==='prime-restore'?'memory.restore':'memory.import',
    {manifest_sha256:snapshot.manifest_sha256,mode,heads:snapshot.heads,
      retained_heads:mode==='prime-restore' ? trustedFixtureAnchors.get(snapshot.owner_subject) : expectedHeads ?? null},stateHeads)}
}
const trustedFixtureAnchors=new Map()
const fixtureAnchorProvider=async h=>({owner_subject:h.owner_subject,heads:trustedFixtureAnchors.get(h.owner_subject)})
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
    const snapshot = await memory.exportSnapshot(captureHost);trustedFixtureAnchors.set(owner,snapshot.heads)
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
      assert.equal((await restored.importSnapshot(captureHost,snapshot,await toyImport(restoredPool,snapshot))).already_imported,true)
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
    const snapshot=await memory.exportSnapshot(host());trustedFixtureAnchors.set(owner,snapshot.heads)
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
    const note = buildRememberedNote({...input,subject:owner,privacy:'local',attributedTo:'owner',source:{state:'UNLINKED',cited:true,sessionId:'missing-synthetic',citedTurn:0,because:'Synthetic event absent'},evidence:[{log:'missing-synthetic',turn:0,turnDigest:digest,quote:'banana'}]})
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
    const before=await memory.exportSnapshot(h);trustedFixtureAnchors.set(owner,before.heads)
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
      await restore.restoreSnapshot(host(),before,await toyImport(restorePool,before,{mode:'prime-restore'}))
      await fixtureForget(restore,host(),approved.record.record_id,at)
      const redacted=await restore.exportSnapshot(host());trustedFixtureAnchors.set(owner,redacted.heads)
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
        await r.restoreSnapshot(host(),redacted,await toyImport(redactedPool,redacted,{mode:'prime-restore',expectedHeads:redacted.heads}))
        await r.drainOutbox(host());assert.equal((await r.recall(host(),{query:'banana'})).records.length,0)
        await assert.rejects(r.cite(host(),approved.record.record_id),{code:'memory:record-tombstoned'})
        assert.equal(inspectSnapshot(await r.exportSnapshot(host()),owner,{expectedHeads:redacted.heads}).redactions.length,1)
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
    for(const table of ['records','events','originals','snapshots','fts','requests','intents'])
      assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+table+' WHERE owner_subject=?').get(owner).n,0)
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
  const draft={statement:'Exact <banana>\n\t🙂',attributed_to:'owner'}
  const params={capture_sha256:'a'.repeat(64),idempotency_key_sha256:'b'.repeat(64),heads:{remembered:'c'.repeat(64)},...draft}
  assert.deepEqual(validateCaptureReview(params,draft),draft)
  for(const unit of ['\u061c','\u200e','\u200f','\u202a','\u202e','\u2066','\u2069','\r','\u0000','\ud800'])
    assert.throws(()=>validateCaptureDraft({...draft,statement:'banana'+unit}),/memory:capture-review-invalid/)
  for(const key of ['capture_sha256','idempotency_key_sha256'])
    assert.throws(()=>validateCaptureReview({...params,[key]:[params[key]]},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,heads:{remembered:['c'.repeat(64)]}},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,statement:'different'},draft),/memory:capture-review-invalid/)
  assert.throws(()=>validateCaptureReview({...params,attributed_to:'agent'},draft),/memory:capture-review-invalid/)
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
    assert.deepEqual(binding.memory_capture,{statement:input.statement,attributed_to:h.attributedTo})
    for(const changed of [{statement:'forged literal'},{attributed_to:'agent'}]) {
      const rejected=toyBoundOperation(h,'memory.save',{...binding.canonical_parameters,...changed})
      await assert.rejects(memory.captureAuthorizedRemembered(h,input,'concurrent-approved',rejected),{code:'memory:capture-review-invalid'})
      assert.equal(reserves,0)
    }
    const options=toyBoundOperation(h,'memory.save',binding.canonical_parameters)
    const saved=await Promise.all(Array.from({length:3},()=>memory.captureAuthorizedRemembered(h,input,'concurrent-approved',options)))
    assert.equal(new Set(saved.map(r=>r.receipt.request_id)).size,1)
    assert.equal(new Set(saved.map(r=>r.record.record_id)).size,1)
    assert.equal(reserves,1);assert.equal(dispatches,1)
    for(const table of ['records','requests','outbox','intents','effects']) assert.equal(pool.db.prepare('SELECT count(*) AS n FROM prime_memory_'+table).get().n,1)
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
    trustedFixtureAnchors.set(owner,before.heads)
    const selfAnchored=await toyImport(emptyPool,before,{mode:'prime-restore',expectedHeads:before.heads})
    await assert.rejects(noAnchor.restoreSnapshot(h,before,selfAnchored),{code:'memory:trusted-restore-anchor-unavailable'})
    await assert.rejects(noAnchor.restoreSnapshot(h,before,{...selfAnchored,mode:'kira-import'}),{code:'memory:restore-mode-invalid'})
    assert.equal(preparedOperations.has(selfAnchored.approval_proof.operation_digest),false)
    await fixtureForget(memory,h,saved.record_id,at)
    const current=await memory.exportSnapshot(h);trustedFixtureAnchors.set(owner,current.heads)
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
