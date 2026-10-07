import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync, openSync, closeSync, fsyncSync, lstatSync, realpathSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { applicationDigest, b64, budgets, canonicalBytes, canonicalJson, closed, fail, h32, hashDomain, keyId,
  nostrPreimage, parseBytes, parseEvent, PROJECTION_ORDER, sha256, snapshotBytes, u64, uint, validateScope } from '../bytes/index.mjs';
import { verifyBip340 } from '../keys/index.mjs';
import { parseObservation, observationEvidence } from '../aperture/observation.mjs';
import { derivedControlBytes, derivedControlDigest } from './control-state.mjs';

const SOURCE = 'aukora.local-test-control.v1';
const MAX = 18446744073709551615n;
const TIME_POLICY = '43044e7df9bd820b2cb064be90ea92c0bd09d8f79f5fa9565c0432a8168aac44';
const CONTROL_POLICY = '0f997602f4ec67af72bd34e30a633d38e2693aada2ceebb1e71df131632e10d4';
const bytes = value => canonicalJson(Buffer.from(JSON.stringify(value)));
const frozen = value => parseBytes(bytes(value), { mode: 'evidence' });
const same = (a, b) => bytes(a).equals(bytes(b));
const must = (condition, code = 'CLOSED_SCHEMA') => { if (!condition) fail(code); };
const increment = value => { const result = BigInt(value) + 1n; must(result <= MAX, 'LIMIT_EXCEEDED'); return String(result); };
const nullable = fn => value => { if (value !== null) fn(value); };
const sortData = list => list.sort((a, b) => Buffer.compare(bytes(a), bytes(b)));
const reservationFields = { subject_id: h32, chain_id: h32, epoch: u64, operation_id: h32, nonce: h32, reservation_id: h32,
  request_ref: h32, actor_key_id: h32, authority_ref: h32, scope: validateScope, payload_commitment: h32,
  budget: budgets, control_checkpoint_ref: h32, not_before: uint, expires: uint };
export function reservationDescriptor(intentRecordBytes) {
  const r = parseBytes(intentRecordBytes);
  must(r.kind === 'intent');
  const descriptor = {};
  for (const key of Object.keys(reservationFields)) descriptor[key] = Object.hasOwn(r, key) ? r[key] : r.body[key];
  const result = bytes(descriptor); closed(parseBytes(result), reservationFields); return result;
}
export function reservationCommitment(descriptorBytes) {
  const descriptor = closed(parseBytes(descriptorBytes), reservationFields);
  return hashDomain('aukora.reservation.v1', canonicalBytes(descriptor));
}
function projectionFor(record) {
  if (record.kind === 'coherence_checkpoint') return null;
  if (record.kind === 'revocation') return ['vouch', 'agent_card'].includes(record.body.target_type) ? 'delegation' : 'identity';
  if (['identity', 'key_binding', 'epoch_transition', 'policy_commitment', 'recovery_policy'].includes(record.kind)) return 'identity';
  if (['vouch', 'vouch_accept', 'agent_card'].includes(record.kind)) return 'delegation';
  if (['emission_request', 'owner_approval', 'intent'].includes(record.kind)) return 'actions';
  if (record.kind === 'receipt') return 'receipts';
  if (record.kind === 'kira_map') return 'memory';
  fail('UNSUPPORTED_KIND');
}
function ensureDirectory(directory, fresh) {
  must(typeof directory === 'string' && directory.length > 0);
  const path = resolve(directory);
  if (!existsSync(path)) { must(fresh, 'ROLLBACK_UNRESOLVED'); mkdirSync(path, { mode: 0o700, recursive: true }); }
  must(lstatSync(path).isDirectory() && !lstatSync(path).isSymbolicLink(), 'ROLLBACK_UNRESOLVED');
  // Canonicalize trusted parent aliases (macOS /var -> /private/var) so every
  // handle names the same lock. The final retained directory itself is not a link.
  return realpathSync(path);
}

// Opening may race SQLite WAL recovery in another process. The busy handler
// must precede every lock-sensitive pragma; SQLite can also return BUSY_RECOVERY
// without invoking it. Retry only these idempotent setup statements, never a
// transaction, COMMIT, fsync, or effect. One monotonic budget covers both handles.
const OPEN_WAIT_MS = 5000;
const retryPause = new Int32Array(new SharedArrayBuffer(4));
function openConnections(guardPath, dataPath) {
  let guard, db;
  const deadline = performance.now() + OPEN_WAIT_MS;
  const setup = (connection, statement) => {
    for (;;) {
      const remaining = Math.max(0, Math.ceil(deadline - performance.now()));
      connection.exec(`PRAGMA busy_timeout=${remaining}`);
      try { connection.exec(statement); return; }
      catch (error) {
        // Low byte is SQLITE_BUSY (5); extended codes include BUSY_RECOVERY.
        // LOCKED, IO, corruption, and all other errors propagate unchanged.
        if (error?.code !== 'ERR_SQLITE_ERROR' || (error.errcode & 255) !== 5 || performance.now() >= deadline) throw error;
        Atomics.wait(retryPause, 0, 0, Math.min(10, Math.max(0, deadline - performance.now())));
      }
    }
  };
  try {
    guard = new DatabaseSync(guardPath);
    db = new DatabaseSync(dataPath);
    for (const statement of ['PRAGMA journal_mode=DELETE', 'PRAGMA synchronous=FULL',
      'CREATE TABLE IF NOT EXISTS writer_lock (id INTEGER PRIMARY KEY)']) setup(guard, statement);
    for (const statement of ['PRAGMA journal_mode=WAL', 'PRAGMA synchronous=FULL', 'PRAGMA foreign_keys=ON']) setup(db, statement);
    // Normal writer acquisition retains its existing bounded wait.
    guard.exec(`PRAGMA busy_timeout=${OPEN_WAIT_MS}`);
    db.exec(`PRAGMA busy_timeout=${OPEN_WAIT_MS}`);
    return { guard, db };
  } catch (error) {
    try { db?.close(); } catch { /* Preserve the opening failure. */ }
    try { guard?.close(); } catch { /* Preserve the opening failure. */ }
    throw error;
  }
}

/** Trusted storage API. Callers must keep this handle away from proposals.
 * appendVerified/reserveIntent require W2 + W3 authority checks under this same
 * lock. Structural/outer-signature checks here are defense in depth, not authority.
 * directory is retained outside every identity/Kira backup/import set.
 */
export function openJournal({ directory, bootstrapBytes } = {}) {
  const fresh = bootstrapBytes !== undefined;
  const config = fresh ? closed(parseBytes(bootstrapBytes), { subject_id: h32, chain_id: h32, now: uint }) : null;
  const path = ensureDirectory(directory, fresh);
  const dataPath = join(path, 'retained.sqlite'), guardPath = join(path, 'writer.sqlite');
  if (fresh) {
    must(!existsSync(dataPath) && !existsSync(guardPath), 'ROLLBACK_UNRESOLVED');
    // Checking existence is not a claim: two processes can both see absence.
    // Exclusively create the existing guard path before any SQLite setup. Keep
    // a failed/partial claim for explicit diagnosis; never reset or delete it.
    let claim;
    try { claim = openSync(guardPath, 'wx', 0o600); fsyncSync(claim); }
    catch (error) { if (error?.code === 'EEXIST') fail('ROLLBACK_UNRESOLVED'); throw error; }
    finally { if (claim !== undefined) closeSync(claim); }
    const directoryFd = openSync(path, 'r');
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } else must(existsSync(dataPath) && existsSync(guardPath), 'ROLLBACK_UNRESOLVED');
  for (const file of [dataPath, guardPath]) if (existsSync(file)) must(lstatSync(file).isFile() && !lstatSync(file).isSymbolicLink(), 'ROLLBACK_UNRESOLVED');
  const { guard, db } = openConnections(guardPath, dataPath);
  // Node 22.5 get() can return a truthy all-null row for an empty result.
  // Every lookup is explicitly bounded; all() preserves actual row absence.
  const firstRow = (sql, ...parameters) => db.prepare(`${sql} LIMIT 1`).all(...parameters)[0];
  const bootId = randomBytes(32).toString('hex');
  let held = false, closedFlag = false, poisoned = false, current;
  let observedDataVersion = null, cacheGeneration = 0, derived = null, controlMemo = null;
  const resetDerived = () => { derived = null; controlMemo = null; cacheGeneration++; };
  const syncDirectory = () => { const fd = openSync(path, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); } };
  try { if (fresh) {
    guard.exec('BEGIN IMMEDIATE');
    db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), state BLOB NOT NULL, floor BLOB NOT NULL);
      CREATE TABLE events (id TEXT PRIMARY KEY, sequence TEXT NOT NULL UNIQUE, previous_event TEXT, bytes BLOB NOT NULL);
      CREATE TABLE operations (operation_id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, reservation_id TEXT UNIQUE NOT NULL, entry BLOB NOT NULL);
      CREATE TABLE buckets (grant_ref TEXT NOT NULL, unit TEXT NOT NULL, currency TEXT NOT NULL, maximum TEXT NOT NULL, spent TEXT NOT NULL, PRIMARY KEY(grant_ref,unit,currency));
      CREATE TABLE debits (operation_id TEXT NOT NULL, grant_ref TEXT NOT NULL, unit TEXT NOT NULL, currency TEXT NOT NULL, amount TEXT NOT NULL, PRIMARY KEY(operation_id,grant_ref,unit,currency));
      CREATE TABLE history (revision TEXT PRIMARY KEY, mutation TEXT NOT NULL, state BLOB NOT NULL, floor BLOB NOT NULL);
      CREATE TABLE conflicts (id TEXT PRIMARY KEY, bytes BLOB NOT NULL);
      CREATE TRIGGER no_event_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'append only'); END;
      CREATE TRIGGER no_event_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'append only'); END;
      CREATE TRIGGER no_operation_delete BEFORE DELETE ON operations BEGIN SELECT RAISE(ABORT,'permanent consumption'); END;
      CREATE TRIGGER no_history_update BEFORE UPDATE ON history BEGIN SELECT RAISE(ABORT,'append only'); END;
      CREATE TRIGGER no_history_delete BEFORE DELETE ON history BEGIN SELECT RAISE(ABORT,'append only'); END;`);
    const state = { ...config, revision: '0', epoch: '0', sequence: null, head: null, checkpoint_ref: null,
      active_root_key_id: null, active_append_key_id: null, active_append_pubkey: null, policies: {}, frozen_conflict: false };
    db.prepare('INSERT INTO meta VALUES (1,?,?)').run(bytes(state), bytes({ initialized: false }));
    db.exec('COMMIT'); syncDirectory();
    guard.exec('ROLLBACK');
  } } catch (error) {
    try { db.close(); } catch { /* Preserve initialization failure. */ }
    try { guard.close(); } catch { /* Preserve initialization failure. */ }
    throw error;
  }
  const load = () => {
    // A racing reopen or failed bootstrap is unresolved retained state, not
    // permission to initialize a replacement identity. Corruption/I/O still throw.
    must(firstRow("SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'"), 'ROLLBACK_UNRESOLVED');
    const row = firstRow('SELECT state,floor FROM meta WHERE id=1');
    must(row, 'ROLLBACK_UNRESOLVED');
    current = JSON.parse(Buffer.from(row.state).toString('utf8'));
    return { state: current, floor: parseBytes(row.floor) };
  };
  const assertLock = () => { must(held && !closedFlag && !poisoned, 'ROLLBACK_UNRESOLVED'); };
  const operation = (subjectId, operationId) => {
    assertLock(); h32(subjectId); h32(operationId); must(subjectId === current.subject_id, 'WRONG_AUTHORITY');
    const row = firstRow('SELECT entry FROM operations WHERE operation_id=?', operationId);
    return row ? parseBytes(row.entry) : null;
  };
  const isNonceConsumed = (subjectId, nonce) => {
    assertLock(); h32(subjectId); h32(nonce); must(subjectId === current.subject_id, 'WRONG_AUTHORITY');
    return Boolean(firstRow('SELECT 1 FROM operations WHERE nonce=?', nonce));
  };
  const events = () => { assertLock(); return db.prepare('SELECT bytes FROM events ORDER BY rowid').all().map(row => Buffer.from(row.bytes)); };
  const ensureDerived = () => {
    if (derived) return;
    const revoked = new Map(), spent = new Map();
    // First open and every external SQLite write rebuild from retained rows.
    // This is derived data only; it never replaces the protected ledger.
    for (const data of events()) {
      const { record } = parseEvent(data);
      if (record.kind === 'revocation') {
        const entry = { target_type: record.body.target_type, target_id: record.body.target_id };
        revoked.set(`${entry.target_type}:${entry.target_id}`, bytes(entry).toString('utf8'));
      }
    }
    // Node 22.5 has StatementSync.all/get but not iterate. Keyset pages keep
    // temporary row material bounded and scan every operation under the lock.
    const first = db.prepare('SELECT operation_id,entry FROM operations ORDER BY operation_id LIMIT 32');
    const next = db.prepare('SELECT operation_id,entry FROM operations WHERE operation_id>? ORDER BY operation_id LIMIT 32');
    let after = null;
    for (;;) {
      const rows = after === null ? first.all() : next.all(after);
      if (!rows.length) break;
      for (const row of rows) {
        h32(row.operation_id);
        const e = parseBytes(row.entry);
        must(e.operation_id === row.operation_id, 'ROLLBACK_UNRESOLVED');
        spent.set(e.operation_id, bytes({ operation_id:e.operation_id, nonce:e.nonce,
          reservation_id:e.reservation_id, intent_ref:e.intent_ref }).toString('utf8'));
      }
      after = rows.at(-1).operation_id;
    }
    derived = { revoked, spent };
  };
  const controlStateBytes = () => {
    assertLock(); ensureDerived();
    if (controlMemo?.head === current.head) return Buffer.from(controlMemo.bytes);
    const value = derivedControlBytes({ subject_id:current.subject_id,chain_id:current.chain_id,
      epoch:current.epoch,basis_event:current.head,active_root_key_id:current.active_root_key_id,
      active_append_key_id:current.active_append_key_id },
      [...derived.revoked.values()].sort(),[...derived.spent.values()].sort(),Object.values(current.policies));
    controlMemo = { head:current.head,bytes:value,digest:derivedControlDigest(value) };
    return Buffer.from(value);
  };
  const floorForCurrent = () => {
    controlStateBytes();
    return { source_id:SOURCE,subject_id:current.subject_id,chain_id:current.chain_id,
      revision:current.revision,time_floor:current.now,epoch:current.epoch,sequence:current.sequence,head:current.head,
      control_state_digest:controlMemo.digest };
  };
  const eventBytes = id => { assertLock(); h32(id); const row=firstRow('SELECT bytes FROM events WHERE id=?', id); return row?Buffer.from(row.bytes):null; };
  const eventsAfter = (id = null) => {
    assertLock(); let rowid = 0;
    if (id !== null) { h32(id); const row=firstRow('SELECT rowid FROM events WHERE id=?', id); must(row,'ROLLBACK_UNRESOLVED'); rowid=row.rowid; }
    return db.prepare('SELECT bytes FROM events WHERE rowid>? ORDER BY rowid LIMIT 32').all(rowid).map(row=>Buffer.from(row.bytes));
  };
  const snapshot = () => {
    assertLock(); must(current.head !== null, 'MISSING_EVIDENCE'); must(!current.frozen_conflict, 'JOURNAL_CONFLICT');
    const floor = floorForCurrent();
    return frozen({ source_id: SOURCE, mode: 'LOCAL_TEST', boot_id: bootId, revision: current.revision,
      time_policy_digest: TIME_POLICY, control_policy_digest: CONTROL_POLICY, now_lower: current.now, now_upper: current.now,
      subject_id: current.subject_id, chain_id: current.chain_id, epoch: current.epoch, sequence: current.sequence, head: current.head,
      checkpoint_ref: current.checkpoint_ref, control_state_digest: floor.control_state_digest, floor });
  };
  const transaction = (mutation, fn) => {
    assertLock(); must(!current.frozen_conflict || mutation === 'conflict', 'JOURNAL_CONFLICT');
    ensureDerived();
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      current.revision = increment(current.revision);
      const stateBytes = bytes(current), floorBytes = bytes(floorForCurrent());
      db.prepare('UPDATE meta SET state=?,floor=? WHERE id=1').run(stateBytes, floorBytes);
      db.prepare('INSERT INTO history VALUES (?,?,?,?)').run(current.revision, mutation, stateBytes, floorBytes);
      db.exec('COMMIT');
      // If either COMMIT or the directory sync fails, no effect may follow.
      syncDirectory();
      return result;
    } catch (error) {
      try { db.exec('ROLLBACK'); } catch { /* May have committed; never retry here. */ }
      poisoned = true;
      throw error;
    }
  };
  const projections = (basis = current.head) => {
    assertLock(); h32(basis);
    const heads = PROJECTION_ORDER.map(role => ({ role, event_id: null, sequence: null }));
    let found = false;
    for (const data of events()) {
      const { record, event } = parseEvent(data); const role = projectionFor(record);
      if (role) heads[PROJECTION_ORDER.indexOf(role)] = { role, event_id: event.id, sequence: record.sequence };
      if (event.id === basis) { found = true; break; }
    }
    must(found, 'MISSING_EVIDENCE'); return frozen(heads);
  };
  const inspectEvent = input => {
    const data = snapshotBytes(input), parsed = parseEvent(data);
    const digest = sha256(nostrPreimage(data));
    must(parsed.event.id === digest.toString('hex') && verifyBip340(Buffer.from(parsed.event.sig, 'hex'), digest, Buffer.from(parsed.event.pubkey, 'hex')), 'BAD_SIGNATURE');
    must(parsed.record.subject_id === current.subject_id && parsed.record.chain_id === current.chain_id, 'WRONG_AUTHORITY');
    return { ...parsed, data };
  };
  const detectConflict = candidate => {
    const { event, record, data } = candidate;
    const position = firstRow('SELECT id FROM events WHERE sequence=?', record.sequence);
    const sibling = record.previous_event === null ? null : firstRow('SELECT id FROM events WHERE previous_event=?', record.previous_event);
    if ((position && position.id !== event.id) || (sibling && sibling.id !== event.id)) {
      transaction('conflict', () => { db.prepare('INSERT OR IGNORE INTO conflicts VALUES (?,?)').run(event.id, data); current.frozen_conflict = true; });
      fail('JOURNAL_CONFLICT');
    }
  };
  const retainVerifiedConflict = eventBytes => {
    assertLock();
    // Trusted W3 must first verify this branch against ONLY its retained
    // preceding prefix. A conflict verdict alone is not proof of authority.
    // All kinds enter this evidence-only path, including intent and receipt;
    // no append, consumption, signing or lifecycle transition occurs here.
    detectConflict(inspectEvent(eventBytes));
    fail('INCONSISTENT_HEAD', 'No competing retained journal event');
  };
  const checkAppend = candidate => {
    const { event, record } = candidate; detectConflict(candidate);
    must(!firstRow('SELECT id FROM events WHERE id=?', event.id), 'REPLAY');
    if (current.head === null) {
      must(record.kind === 'identity' && record.sequence === '0' && record.epoch === '0' && record.previous_event === null, 'INCONSISTENT_HEAD');
      must(event.pubkey === record.body.root_key.bip340_public_key, 'WRONG_SIGNER');
    } else {
      must(record.kind !== 'identity' && record.sequence === increment(current.sequence) && record.previous_event === current.head && record.epoch === current.epoch, 'INCONSISTENT_HEAD');
      must(event.pubkey === current.active_append_pubkey, 'WRONG_SIGNER');
    }
    if (record.kind === 'coherence_checkpoint') {
      const basisRow = firstRow('SELECT bytes FROM events WHERE id=?', record.body.basis_event);
      must(basisRow, 'MISSING_EVIDENCE'); const basis = parseEvent(basisRow.bytes).record;
      must(record.body.basis_sequence === basis.sequence && record.body.basis_epoch === basis.epoch &&
        record.body.previous_checkpoint === current.checkpoint_ref && same(record.body.heads, projections(record.body.basis_event)), 'INCONSISTENT_HEAD');
      // Only a checkpoint over the exact preceding current state is supported by
      // this storage source. Older bases can be verified historically by W2.
      must(record.body.basis_event === current.head && record.body.control_state_digest === floorForCurrent().control_state_digest, 'INCONSISTENT_HEAD');
    }
    if (record.kind === 'epoch_transition') {
      must(record.body.next_root_key === null, 'UNSUPPORTED_PROFILE');
      const row = firstRow('SELECT bytes FROM events WHERE id=?', record.body.next_append_certificate);
      must(row, 'MISSING_EVIDENCE'); const binding = parseEvent(row.bytes).record;
      must(binding.kind === 'key_binding' && binding.body.role === 'journal_append' && binding.body.key_id === record.body.next_append_key_id &&
        binding.body.key_id !== current.active_append_key_id && binding.body.restriction.append_epoch === record.body.to_epoch, 'WRONG_AUTHORITY');
    }
  };
  const insertEvent = ({ event, record, data }) => {
    controlMemo = null;
    if (record.kind === 'revocation') {
      const entry={target_type:record.body.target_type,target_id:record.body.target_id};
      derived.revoked.set(`${entry.target_type}:${entry.target_id}`,bytes(entry).toString('utf8'));
    }
    db.prepare('INSERT INTO events VALUES (?,?,?,?)').run(event.id, record.sequence, record.previous_event, data);
    current.head = event.id; current.sequence = record.sequence;
    if (record.kind === 'identity') {
      current.active_root_key_id = keyId(canonicalBytes(record.body.root_key)).toString('hex');
      current.active_append_key_id = keyId(canonicalBytes(record.body.initial_append_key)).toString('hex');
      current.active_append_pubkey = record.body.initial_append_key.bip340_public_key;
    }
    if (record.kind === 'epoch_transition') {
      const binding = parseEvent(firstRow('SELECT bytes FROM events WHERE id=?', record.body.next_append_certificate).bytes).record;
      current.epoch = record.body.to_epoch; current.active_append_key_id = record.body.next_append_key_id;
      current.active_append_pubkey = binding.body.descriptor.bip340_public_key;
    }
    if (record.kind === 'policy_commitment') current.policies[record.body.policy_type] = event.id;
    if (record.kind === 'coherence_checkpoint') current.checkpoint_ref = event.id;
  };
  const appendVerified = input => {
    assertLock(); const candidate = inspectEvent(input);
    // An intent may never bypass the atomic consumption path; a receipt binds
    // the protected operation through its dedicated transaction below.
    must(!['intent', 'receipt'].includes(candidate.record.kind), 'WRONG_AUTHORITY');
    checkAppend(candidate);
    transaction('append', () => insertEvent(candidate)); return candidate.event.id;
  };
  const checkBudgetDebits = debitInput => {
    assertLock();
    const debits = parseBytes(debitInput); must(Array.isArray(debits) && debits.length > 0);
    const byGrant = new Map(); let previous = '';
    for (const d of debits) {
      closed(d, { grant_ref: h32, unit: v => must(v === 'bytes' || v === 'requests'), currency: v => must(v === null), maximum: u64, amount: u64 });
      const order = `${d.grant_ref}:${d.unit}`; must(order > previous); previous = order;
      must(d.amount === (d.unit === 'bytes' ? '18' : '1'), 'SCOPE_MISMATCH');
      const dimensions = byGrant.get(d.grant_ref) ?? []; dimensions.push(d.unit); byGrant.set(d.grant_ref, dimensions);
      const bucket = firstRow('SELECT maximum,spent FROM buckets WHERE grant_ref=? AND unit=? AND currency=?', d.grant_ref, d.unit, '');
      must(!bucket || bucket.maximum === d.maximum, 'WRONG_AUTHORITY');
      must(BigInt(bucket?.spent ?? '0') + BigInt(d.amount) <= BigInt(d.maximum), 'SCOPE_MISMATCH');
    }
    must([...byGrant.values()].every(units => units.length === 2), 'WRONG_AUTHORITY');
    return debits;
  };
  const reserveIntent = (eventBytes, descriptorInput, debitInput) => {
    assertLock(); const candidate = inspectEvent(eventBytes), r = candidate.record, b = r.body;
    must(r.kind === 'intent', 'WRONG_DOMAIN'); checkAppend(candidate);
    const descriptor = closed(parseBytes(descriptorInput), reservationFields);
    must(canonicalBytes(descriptor).equals(reservationDescriptor(canonicalBytes(r))), 'WRONG_AUTHORITY');
    must(reservationCommitment(canonicalBytes(descriptor)).toString('hex') === b.consumption_commitment, 'WRONG_AUTHORITY');
    must(r.not_before <= current.now && current.now < r.expires, current.now >= r.expires ? 'EXPIRED' : 'NOT_YET_VALID');
    must(current.checkpoint_ref !== null && b.control_checkpoint_ref === current.checkpoint_ref, 'STALE_CONTROL');
    must(!firstRow('SELECT 1 FROM operations WHERE operation_id=? OR nonce=? OR reservation_id=?', b.operation_id, b.nonce, b.reservation_id), 'REPLAY');
    const debits = checkBudgetDebits(debitInput);
    must(debits.some(d => d.grant_ref === b.authority_ref), 'WRONG_AUTHORITY');
    must(same(b.budget, [{ unit: 'bytes', maximum: '18', currency: null }, { unit: 'requests', maximum: '1', currency: null }]), 'SCOPE_MISMATCH');
    const entry = { subject_id: r.subject_id, operation_id: b.operation_id, nonce: b.nonce, reservation_id: b.reservation_id,
      intent_ref: candidate.event.id, reservation_commitment: b.consumption_commitment, state: 'reserved_not_dispatched',
      reserved_at: current.now, dispatch_started_at: null, last_receipt_ref: null };
    transaction('reserve_intent', () => {
      insertEvent(candidate);
      db.prepare('INSERT INTO operations VALUES (?,?,?,?)').run(b.operation_id, b.nonce, b.reservation_id, bytes(entry));
      derived.spent.set(b.operation_id,bytes({operation_id:b.operation_id,nonce:b.nonce,reservation_id:b.reservation_id,intent_ref:candidate.event.id}).toString('utf8'));
      controlMemo=null;
      for (const d of debits) {
        const old = firstRow('SELECT spent FROM buckets WHERE grant_ref=? AND unit=? AND currency=?', d.grant_ref, d.unit, '');
        const spent = String(BigInt(old?.spent ?? '0') + BigInt(d.amount));
        db.prepare('INSERT INTO buckets VALUES (?,?,?,?,?) ON CONFLICT(grant_ref,unit,currency) DO UPDATE SET spent=excluded.spent').run(d.grant_ref, d.unit, '', d.maximum, spent);
        db.prepare('INSERT INTO debits VALUES (?,?,?,?,?)').run(b.operation_id, d.grant_ref, d.unit, '', d.amount);
      }
    });
    return frozen(entry);
  };
  const markDispatchStarted = operationId => {
    assertLock(); const prior = operation(current.subject_id, operationId); must(prior, 'MISSING_EVIDENCE');
    must(prior.state === 'reserved_not_dispatched', 'REPLAY');
    const r = parseEvent(firstRow('SELECT bytes FROM events WHERE id=?', prior.intent_ref).bytes).record;
    must(r.epoch === current.epoch, 'WRONG_AUTHORITY');
    must(r.not_before <= current.now && current.now < r.expires, current.now >= r.expires ? 'EXPIRED' : 'NOT_YET_VALID');
    const entry = { ...prior, state: 'dispatch_started', dispatch_started_at: current.now };
    transaction('dispatch_started', () => db.prepare('UPDATE operations SET entry=? WHERE operation_id=?').run(bytes(entry), operationId));
    return frozen(entry);
  };
  const receiptArtifacts = (digests = null) => {
    assertLock();
    if (!firstRow("SELECT 1 FROM sqlite_master WHERE type='table' AND name='receipt_artifacts'")) return [];
    if (digests !== null) {
      must(Array.isArray(digests)&&digests.length<=256,'LIMIT_EXCEEDED');
      const rows=[...new Set(digests)].sort().map(digest=>{h32(digest);return firstRow('SELECT digest,bytes FROM receipt_artifacts WHERE digest=?', digest);}).filter(Boolean);
      return rows.map(row=>({digest:row.digest,blob:Buffer.from(row.bytes).toString('base64url')}));
    }
    return db.prepare('SELECT digest,bytes FROM receipt_artifacts ORDER BY digest').all()
      .map(row => ({ digest: row.digest, blob: Buffer.from(row.bytes).toString('base64url') }));
  };
  const recordReceipt = (eventBytes, artifactInput = null) => {
    assertLock(); const candidate = inspectEvent(eventBytes), r = candidate.record, b = r.body;
    must(r.kind === 'receipt', 'WRONG_DOMAIN'); checkAppend(candidate);
    const prior = operation(current.subject_id, b.operation_id); must(prior && prior.state === 'dispatch_started', 'WRONG_AUTHORITY');
    const intent = parseEvent(firstRow('SELECT bytes FROM events WHERE id=?', prior.intent_ref).bytes).record;
    must(b.intent_ref === prior.intent_ref && b.intent_record_digest === applicationDigest(canonicalBytes(intent)).toString('hex') &&
      b.actor_key_id === intent.body.actor_key_id && ![intent.body.requester_key_id, intent.body.actor_key_id, current.active_append_key_id, current.active_root_key_id].includes(b.observer_key_id), 'WRONG_AUTHORITY');
    must(b.reconciles_receipt === prior.last_receipt_ref && b.observed_at === current.now, 'WRONG_AUTHORITY');
    let artifact = null, artifactDigest = null;
    if (b.outcome === 'unknown' && b.dispatch_state === 'dispatched_uncertain' && b.evidence.length === 0) {
      must(artifactInput === null, 'WRONG_AUTHORITY');
    } else {
      must(b.outcome === 'done' && b.dispatch_state === 'observed' && b.evidence.length === 1 && artifactInput !== null, 'UNSUPPORTED_PROFILE');
      artifact = snapshotBytes(artifactInput, 8192);
      const observation = parseObservation(artifact);
      must(observation.subject_id === r.subject_id && observation.chain_id === r.chain_id && observation.epoch === intent.epoch &&
        observation.operation_id === b.operation_id && observation.intent_ref === b.intent_ref &&
        observation.intent_record_digest === b.intent_record_digest && observation.actor_key_id === b.actor_key_id &&
        observation.observer_key_id === b.observer_key_id && observation.observer_certificate_ref === b.observer_certificate_ref &&
        observation.observed_at === b.observed_at && same(b.evidence[0], observationEvidence(artifact, b.observer_key_id, b.observed_at)), 'WRONG_AUTHORITY');
      artifactDigest = sha256(artifact).toString('hex');
    }
    transaction(artifact ? 'observed_receipt' : 'uncertainty_receipt', () => {
      if (artifact) {
        // Additive table creation and evidence/event/lifecycle transition commit
        // together. Old stores need no separate migration or authority reset.
        db.exec(`CREATE TABLE IF NOT EXISTS receipt_artifacts (digest TEXT PRIMARY KEY, bytes BLOB NOT NULL);
          CREATE TRIGGER IF NOT EXISTS no_receipt_artifact_update BEFORE UPDATE ON receipt_artifacts BEGIN SELECT RAISE(ABORT,'append only'); END;
          CREATE TRIGGER IF NOT EXISTS no_receipt_artifact_delete BEFORE DELETE ON receipt_artifacts BEGIN SELECT RAISE(ABORT,'append only'); END;`);
        db.prepare('INSERT INTO receipt_artifacts VALUES (?,?)').run(artifactDigest, artifact);
      }
      insertEvent(candidate);
      db.prepare('UPDATE operations SET entry=? WHERE operation_id=?').run(bytes({ ...prior,
        state: artifact ? 'settled' : prior.state, last_receipt_ref: candidate.event.id }), b.operation_id);
    });
    return candidate.event.id;
  };
  const advanceClock = now => { assertLock(); uint(now); must(now >= current.now, 'ROLLBACK_UNRESOLVED'); if (now !== current.now) transaction('clock', () => { current.now = now; }); return current.now; };
  const inspectLocked = () => {
    assertLock(); const floor = current.head === null ? null : floorForCurrent();
    return { snapshot: current.head === null || current.frozen_conflict ? null : snapshot(), floor: floor ? frozen(floor) : null,
      frozen_conflict: current.frozen_conflict, events: events(), artifacts: receiptArtifacts(), operations: db.prepare('SELECT entry FROM operations ORDER BY operation_id').all().map(row => parseBytes(row.entry)),
      buckets: db.prepare('SELECT * FROM buckets ORDER BY grant_ref,unit,currency').all().map(value => frozen(value)),
      conflicts: db.prepare('SELECT bytes FROM conflicts ORDER BY id').all().map(row => Buffer.from(row.bytes)) };
  };
  const writer = Object.freeze({ controlSummary: () => { assertLock(); return frozen({active_append_key_id:current.active_append_key_id,active_policy_refs:Object.values(current.policies).sort()}); }, snapshot, events, eventsAfter, eventBytes, cacheEpoch: () => { assertLock(); return `${bootId}:${cacheGeneration}`; }, operation, isNonceConsumed, checkBudgetDebits, appendVerified, retainVerifiedConflict, reserveIntent, markDispatchStarted, recordReceipt, receiptArtifacts, advanceClock, projections,
    controlStateBytes, inspect: inspectLocked });
  const withWriterLock = fn => {
    must(typeof fn === 'function' && !held && !closedFlag && !poisoned, 'ROLLBACK_UNRESOLVED');
    // Separate connection deliberately retains this OS lock across data COMMIT.
    guard.exec('BEGIN IMMEDIATE'); held = true;
    try {
      const dataVersion=db.prepare('PRAGMA data_version').all()[0].data_version;
      if(dataVersion!==observedDataVersion){resetDerived();observedDataVersion=dataVersion;}
      const retained = load();
      if (current.head !== null) must(same(retained.floor, floorForCurrent()), 'ROLLBACK_UNRESOLVED');
      else must(fresh && retained.floor.initialized === false, 'ROLLBACK_UNRESOLVED');
      const result = fn(writer);
      must(!(result && typeof result.then === 'function'), 'WRONG_AUTHORITY');
      return result;
    } finally { held = false; guard.exec('ROLLBACK'); }
  };
  const close = () => { must(!held, 'WRONG_AUTHORITY'); if (!closedFlag) { closedFlag = true; db.close(); guard.close(); } };
  try { withWriterLock(() => { /* Validate the retained floor before exposing a handle. */ }); }
  catch (error) { close(); throw error; }
  return Object.freeze({ withWriterLock, inspect: () => withWriterLock(inspectLocked), close });
}
