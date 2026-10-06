// Append-only, hash-chained, Ed25519-signed change ledger (SQLite, WAL, synchronous=FULL). Every gate event
// (propose, reject, decide, apply, expire, reconcile, start) is one entry; UPDATE/DELETE are refused by triggers.
import fs from 'node:fs'
import path from 'node:path'
import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'

export const sha256 = (b) => createHash('sha256').update(b).digest('hex')
export const SHA = /^[0-9a-f]{64}$/

// Public-only preconstruction support retained locally for the flat gate package.
// AGPL-3.0-or-later selected pure JSON decoder from Prime packages/contracts/src/json.mjs,
// SHA256 068aa14d3be101413cb028dc5f39e442130b4eeb87c40e18209ddce3ffce4639.
// Its duplicate/depth scan preserves Genesis 645d3213b8aede3b544269b4224ae09df06b0a42 provenance.
// Bounded no-follow public reader from H protected-public-data.mjs,
// SHA256 ab9f809f37831e2c227c330350ba5cedb14831e96c9ec970230ef81f431a50cd.
// Only public data and Node builtins; no Aura/Nostr/contracts runtime imports.
class ContractValidationError extends TypeError {
 constructor(reason, path = '$') {
  super(`INVALID: ${reason} at ${path}`);
  this.name = 'ContractValidationError'; this.code = 'INVALID'; this.error_code = 'INVALID';
  this.reason = reason; this.path = path;
 }
}
function invalid(reason, path) { throw new ContractValidationError(reason, path); }
const MAX_JSON_DEPTH = 64;
const MAX_JSON_BYTES = 8 * 1024 * 1024;
function assertUnicode(value, path = '$') {
 if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) invalid('JSON_LONE_SURROGATE', path);
}
function canonicalJson(value) {
 const ancestors = new Set();
 function encode(node, depth) {
  if (depth > MAX_JSON_DEPTH) invalid('JSON_DEPTH');
  if (node === null || typeof node === 'boolean') return JSON.stringify(node);
  if (typeof node === 'string') { assertUnicode(node); return JSON.stringify(node); }
  if (typeof node === 'number') {
   if (Object.is(node, -0)) invalid('JSON_NEGATIVE_ZERO');
   if (!Number.isSafeInteger(node)) invalid('JSON_UNSAFE_NUMBER');
   return JSON.stringify(node);
  }
  if (!node || typeof node !== 'object') invalid('JSON_VALUE');
  if (ancestors.has(node)) invalid('JSON_CYCLE');
  const array = Array.isArray(node), proto = Object.getPrototypeOf(node);
  if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) invalid('JSON_PROTOTYPE');
  const keys = Reflect.ownKeys(node);
  for (const key of keys) {
   if (array && key === 'length') continue;
   const d = Object.getOwnPropertyDescriptor(node, key);
   if (typeof key !== 'string' || !d?.enumerable || !Object.hasOwn(d, 'value')) invalid('JSON_DATA_PROPERTY');
   assertUnicode(key);
  }
  if (array && (keys.length !== node.length + 1 || Array.from({length: node.length}, (_, i) => Object.hasOwn(node, i)).some(present => !present))) invalid('JSON_ARRAY');
  ancestors.add(node);
  const result = array ? '[' + node.map(item => encode(item, depth + 1)).join(',') + ']'
   : '{' + Object.keys(node).sort().map(key => JSON.stringify(key) + ':' + encode(node[key], depth + 1)).join(',') + '}';
  ancestors.delete(node);
  return result;
 }
 return encode(value, 0);
}

// Check the mathematical value before native parsing can round a decimal token
// such as 1.00000000000000001 to the safe integer 1. Exact 1e0/1.0 remain usable.
function exactNumber(token) {
 const m = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
 let digits = (m[2] + (m[3] ?? '')).replace(/^0+/, '');
 if (!digits) { if (m[1]) invalid('JSON_NEGATIVE_ZERO'); return; }
 const scale = Number(m[4] ?? 0) - (m[3]?.length ?? 0);
 if (!Number.isSafeInteger(scale)) invalid('JSON_UNSAFE_NUMBER');
 if (scale < 0) {
  const count = -scale;
  if (count > digits.length || !/^0*$/.test(digits.slice(-count))) invalid('JSON_UNSAFE_NUMBER');
  digits = digits.slice(0, -count);
 } else {
  if (digits.length + scale > 16) invalid('JSON_UNSAFE_NUMBER');
  digits += '0'.repeat(scale);
 }
 if (digits.length > 16 || BigInt(digits) > BigInt(Number.MAX_SAFE_INTEGER)) invalid('JSON_UNSAFE_NUMBER');
}
function parseStrictJson(text, options = {}) {
 if (!options || typeof options !== 'object' || Array.isArray(options)) invalid('JSON_LIMIT');
 const {maxBytes = MAX_JSON_BYTES, maxDepth = MAX_JSON_DEPTH} = options;
 if (typeof text !== 'string') invalid('JSON_TEXT_REQUIRED');
 if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_JSON_BYTES
  || !Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_JSON_DEPTH) invalid('JSON_LIMIT');
 assertUnicode(text);
 if (text.length > maxBytes || new TextEncoder().encode(text).length > maxBytes) invalid('JSON_SIZE');
 // Bound depth BEFORE the native parser. Escaped quotes/brackets do not count.
 let depth = 0;
 for (let i = 0; i < text.length; i++) {
  if (text[i] === '"') { for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === '\\') i++; }
  else if (text[i] === '{' || text[i] === '[') { if (++depth > maxDepth) invalid('JSON_DEPTH'); }
  else if (text[i] === '}' || text[i] === ']') depth--;
 }
 let value;
 try { value = JSON.parse(text); } catch { invalid('JSON_MALFORMED'); }
 // Scan the SAME validated text for decoded keys, scoped to each object, before
 // returning a value whose duplicate keys would already have been discarded.
 const stack = [];
 for (let i = 0; i < text.length; i++) {
  const ch = text[i];
  if (ch === '"') {
   const start = i;
   for (i++; text[i] !== '"'; i++) if (text[i] === '\\') i++;
   let probe = i + 1;
   while (/^[\x20\t\r\n]$/.test(text[probe] ?? '')) probe++;
   if (text[probe] === ':') {
    const key = JSON.parse(text.slice(start, i + 1)), frame = stack[stack.length - 1];
    if (frame.has(key)) invalid('JSON_DUPLICATE_KEY');
    frame.add(key);
   }
  } else if (ch === '{') stack.push(new Set());
  else if (ch === '[') stack.push(null);
  else if (ch === '}' || ch === ']') stack.pop();
  else if (ch === '-' || /[0-9]/.test(ch)) {
   const start = i;
   while (i + 1 < text.length && /[0-9.eE+-]/.test(text[i + 1])) i++;
   exactNumber(text.slice(start, i + 1));
  }
 }
 canonicalJson(value); // Includes decoded lone surrogates in values AND keys.
 return value;
}

const canonicalAbsolutePath = value => typeof value === 'string' && path.isAbsolute(value)
  && value.length <= 4096 && value.isWellFormed() && !/[\u0000-\u001f\u007f]/u.test(value)
  && path.normalize(value) === value && !value.startsWith('//')
const refuse = () => { throw new Error('protected-public-data:unavailable') }
const sameFileIdentity = (before, after) => ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeMs', 'ctimeMs']
  .every(field => before[field] === after[field])

function checkProtectedPublicAncestors(file, { readerGid } = {}) {
  if (!canonicalAbsolutePath(file)) refuse()
  for (let directory = path.dirname(file); ; directory = path.dirname(directory)) {
    const info = fs.lstatSync(directory)
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0
      || (readerGid !== undefined && (info.mode & 0o001) === 0
        && !(info.gid === readerGid && (info.mode & 0o010) !== 0))) refuse()
    if (directory === '/') break
  }
}

/** No-follow descriptor read; bounded UTF8; no key creation, discovery or writes. */
function readProtectedPublicBytes(file, maximum = 4096) {
  let fd
  try {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 32 * 1024 * 1024
      || typeof fs.constants.O_NOFOLLOW !== 'number' || typeof fs.constants.O_NONBLOCK !== 'number') refuse()
    checkProtectedPublicAncestors(file)
    const named = fs.lstatSync(file)
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
    const before = fs.fstatSync(fd)
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 || (before.mode & 0o022) !== 0
      || before.size < 1 || before.size > maximum || !sameFileIdentity(named, before)) refuse()
    const bytes = Buffer.alloc(maximum + 1)
    let used = 0, count
    while ((count = fs.readSync(fd, bytes, used, bytes.length - used, null)) > 0) {
      used += count
      if (used > maximum) refuse()
    }
    if (used !== before.size || !sameFileIdentity(before, fs.fstatSync(fd))
      || !sameFileIdentity(before, fs.lstatSync(file))) refuse()
    checkProtectedPublicAncestors(file)
    return bytes.subarray(0, used)
  } catch { refuse() }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

function readProtectedPublicText(file, maximum = 4096) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readProtectedPublicBytes(file, maximum)) }
  catch { refuse() }
}

const GATE_READINESS_SOURCE_FILE = '/etc/aukora-boundary-gate/aura-context.json'
// H must independently pin this fixed existing public document before admission.
// Its full collector configuration is not a G authority profile or runtime dependency.
export function readGateReadinessPublicSource() {
  const text = readProtectedPublicText(GATE_READINESS_SOURCE_FILE, 1024 * 1024)
  const value = parseStrictJson(text, { maxBytes: 1024 * 1024 })
  return { text, value }
}

// Bounds apply to NEW audit entries only. Retained signed TEXT is never normalized,
// truncated or rewritten. Detached data prevents caller getters/toJSON from signing a
// different payload, while ordinary JSON property order and bytes stay unchanged.
export const LEDGER_DETAIL_MAX_BYTES = 64 * 1024
export const LEDGER_BODY_MAX_BYTES = 160 * 1024
export function boundedLedgerJson(value) {
  let nodes = 0, textBytes = 0
  const seen = new Set()
  const fail = () => { throw new Error('ledger entry refused: bounded JSON data required') }
  const text = s => {
    if (!s.isWellFormed()) fail()
    textBytes += Buffer.byteLength(s, 'utf8')
    if (textBytes > LEDGER_DETAIL_MAX_BYTES) fail()
    return s
  }
  function copy(v, depth) {
    if (++nodes > 4096 || depth > 16) fail()
    if (v === null || typeof v === 'boolean') return v
    if (typeof v === 'string') return text(v)
    if (typeof v === 'number' && Number.isFinite(v)) return v
    if (!v || typeof v !== 'object' || seen.has(v)) fail()
    const array = Array.isArray(v), proto = Object.getPrototypeOf(v)
    if (array ? proto !== Array.prototype : ![Object.prototype, null].includes(proto)) fail()
    const keys = Reflect.ownKeys(v)
    if (keys.length > 4097 || keys.some(k => typeof k !== 'string')) fail()
    seen.add(v)
    const out = array ? [] : Object.create(null)
    if (array) {
      const length = Object.getOwnPropertyDescriptor(v, 'length')?.value
      if (!Number.isSafeInteger(length) || length > 4096 || keys.length !== length + 1) fail()
      // JSON.stringify still recognizes an array after removing inherited hooks.
      Object.setPrototypeOf(out, null)
      for (let i = 0; i < length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, String(i))
        if (!d?.enumerable || !Object.hasOwn(d, 'value')) fail()
        out[i] = d.value === undefined ? null : copy(d.value, depth + 1)
      }
    } else for (const k of keys) {
      const d = Object.getOwnPropertyDescriptor(v, k)
      if (!d?.enumerable || !Object.hasOwn(d, 'value')) fail()
      if (d.value === undefined) continue
      out[text(k)] = copy(d.value, depth + 1)
    }
    seen.delete(v)
    return out
  }
  const encoded = JSON.stringify(copy(value, 0))
  if (Buffer.byteLength(encoded, 'utf8') > LEDGER_DETAIL_MAX_BYTES) fail()
  return encoded
}

export const GATE_COMPLETED_RESULT_DOMAIN = 'aukora:gate-completed-result:v1\0'
export const GATE_CAPTURE_DOMAIN = 'aukora:gate-capture:v1\0'
export const GATE_COMPLETED_RESULT_FIELDS = Object.freeze(['applied', 'state', 'entry', 'receipt', 'receipt_sig', 'ledger_seq', 'ledger_hash', 'message'])
const CAPTURE_FIELDS = ['version', 'kind', 'source', 'proposal_id', 'gate_pubkey_sha256', 'completed_result_sha256']
const RECEIPT_FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver', 'pubkey_fp',
  'gate_pubkey_sha256', 'owner_authorization', 'owner_accepted_at_ms', 'owner_consumption']
const LEGACY_RECEIPT_FIELDS = ['v', 'kind', 'proposal', 'target', 'base_sha', 'new_sha', 'applied_at', 'approver',
  'approval_evidence_hmac', 'pubkey_fp']
const hex64 = value => typeof value === 'string' && value.length === 64 && SHA.test(value)
const safeTime = value => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0
const sequence = value => safeTime(value) && value > 0
const printable = value => typeof value === 'string' && value.length >= 1 && value.length <= 200 && !/[^\x20-\x7e]/u.test(value)
const journalIdentifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 128
  && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) && !/[^A-Za-z0-9._:-]/u.test(value)
const uuid = value => typeof value === 'string' && value.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
const captureFail = () => { throw new Error('gate-capture:unavailable-or-invalid') }
function closedCaptureRecord(value, fields, preserveOrder = false) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) captureFail()
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(k => typeof k !== 'string' || !fields.includes(k))) captureFail()
  const out = Object.create(null)
  for (const field of preserveOrder ? keys : fields) {
    const d = descriptors[field]
    if (!d?.enumerable || !Object.hasOwn(d, 'value')) captureFail()
    out[field] = d.value
  }
  return out
}
function signatureBytes(text) {
  if (typeof text !== 'string' || text.length !== 88) captureFail()
  const bytes = Buffer.from(text, 'base64')
  if (bytes.length !== 64 || bytes.toString('base64') !== text) captureFail()
  return bytes
}
function completedResultCore(value) {
  const core = closedCaptureRecord(value, GATE_COMPLETED_RESULT_FIELDS)
  if (core.applied !== true || core.state !== 'applied' || core.message !== 'applied' || !printable(core.entry)
    || !sequence(core.ledger_seq) || !hex64(core.ledger_hash)) captureFail()
  signatureBytes(core.receipt_sig)
  const version = core.receipt && typeof core.receipt === 'object'
    ? Object.getOwnPropertyDescriptor(core.receipt, 'v') : null
  const legacy = version && Object.hasOwn(version, 'value') && version.value === 2
  const receipt = closedCaptureRecord(core.receipt, legacy ? LEGACY_RECEIPT_FIELDS : RECEIPT_FIELDS, true)
  if (legacy) {
    const hmac = typeof receipt.approval_evidence_hmac === 'string' ? Buffer.from(receipt.approval_evidence_hmac, 'base64') : null
    // A v2 receipt records the original owner-channel/HMAC ceremony. Its gate capture proves
    // source association only; it never supplies or implies a G owner-authorization proof.
    if (receipt.v !== 2 || !['change', 'revert'].includes(receipt.kind) || !uuid(receipt.proposal)
      || !printable(receipt.target) || !(receipt.base_sha === 'absent' || hex64(receipt.base_sha)) || !hex64(receipt.new_sha)
      || receipt.base_sha === receipt.new_sha || typeof receipt.applied_at !== 'string' || receipt.applied_at.length > 32
      || !Number.isFinite(Date.parse(receipt.applied_at)) || typeof receipt.approver !== 'string' || receipt.approver.length === 0
      || typeof receipt.pubkey_fp !== 'string' || !/^[0-9a-f]{16}$/u.test(receipt.pubkey_fp) || receipt.pubkey_fp.length !== 16
      || !hmac || hmac.length !== 32 || hmac.toString('base64') !== receipt.approval_evidence_hmac) captureFail()
    core.receipt = receipt
    return core
  }
  const reference = closedCaptureRecord(receipt.owner_authorization, ['version', 'kind', 'authorization_id', 'proof_sha256'], true)
  const consumption = closedCaptureRecord(receipt.owner_consumption, ['ledger_seq', 'ledger_hash', 'review_issue'], true)
  const issue = closedCaptureRecord(consumption.review_issue, ['ledger_seq', 'ledger_hash'], true)
  if (receipt.v !== 3 || !['change', 'revert'].includes(receipt.kind) || !uuid(receipt.proposal)
    || !printable(receipt.target) || !(receipt.base_sha === 'absent' || hex64(receipt.base_sha)) || !hex64(receipt.new_sha)
    || receipt.base_sha === receipt.new_sha || typeof receipt.applied_at !== 'string' || receipt.applied_at.length > 32
    || !Number.isFinite(Date.parse(receipt.applied_at)) || typeof receipt.approver !== 'string'
    || !/^aukora:1:[0-9a-f]{64}$/u.test(receipt.approver) || receipt.approver.length !== 73
    || !hex64(receipt.gate_pubkey_sha256) || receipt.pubkey_fp !== receipt.gate_pubkey_sha256.slice(0, 16)
    || !safeTime(receipt.owner_accepted_at_ms) || reference.version !== 1 || reference.kind !== 'aukora-owner-authorization-ref/v1'
    || !hex64(reference.authorization_id) || !hex64(reference.proof_sha256)
    || !sequence(issue.ledger_seq) || !hex64(issue.ledger_hash) || !sequence(consumption.ledger_seq)
    || !hex64(consumption.ledger_hash) || issue.ledger_seq >= consumption.ledger_seq || consumption.ledger_seq >= core.ledger_seq) captureFail()
  // Detach every descriptor snapshot, preserving the receipt's original property order. Never
  // serialize a raw caller object: a Proxy/toJSON trap could substitute different signed bytes.
  consumption.review_issue = issue
  receipt.owner_authorization = reference
  receipt.owner_consumption = consumption
  core.receipt = receipt
  return core
}
export function gateCompletedResultDigest(result) {
  return sha256(Buffer.from(GATE_COMPLETED_RESULT_DOMAIN + JSON.stringify(completedResultCore(result)), 'utf8'))
}
export function gateCaptureSigningBytes(supplied) {
  const capture = closedCaptureRecord(supplied, CAPTURE_FIELDS)
  const source = closedCaptureRecord(capture.source, ['journal_id', 'position', 'hash'])
  if (capture.version !== 1 || capture.kind !== 'aukora-gate-capture/v1' || !journalIdentifier(source.journal_id)
    || !sequence(source.position) || !hex64(source.hash) || !uuid(capture.proposal_id)
    || !hex64(capture.gate_pubkey_sha256) || !hex64(capture.completed_result_sha256)) captureFail()
  capture.source = source
  return Buffer.from(GATE_CAPTURE_DOMAIN + JSON.stringify(capture), 'utf8')
}
function completedGateResult(supplied) {
  const full = closedCaptureRecord(supplied, [...GATE_COMPLETED_RESULT_FIELDS, 'gate_capture'])
  const core = completedResultCore(Object.fromEntries(GATE_COMPLETED_RESULT_FIELDS.map(field => [field, full[field]])))
  const envelope = closedCaptureRecord(full.gate_capture, ['capture', 'signature_base64'])
  const capture = closedCaptureRecord(envelope.capture, CAPTURE_FIELDS)
  capture.source = closedCaptureRecord(capture.source, ['journal_id', 'position', 'hash'])
  gateCaptureSigningBytes(capture)
  signatureBytes(envelope.signature_base64)
  return { ...core, gate_capture: { capture, signature_base64: envelope.signature_base64 } }
}

/** Public completion/capture verification only. Expectations are independent trusted public pins.
 * This projects a source pointer, not owner enrollment or archival owner-authorization acceptance. */
export function verifyCompletedGateCapture(supplied, expectations) {
  const full = completedGateResult(supplied)
  const core = completedResultCore(Object.fromEntries(GATE_COMPLETED_RESULT_FIELDS.map(field => [field, full[field]])))
  const e = closedCaptureRecord(expectations, ['journal_id', 'gate_public_key_pem', 'gate_pubkey_sha256'])
  if (!journalIdentifier(e.journal_id) || !hex64(e.gate_pubkey_sha256) || typeof e.gate_public_key_pem !== 'string'
    || Buffer.byteLength(e.gate_public_key_pem) > 1024) captureFail()
  const key = createPublicKey(e.gate_public_key_pem)
  if (key.asymmetricKeyType !== 'ed25519' || sha256(key.export({ format: 'der', type: 'spki' })) !== e.gate_pubkey_sha256) captureFail()
  const envelope = closedCaptureRecord(full.gate_capture, ['capture', 'signature_base64'])
  const capture = closedCaptureRecord(envelope.capture, CAPTURE_FIELDS)
  const source = closedCaptureRecord(capture.source, ['journal_id', 'position', 'hash'])
  if (source.journal_id !== e.journal_id || source.position !== core.ledger_seq || source.hash !== core.ledger_hash
    || capture.proposal_id !== core.receipt.proposal || capture.gate_pubkey_sha256 !== e.gate_pubkey_sha256
    || (core.receipt.v === 3 ? core.receipt.gate_pubkey_sha256 !== e.gate_pubkey_sha256
      : core.receipt.pubkey_fp !== e.gate_pubkey_sha256.slice(0, 16))
    || capture.completed_result_sha256 !== gateCompletedResultDigest(core)
    || !verify(null, Buffer.from(JSON.stringify(core.receipt)), key, signatureBytes(core.receipt_sig))
    || !verify(null, gateCaptureSigningBytes(capture), key, signatureBytes(envelope.signature_base64))) captureFail()
  return Object.freeze({ source: Object.freeze({ journal_id: source.journal_id, position: source.position, hash: source.hash }) })
}

export function keyFingerprint(pub) { return sha256(pub.export({ type: 'spki', format: 'der' })).slice(0, 16) }

// Receipt signing key, created once (0600, exclusive create) in the gate's private home.
export function loadOrCreateKey(home) {
  const kp = path.join(home, 'receipt-ed25519.pem')
  if (!fs.existsSync(kp)) fs.writeFileSync(kp, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' })
  const priv = createPrivateKey(fs.readFileSync(kp)); const pub = createPublicKey(priv)
  return { priv, pub, pubPem: pub.export({ type: 'spki', format: 'pem' }).toString(), fp: keyFingerprint(pub) }
}

export function openDb(file, { readOnly = false } = {}) {
  const db = new DatabaseSync(file, readOnly ? { readOnly: true } : {})
  if (readOnly) return db
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
    CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY, kind TEXT, target TEXT, base_sha TEXT, new_sha TEXT, diff TEXT,
      why TEXT, session TEXT, call_id TEXT, created INTEGER, expires INTEGER, displayable INTEGER, state TEXT, note TEXT, updated INTEGER);
    CREATE TABLE IF NOT EXISTS blobs(sha TEXT PRIMARY KEY, target TEXT, bytes BLOB, first_seen TEXT);
    CREATE TABLE IF NOT EXISTS ledger(seq INTEGER PRIMARY KEY, at TEXT NOT NULL, event TEXT NOT NULL, proposal TEXT, target TEXT,
      base_sha TEXT, new_sha TEXT, detail TEXT, prev TEXT NOT NULL, hash TEXT NOT NULL, sig TEXT NOT NULL);
    CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
    -- A shared bounded-window admission counter, not signed history or an owner limit.
    CREATE TABLE IF NOT EXISTS propose_budget(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      window_start_ms INTEGER NOT NULL CHECK(window_start_ms>=0), used INTEGER NOT NULL CHECK(used>=0));
    -- Additive source migration: existing signed rows and positional inserts stay byte-identical.
    CREATE TABLE IF NOT EXISTS owner_authorization_required(
      singleton INTEGER PRIMARY KEY CHECK(singleton=1), gate TEXT NOT NULL,
      require_seq INTEGER NOT NULL UNIQUE, require_hash TEXT NOT NULL);
    CREATE TRIGGER IF NOT EXISTS owner_authorization_required_no_update BEFORE UPDATE ON owner_authorization_required
      BEGIN SELECT RAISE(ABORT, 'owner authorization enforcement is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS owner_authorization_required_no_delete BEFORE DELETE ON owner_authorization_required
      BEGIN SELECT RAISE(ABORT, 'owner authorization enforcement is retained'); END;
    CREATE TABLE IF NOT EXISTS owner_authorization_reviews(
      gate TEXT NOT NULL, challenge TEXT NOT NULL, proposal_id TEXT NOT NULL,
      authorization_id TEXT NOT NULL UNIQUE, authorization_text TEXT NOT NULL, owner_state_text TEXT NOT NULL,
      issued_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, issue_seq INTEGER NOT NULL, issue_hash TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('live','spent','invalidated','expired')),
      spent_at_ms INTEGER, spend_seq INTEGER, PRIMARY KEY(gate,challenge));
    CREATE UNIQUE INDEX IF NOT EXISTS owner_authorization_live_review ON owner_authorization_reviews(proposal_id) WHERE state='live';
    CREATE TRIGGER IF NOT EXISTS owner_authorization_review_no_delete BEFORE DELETE ON owner_authorization_reviews
      BEGIN SELECT RAISE(ABORT, 'owner review facts are retained'); END;
    CREATE TRIGGER IF NOT EXISTS owner_authorization_review_facts BEFORE UPDATE ON owner_authorization_reviews
      WHEN OLD.gate IS NOT NEW.gate OR OLD.challenge IS NOT NEW.challenge OR OLD.proposal_id IS NOT NEW.proposal_id
        OR OLD.authorization_id IS NOT NEW.authorization_id OR OLD.authorization_text IS NOT NEW.authorization_text
        OR OLD.owner_state_text IS NOT NEW.owner_state_text OR OLD.issued_at_ms IS NOT NEW.issued_at_ms
        OR OLD.expires_at_ms IS NOT NEW.expires_at_ms OR OLD.issue_seq IS NOT NEW.issue_seq OR OLD.issue_hash IS NOT NEW.issue_hash
        OR OLD.state != 'live' OR NEW.state = 'live'
      BEGIN SELECT RAISE(ABORT, 'owner review facts are immutable; terminal reviews cannot revive'); END;
    CREATE TABLE IF NOT EXISTS owner_authorization_consumptions(
      authorization_id TEXT PRIMARY KEY, proof_sha256 TEXT NOT NULL UNIQUE, gate TEXT NOT NULL, challenge TEXT NOT NULL,
      proposal_id TEXT NOT NULL UNIQUE, proof_text TEXT NOT NULL, accepted_at_ms INTEGER NOT NULL,
      consume_seq INTEGER NOT NULL UNIQUE, consume_hash TEXT NOT NULL, issue_seq INTEGER NOT NULL, issue_hash TEXT NOT NULL,
      owner_state_text TEXT NOT NULL, UNIQUE(gate,challenge));
    CREATE TRIGGER IF NOT EXISTS owner_authorization_consumption_no_update BEFORE UPDATE ON owner_authorization_consumptions
      BEGIN SELECT RAISE(ABORT, 'owner consumption is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS owner_authorization_consumption_no_delete BEFORE DELETE ON owner_authorization_consumptions
      BEGIN SELECT RAISE(ABORT, 'owner consumption is retained'); END;
    CREATE TABLE IF NOT EXISTS gate_completed_results(
      proposal_id TEXT PRIMARY KEY NOT NULL, apply_seq INTEGER NOT NULL UNIQUE, apply_hash TEXT NOT NULL,
      completed_result_sha256 TEXT NOT NULL, result_text TEXT NOT NULL, retained_at_ms INTEGER NOT NULL);
    CREATE TRIGGER IF NOT EXISTS gate_completed_result_no_update BEFORE UPDATE ON gate_completed_results
      BEGIN SELECT RAISE(ABORT, 'original gate completion is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS gate_completed_result_no_delete BEFORE DELETE ON gate_completed_results
      BEGIN SELECT RAISE(ABORT, 'original gate completion is retained'); END;`)
  return db
}

export const entryBody = (e) => JSON.stringify([e.seq, e.at, e.event, e.proposal ?? null, e.target ?? null, e.base_sha ?? null, e.new_sha ?? null, e.detail ?? null, e.prev])

// Preserve the original TEXT detail: parsing and reserializing it would change the signed ledger body.
export function signedEntryData(e) {
  return Object.fromEntries(['seq', 'at', 'event', 'proposal', 'target', 'base_sha', 'new_sha', 'detail', 'prev', 'hash', 'sig'].map(k => [k, e[k]]))
}

export function verifyLedger(db, pub) {
  let prev = 'GENESIS', n = 0; const errors = []
  for (const e of db.prepare('SELECT * FROM ledger ORDER BY seq').iterate()) {
    n++
    if (e.seq !== n) errors.push(`seq gap at ${e.seq} (expected ${n})`)
    if (e.prev !== prev) errors.push(`seq ${e.seq}: prev ${String(e.prev).slice(0, 12)} != ${prev.slice(0, 12)}`)
    if (sha256(entryBody(e)) !== e.hash) errors.push(`seq ${e.seq}: hash mismatch`)
    let good = false; try { good = verify(null, Buffer.from(e.hash, 'hex'), pub, Buffer.from(e.sig, 'base64')) } catch {}
    if (!good) errors.push(`seq ${e.seq}: bad signature`)
    prev = e.hash; if (errors.length > 20) break
  }
  return { ok: errors.length === 0, entries: n, head: prev, errors }
}

export function createLedger(db, key, iso = () => new Date().toISOString()) {
  function append(event, f = {}) {
    const field = (v, max, nullable = true) => {
      if (v === null && nullable) return v
      if (typeof v !== 'string' || !v.isWellFormed() || Buffer.byteLength(v, 'utf8') > max)
        throw new Error('ledger entry refused: field exceeds bound or is invalid')
      return v
    }
    const detail = f.detail === undefined ? null : boundedLedgerJson(f.detail)
    const last = db.prepare('SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1').get()
    const e = { seq: (last?.seq ?? 0) + 1, at: field(iso(), 64, false), event: field(event, 128, false),
      proposal: field(f.proposal ?? null, 128), target: field(f.target ?? null, 512),
      base_sha: field(f.base_sha ?? null, 128), new_sha: field(f.new_sha ?? null, 128), detail, prev: last?.hash ?? 'GENESIS' }
    const body = entryBody(e)
    if (Buffer.byteLength(body, 'utf8') > LEDGER_BODY_MAX_BYTES) throw new Error('ledger entry refused: body exceeds byte bound')
    e.hash = sha256(body); e.sig = sign(null, Buffer.from(e.hash, 'hex'), key.priv).toString('base64')
    db.prepare('INSERT INTO ledger VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(e.seq, e.at, e.event, e.proposal, e.target, e.base_sha, e.new_sha, e.detail, e.prev, e.hash, e.sig)
    return e
  }
  function checkedCompletion(supplied) {
    const result = completedGateResult(supplied)
    const core = Object.fromEntries(GATE_COMPLETED_RESULT_FIELDS.map(field => [field, result[field]]))
    verifyCompletedGateCapture(result, { journal_id: result.gate_capture.capture.source.journal_id,
      gate_public_key_pem: key.pub.export({ type: 'spki', format: 'pem' }).toString(),
      gate_pubkey_sha256: sha256(key.pub.export({ type: 'spki', format: 'der' })) })
    const row = db.prepare('SELECT * FROM ledger WHERE seq=?').get(result.ledger_seq)
    if (!row || row.proposal !== result.receipt.proposal || row.hash !== result.ledger_hash
      || row.event !== (result.receipt.kind === 'revert' ? 'revert-applied' : 'apply')
      || row.target !== result.receipt.target || row.base_sha !== result.receipt.base_sha || row.new_sha !== result.receipt.new_sha
      || sha256(entryBody(row)) !== row.hash || !verify(null, Buffer.from(row.hash, 'hex'), key.pub, signatureBytes(row.sig))) captureFail()
    const detail = JSON.parse(row.detail)
    if (JSON.stringify(detail.receipt) !== JSON.stringify(result.receipt) || detail.receipt_sig !== result.receipt_sig) captureFail()
    return { result, digest: gateCompletedResultDigest(core), text: JSON.stringify(result) }
  }
  // Called only after original apply COMMIT and capture mint. This never signs or reconstructs
  // a completion from target bytes, a current entry spec, a later row, or the current journal tip.
  function retainCompletedResult(supplied, retainedAtMs) {
    if (!safeTime(retainedAtMs)) captureFail()
    const { result, digest, text } = checkedCompletion(supplied)
    const proposal = db.prepare('SELECT state FROM proposals WHERE id=?').get(result.receipt.proposal)
    if (proposal?.state !== 'applied') captureFail()
    const written = db.prepare(`INSERT INTO gate_completed_results(proposal_id,apply_seq,apply_hash,completed_result_sha256,result_text,retained_at_ms)
      VALUES(?,?,?,?,?,?)`).run(result.receipt.proposal, result.ledger_seq, result.ledger_hash, digest, text, retainedAtMs)
    if (written.changes !== 1) throw new Error('gate-capture:original-completion-retention-unavailable')
    const retained = db.prepare('SELECT * FROM gate_completed_results WHERE proposal_id=?').get(result.receipt.proposal)
    if (!retained || retained.apply_seq !== result.ledger_seq || retained.apply_hash !== result.ledger_hash
      || retained.completed_result_sha256 !== digest || retained.result_text !== text || retained.retained_at_ms !== retainedAtMs)
      throw new Error('gate-capture:original-completion-retention-unavailable')
    return supplied
  }
  function retainedCompletedResult(proposalId) {
    const row = db.prepare('SELECT * FROM gate_completed_results WHERE proposal_id=?').get(proposalId)
    if (!row) return null
    const original = JSON.parse(row.result_text)
    const { result, digest, text } = checkedCompletion(original)
    if (result.receipt.proposal !== proposalId || row.apply_seq !== result.ledger_seq || row.apply_hash !== result.ledger_hash
      || row.completed_result_sha256 !== digest || row.result_text !== text) captureFail()
    return original
  }
  return { append, retainCompletedResult, retainedCompletedResult, verify: () => verifyLedger(db, key.pub) }
}
