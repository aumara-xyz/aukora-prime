// SPDX-License-Identifier: AGPL-3.0-or-later
// JOIN1 integration only. B owns plugins/aukora-nostr/lib/records.mjs and all
// record cryptography. This collector never creates keys or repeats gate effects.
// Run: node scripts/aura/collect-gate.mjs /absolute/trusted-context.mjs
// That operator-owned module exports {snapshotOptions,storeDir,codec}; codec is
// createNostrCollectorCodec(...) using EXISTING scoped material and public pins.
// No private key is accepted in argv, checkpoint, stdout or source ledger I/O.
import { spawn } from 'node:child_process'
import { isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readGateSnapshot } from './gate-snapshot.mjs'
import { parseUniqueJson, verifyAuraStream, verifyGateSnapshot, verifyCollectorStoreCitation } from './verify-collected.mjs'
import { canonicalJson } from '../../packages/contracts/src/json.mjs'

export const ZERO_ID = '0'.repeat(64)
export const OBSERVATION_SCHEMA = 'aukora:aura:gate-observation:v1'
export const CHECKPOINT_SCHEMA = 'aukora:aura:collector-checkpoint:v1'
const MAX_LOG_BYTES = 32 * 1024 * 1024
const MAX_EVENT_BYTES = 512 * 1024
const CODEC_OWNER_SCOPES = new WeakMap()
const incomplete = reason => Object.assign(new Error(reason), { code: reason })

/** B's frozen API, with mandatory independent public pins; no alternate codec. */
export async function createNostrCollectorCodec({ records, authorSecretKeyHex,
  binding, controllerKeyHex, ownerSubject, authorPubkeyHex, ownerPubkeyHex } = {}) {
  // The record library is passed in by the operator's trusted context (no default path): the repo
  // carries it at plugins/aukora-nostr/lib, a release at aukora-nostr/lib.
  if (records === null || typeof records !== 'object') throw incomplete('aura-collector:record-library-unavailable')
  for (const name of ['buildRecord', 'signRecord', 'verifyRecord', 'encryptPrivateContent', 'decryptRecord'])
    if (typeof records[name] !== 'function') throw incomplete('aura-collector:record-library-unavailable')
  if (typeof authorSecretKeyHex !== 'string' || !/^[0-9a-f]{64}$/u.test(authorSecretKeyHex))
    throw incomplete('aura-collector:scoped-signer-unavailable')
  if (typeof ownerSubject !== 'string' || !/^aukora:1:[0-9a-f]{64}$/u.test(ownerSubject)
      || typeof ownerPubkeyHex !== 'string' || !/^[0-9a-f]{64}$/u.test(ownerPubkeyHex))
    throw incomplete('aura-collector:owner-scope-invalid')
  const pins = Object.freeze({ binding, controllerKeyHex, ownerSubject, authorPubkeyHex, ownerPubkeyHex })
  const verify = event => {
    const metadata = records.verifyRecord(event, pins)
    const plaintext = records.decryptRecord(event, { ...pins, authorSecretKeyHex })
    return { ...metadata, plaintext }
  }
  const build = ({ sequence, previous_id, source, action_id, content, created_at }) => {
    const ciphertext = records.encryptPrivateContent(content, { authorSecretKeyHex, ownerPubkeyHex })
    const draft = records.buildRecord({ type: 'aura', pubkey: authorPubkeyHex, created_at,
      sequence, previous_id, source, action_id, owner_pubkey_hex: ownerPubkeyHex, content: ciphertext })
    const event = records.signRecord(draft, authorSecretKeyHex)
    records.verifyRecord(event, pins)
    return event
  }
  const codec = Object.freeze({ build, verify })
  CODEC_OWNER_SCOPES.set(codec, Object.freeze({ owner_subject: ownerSubject, owner_pubkey_hex: ownerPubkeyHex }))
  return codec
}

/**
 * Trusted-worker facade: construct from the operator's collectorContext, then
 * pass the authenticated subject resolved by the host, never guest owner text.
 * The private codec brand captures the same owner pins used by B verification.
 * Selectors carry only exact source coordinates and an optional actual record ID.
 * Request authentication and verified note-to-source associations are host obligations.
 */
export function createCollectorCitationReader(collectorContext) {
  const codec = collectorContext?.codec
  const scope = CODEC_OWNER_SCOPES.get(codec)
  if (!scope) throw incomplete('aura-citation:owner-scope-unavailable')
  let snapshotOptions, anchors
  try {
    snapshotOptions = parseUniqueJson(canonicalJson(collectorContext.snapshotOptions))
    if (collectorContext.anchors !== undefined) anchors = parseUniqueJson(canonicalJson(collectorContext.anchors))
  } catch { throw incomplete('aura-citation:context-invalid') }
  const context = Object.freeze({ snapshotOptions, anchors, codec,
    storeDir: collectorContext.storeDir, pythonExecutable: collectorContext.pythonExecutable })
  return Object.freeze({
    async readCitation(authenticatedOwnerSubject, selector) {
      if (typeof authenticatedOwnerSubject !== 'string' || authenticatedOwnerSubject !== scope.owner_subject)
        return Object.freeze({ ok: false, status: 'incomplete', reason: 'aura-citation:owner-mismatch',
          grants_authority: false, citation: null, verification: null })
      return verifyCollectorStoreCitation(context, selector, scope)
    },
  })
}

// A short-lived private stdio helper holds flock AND performs all output I/O.
// Its kernel lock releases on death/pipe EOF. No stale PID lease is reclaimed,
// no sibling process is killed, and a dead lock helper cannot leave a Node writer.
// Standard-library Python only; no new database, daemon, credentials or service.
const STORE_HELPER = String.raw`
import os,sys,json,stat,fcntl
MAX_LOG=32*1024*1024
MAX_EVENT=512*1024
def reply(value):
    sys.stdout.write(json.dumps(value,separators=(',',':'))+'\n');sys.stdout.flush()
def safe(fd):
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_uid!=os.getuid() or info.st_nlink!=1:
        raise ValueError('unsafe')
    return info
def read_fd(fd,limit):
    if safe(fd).st_size>limit: raise ValueError('size')
    os.lseek(fd,0,os.SEEK_SET)
    result=b''
    while True:
        block=os.read(fd,min(65536,limit+1-len(result)))
        if not block: break
        result+=block
        if len(result)>limit: raise ValueError('size')
    return result.decode('utf-8','strict')
def full_write(fd,data):
    offset=0
    while offset<len(data):
        n=os.write(fd,data[offset:])
        if n<=0: raise OSError('write')
        offset+=n
try:
    root=sys.argv[1]
    if not os.path.isabs(root): raise ValueError('path')
    os.makedirs(root,mode=0o700,exist_ok=True)
    info=os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o077 or info.st_uid!=os.getuid(): raise ValueError('directory')
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    opened=os.fstat(directory)
    if not stat.S_ISDIR(opened.st_mode) or opened.st_mode&0o077 or opened.st_uid!=os.getuid() or (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino): raise ValueError('directory')
    flags=os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK
    lock=os.open('collector.lock',flags,0o600,dir_fd=directory);safe(lock)
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        reply({'ok':False,'reason':'aura-collector:busy'});sys.exit(1)
    log=os.open('gate-observations.nostr.jsonl',flags|os.O_APPEND,0o600,dir_fd=directory)
    text=read_fd(log,MAX_LOG)
    checkpoint=None
    try:
        cp=os.open('checkpoint.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try: checkpoint=read_fd(cp,65536)
        finally: os.close(cp)
    except FileNotFoundError: pass
    os.fsync(directory)
    reply({'ok':True,'log':text,'checkpoint':checkpoint})
    while True:
        raw=sys.stdin.buffer.readline(MAX_EVENT+65537)
        if not raw: break
        if not raw.endswith(b'\n') or len(raw)>MAX_EVENT+65536: raise ValueError('frame')
        request=json.loads(raw)
        if request.get('op')=='append' and set(request)=={'op','line'}:
            line=request['line']
            if not isinstance(line,str) or not line.endswith('\n') or line.count('\n')!=1: raise ValueError('line')
            data=line.encode('utf-8')
            if len(data)>MAX_EVENT or safe(log).st_size+len(data)>MAX_LOG: raise ValueError('size')
            json.loads(line)
            full_write(log,data);os.fsync(log)
            reply({'ok':True,'events_bytes':os.fstat(log).st_size})
        elif request.get('op')=='checkpoint' and set(request)=={'op','value'}:
            data=(json.dumps(request['value'],separators=(',',':'))+'\n').encode('utf-8')
            if len(data)>65536: raise ValueError('checkpoint')
            temp='checkpoint.pending.'+str(os.getpid())
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try: full_write(fd,data);os.fsync(fd)
            finally: os.close(fd)
            os.replace(temp,'checkpoint.json',src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
            reply({'ok':True})
        else: raise ValueError('operation')
    os.close(log);os.close(lock);os.close(directory)
except SystemExit: raise
except Exception:
    reply({'ok':False,'reason':'aura-collector:store-unavailable'});sys.exit(1)
`

/** Open only collector-owned output files; the source SQLite is never passed. */
export async function openCollectorStore(storeDir, { pythonExecutable = 'python3' } = {}) {
  if (typeof storeDir !== 'string' || !isAbsolute(storeDir) || /[\x00-\x1f\x7f]/u.test(storeDir))
    throw incomplete('aura-collector:store-path-invalid')
  const child = spawn(pythonExecutable, ['-I', '-c', STORE_HELPER, storeDir], { stdio: ['pipe', 'pipe', 'pipe'] })
  let partial = '', partialBytes = 0, terminal, pending
  const ready = new Promise((resolve, reject) => { pending = { resolve, reject } })
  const fail = () => {
    terminal = incomplete('aura-collector:store-unavailable')
    pending?.reject(terminal); pending = undefined
  }
  child.once('error', fail)
  child.stdin.on('error', fail)
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', chunk => {
    partialBytes += Buffer.byteLength(chunk)
    if (partialBytes > MAX_LOG_BYTES * 2 + 65536) { fail(); child.stdin.destroy(); return }
    partial += chunk
    let at
    while ((at = partial.indexOf('\n')) >= 0) {
      const line = partial.slice(0, at); partial = partial.slice(at + 1)
      partialBytes = Buffer.byteLength(partial)
      if (!pending) { fail(); child.stdin.destroy(); return }
      const replyTo = pending; pending = undefined
      try {
        const result = JSON.parse(line)
        if (result?.ok !== true) throw incomplete(result?.reason === 'aura-collector:busy'
          ? result.reason : 'aura-collector:store-unavailable')
        replyTo.resolve(result)
      } catch (error) { replyTo.reject(error.code ? error : incomplete('aura-collector:store-unavailable')) }
    }
  })
  // Suppress all helper diagnostics; paths and private content never reach logs.
  child.stderr.resume()
  const ended = new Promise(resolve => child.once('close', () => { fail(); resolve() }))
  let opened
  try { opened = await ready } catch (error) { child.stdin.end(); await ended; throw error }
  const request = value => {
    if (terminal || pending) return Promise.reject(terminal ?? incomplete('aura-collector:store-busy'))
    return new Promise((resolve, reject) => {
      pending = { resolve, reject }
      child.stdin.write(`${JSON.stringify(value)}\n`, error => { if (error) fail() })
    })
  }
  return Object.freeze({ log: opened.log, checkpoint: opened.checkpoint,
    append: line => request({ op: 'append', line }),
    checkpointWrite: value => request({ op: 'checkpoint', value }),
    close: async () => { child.stdin.end(); await ended } })
}

function parseStream(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_LOG_BYTES || (text && !text.endsWith('\n')))
    throw incomplete('aura-collector:torn-or-oversized-log')
  const lines = text ? text.slice(0, -1).split('\n') : []
  const events = [], bytes = [0]
  for (const line of lines) {
    if (!line || Buffer.byteLength(line) + 1 > MAX_EVENT_BYTES) throw incomplete('aura-collector:log-malformed')
    events.push(parseUniqueJson(line)); bytes.push(bytes.at(-1) + Buffer.byteLength(line) + 1)
  }
  return { events, bytes }
}

function checkpointAt(source, stream, events, bytes, position) {
  return { schema: CHECKPOINT_SCHEMA, source: { ...source },
    source_head: position ? { position, hash: stream.verified_records[position - 1].hash } : { position: 0, hash: 'GENESIS' },
    aura_head: position ? { sequence: position, id: events[position - 1].id } : { sequence: 0, id: ZERO_ID },
    events_bytes: bytes[position] }
}
function checkCheckpoint(text, source, stream, events, bytes) {
  if (text === null) return
  const cp = parseUniqueJson(text), n = cp?.source_head?.position
  if (!Number.isSafeInteger(n) || n < 0 || n > events.length
    || canonicalJson(cp) !== canonicalJson(checkpointAt(source, stream, events, bytes, n)))
    throw incomplete('aura-collector:checkpoint-divergence')
}

/** One complete selected snapshot. Success is source coverage, never approval. */
export async function collectGateOnce({ snapshotOptions, snapshot, storeDir, codec,
  now = () => Math.floor(Date.now() / 1000), afterAppend, pythonExecutable } = {}) {
  let store, retained, selected
  const result = (status, reason, extra = {}) => ({ ok: status === 'complete', status,
    ...(reason ? { reason } : {}), grants_authority: false,
    claim: status === 'complete' ? 'gate records collected through the selected head' : 'source coverage incomplete',
    full_aura_coverage: 'OPEN',
    ...(selected ? { selected_head: selected } : {}), ...extra })
  try {
    if (!codec || typeof codec.build !== 'function' || typeof codec.verify !== 'function')
      throw incomplete('aura-collector:record-codec-unavailable')
    // Snapshot verifier pins the source; missing/gap/altered rows never reach append.
    const input = snapshot ?? readGateSnapshot(snapshotOptions)
    selected = input.selected_head
    if (input.ok !== true) return result('incomplete', input.reason ?? 'aura-collector:source-incomplete')
    const gatePublicKey = snapshotOptions?.publicKeyPem
    if (!gatePublicKey) throw incomplete('aura-collector:gate-public-key-unavailable')
    if (input.source?.journal_id !== snapshotOptions.sourceId
        || input.source?.key_sha256 !== snapshotOptions.expectedKeySha256)
      throw incomplete('aura-collector:source-pin-mismatch')
    verifyGateSnapshot(input, input.source, gatePublicKey)
    store = await openCollectorStore(storeDir, { pythonExecutable })
    const { events, bytes } = parseStream(store.log)
    retained = await verifyAuraStream(events, { codec, source: input.source, gatePublicKey })
    if (retained.ok !== true) return result('incomplete', retained.reason)
    checkCheckpoint(store.checkpoint, input.source, retained, events, bytes)
    if (retained.coverage.position > input.selected_head.position)
      throw incomplete('aura-collector:source-truncated')
    // Historical coverage is checked even when the current snapshot has grown.
    for (let i = 0; i < retained.verified_records.length; i++) {
      const old = retained.verified_records[i], current = input.records[i]
      if (!current || old.hash !== current.hash || old.entry_body !== current.entry_body)
        throw incomplete('aura-collector:source-history-altered')
    }
    let appended = 0
    for (let i = retained.coverage.position; i < input.records.length; i++) {
      const record = input.records[i]
      const payload = { schema: OBSERVATION_SCHEMA, classification: 'gate-ledger-observation',
        grants_authority: false, source: { ...input.source, position: record.position, hash: record.hash },
        action_id: record.action_id, entry: record.entry, entry_body: record.entry_body }
      const previous_id = events.at(-1)?.id ?? ZERO_ID
      const draft = await codec.build({ sequence: events.length + 1, previous_id,
        source: { journal_id: input.source.journal_id, position: record.position, hash: record.hash },
        action_id: record.action_id, content: JSON.stringify(payload), created_at: now() })
      const event = parseUniqueJson(JSON.stringify(draft))
      // Verify the actual signed/encrypted result, not merely the unsigned draft.
      const candidate = await verifyAuraStream([event], { codec, source: input.source, gatePublicKey, verifiedPrefix: retained })
      if (candidate.ok !== true) throw incomplete(candidate.reason)
      const line = `${JSON.stringify(event)}\n`
      const written = await store.append(line) // full append + fsync ACK precedes checkpoint
      events.push(event); bytes.push(written.events_bytes); retained = candidate; appended++
      await afterAppend?.({ position: record.position, event_id: event.id })
      await store.checkpointWrite(checkpointAt(input.source, retained, events, bytes, record.position))
    }
    // A previously flushed append with a stale/missing checkpoint is committed;
    // rebuild only its public checkpoint, never sign or append that event again.
    await store.checkpointWrite(checkpointAt(input.source, retained, events, bytes, events.length))
    return result('complete', undefined, { source: input.source, coverage: retained.coverage,
      aura_head: retained.aura_head, appended, deduplicated: events.length - appended })
  } catch (error) {
    const reason = typeof error?.code === 'string' && /^(aura-collector:|aura-collected:|gate-source:)[a-z-]+$/u.test(error.code)
      ? error.code : 'aura-collector:collection-incomplete'
    return result('incomplete', reason, retained ? { coverage: retained.coverage, aura_head: retained.aura_head } : {})
  } finally { await store?.close() }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const file = process.argv[2]
    if (process.argv.length !== 3 || !file || !isAbsolute(file)) throw incomplete('aura-collector:trusted-context-required')
    const { collectorContext } = await import(pathToFileURL(file).href)
    const context = typeof collectorContext === 'function' ? await collectorContext() : collectorContext
    const result = await collectGateOnce(context)
    process.stdout.write(`${JSON.stringify(result)}\n`); process.exitCode = result.ok ? 0 : 2
  } catch { process.stderr.write('aura-collector:trusted-context-unavailable\n'); process.exitCode = 2 }
}
