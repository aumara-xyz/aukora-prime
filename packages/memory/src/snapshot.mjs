// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, CHAIN_DOMAINS, parseOriginal, sha256, requireMemory, validateOriginal,
  verifyChain, verifyMembership, verifySources } from './codecs.mjs'

export const SNAPSHOT_SCHEMA = 'aukora-prime-memory-snapshot/v1'
const ROLES = ['record', 'chain', 'event', 'tombstone', 'control', 'original', 'approved-evidence']
const indexOf = snapshot => ({ schema: snapshot.schema, owner_subject: snapshot.owner_subject,
  heads: snapshot.heads, files: snapshot.files.map(({ bytes_base64, ...metadata }) => metadata) })
export function makeSnapshot(owner, files, heads) {
  const snapshot = { schema: SNAPSHOT_SCHEMA, owner_subject: owner, heads,
    files: files.map(({ bytes, ...metadata }) => ({ ...metadata, sha256: sha256(bytes),
      bytes_base64: Buffer.from(bytes).toString('base64') })).sort((a,b) => a.path.localeCompare(b.path)) }
  return { ...snapshot, manifest_sha256: sha256(Buffer.from(canonicalJSON(indexOf(snapshot)))) }
}

// This is an inert byte snapshot, never a filesystem path or a mutable source store.
export function inspectSnapshot(snapshot, owner, { expectedHeads, quarantineInvalid = false } = {}) {
  requireMemory(snapshot?.schema === SNAPSHOT_SCHEMA && snapshot.owner_subject === owner, 'memory:snapshot-owner-schema')
  requireMemory(Array.isArray(snapshot.files) && snapshot.files.length <= 10000 && snapshot.heads
    && typeof snapshot.heads === 'object' && !Array.isArray(snapshot.heads), 'memory:snapshot-shape')
  requireMemory(sha256(Buffer.from(canonicalJSON(indexOf(snapshot)))) === snapshot.manifest_sha256, 'memory:snapshot-manifest-changed')
  const paths = new Set(), events = new Map(), chains = new Map(), records = [], tombstones = [], controls = [], quarantine = []
  let total = 0
  const files = snapshot.files.map(file => {
    requireMemory(typeof file.path === 'string' && /^[A-Za-z0-9_.:@/-]+$/.test(file.path)
      && !file.path.startsWith('/') && !file.path.split('/').some(p => p === '..' || p === ''), 'memory:snapshot-path-invalid')
    requireMemory(!paths.has(file.path) && ROLES.includes(file.role), 'memory:snapshot-file-duplicate-role')
    paths.add(file.path)
    requireMemory(typeof file.bytes_base64 === 'string', 'memory:snapshot-bytes-invalid')
    const bytes = Buffer.from(file.bytes_base64, 'base64'); total += bytes.length
    requireMemory(bytes.toString('base64') === file.bytes_base64 && total <= MAX_BYTES
      && sha256(bytes) === file.sha256, 'memory:snapshot-file-changed')
    return { ...file, bytes }
  })
  for (const file of files.filter(f => f.role === 'event')) {
    parseOriginal(file.bytes); events.set(file.sha256, file.bytes)
  }
  for (const file of files.filter(f => f.role === 'chain')) {
    requireMemory(CHAIN_DOMAINS.includes(file.chain_domain) && !chains.has(file.chain_domain), 'memory:snapshot-chain-domain')
    try {
      const chain = verifyChain(file.bytes, snapshot.heads[file.chain_domain])
      if (expectedHeads?.[file.chain_domain] !== undefined) verifyChain(file.bytes, expectedHeads[file.chain_domain])
      chains.set(file.chain_domain, { ...chain, file })
    } catch (error) {
      if (!quarantineInvalid) throw error
      quarantine.push({ path: file.path, reason: error.code ?? 'memory:chain-invalid' })
    }
  }
  for (const domain of Object.keys(snapshot.heads)) {
    requireMemory(CHAIN_DOMAINS.includes(domain) && files.some(f => f.role === 'chain' && f.chain_domain === domain), 'memory:snapshot-head-without-chain')
  }
  for (const [domain,head] of Object.entries(expectedHeads ?? {})) {
    requireMemory(snapshot.heads[domain] === head && chains.has(domain), 'memory:retained-head-mismatch')
  }
  for (const file of files.filter(f => f.role === 'record')) {
    try {
      requireMemory(Number.isSafeInteger(file.revision) && file.revision > 0, 'memory:snapshot-revision-invalid')
      const meta = validateOriginal(file.bytes, owner)
      requireMemory(file.record_id === meta.id && CHAIN_DOMAINS.includes(file.chain_domain), 'memory:snapshot-record-metadata')
      requireMemory((meta.tier === 'remembered' && file.chain_domain !== 'approved')
        || (meta.tier === 'approved' && file.chain_domain !== 'remembered'), 'memory:chain-tier-mismatch')
      const chain = chains.get(file.chain_domain)
      requireMemory(chain, 'memory:snapshot-record-chain-missing')
      const entry = verifyMembership(meta, chain.entries, file.chain_sequence)
      const citation = verifySources(meta, events)
      records.push({ meta, file, citation, entry })
    } catch (error) {
      if (!quarantineInvalid) throw error
      quarantine.push({ path: file.path, reason: error.code ?? 'memory:record-invalid' })
    }
  }
  for (const file of files.filter(f => f.role === 'tombstone')) {
    const value = parseOriginal(file.bytes)
    // Retain historical content-free tombstone wrappers, with their original bytes.
    const t = value.tombstone ?? value
    requireMemory(t.kind === 'tombstone' && typeof t.recordId === 'string' && typeof t.at === 'string'
      && Object.keys(t).sort().join(',') === 'at,kind,recordId', 'memory:tombstone-invalid')
    tombstones.push({ id: t.recordId, file })
  }
  for (const file of files.filter(f => f.role === 'control')) {
    const value = parseOriginal(file.bytes)
    requireMemory(typeof file.scope === 'string' && value.grantsAuthority !== true, 'memory:control-invalid')
    controls.push({ scope: file.scope, file, value })
  }
  return { files, events, chains, records, tombstones, controls, quarantine,
    digest: snapshot.manifest_sha256, manifestBytes: Buffer.from(canonicalJSON(indexOf(snapshot))) }
}
