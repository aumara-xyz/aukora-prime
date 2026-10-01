// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { MAX_BYTES, CHAIN_DOMAINS, AURA_RECORD_DOMAIN, parseOriginal, sha256, requireMemory, validateOriginal,
  verifyChain, verifyMembership, verifySources, closedKeys, chainRecordId, isCreation, requireRedactableChain } from './codecs.mjs'

export const SNAPSHOT_SCHEMA = 'aukora-prime-memory-snapshot/v1'
export const REDACTED_SCHEMA = 'aukora-prime-memory-snapshot/v2'
export const REDACTED_PROFILE = 'normal-redacted/v1'
const ROLES = ['record', 'chain', 'event', 'tombstone', 'control', 'original', 'approved-evidence', 'redaction', 'opaque-original']
const META = {record:['record_id','revision','task_id','chain_domain','chain_sequence'],chain:['chain_domain'],
  event:[],tombstone:[],control:['scope'],original:['original_metadata'],
  'approved-evidence':['record_id','original_metadata'],redaction:[],'opaque-original':[]}
const validRecordId = id => typeof id === 'string' && /^(?:rem:|kira:)?[0-9a-f]{64}$/.test(id)
const validHead = head => typeof head === 'string' && (head === AURA_RECORD_DOMAIN || /^[0-9a-f]{64}$/.test(head))
function validateHeads(heads, code) {
  requireMemory(heads && typeof heads === 'object' && !Array.isArray(heads)
    && Object.entries(heads).every(([domain, head]) => CHAIN_DOMAINS.includes(domain) && validHead(head)), code)
}
const sourceDigestsOf = record => [record.source?.sha256, ...(record.evidence ?? []).map(e => e.turnDigest)]
  .filter(hash => typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash))
const indexOf = snapshot => ({ schema: snapshot.schema, ...(snapshot.profile ? {profile:snapshot.profile} : {}),
  owner_subject: snapshot.owner_subject, heads: snapshot.heads,
  files: snapshot.files.map(({ bytes_base64, ...metadata }) => metadata) })
export function makeSnapshot(owner, files, heads, { redacted = false } = {}) {
  const snapshot = { schema: redacted ? REDACTED_SCHEMA : SNAPSHOT_SCHEMA,
    ...(redacted ? {profile:REDACTED_PROFILE} : {}), owner_subject: owner, heads,
    files: files.map(({ bytes, bytes_base64, sha256: ignored, ...metadata }) => ({ ...metadata, sha256: sha256(bytes),
      bytes_base64: Buffer.from(bytes).toString('base64') })).sort((a,b) => a.path.localeCompare(b.path)) }
  return { ...snapshot, manifest_sha256: sha256(Buffer.from(canonicalJSON(indexOf(snapshot)))) }
}
export function recordCommitment(row, bytes) {
  const record=parseOriginal(bytes),sourceDigests = new Set()
  if (/^[0-9a-f]{64}$/.test(record.source?.sha256 ?? '')) sourceDigests.add(record.source.sha256)
  for (const evidence of record.evidence ?? []) if (/^[0-9a-f]{64}$/.test(evidence.turnDigest ?? '')) sourceDigests.add(evidence.turnDigest)
  return {kind:'redacted-record/v1',record_id:row.record_id,revision:row.revision,canonical_sha256:sha256(bytes),
    chain_domain:row.chain_domain,chain_sequence:row.chain_sequence,source_digests:[...sourceDigests].sort()}
}

// Inert bytes only. Hash integrity is self-consistency; an independently retained head anchors history.
export function inspectSnapshot(snapshot, owner, { expectedHeads, quarantineInvalid = false } = {}) {
  closedKeys(snapshot,['schema','profile','owner_subject','heads','files','manifest_sha256'],'memory:snapshot-fields-invalid')
  const redacted=snapshot?.schema===REDACTED_SCHEMA
  requireMemory((snapshot?.schema===SNAPSHOT_SCHEMA || (redacted && snapshot.profile===REDACTED_PROFILE))
    && snapshot.owner_subject===owner && (redacted || snapshot.profile===undefined), 'memory:snapshot-owner-schema')
  requireMemory(Array.isArray(snapshot.files) && snapshot.files.length<=10000 && snapshot.heads
    && typeof snapshot.heads==='object' && !Array.isArray(snapshot.heads), 'memory:snapshot-shape')
  validateHeads(snapshot.heads,'memory:snapshot-head-invalid')
  if (expectedHeads !== undefined) validateHeads(expectedHeads,'memory:retained-head-invalid')
  requireMemory(sha256(Buffer.from(canonicalJSON(indexOf(snapshot))))===snapshot.manifest_sha256,'memory:snapshot-manifest-changed')
  const paths=new Set(),events=new Map(),chains=new Map(),records=[],tombstones=[],controls=[],quarantine=[],redactions=[]
  let total=0
  const files=snapshot.files.map(file=>{
    closedKeys(file,['path','role','sha256','bytes_base64',...(META[file.role] ?? [])],'memory:snapshot-file-fields-invalid')
    requireMemory(!redacted || file.original_metadata===undefined,'memory:redacted-original-metadata-forbidden')
    requireMemory(typeof file.path==='string' && /^[A-Za-z0-9_.:@/-]+$/.test(file.path)
      && !file.path.startsWith('/') && !file.path.split('/').some(p=>p==='..'||p===''),'memory:snapshot-path-invalid')
    requireMemory(!paths.has(file.path) && ROLES.includes(file.role),'memory:snapshot-file-duplicate-role');paths.add(file.path)
    requireMemory(typeof file.bytes_base64==='string','memory:snapshot-bytes-invalid')
    const bytes=Buffer.from(file.bytes_base64,'base64');total+=bytes.length
    requireMemory(bytes.toString('base64')===file.bytes_base64 && total<=MAX_BYTES && sha256(bytes)===file.sha256,'memory:snapshot-file-changed')
    requireMemory(redacted || !['redaction','opaque-original'].includes(file.role),'memory:redaction-profile-required')
    requireMemory(!redacted || file.role!=='original','memory:redacted-original-payload-forbidden')
    return {...file,bytes}
  })
  for (const file of files.filter(f=>f.role==='event')) {parseOriginal(file.bytes);events.set(file.sha256,file.bytes)}
  for (const file of files.filter(f=>f.role==='chain')) {
    requireMemory(CHAIN_DOMAINS.includes(file.chain_domain) && !chains.has(file.chain_domain),'memory:snapshot-chain-domain')
    requireMemory(Object.hasOwn(snapshot.heads,file.chain_domain),'memory:snapshot-chain-head-omitted')
    // A broken chain is a whole-snapshot contradiction, never a quarantine bypass.
    const chain=verifyChain(file.bytes,snapshot.heads[file.chain_domain]);chains.set(file.chain_domain,{...chain,file})
  }
  for (const domain of Object.keys(snapshot.heads)) requireMemory(CHAIN_DOMAINS.includes(domain)
    && chains.has(domain),'memory:snapshot-head-without-chain')
  for (const [domain,head] of Object.entries(expectedHeads ?? {})) requireMemory(snapshot.heads[domain]===head
    && chains.has(domain),'memory:retained-head-mismatch')
  for (const file of files.filter(f=>f.role==='tombstone')) {
    const value=parseOriginal(file.bytes),t=value.tombstone ?? value
    requireMemory(!redacted || value.tombstone===undefined,'memory:redacted-tombstone-wrapper-forbidden')
    requireMemory(t.kind==='tombstone' && validRecordId(t.recordId) && typeof t.at==='string'
      && Object.keys(t).sort().join(',')==='at,kind,recordId','memory:tombstone-invalid')
    requireMemory(!tombstones.some(existing=>existing.id===t.recordId),'memory:tombstone-duplicate')
    tombstones.push({id:t.recordId,at:t.at,file})
  }
  const forgotten=new Set(tombstones.map(t=>t.id)),removedEvents=new Set()
  for (const file of files.filter(f=>f.role==='redaction')) {
    const value=parseOriginal(file.bytes)
    requireMemory(Object.keys(value).sort().join(',')==='canonical_sha256,chain_domain,chain_sequence,kind,record_id,revision,source_digests'
      && value.kind==='redacted-record/v1' && validRecordId(value.record_id) && forgotten.has(value.record_id) && CHAIN_DOMAINS.includes(value.chain_domain)
      && Number.isSafeInteger(value.revision) && value.revision>0 && Number.isSafeInteger(value.chain_sequence)
      && value.chain_sequence>0 && /^[0-9a-f]{64}$/.test(value.canonical_sha256) && Array.isArray(value.source_digests)
      && value.source_digests.every(h=>typeof h==='string' && /^[0-9a-f]{64}$/.test(h))
      && new Set(value.source_digests).size===value.source_digests.length,'memory:redaction-invalid')
    requireMemory(!redactions.some(r=>r.value.record_id===value.record_id && r.value.revision===value.revision),'memory:redaction-duplicate')
    for (const hash of value.source_digests) removedEvents.add(hash)
    redactions.push({file,value})
  }
  for (const hash of removedEvents) requireMemory(!events.has(hash),'memory:redacted-event-payload-forbidden')
  for (const file of files.filter(f=>f.role==='opaque-original')) {
    const value=parseOriginal(file.bytes)
    requireMemory(Object.keys(value).sort().join(',')==='kind,sha256' && value.kind==='opaque-original/v1'
      && /^[0-9a-f]{64}$/.test(value.sha256),'memory:opaque-original-invalid')
  }
  const recordFiles=new Set()
  for (const file of files.filter(f=>f.role==='record')) {
    requireMemory(!redacted || !forgotten.has(file.record_id),'memory:redacted-record-payload-forbidden')
    requireMemory(validRecordId(file.record_id) && Number.isSafeInteger(file.revision) && file.revision>0 && CHAIN_DOMAINS.includes(file.chain_domain)
      && Number.isSafeInteger(file.chain_sequence) && file.chain_sequence>0,'memory:snapshot-record-metadata')
    const recordKey=file.record_id+':'+file.revision
    requireMemory(!recordFiles.has(recordKey),'memory:snapshot-record-duplicate');recordFiles.add(recordKey)
    // A malformed historical value may be quarantined, but projection metadata cannot forge its membership.
    const chain=chains.get(file.chain_domain);requireMemory(chain,'memory:snapshot-record-chain-missing')
    requireMemory(chainRecordId(chain.entries[file.chain_sequence-1] ?? {})===file.record_id,
      'memory:snapshot-record-metadata')
    let meta
    try {
      meta=validateOriginal(file.bytes,owner)
    } catch(error) {
      if (!quarantineInvalid) throw error
      quarantine.push({path:file.path,reason:error.code ?? 'memory:record-invalid'})
      continue
    }
    // Contradictions between intact records, committed chains and evidence are snapshot failures, not quarantine.
    requireMemory(file.record_id===meta.id,'memory:snapshot-record-metadata')
    requireMemory((meta.tier==='remembered' && file.chain_domain!=='approved')
      || (meta.tier==='approved' && file.chain_domain!=='remembered'),'memory:chain-tier-mismatch')
    const entry=verifyMembership(meta,chain.entries,file.chain_sequence),citation=verifySources(meta,events)
    if (citation.verdict==='MISSING' && meta.record.source?.state!=='UNLINKED') {
      const needed=sourceDigestsOf(meta.record)
      requireMemory(redacted && needed.filter(h=>!events.has(h)).every(h=>removedEvents.has(h)), 'memory:snapshot-evidence-omitted')
    }
    requireMemory(!records.some(r=>r.meta.id===meta.id && r.file.revision===file.revision),'memory:snapshot-record-duplicate')
    records.push({meta,file,citation,entry})
  }
  for (const file of files.filter(f=>f.role==='control')) {
    const value=parseOriginal(file.bytes)
    closedKeys(value,['controls','paused','offTheRecord','grantsAuthority'],'memory:control-fields-invalid')
    requireMemory(typeof file.scope==='string' && value.grantsAuthority!==true
      && ['paused','offTheRecord'].every(k=>value[k]===undefined || typeof value[k]==='boolean'),'memory:control-invalid')
    const allowed=['pause','off-the-record','someone-is-here','hide']
    if(value.controls) requireMemory(typeof value.controls==='object' && Object.entries(value.controls)
      .every(([k,v])=>allowed.includes(k) && typeof v==='boolean'),'memory:control-invalid')
    requireMemory(!controls.some(c=>c.scope===file.scope),'memory:control-duplicate');controls.push({scope:file.scope,file,value})
  }
  // Reconcile the complete ledger, including historical entries absent from current projection lists.
  const creations=new Map(),forgets=new Map(),latestControls=new Map()
  for (const [domain,chain] of chains) {
    const domainCreations=new Set(),domainForgets=new Set(),domainControls=new Map()
    for (const entry of chain.entries) {
      const id=chainRecordId(entry)
      requireMemory(['id','recordId','key'].every(k=>entry[k]===undefined || entry[k]===id),'memory:chain-record-id-contradiction')
      if (isCreation(entry)) {
        requireMemory(validRecordId(id),'memory:chain-record-id-missing')
        const key=domain+':'+entry.sequence;creations.set(key,id)
        const projections=files.filter(f=>f.role==='record' && f.chain_domain===domain && f.chain_sequence===entry.sequence && f.record_id===id)
          .concat(redactions.filter(r=>r.value.chain_domain===domain && r.value.chain_sequence===entry.sequence && r.value.record_id===id))
        requireMemory(projections.length>0,'memory:chain-record-omitted')
        requireMemory(!domainForgets.has(id),'memory:remember-after-forget');domainCreations.add(id)
      } else if (entry.op==='forget') {
        requireMemory(validRecordId(id) && domainCreations.has(id),'memory:forget-without-record')
        const t=tombstones.find(t=>t.id===id)
        requireMemory(t && t.at===entry.at,'memory:chain-tombstone-omitted');forgets.set(id,entry);domainForgets.add(id)
      } else if (entry.op==='control') {
        requireMemory(typeof entry.scope==='string' && /^[0-9a-f]{64}$/.test(entry.controlDigest),'memory:chain-control-invalid')
        domainControls.set(entry.scope,entry.controlDigest)
      } else requireMemory(false,'memory:chain-operation-unsupported')
    }
    // Separate domain sequences have no shared trusted total order; file order cannot choose the active control.
    for (const [scope,digest] of domainControls) {
      requireMemory(!latestControls.has(scope) || latestControls.get(scope)===digest,'memory:control-history-ambiguous')
      latestControls.set(scope,digest)
    }
  }
  for (const t of tombstones) requireMemory(forgets.has(t.id),'memory:tombstone-without-forget')
  for (const [scope,digest] of latestControls) requireMemory(controls.some(c=>c.scope===scope && c.file.sha256===digest),'memory:chain-control-omitted')
  for (const c of controls) requireMemory(latestControls.get(c.scope)===c.file.sha256,'memory:control-without-chain')
  for (const item of redactions) requireMemory(creations.get(item.value.chain_domain+':'+item.value.chain_sequence)===item.value.record_id,'memory:redaction-membership-missing')
  if (redacted && forgotten.size) for (const chain of chains.values()) requireRedactableChain(chain.entries)
  // Unbound evidence cannot silently reintroduce redacted plaintext. v2 requires a live record association.
  if (redacted) for (const f of files.filter(f=>f.role==='approved-evidence')) requireMemory(records.some(r=>r.meta.id===f.record_id
    && r.meta.tier==='approved') && !forgotten.has(f.record_id),'memory:redacted-evidence-unbound')
  if (redacted) {
    const liveEvents=new Set(records.flatMap(r=>sourceDigestsOf(r.meta.record)))
    for (const hash of events.keys()) requireMemory(liveEvents.has(hash),'memory:redacted-event-unbound')
  }
  const anchorSupplied=expectedHeads && Object.keys(expectedHeads).length>0
    && [...chains.values()].some(chain=>chain.sequence>0)
    && Object.keys(snapshot.heads).length>0 && Object.keys(snapshot.heads).every(k=>expectedHeads[k]===snapshot.heads[k])
  return {files,events,chains,records,tombstones,controls,quarantine,redactions,removedEvents,
    anchored:Boolean(anchorSupplied),digest:snapshot.manifest_sha256,manifestBytes:Buffer.from(canonicalJSON(indexOf(snapshot)))}
}
