#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync, realpathSync } from 'node:fs'
import { resolve, dirname, relative, isAbsolute } from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const e = JSON.parse(readFileSync(resolve(root, 'evidence/current.json'), 'utf8'))
const argv = process.argv.slice(2)
if (argv.length !== 1 || !['--write', '--check'].includes(argv[0])) throw new Error('use --write or --check')
if (e.schema !== 'aukora-current-evidence/v1' || e.boundary_files.length > 20 || new Set(e.boundary_files).size !== e.boundary_files.length) throw new Error('invalid current evidence inventory')
for (const path of e.boundary_files) if (!existsSync(resolve(root, path))) throw new Error('missing boundary file: ' + path)
const esc = v => String(v).replaceAll('|', '\\|').replaceAll('\n', ' ')
const labels = new Set(['REPORTED', 'RECORDED', 'SOURCE', 'RESEARCH', 'NOT YET', 'NOT CLAIMED', 'UNPERFORMED', 'PROPOSED', 'DISABLED'])
for (const row of e.claims) if (!labels.has(row.status) || !row.limit || !row.basis) throw new Error('claim needs status, evidence basis and limit')
// Invariant: reports, source and installed observations retain distinct types; an
// exception disclosure supplies no authority. Threat: stale dates or missing
// custody are rendered as acceptance. Validate before any output is written.
const kinds = { REPORTED: 'OPERATOR_REPORT', RECORDED: 'RETAINED_RECORD', SOURCE: 'SOURCE_RECORD', RESEARCH: 'RESEARCH_RECORD' }
const scopes = new Set(['SOURCE', 'STAGING', 'LIVE', 'HISTORICAL', 'RESEARCH', 'UNQUALIFIED'])
const timestamp = (value, name, futureAllowed = false) => {
  if (value === null) return
  const parsed = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ? Date.parse(value) : NaN
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value.replace('Z', '.000Z') || (!futureAllowed && parsed > Date.now())) throw new Error('invalid/future evidence timestamp: ' + name)
}
const evidenceDates = (value, name = 'evidence') => {
  if (!value || typeof value !== 'object') return
  for (const [key, item] of Object.entries(value)) {
    if (['evidence_at', 'reported_at', 'updated_at'].includes(key)) timestamp(item, name + '.' + key)
    else evidenceDates(item, name + '.' + key)
  }
}
evidenceDates(e)
for (const row of e.claims) {
  if (row.evidence_kind !== (kinds[row.status] ?? 'UNQUALIFIED') || !scopes.has(row.scope)) throw new Error('claim needs matching evidence kind and scope: ' + row.id)
  if (row.status === 'SOURCE' && row.scope !== 'SOURCE') throw new Error('source check cannot claim installed scope: ' + row.id)
}
const typedExceptions = e.observations.containment.named_exceptions
if (typedExceptions) {
  if (typedExceptions.schema !== 'aukora-containment-exceptions/v1' || typedExceptions.scope !== 'STAGING' || !['OPERATOR_REPORT', 'RETAINED_RECORD'].includes(typedExceptions.evidence_kind) || !Array.isArray(typedExceptions.raw_transcripts)) throw new Error('invalid typed containment exceptions')
  const seen = new Set()
  for (const row of typedExceptions.routes) {
    if (!row.route || !row.nature || !row.risk || seen.has(row.route) || !['DISCLOSED_ONLY', 'APPROVED_EXCEPTION'].includes(row.status) || !Object.hasOwn(row, 'owner_approval') || !Object.hasOwn(row, 'expires_at')) throw new Error('exception needs unique route, risk, status, approval and expiry')
    seen.add(row.route)
    if (row.owner_approval !== null) {
      const approval = row.owner_approval
      if (!approval || approval.owner !== 'Peter' || !approval.evidence_ref || !approval.approved_at) throw new Error('invalid owner approval evidence')
      timestamp(approval.approved_at, 'owner approval')
      const approvalPath = resolve(root, approval.evidence_ref)
      if (!existsSync(approvalPath) || relative(root, realpathSync(approvalPath)).startsWith('..')) throw new Error('missing/outside owner approval evidence')
    }
    if (row.expires_at !== null) timestamp(row.expires_at, 'exception expiry', true)
    if (row.status === 'APPROVED_EXCEPTION' && (row.owner_approval === null || row.expires_at === null || Date.parse(row.expires_at) <= Date.now())) throw new Error('approved exception needs retained owner approval and unexpired expiry')
  }
  for (const record of typedExceptions.raw_transcripts) {
    if (record.custody === 'REMOTE_REFERENCE') {
      if (!/^aukora-staging:\/root\/evidence\/containment-\d{8}T\d{6}Z\/raw\.log$/.test(record.source_uri ?? '') || !/^[a-f0-9]{64}$/.test(record.sha256 ?? '') || !Number.isSafeInteger(record.lines) || record.lines < 1 || !Number.isSafeInteger(record.bytes) || record.bytes < 1 || !record.inspection) throw new Error('invalid remote raw transcript reference')
      continue // Metadata is typed, not a byte/digest verification of remote custody.
    }
    const path = typeof record.path === 'string' ? resolve(root, record.path) : root
    const rel = relative(root, path)
    if (!rel || rel.startsWith('..') || isAbsolute(rel) || !/^[a-f0-9]{64}$/.test(record.sha256 ?? '') || !existsSync(path)) throw new Error('invalid/missing raw containment transcript')
    if (relative(root, realpathSync(path)).startsWith('..')) throw new Error('outside raw containment transcript')
    if (createHash('sha256').update(readFileSync(path)).digest('hex') !== record.sha256) throw new Error('raw containment transcript digest mismatch')
  }
}
const prefix = path => path.startsWith('docs/') ? '../' : ''
const ref = (r, path) => r.startsWith('https://') ? r : prefix(path) + r
const references = (rows, path) => rows.map(x => `[${x.label}](${ref(x.path, path)})`).join('; ')
const basis = row => `${esc(row.basis)}${row.evidence_kind ? `; ${esc(row.evidence_kind)} / ${esc(row.scope)}` : ''}${row.evidence_at ? `; evidence at ${esc(row.evidence_at)}` : ''}`
const claims = path => ['| Claim | Status / basis | Code or check | Limit |', '| --- | --- | --- | --- |',
  ...e.claims.map(r => `| ${esc(r.claim)} | **${r.status}** · ${basis(r)} | ${references(r.references, path)} | ${esc(r.limit)} |`)].join('\n')
const revisions = path => ['| Identity | Revision / observation | Meaning |', '| --- | --- | --- |',
  `| Source account | \`${e.revisions.source}\` | Base reviewed for this documentation snapshot; the review command emits the received HEAD and dirty state. |`,
  `| Public main observed | \`${e.revisions.main_observed.sha}\`, ${e.revisions.main_observed.at} | Read/fetch observation, not a deployment proof; main may advance. |`,
  `| Pilot deployment | \`${e.revisions.deployment.sha}\`, ${e.revisions.deployment.reported_at} · **REPORTED** | ${esc(e.revisions.deployment.limit)} |`,
  `| Tested revision | Per-check HEAD and file digests from \`./security-review\` | No current test result is inferred from a commit message or this table. Historical results stay in [evidence history](${ref('docs/EVIDENCE-HISTORY.md', path)}). |`].join('\n')
// Invariant: generated rows have one factual source. Threat: stale prose implies
// qualification. Reason: write/check exact marked sections, preserving history.
const byId = new Map(e.claims.map(row => [row.id, row]))
if (byId.size !== e.claims.length || e.frontdoor?.version !== 1) throw new Error('invalid front-door claim profile')
const selectedClaims = e.frontdoor.boundary_claim_ids.map(id => {
  const row = byId.get(id)
  if (!row) throw new Error('missing boundary claim: ' + id)
  return row
})
const boundaryStatus = ['| Current boundary claim | Status / evidence timestamp | Limit |', '| --- | --- | --- |',
  ...selectedClaims.map(row => `| ${esc(row.claim)} | **${row.status}** · ${basis(row)} | ${esc(row.limit)} |`)].join('\n')
const componentStatus = ['| Component | Role and code | Existing check / observation | Status / evidence timestamp | Limit |', '| --- | --- | --- | --- | --- |',
  ...e.frontdoor.components.map(row => {
    const claim = byId.get(row.claim_id)
    if (!claim || !row.name || !row.role || !row.code?.length || !row.checks?.length) throw new Error('invalid component row')
    return `| ${esc(row.name)} | ${esc(row.role)}; ${references(row.code, 'ARCHITECTURE.md')} | ${references(row.checks, 'ARCHITECTURE.md')} | **${claim.status}** · ${basis({ ...claim, basis: row.basis ?? claim.basis })} | ${esc(row.limit ?? claim.limit)} |`
  })].join('\n')
const containment = e.observations.containment
const baseline = containment.original_baseline
const admission = e.observations.admission
const exceptions = containment.named_exceptions
const containmentStatus = [
  ...(admission ? [`**Current admission · REPORTED at ${esc(admission.evidence_at)}:** ${esc(admission.basis)} ${esc(admission.limit)}`] : []),
  `**Historical containment baseline. ${esc(containment.verdict_rule)}** The supplied operator result at ${esc(containment.evidence_at)} for runtime \`${containment.runtime_revision}\` remains **${containment.verdict}**: guest **${containment.guest.denied} DENIED / ${containment.guest.allowed} ALLOWED** (${esc(containment.guest.open_finding)}); host-as-auma **${containment.host_as_auma.denied} DENIED / ${containment.host_as_auma.allowed} ALLOWED** after the host firewall.`,
  `The original baseline at ${esc(baseline.evidence_at)} had guest **${baseline.guest_denied} DENIED / ${baseline.guest_allowed} ALLOWED** and host-as-auma **${baseline.host_denied} DENIED / ${baseline.host_allowed} ALLOWED**. The observer was ${esc(baseline.observer)}. The disposable control had ${esc(baseline.control)}; that is detection evidence, not containment PASS. Workspace operations were reported working.`,
  `See the [three findings and their disposition](${containment.disposition_review_path}), [command scope](scripts/audit/containment/README.md) and [host-firewall scope](host/auma-local-deny/README.md). The inherited-descriptor finding stays OPEN. Required evidence: ${esc(containment.required)}. This docs task reran no live check; full containment remains unqualified.`,
  ...(exceptions ? [
    `**Named host-as-auma exceptions · ${esc(exceptions.evidence_kind)} / STAGING at ${exceptions.evidence_at === null ? 'timestamp not supplied' : esc(exceptions.evidence_at)}:** ${esc(exceptions.context).replace(/\.+$/, '')}. ${esc(exceptions.disposition).replace(/\.+$/, '')}.\n\n${exceptions.routes.map(route => `- \`${esc(route.route)}\` — ${esc(route.nature)}; ${esc(route.risk)}; ${esc(route.status)}; owner approval: ${route.owner_approval === null ? 'NOT SUPPLIED' : esc(route.owner_approval.evidence_ref)}; expiry: ${route.expires_at === null ? 'NOT SUPPLIED' : esc(route.expires_at)}`).join('\n')}\n\n${esc(exceptions.verdict_rule).replace(/\.+$/, '')}.\n\nRaw containment transcripts: ${exceptions.raw_transcripts.length ? exceptions.raw_transcripts.map(record => record.custody === 'REMOTE_REFERENCE' ? `\`${esc(record.source_uri)}\` (REMOTE_REFERENCE; SHA-256 \`${record.sha256}\`; ${record.lines} lines / ${record.bytes} bytes; ${esc(record.inspection)}; renderer does not verify remote bytes)` : `[${esc(record.path)}](${esc(record.path)}) (SHA-256 \`${record.sha256}\`)`).join('; ') : '**UNPERFORMED** — no raw transcripts supplied; the dated disposition is a summary, not a raw run attachment'}. ${esc(exceptions.timestamp_basis)}`
  ] : [])
].join('\n\n')
const outputs = [['README.md', 'current-revisions', revisions('README.md')], ['README.md', 'current-claims', claims('README.md')],
  ['README.md', 'current-containment', containmentStatus],
  ['docs/CLAIMS.md', 'current-revisions', revisions('docs/CLAIMS.md')], ['docs/CLAIMS.md', 'current-claims', claims('docs/CLAIMS.md')],
  ['SECURITY-BOUNDARY.md', 'current-boundary-status', boundaryStatus],
  ['ARCHITECTURE.md', 'current-revisions', revisions('ARCHITECTURE.md')], ['ARCHITECTURE.md', 'current-components', componentStatus]]
let bad = 0
for (const [path, id, body] of outputs) {
  const file = resolve(root, path), source = readFileSync(file, 'utf8')
  const start = `<!-- BEGIN GENERATED ${id} -->`, end = `<!-- END GENERATED ${id} -->`
  if (source.split(start).length !== 2 || source.split(end).length !== 2 || source.indexOf(start) > source.indexOf(end)) throw new Error('missing/duplicate evidence markers: ' + path)
  const expected = source.slice(0, source.indexOf(start) + start.length) + '\n' + body + '\n' + source.slice(source.indexOf(end))
  if (argv[0] === '--write') writeFileSync(file, expected)
  else if (source !== expected) { console.error('stale generated evidence section: ' + path + ' / ' + id); bad++ }
}
console.log(JSON.stringify({ status: bad ? 'FAIL' : 'PASS', mode: argv[0], sections: outputs.length, claims: e.claims.length, boundary_files: e.boundary_files.length }))
process.exitCode = bad ? 1 : 0
