#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
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
const prefix = path => path.startsWith('docs/') ? '../' : ''
const ref = (r, path) => r.startsWith('https://') ? r : prefix(path) + r
const references = (rows, path) => rows.map(x => `[${x.label}](${ref(x.path, path)})`).join('; ')
const basis = row => `${esc(row.basis)}${row.evidence_at ? `; evidence at ${esc(row.evidence_at)}` : ''}`
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
const containmentStatus = [
  `**${esc(containment.verdict_rule)}** The supplied operator result at ${esc(containment.evidence_at)} for runtime \`${containment.runtime_revision}\` remains **${containment.verdict}**: guest **${containment.guest.denied} DENIED / ${containment.guest.allowed} ALLOWED** (${esc(containment.guest.open_finding)}); host-as-auma **${containment.host_as_auma.denied} DENIED / ${containment.host_as_auma.allowed} ALLOWED** after the host firewall.`,
  `The original baseline at ${esc(baseline.evidence_at)} had guest **${baseline.guest_denied} DENIED / ${baseline.guest_allowed} ALLOWED** and host-as-auma **${baseline.host_denied} DENIED / ${baseline.host_allowed} ALLOWED**. The observer was ${esc(baseline.observer)}. The disposable control had ${esc(baseline.control)}; that is detection evidence, not containment PASS. Workspace operations were reported working.`,
  `See the [three findings and their disposition](${containment.disposition_review_path}), [command scope](scripts/audit/containment/README.md) and [host-firewall scope](host/auma-local-deny/README.md). The inherited-descriptor finding stays OPEN. Required evidence: ${esc(containment.required)}. This docs task reran no live check; full containment remains unqualified.`
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
