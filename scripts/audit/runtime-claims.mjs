#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify bounded evidence pointers and refuse stale or unsupported runtime statuses.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, realpathSync, openSync, closeSync, fstatSync, constants } from 'node:fs'
import { dirname, resolve, relative } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseUniqueJson } from '../aura/verify-collected.mjs'
import { parsePluginSetApproval, PLUGIN_SET_TARGET } from '../../packages/boundary-gate/src/vendor/operator-data.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const refuse = name => { throw Error(`runtime-claims:${name}`) }
const requireValue = (ok, name) => { if (!ok) refuse(name) }
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value)
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 4000 && !/[\x00-\x1f\x7f]/u.test(value)
const path = value => text(value) && /^[a-zA-Z0-9_./-]+$/u.test(value)
  && !value.startsWith('/') && value.split('/').every(part => part && part !== '.' && part !== '..')
function keys(value, names) {
  requireValue(value && !Array.isArray(value) && typeof value === 'object'
    && Object.keys(value).sort().join(',') === [...names].sort().join(','), 'schema-fields')
}

export function validateDocument(document) {
  keys(document, ['schema', 'claims'])
  requireValue(document.schema === 'aukora-runtime-claims/v1' && Array.isArray(document.claims)
    && document.claims.length > 0 && document.claims.length <= 12, 'schema-inventory')
  const ids = new Set()
  for (const row of document.claims) {
    keys(row, ['id', 'statement', 'where', 'date', 'commit', 'verification', 'source', 'evidence', 'upgrade', 'limit'])
    requireValue(typeof row.id === 'string' && /^[a-z][a-z0-9-]{0,63}$/u.test(row.id) && !ids.has(row.id), 'schema-id')
    ids.add(row.id)
    requireValue([row.statement, row.upgrade, row.limit].every(text) && path(row.source), 'schema-text')
    requireValue(['ci', 'pilot', 'staging', 'mac'].includes(row.where), 'schema-location')
    requireValue(typeof row.date === 'string' && /^\d{4}-\d{2}-\d{2}$/u.test(row.date)
      && !Number.isNaN(Date.parse(row.date)) && new Date(row.date).toISOString().slice(0, 10) === row.date, 'schema-date')
    requireValue(row.commit === null || (typeof row.commit === 'string' && /^[a-f0-9]{40}$/u.test(row.commit)), 'schema-commit')
    requireValue(['reported', 'verified'].includes(row.verification), 'schema-verification')
    if (row.evidence === 'reported-only') {
      requireValue(row.verification === 'reported', 'reported-cannot-be-verified')
      continue
    }
    requireValue(row.commit !== null && row.verification === 'verified', 'evidence-needs-commit-and-verification')
    const evidence = row.evidence
    if (evidence?.kind === 'clone') {
      keys(evidence, ['kind', 'command', 'stdoutSha256', 'timeoutMs'])
      requireValue(Array.isArray(evidence.command) && evidence.command.length >= 2 && evidence.command.length <= 16
        && ['node', 'python3', 'bash', 'sh'].includes(evidence.command[0]) && path(evidence.command[1]) && !evidence.command[1].startsWith('-')
        && evidence.command.slice(2).every(text) && hex(evidence.stdoutSha256)
        && Number.isSafeInteger(evidence.timeoutMs) && evidence.timeoutMs > 0 && evidence.timeoutMs <= 5000, 'schema-clone')
    } else if (evidence?.kind === 'ci') {
      keys(evidence, ['kind', 'runId', 'attempt', 'job', 'artifact'])
      requireValue(row.where === 'ci' && Number.isSafeInteger(evidence.runId) && evidence.runId > 0
        && Number.isSafeInteger(evidence.attempt) && evidence.attempt > 0 && text(evidence.job) && text(evidence.artifact), 'schema-ci')
    } else if (evidence?.kind === 'ledger') {
      keys(evidence, ['kind', 'file', 'sha256', 'publicKey', 'keySha256', 'anchor', 'approval', 'sequence', 'entryHash'])
      requireValue(path(evidence.file) && evidence.file.startsWith('evidence/') && hex(evidence.sha256)
        && path(evidence.publicKey) && evidence.publicKey.startsWith('evidence/') && hex(evidence.keySha256)
        && (evidence.anchor === null || (path(evidence.anchor) && evidence.anchor.startsWith('evidence/')))
        && (evidence.approval === null || (path(evidence.approval) && evidence.approval.startsWith('evidence/')))
        && Number.isSafeInteger(evidence.sequence) && evidence.sequence > 0 && hex(evidence.entryHash), 'schema-ledger')
    } else refuse('schema-evidence')
  }
  return document
}

function localFile(directory, file) {
  const full = realpathSync(resolve(directory, file))
  requireValue(!relative(realpathSync(directory), full).startsWith('..') && full !== realpathSync(directory), 'path-outside-clone')
  return full
}
function readBounded(file, maxBytes) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW)
  try {
    const info = fstatSync(fd)
    requireValue(info.isFile() && info.size <= maxBytes, 'file-type-or-size')
    const bytes = readFileSync(fd)
    requireValue(bytes.length <= maxBytes, 'file-size-changed')
    return bytes
  } finally { closeSync(fd) }
}
function runCommand(command, directory, timeout) {
  return spawnSync(command[0] === 'node' ? process.execPath : command[0], command.slice(1), {
    cwd: directory, env: { PATH: process.env.PATH, LANG: 'C', TZ: 'UTC', GIT_NO_LAZY_FETCH: '1' },
    encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
  })
}
function cleanCommit(directory, timeout) {
  const deadline = performance.now() + timeout
  const head = runCommand(['git', 'rev-parse', 'HEAD'], directory, timeout)
  const left = Math.ceil(deadline - performance.now())
  if (left <= 0) return false
  const status = runCommand(['git', 'status', '--porcelain', '--untracked-files=normal'], directory, left)
  return head.status === 0 && /^[a-f0-9]{40}$/u.test(head.stdout.trim()) && status.status === 0 && status.stdout === ''
    ? head.stdout.trim() : null
}
function isCommitted(file, bytes, directory, timeout) {
  const result = runCommand(['git', 'ls-tree', 'HEAD', '--', file], directory, timeout)
  const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
  return result.status === 0 && result.stdout === `100644 blob ${blob}\t${file}\n`
}
async function fetchJson(url, timeout) {
  let response
  try {
    response = await fetch(url, { headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'aukora-runtime-claims' },
      redirect: 'error', signal: AbortSignal.timeout(timeout) })
  } catch { refuse('network-unavailable') }
  if ([403, 429].includes(response.status)) refuse('network-unavailable')
  requireValue(response.ok, 'ci-api-response')
  const chunks = [], reader = response.body.getReader()
  let size = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      requireValue(size <= 1024 * 1024, 'ci-response-bound')
      chunks.push(value)
    }
  } catch (error) {
    await reader.cancel().catch(() => {})
    if (error?.message === 'runtime-claims:ci-response-bound') throw error
    refuse('network-unavailable')
  }
  return parseUniqueJson(Buffer.concat(chunks).toString('utf8'), { maxBytes: 1024 * 1024 })
}

export async function verifyClaim(row, { directory = root, offline = false, remaining = () => 5000,
  run = runCommand, clean = cleanCommit, request = fetchJson, committed = isCommitted } = {}) {
  if (row.evidence === 'reported-only') return { status: 'REPORTED', reason: 'runtime-claims:no-reproducible-evidence' }
  const evidence = row.evidence
  try {
    const budget = () => { const ms = Math.floor(Math.min(5000, remaining())); requireValue(ms > 0, 'time-budget-exhausted'); return ms }
    if (evidence.kind === 'ci') {
      if (offline) return { status: 'UNPERFORMED', reason: 'runtime-claims:network-disabled' }
      const base = `https://api.github.com/repos/aumara-xyz/aukora-prime/actions/runs/${evidence.runId}`
      const observed = await request(`${base}/attempts/${evidence.attempt}`, budget())
      requireValue(observed.id === evidence.runId && observed.head_sha === row.commit
        && observed.run_attempt === evidence.attempt && observed.repository?.full_name === 'aumara-xyz/aukora-prime', 'ci-run-binding')
      const jobs = await request(`${base}/attempts/${evidence.attempt}/jobs?per_page=100`, budget())
      requireValue(Array.isArray(jobs.jobs) && jobs.total_count === jobs.jobs.length, 'ci-job-inventory')
      const selected = jobs.jobs.filter(job => job.name === evidence.job)
      requireValue(selected.length === 1 && selected[0].head_sha === row.commit
        && selected[0].run_id === evidence.runId && selected[0].status === 'completed'
        && selected[0].conclusion === 'success', 'ci-job-not-successful')
      const artifacts = await request(`${base}/artifacts?per_page=100`, budget())
      requireValue(Array.isArray(artifacts.artifacts) && artifacts.total_count === artifacts.artifacts.length, 'ci-artifact-inventory')
      const named = artifacts.artifacts.filter(artifact => artifact.name === evidence.artifact)
      requireValue(named.length === 1 && named[0].expired === false && named[0].size_in_bytes > 0
        && named[0].workflow_run?.id === evidence.runId && named[0].workflow_run?.head_sha === row.commit, 'ci-artifact-unavailable')
      return { status: 'VERIFIED', reason: 'runtime-claims:public-job-and-artifact-metadata' }
    }
    if (evidence.kind === 'clone') {
      const checkedCommit = clean(directory, budget())
      requireValue(checkedCommit, 'clone-dirty-tree')
      localFile(directory, evidence.command[1])
      const result = run(evidence.command, directory, Math.min(evidence.timeoutMs, budget()))
      requireValue(!result.error && !result.signal && result.status === 0 && hash(result.stdout) === evidence.stdoutSha256, 'clone-output-mismatch')
      return { status: 'VERIFIED', reason: 'runtime-claims:clone-command-output', checkedCommit }
    }
    const bytes = readBounded(localFile(directory, evidence.file), 8 * 1024 * 1024)
    requireValue(bytes.length <= 8 * 1024 * 1024 && hash(bytes) === evidence.sha256, 'ledger-file-digest')
    const key = readBounded(localFile(directory, evidence.publicKey), 8192)
    requireValue(key.length <= 8192 && hash(key) === evidence.keySha256, 'ledger-key-digest')
    requireValue(committed(evidence.file, bytes, directory, budget())
      && committed(evidence.publicKey, key, directory, budget()), 'ledger-not-committed')
    const document = parseUniqueJson(bytes.toString('utf8'), { maxBytes: 8 * 1024 * 1024 })
    const entries = Array.isArray(document) ? document : document.entries
    requireValue(entries?.[evidence.sequence - 1]?.seq === evidence.sequence
      && entries[evidence.sequence - 1].hash === evidence.entryHash, 'ledger-entry-binding')
    if (evidence.approval !== null) {
      const content = readBounded(localFile(directory, evidence.approval), 512)
      const approval = parsePluginSetApproval(content.toString('utf8')), entry = entries[evidence.sequence - 1]
      requireValue(committed(evidence.approval, content, directory, budget()), 'approval-not-committed')
      requireValue(approval?.release === row.commit && entry.event === 'apply'
        && entry.target === PLUGIN_SET_TARGET && entry.new_sha === hash(content), 'ledger-release-approval-binding')
    }
    const command = ['node', 'scripts/aura/verify-export.mjs', evidence.file, '--public-key', evidence.publicKey]
    if (evidence.anchor !== null) {
      const anchor = readBounded(localFile(directory, evidence.anchor), 8 * 1024 * 1024)
      requireValue(committed(evidence.anchor, anchor, directory, budget()), 'anchor-not-committed')
      command.push('--anchor', evidence.anchor)
    }
    const result = run(command, directory, budget())
    requireValue(!result.error && !result.signal && result.status === 0 && /^VERIFIED gate-chain-(?:only|and-supplied-anchor) /mu.test(result.stdout), 'ledger-verification-failed')
    return { status: 'VERIFIED', reason: 'runtime-claims:signed-prefix-and-selected-entry' }
  } catch (error) {
    const reason = /^runtime-claims:[a-z-]+$/u.test(error?.message) ? error.message : 'runtime-claims:evidence-unavailable-or-invalid'
    return { status: ['runtime-claims:network-unavailable', 'runtime-claims:time-budget-exhausted'].includes(reason)
      ? 'UNPERFORMED' : 'FAILED', reason }
  }
}

const escape = value => String(value).replaceAll('|', '\\|').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('`', '&#96;')
export function renderTable(document) {
  return ['| Claim / date / place / commit | Evidence status | Pointer or upgrade | Limit |', '| --- | --- | --- | --- |',
    ...document.claims.map(row => {
      const e = row.evidence
      const pointer = e === 'reported-only' ? `**REPORTED** · ${escape(row.upgrade)}`
        : e.kind === 'ci' ? `**UNPERFORMED until checked** · [run ${e.runId}](https://github.com/aumara-xyz/aukora-prime/actions/runs/${e.runId}), attempt ${e.attempt}; job ${escape(e.job)}; artifact ${escape(e.artifact)}`
          : e.kind === 'clone' ? `**UNPERFORMED until checked** · ${escape(e.command.join(' '))}; stdout SHA-256 ${e.stdoutSha256}`
            : `**UNPERFORMED until checked** · [export](../${e.file}); node scripts/aura/verify-export.mjs ${escape(e.file)} --public-key ${escape(e.publicKey)}${e.anchor ? ` --anchor ${escape(e.anchor)}` : ''}; sequence ${e.sequence}${e.approval ? `; [release approval](../${e.approval}) bound to commit` : '; signed prefix only, no release binding'}`
      return `| ${escape(row.statement)} · ${row.date} · ${row.where} · ${row.commit ?? 'commit not supplied'} ([source](../${row.source})) | ${e === 'reported-only' ? '**REPORTED**' : 'Verification required; run the audit'} | ${pointer} | ${escape(row.limit)} |`
    })].join('\n')
}
export function generatedPage(source, document) {
  const start = '<!-- BEGIN GENERATED runtime-claims -->', end = '<!-- END GENERATED runtime-claims -->'
  requireValue(source.split(start).length === 2 && source.split(end).length === 2
    && source.indexOf(start) < source.indexOf(end), 'generated-markers')
  return source.slice(0, source.indexOf(start) + start.length) + '\n' + renderTable(document) + '\n' + source.slice(source.indexOf(end))
}
export function resultCode(rows, claims) {
  // A claim recorded as verified must verify, or be plainly unreachable right now (no network, rate limit): that is
  // UNPERFORMED (exit 2), never a pass, and never a failure that makes every offline run red. Evidence that is
  // reachable and does not match is FAILED.
  if (rows.some((row, index) => row.status === 'FAILED' || (claims[index].verification === 'verified' && !['VERIFIED', 'UNPERFORMED'].includes(row.status)))) return 1
  return rows.some(row => row.status === 'UNPERFORMED') ? 2 : 0
}

export async function main(argv = process.argv.slice(2)) {
  try {
    requireValue(process.versions.node === '24.11.1', 'node-version')
    requireValue(argv.every(arg => ['--check', '--write', '--offline'].includes(arg))
      && new Set(argv).size === argv.length && !(argv.includes('--check') && argv.includes('--write')), 'usage')
    const document = validateDocument(parseUniqueJson(readBounded(resolve(root, 'evidence/runtime-claims.json'), 128 * 1024).toString('utf8'), { maxBytes: 128 * 1024 }))
    const file = resolve(root, 'docs/CLAIMS.md'), source = readBounded(file, 2 * 1024 * 1024).toString('utf8')
    const expected = generatedPage(source, document)
    if (argv.includes('--write')) {
      writeFileSync(file, expected)
      console.log(`GENERATED runtime-claims rows=${document.claims.length}; no verification inferred`)
    }
    const deadline = performance.now() + 25000, rows = []
    console.log('| Claim | Status | Reason |\n| --- | --- | --- |')
    for (const claim of document.claims) {
      const result = await verifyClaim(claim, { offline: argv.includes('--offline'), remaining: () => deadline - performance.now() })
      rows.push(result)
      console.log(`| ${claim.id} | ${result.status} | ${result.reason} |`)
      if (result.checkedCommit) console.log(`CHECKED ${claim.id} clone=${result.checkedCommit}; historical runtime not attested`)
    }
    if (argv.includes('--check') && source !== expected) {
      console.log('FAILED runtime-claims:stale-generated-table')
      return 1
    }
    const counts = ['VERIFIED', 'REPORTED', 'UNPERFORMED', 'FAILED'].map(status => `${status} ${rows.filter(row => row.status === status).length}`).join(' / ')
    console.log(`runtime-claims: ${counts}`)
    if (rows.some(row => row.status === 'UNPERFORMED')) console.log(`UNPERFORMED: ${rows.filter(row => row.status === 'UNPERFORMED').length} claim(s) could not be checked now (${[...new Set(rows.filter(row => row.status === 'UNPERFORMED').map(row => row.reason))].join(', ')})`)
    return resultCode(rows, document.claims)
  } catch (error) {
    console.log(`FAILED ${/^runtime-claims:[a-z-]+$/u.test(error?.message) ? error.message : 'runtime-claims:input-unavailable-or-invalid'}`)
    return 1
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) process.exitCode = await main()
