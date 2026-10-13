#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Checks status labels, local references and generated page freshness.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const states = new Set(['RAN on a real node', 'RAN in staging', 'RAN in CI', 'SOURCE only', 'NOT BUILT'])
const esc = text => text.replaceAll('|', '\\|').replaceAll('\n', ' ')
const link = path => `[${path}](../${path})`

export function anchors(text) {
  const counts = new Map()
  return new Set([...text.matchAll(/^#{1,6} (.+)$/gm)].map(([, heading]) => {
    const slug = heading.toLowerCase().replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
      .replace(/[^\p{L}\p{N}_\-\s]/gu, '').replace(/\s/g, '-')
    const count = counts.get(slug) ?? 0
    counts.set(slug, count + 1)
    return count ? `${slug}-${count}` : slug
  }))
}

export function checkReference(root, from, target) {
  if (/^(?:https?:|mailto:)/.test(target)) return
  const [path, fragment] = decodeURIComponent(target).split('#')
  const file = path ? resolve(root, dirname(from), path) : resolve(root, from)
  const local = relative(root, file)
  if (local.startsWith('..') || local.startsWith('/')) throw Error('reading:path-outside-repository')
  // Only this parallel page may be absent until its worker lands.
  if (local === 'docs/THREAT-MODEL.md' && !existsSync(file)) return
  if (!existsSync(file)) throw Error(`reading:path-missing:${from}:${target}`)
  if (fragment && !anchors(readFileSync(file, 'utf8')).has(fragment)) throw Error(`reading:anchor-missing:${from}:${target}`)
}

export function commandPaths(command) {
  return [...command.matchAll(/(?:^|\s)(?:\.\/)?((?:scripts|tests|packages|plugins|ops|vendor|docs|harness|host|labs)\/[\w./-]+|prime|security-review(?:-containment)?)(?=\s|$)/g)]
    .map(match => match[1])
}

export function validateStatus(data, root) {
  for (const row of data.rows) {
    if (!states.has(row.state)) throw Error('status:label-invalid')
    for (const path of [...row.code, ...row.evidence, ...row.commandPaths]) checkReference(root, 'docs/STATUS.md', `../${path}`)
    const cited = commandPaths(row.command)
    if (!cited.length || cited.some(path => !row.commandPaths.includes(path)) || row.commandPaths.some(path => !cited.includes(path)))
      throw Error('status:command-paths-mismatch')
  }
  for (const join of data.joins) for (const path of join.paths) checkReference(root, 'docs/STATUS.md', `../${path}`)
}

export function renderStatus(data) {
  return [
    '# What exists and what ran', '',
    `As of ${data.asOf}. ${data.scope}`, '',
    'The vision and reading order remain in [the reading guide](READING-GUIDE.md). These labels describe the scope of retained runs, not a new observation of an installed program. **RAN on a real node**, **RAN in staging** and **RAN in CI** apply only to the named experiment; **SOURCE only** means present code without that runtime evidence; **NOT BUILT** means the named behavior is absent. A source test listed below is an entry point, not a report that it ran today.', '',
    'Later dated [plan entries](../plan/NORTH-STAR.md) and the [pilot procedure](../ops/pilot/README.md) supersede older status statements in the reading pages and the generated [component map](../ARCHITECTURE.md). The latest plan records live `c603bbf`, a successful signed-in screen probe, and Buzz configured briefly before the owner parked it idle. No remote machine was inspected for this page.', '',
    '| Part | What it is | Code | State and retained basis | Command or test; evidence | Next concrete step and limit |',
    '| --- | --- | --- | --- | --- | --- |',
    ...data.rows.map(row => `| ${esc(row.name)} | ${esc(row.description)} | ${row.code.map(link).join('; ')} | **${row.state}**. ${esc(row.basis)} | \`${esc(row.command)}\`; ${row.evidence.map(link).join('; ')} | ${esc(row.next)} |`), '',
    '## Do the parts work as one system?', '',
    ...data.joins.map(join => `${join.text} ${join.paths.map(link).join('; ')}.\n`),
    '## Keep this page current', '',
    'Edit [the status data](../evidence/status.json), then run:', '',
    '```sh', 'node scripts/audit/render-status.mjs --write', 'node scripts/audit/render-status.mjs --check',
    'node --test --test-reporter=tap tests/reading-route.test.mjs', '```', '',
    'The check detects stale rendering and missing local references; it cannot detect a false status entered in the data. Review the cited observation and its limits before changing a label. See [review questions](REVIEW-PROMPTS.md), [known gaps](../README.md#known-gaps), [historical hard questions](HARD-QUESTIONS.md) and the paper’s [falsifiers](AUKORA-GOLDEN-BOUNDARY.md#18-what-would-make-the-claim-fail).', '',
  ].join('\n')
}

export function checkStatus(data, root, page) {
  validateStatus(data, root)
  if (page !== renderStatus(data)) throw Error('status:page-stale')
}

export function checkMode(mode) {
  if (mode.length !== 1 || !['--write', '--check'].includes(mode[0])) throw Error('status:mode-invalid')
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
  const mode = process.argv.slice(2)
  checkMode(mode)
  const data = JSON.parse(readFileSync(resolve(root, 'evidence/status.json'), 'utf8'))
  validateStatus(data, root)
  const page = resolve(root, 'docs/STATUS.md')
  if (mode[0] === '--write') writeFileSync(page, renderStatus(data))
  else checkStatus(data, root, readFileSync(page, 'utf8'))
  console.log(`status: ${data.rows.length} rows PASS (${mode[0]})`)
}
