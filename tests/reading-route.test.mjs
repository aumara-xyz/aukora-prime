// SPDX-License-Identifier: AGPL-3.0-or-later
// Local reading references, status evidence and generated-page freshness stay checkable.
import assert from 'node:assert/strict'
import test from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import * as renderer from '../scripts/audit/render-status.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const script = join(root, 'scripts/audit/render-status.mjs')
const source = readFileSync(script, 'utf8')
const files = ['README.md', 'AGENTS.md', 'CLAUDE.md', 'SHARE.md', 'docs/READING-GUIDE.md',
  'docs/STATUS.md', 'docs/REVIEW-PROMPTS.md']
if (existsSync(join(root, 'docs/VISION.md'))) files.push('docs/VISION.md')
const repoPaths = /(?<![\w./:-])((?:apps|docs|evidence|harness|host|labs|licenses|ops|overlays|packages|patches|plan|plugins|presets|provenance|research|scripts|tests|vendor)\/[\w./-]+)/gu
const data = () => JSON.parse(readFileSync(join(root, 'evidence/status.json'), 'utf8'))
const refusal = (run, message) => assert.throws(run, error => error.message === message)

function inspectReferences(api, repository, from, text) {
  let links = 0
  for (const [, target] of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/gu)) {
    api.checkReference(repository, from, target)
    links++
  }
  const prose = text.replace(/!?\[[^\]]*\]\([^)]*\)/gu, '')
  const paths = new Set([...prose.matchAll(repoPaths)].map(match => match[1]))
  for (const [, code] of text.matchAll(/`([^`\n]+)`/gu))
    for (const path of api.commandPaths(code)) paths.add(path)
  for (const [, code] of text.matchAll(/```[^\n]*\n([\s\S]*?)```/gu))
    for (const line of code.split('\n')) for (const path of api.commandPaths(line)) paths.add(path)
  for (const path of paths) api.checkReference(repository, from, relative(dirname(from), path))
  return { links, paths: paths.size }
}

test('existing owner reading route and new evidence pages have no dead local reference', () => {
  let links = 0, paths = 0
  for (const file of files) {
    let text = readFileSync(join(root, file), 'utf8')
    if (file === 'README.md') {
      assert.ok(text.includes('\n## Check it yourself\n'), 'keep the README top-section boundary')
      text = text.split('\n## Check it yourself\n')[0]
    }
    const found = inspectReferences(renderer, root, file, text)
    assert.ok(found.links > 0, `${file} retains a linked reading stop`)
    links += found.links; paths += found.paths
  }
  console.log(`reading-route: ${files.length} pages, ${links} links, ${paths} paths PASS (local references only)`)
})

test('status data cites resolving paths and command paths; the page matches its data', () => {
  const status = data()
  renderer.validateStatus(status, root)
  renderer.checkStatus(status, root, readFileSync(join(root, 'docs/STATUS.md'), 'utf8'))
  assert.equal(renderer.renderStatus(status), readFileSync(join(root, 'docs/STATUS.md'), 'utf8'))
})

test('the real status --check command passes', () => {
  const child = spawnSync(process.execPath, [script, '--check'], {
    cwd: root, encoding: 'utf8', timeout: 10000, env: { ...process.env, NODE_OPTIONS: '' },
  })
  assert.equal(child.error, undefined)
  assert.equal(child.signal, null)
  assert.equal(child.status, 0, child.stdout + child.stderr)
  assert.match(child.stdout, /^status: \d+ rows PASS \(--check\)$/mu)
  const invalid = spawnSync(process.execPath, [script, '--bogus'], {
    cwd: root, encoding: 'utf8', timeout: 10000, env: { ...process.env, NODE_OPTIONS: '' },
  })
  assert.equal(invalid.error, undefined)
  assert.equal(invalid.status, 1)
  assert.match(invalid.stderr, /status:mode-invalid/u)
})

test('heading slugs, external links and the one pending parallel page are handled explicitly', () => {
  assert.deepEqual([...renderer.anchors('# One\n## One\n## Aura coverage audit — 2026-10-12\n')],
    ['one', 'one-1', 'aura-coverage-audit--2026-10-12'])
  renderer.checkReference(root, 'README.md', 'https://example.invalid/no-network-check')
  renderer.checkReference(root, 'README.md', 'mailto:review@example.invalid')
  renderer.checkReference(root, 'README.md', 'docs/THREAT-MODEL.md')
  refusal(() => renderer.checkReference(root, 'README.md', 'docs/THREAT-MODEL-OTHER.md'),
    'reading:path-missing:README.md:docs/THREAT-MODEL-OTHER.md')
  for (const mode of [['--write'], ['--check']]) renderer.checkMode(mode)
  for (const mode of [[], ['--bogus'], ['--check', '--write']])
    refusal(() => renderer.checkMode(mode), 'status:mode-invalid')
})

const controls = [
  ['CLI mode', "if (mode.length !== 1 || !['--write', '--check'].includes(mode[0])) throw Error('status:mode-invalid')", '', api =>
    refusal(() => api.checkMode(['--bogus']), 'status:mode-invalid')],
  ['status label', "if (!states.has(row.state)) throw Error('status:label-invalid')", '', (api, fixture, status) =>
    refusal(() => api.validateStatus({ ...status, rows: [{ ...status.rows[0], state: 'LIVE AND SAFE' }] }, fixture), 'status:label-invalid')],
  ['repository path scope', "if (local.startsWith('..') || local.startsWith('/')) throw Error('reading:path-outside-repository')", '', (api, fixture) =>
    refusal(() => api.checkReference(fixture, 'docs/route.md', join(root, 'README.md')), 'reading:path-outside-repository')],
  ['missing path', "if (!existsSync(file)) throw Error(`reading:path-missing:${from}:${target}`)", '', (api, fixture) =>
    refusal(() => api.checkReference(fixture, 'docs/route.md', 'missing.md'), 'reading:path-missing:docs/route.md:missing.md')],
  ['no dead reading stop', "if (!existsSync(file)) throw Error(`reading:path-missing:${from}:${target}`)", '', (api, fixture) =>
    refusal(() => inspectReferences(api, fixture, 'docs/route.md', '1. [Missing stop](missing.md)'),
      'reading:path-missing:docs/route.md:missing.md')],
  ['heading anchor', "if (fragment && !anchors(readFileSync(file, 'utf8')).has(fragment)) throw Error(`reading:anchor-missing:${from}:${target}`)", '', (api, fixture) =>
    refusal(() => api.checkReference(fixture, 'docs/route.md', 'target.md#absent'), 'reading:anchor-missing:docs/route.md:target.md#absent')],
  ['command path agreement', "if (!cited.length || cited.some(path => !row.commandPaths.includes(path)) || row.commandPaths.some(path => !cited.includes(path)))\n      throw Error('status:command-paths-mismatch')", '', (api, fixture, status) =>
    refusal(() => api.validateStatus({ ...status, rows: [{ ...status.rows[0], command: 'node scripts/other.mjs' }] }, fixture), 'status:command-paths-mismatch')],
  ['page freshness', "if (page !== renderStatus(data)) throw Error('status:page-stale')", '', (api, fixture, status) =>
    refusal(() => api.checkStatus(status, fixture, api.renderStatus(status) + '\nSTALE\n'), 'status:page-stale')],
]

for (const [name, before, after, inspect] of controls) test(`removing ${name} turns its control red`, async () => {
  const fixture = mkdtempSync(join(root, '.reading-route-'))
  try {
    mkdirSync(join(fixture, 'docs')); mkdirSync(join(fixture, 'scripts'))
    writeFileSync(join(fixture, 'docs/target.md'), '# Present\n')
    writeFileSync(join(fixture, 'scripts/check.mjs'), '// fixture\n')
    const status = { asOf: 'synthetic', scope: 'fixture', joins: [], rows: [{ name: 'fixture', description: 'fixture',
      state: 'SOURCE only', basis: 'fixture', code: ['scripts/check.mjs'], evidence: ['docs/target.md'],
      command: 'node scripts/check.mjs', commandPaths: ['scripts/check.mjs'], next: 'fixture' }] }
    renderer.validateStatus(status, fixture)
    renderer.checkStatus(status, fixture, renderer.renderStatus(status))
    inspect(renderer, fixture, status)
    assert.equal(source.split(before).length, 2, `${name}: mutate one production guard`)
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(source.replace(before, after)).toString('base64')}`)
    assert.throws(() => inspect(mutant, fixture, status), { code: 'ERR_ASSERTION' },
      'removed protection must fail its assertion, not an import or execution accident')
    console.log(`KILLED reading-route ${name}`)
  } finally { rmSync(fixture, { recursive: true, force: true }) }
})
