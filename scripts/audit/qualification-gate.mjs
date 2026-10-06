#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The qualification gate every worker passes before handoff (Peter, 2026-10-06,
// candidate-3 must-fix item 6). One command, five defect classes, each observed
// breaking a handoff in the r4 cycle:
//
//   1. schema-dialect   — added JSON-schema keywords must stay inside the
//      harness-enforced subset (assertObjectJsonSchema in the pinned DSH:
//      single `type`, oneOf, properties/required/boolean additionalProperties,
//      items, scalar enum/const, annotations). Anything else mounts on a dev
//      box and refuses in production.
//   2. fixture-custody  — protected/secret fixture paths must live under a
//      caller-owned private (0700) parent, never the repo checkout or a shared
//      tmp: the validator's ancestor rule refuses group/other-writable parents.
//   3. accepted-pins    — added hex literals used as git objects must name an
//      object that EXISTS in this repository (the pre-squash private-commit pin
//      class), and the repo's pinned-hash tests must pass against the tree.
//   4. dsh-drift        — when a DSH-dependent file changes, the pinned DSH
//      tree must be supplied and the changed DSH-dependent tests must run
//      against it, not against a stale copy or none at all.
//   5. repo-tree-collisions — new symlinks must resolve inside the repo, no
//      tracked path may collide with protected basenames outside their vendored
//      home, and .gitignore directory rules must stay anchored (the `runtime/`
//      swallow class).
//
// Usage: node scripts/audit/qualification-gate.mjs --base <sha> [--dsh-source <path>]
// Exit 0 with every class PASS; exit 1 naming every FAIL. The diff is read from
// the object database (BASE..HEAD), never from the working tree: a handoff is
// commits, and uncommitted bytes are invisible here by design.
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const args = process.argv.slice(2)
const option = name => {
  const at = args.indexOf(name)
  return at >= 0 ? args[at + 1] : undefined
}
const BASE = option('--base')
const DSH_SOURCE = option('--dsh-source') ?? process.env.AUKORA_DSH_SOURCE
if (!BASE) {
  console.error('usage: node scripts/audit/qualification-gate.mjs --base <sha> [--dsh-source <path>]')
  process.exit(2)
}

const git = (...argv) => execFileSync('git', ['-C', ROOT, ...argv], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
const failures = []
const report = (klass, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${klass}: ${detail}`)
  if (!ok) failures.push(`${klass}: ${detail}`)
}
// Child tests get the same private per-user temporary parent check.sh provides:
// several suites declare UNPERFORMED without one, by design.
const privateTmp = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-qualification-'))
chmodSync(privateTmp, 0o700)
process.on('exit', () => { try { rmSync(privateTmp, { recursive: true, force: true }) } catch { /* retained on error */ } })
const childEnv = extra => ({ ...process.env, TMPDIR: privateTmp, ...extra })

let changed, diff
try {
  changed = git('diff', '--name-only', '--diff-filter=ACMR', `${BASE}..HEAD`).split('\n').filter(Boolean)
  diff = git('diff', '--unified=0', `${BASE}..HEAD`)
} catch (error) {
  console.error(`gate setup: cannot diff ${BASE}..HEAD: ${error.message}`)
  process.exit(2)
}
const addedLines = diff.split('\n').filter(line => line.startsWith('+') && !line.startsWith('+++'))
  .map(line => line.slice(1))
const protectedWord = /secret|credential|token|\.key|protected/i

// ── Class 1: schema dialect ──────────────────────────────────────────────────
// Complement of the enforced subset. A keyword only flags when a JSON-schema
// `type: '<scalar|container>'` sits on the same line (grep arguments, byte
// limits and key-export options share these names) and the line is not a
// comment. `format:` is not screened (key-export options make it unusable as a
// signal); the host assertion remains the enforcer.
const SCHEMA_FORBIDDEN = /\b(pattern|patternProperties|minItems|maxItems|minimum|maximum|exclusiveMinimum|exclusiveMaximum|minLength|maxLength|multipleOf|contains|minContains|maxContains|uniqueItems|propertyNames|dependencies|dependentRequired|dependentSchemas|if|then|else|not|anyOf|allOf|\$ref|\$defs|definitions)\s*:/
const SCHEMA_TYPE = /\btype\s*:\s*'(string|number|integer|boolean|object|array|null)'/
// Known pre-existing tool-parameter schemas on the harness mount path, which
// production accepts (RAN: relay posts and the theme route work mounted). They
// are pinned here verbatim; any NEW occurrence outside the strict path fails.
const SCHEMA_KNOWN_MOUNT_PATH = [
  `accent: { type: 'string', pattern: '^(default|#[0-9A-Fa-f]{6})$'`,
  `why: { type: 'string', maxLength: 200`,
  `count: { type: 'integer', minimum: 1, maximum: MAX_READ }`,
  `after: { type: 'string', pattern: '^(0|[1-9][0-9]{0,15})$' }`,
  `author: { type: 'string', pattern: '^[a-z][a-z0-9-]{0,31}$' }`,
  `text: { type: 'string', maxLength: MAX_TEXT_BYTES }`,
]
const schemaFiles = changed.filter(name => /^(plugins|packages)\/.*\.(mjs|js|ts|cjs)$/.test(name)
  && !/\/(checks|tests|test|fixtures)\//.test(name))
const schemaHits = []
for (const file of schemaFiles) {
  const fileDiff = git('diff', '--unified=0', `${BASE}..HEAD`, '--', file)
  for (const line of fileDiff.split('\n')) {
    if (!line.startsWith('+') || line.startsWith('+++')) continue
    const text = line.slice(1)
    if (/^\s*(\/\/|\*)/.test(text)) continue
    if (SCHEMA_KNOWN_MOUNT_PATH.some(known => text.includes(known))) continue
    if (SCHEMA_FORBIDDEN.test(text) && SCHEMA_TYPE.test(text))
      schemaHits.push(`${file}: ${text.trim().slice(0, 120)}`)
    if (/\btype\s*:\s*\[/.test(text)) schemaHits.push(`${file} (type array): ${text.trim().slice(0, 120)}`)
  }
}
report('schema-dialect', schemaHits.length === 0,
  schemaHits.length === 0
    ? `no forbidden JSON-schema keyword in ${schemaFiles.length} schema-bearing changed file(s)`
    : `${schemaHits.length} forbidden keyword occurrence(s) outside the host subset — ${schemaHits[0]}`)

// ── Class 2: fixture custody ─────────────────────────────────────────────────
const custodyHits = []
for (const file of changed) {
  if (!/\.(mjs|js|ts|cjs)$/.test(file)) continue
  const fileDiff = git('diff', '--unified=0', `${BASE}..HEAD`, '--', file)
  const fileIsProtected = protectedWord.test(file)
  for (const line of fileDiff.split('\n')) {
    if (!line.startsWith('+') || line.startsWith('+++')) continue
    const text = line.slice(1)
    if (/mkdtemp(Sync)?\(\s*(path\.)?join\(\s*(os\.)?tmpdir\(\)/.test(text) && (fileIsProtected || protectedWord.test(text)))
      custodyHits.push(`${file}: protected fixture under shared tmp — use a caller-home 0700 parent: ${text.trim().slice(0, 100)}`)
    if (/mkdtemp(Sync)?\(\s*(path\.)?join\(\s*(checksRoot|repoRoot|checkoutRoot)/.test(text))
      custodyHits.push(`${file}: fixture anchored at the repo checkout — the ancestor rule refuses shared checkouts: ${text.trim().slice(0, 100)}`)
    if (/['"]\.[a-z-]*fixtures['"]/.test(text) && /checksRoot|import\.meta\.url/.test(text))
      custodyHits.push(`${file}: fixture parent inside the repo tree: ${text.trim().slice(0, 100)}`)
  }
}
report('fixture-custody', custodyHits.length === 0,
  custodyHits.length === 0
    ? 'no protected fixture created under a shared-tmp or repo-anchored parent'
    : `${custodyHits.length} custody violation(s) — ${custodyHits[0]}`)

// ── Class 3: accepted pins ───────────────────────────────────────────────────
// Only hex used AS a git object is checked: a `<hex>:` path selector, or any
// 40-hex on a line that drives git. Content-hash pins are legitimate non-objects.
const objectHexes = new Set()
for (const line of addedLines) {
  for (const match of line.matchAll(/\b([0-9a-f]{40}):/g)) objectHexes.add(match[1])
  if (/\bgit\b/.test(line))
    for (const match of line.matchAll(/\b([0-9a-f]{40})\b/g)) objectHexes.add(match[1])
}
const missing = []
for (const hex of objectHexes) {
  const probe = spawnSync('git', ['-C', ROOT, 'cat-file', '-t', hex], { encoding: 'utf8' })
  if (probe.status !== 0) missing.push(hex)
}
const pinTests = ['tests/kira-gate-capture-host.test.mjs', 'tests/check-shell-status.test.mjs']
const pinResults = []
for (const test of pinTests) {
  if (!existsSync(join(ROOT, test))) continue
  const run = spawnSync(process.execPath, ['--test', join(ROOT, test)], { encoding: 'utf8', timeout: 180000, env: childEnv() })
  pinResults.push(`${test.split('/').pop()}=${run.status === 0 ? 'PASS' : 'FAIL'}`)
}
const pinsOk = missing.length === 0 && pinResults.every(result => result.endsWith('PASS'))
report('accepted-pins', pinsOk,
  missing.length > 0
    ? `${missing.length} added hex literal(s) name no object in this repo: ${missing[0]}`
    : pinResults.every(result => result.endsWith('PASS'))
      ? `${objectHexes.size} git-object hex literal(s) all resolve; ${pinResults.join(', ')}`
      : `pin test failure: ${pinResults.join(', ')}`)

// ── Class 4: DSH drift ───────────────────────────────────────────────────────
const dshTests = changed.filter(name => /^tests\/.*\.test\.mjs$/.test(name) && /filetool|dsh|grep|search/i.test(name))
const dshNeeded = dshTests.length > 0 || changed.some(name => /filetool|dsh/i.test(name))
if (!dshNeeded) {
  report('dsh-drift', true, 'no DSH-dependent file changed; no DSH source required')
} else if (!DSH_SOURCE) {
  report('dsh-drift', false, 'a DSH-dependent file changed but --dsh-source/AUKORA_DSH_SOURCE is unset')
} else {
  const dshOk = existsSync(DSH_SOURCE) && existsSync(join(DSH_SOURCE, 'packages'))
    && existsSync(join(DSH_SOURCE, 'vendor'))
  let identity = 'upstream-dsh.json unreadable'
  try {
    const upstream = JSON.parse(readFileSync(join(ROOT, 'upstream-dsh.json'), 'utf8'))
    identity = `repo pins archive ${String(upstream.archiveSha256 ?? upstream.sha256 ?? '?').slice(0, 12)}`
  } catch { /* identity stays unreadable */ }
  const dshResults = []
  for (const test of dshTests) {
    const run = spawnSync(process.execPath, ['--test', join(ROOT, test)],
      { encoding: 'utf8', timeout: 300000, env: childEnv({ AUKORA_DSH_SOURCE: DSH_SOURCE }) })
    dshResults.push(`${test.split('/').pop()}=${run.status === 0 ? 'PASS' : 'FAIL'}`)
  }
  const ok = dshOk && dshResults.every(result => result.endsWith('PASS'))
  report('dsh-drift', ok,
    !dshOk
      ? `DSH source ${DSH_SOURCE} is not a complete pinned tree`
      : dshResults.length > 0
        ? `real tree present (${identity}); ${dshResults.join(', ')}`
        : `real tree present (${identity}); no DSH-dependent test changed`)
}

// ── Class 5: repo-tree collisions ────────────────────────────────────────────
const collisionHits = []
const addedLinks = git('diff', '--raw', '--diff-filter=A', `${BASE}..HEAD`).split('\n')
  .filter(line => line.startsWith(':120000'))
for (const line of addedLinks) {
  const target = line.split('\t')[1]
  const link = join(ROOT, target)
  if (!existsSync(link)) { collisionHits.push(`dangling new symlink: ${target}`); continue }
  const resolved = realpathSync(link)
  if (!resolved.startsWith(ROOT + sep)) collisionHits.push(`escaping new symlink: ${target} -> ${resolved}`)
}
const PROTECTED_BASENAMES = new Map([['openviking', /^vendor\/openviking\//]])
for (const name of changed) {
  for (const [basename, allowed] of PROTECTED_BASENAMES) {
    if (name.split('/').includes(basename) && !allowed.test(name))
      collisionHits.push(`protected basename outside its vendored home: ${name}`)
  }
}
const ignoreDiff = git('diff', '--unified=0', `${BASE}..HEAD`, '--', '.gitignore')
for (const line of ignoreDiff.split('\n')) {
  if (!line.startsWith('+') || line.startsWith('+++')) continue
  const rule = line.slice(1).trim()
  if (rule && !rule.startsWith('#') && !rule.startsWith('/') && !rule.startsWith('!')
    && !/[*?[\]]/.test(rule) && rule.endsWith('/'))
    collisionHits.push(`unanchored .gitignore directory rule swallows every depth: ${rule}`)
}
report('repo-tree-collisions', collisionHits.length === 0,
  collisionHits.length === 0
    ? 'new symlinks resolve inside the repo; no protected-basename or unanchored-ignore collision'
    : `${collisionHits.length} collision(s) — ${collisionHits[0]}`)

console.log(failures.length === 0
  ? `QUALIFICATION GATE: 5/5 PASS over ${changed.length} changed file(s) on ${git('rev-parse', '--short', 'HEAD').trim()} (base ${BASE.slice(0, 12)})`
  : `QUALIFICATION GATE: ${failures.length} class(es) FAIL — handoff refused until every class passes`)
process.exit(failures.length === 0 ? 0 : 1)
