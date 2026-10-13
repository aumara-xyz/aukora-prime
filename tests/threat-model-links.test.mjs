// Cited files and researcher entry links must exist.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, statSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const documentDirectory = resolve(root, 'docs')
const page = readFileSync(resolve(documentDirectory, 'THREAT-MODEL.md'), 'utf8')
const readme = readFileSync(resolve(root, 'README.md'), 'utf8')
const security = readFileSync(resolve(root, 'SECURITY.md'), 'utf8')

function checkReferences(markdown) {
  const citations = [...markdown.matchAll(/\[[^\]\n]+\]\(([^)\s]+)\)/gu)]
    .map(match => [documentDirectory, match[1].split('#')[0]])
  for (const match of markdown.matchAll(/`(\.\/[^`\s]+)(?: [^`]*)?`/gu)) citations.push([root, match[1]])
  assert.ok(citations.length, 'THREAT_MODEL_CITATIONS_MISSING')
  for (const [base, target] of citations) {
    let present = false
    try { present = statSync(resolve(base, target)).isFile() }
    catch (error) { if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error }
    assert.ok(present, 'THREAT_MODEL_REFERENCE_MISSING: ' + target)
  }
  return new Set(citations.map(([base, target]) => resolve(base, target))).size
}

function checkEntrypoints(front, policy) {
  assert.match(front.split('\n').slice(0, 6).join('\n'), /\[Threat model\]\(docs\/THREAT-MODEL\.md\)/u, 'THREAT_MODEL_README_LINK_MISSING')
  assert.match(policy, /\[threat model\]\(docs\/THREAT-MODEL\.md\)/u, 'THREAT_MODEL_SECURITY_LINK_MISSING')
}

function mutate(fn, before, after) {
  const source = fn.toString()
  assert.equal(source.split(before).length, 2, 'one mutation anchor')
  return Function('assert', 'statSync', 'resolve', 'root', 'documentDirectory',
    'return (' + source.replace(before, after) + ')')(assert, statSync, resolve, root, documentDirectory)
}

test('every cited file, check and command exists; both entry links reach the page', t => {
  t.diagnostic('PASS threat-model references: ' + checkReferences(page) + ' distinct files')
  checkEntrypoints(readme, security)
})

test('missing document, test and command references refuse; removed file guard fails each control', t => {
  const mutant = mutate(checkReferences,
    "assert.ok(present, 'THREAT_MODEL_REFERENCE_MISSING: ' + target)",
    "assert.ok(true, 'THREAT_MODEL_REFERENCE_MISSING: ' + target)")
  for (const broken of ['[source](../docs/absent-threat-model.md)',
    '[check](../tests/absent-threat-model.test.mjs)', '`./scripts/absent-threat-model.sh .`']) {
    const control = check => assert.throws(() => check(broken), /THREAT_MODEL_REFERENCE_MISSING/u)
    control(checkReferences)
    assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
  }
  t.diagnostic('MUTATION KILLED missing-reference guard: document, test, command')
})

test('empty citation set refuses; removing its guard fails the control', t => {
  const control = check => assert.throws(() => check('No citations.'), /THREAT_MODEL_CITATIONS_MISSING/u)
  control(checkReferences)
  const mutant = mutate(checkReferences,
    "assert.ok(citations.length, 'THREAT_MODEL_CITATIONS_MISSING')", '')
  assert.throws(() => control(mutant), { code: 'ERR_ASSERTION' })
  t.diagnostic('MUTATION KILLED empty-citation guard')
})

test('entry link removals refuse; removing either guard fails its control', t => {
  for (const [name, before, args] of [
    ['README', "assert.match(front.split('\\n').slice(0, 6).join('\\n'), /\\[Threat model\\]\\(docs\\/THREAT-MODEL\\.md\\)/u, 'THREAT_MODEL_README_LINK_MISSING')", ['', security]],
    ['SECURITY', "assert.match(policy, /\\[threat model\\]\\(docs\\/THREAT-MODEL\\.md\\)/u, 'THREAT_MODEL_SECURITY_LINK_MISSING')", [readme, '']],
  ]) {
    const control = check => assert.throws(() => check(...args), /THREAT_MODEL_.*_LINK_MISSING/u)
    control(checkEntrypoints)
    assert.throws(() => control(mutate(checkEntrypoints, before, '')), { code: 'ERR_ASSERTION' })
    t.diagnostic('MUTATION KILLED ' + name + ' entry-link guard')
  }
})
