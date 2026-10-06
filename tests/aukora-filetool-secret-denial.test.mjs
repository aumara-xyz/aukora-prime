// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the real plugin's global tool guard against harmless fixture files.
// No installed runtime or real credentials are accessed. Removal controls load
// modified production policy in memory only; its other dependencies stay real.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'

// The control compares against a real ripgrep: prefer the DSH tree's packaged
// binary (what production spawns), fall back to a system rg.
const rgBinary = (() => {
  try {
    return createRequire(new URL('../vendor/dsh/packages/fs/tool-fs-search/package.json', import.meta.url))('@vscode/ripgrep').rgPath
  } catch { return 'rg' }
})()

const indexUrl = new URL('../plugins/aukora-action-gate/lib/index.mjs', import.meta.url)
const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
const mutant = process.env.FILETOOL_SECRET_MUTANT
const absoluteImports = (source, base) => source.replace(/from (['"])(\.[^'"]+)\1/gu,
  (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, base).href)}`)
const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`

async function loadGate() {
  if (!mutant) return import(indexUrl.href)
  let source = readFileSync(policyUrl, 'utf8')
  const removals = {
    'auma-key': "  ['**/auma.key', 'auma-relay-key', \"Auma's relay bearer credential\"],\n",
    'nostr-identity': "  ['**/nostr/identity.json', 'nostr-identity', 'the Nostr identity, including its secret signing key'],\n",
    'search-descendants': '      const refused = judgeSearchTree(root, call)\n',
  }
  const target = removals[mutant]
  assert.ok(target, 'unknown removal control')
  assert.equal(source.split(target).length, 2, 'remove exactly one production guard')
  source = source.replace(target, mutant === 'search-descendants' ? '      const refused = null\n' : '')
  const policy = moduleUrl(absoluteImports(source, policyUrl))
  let index = absoluteImports(readFileSync(indexUrl, 'utf8'), indexUrl)
  index = index.replace(JSON.stringify(policyUrl.href), JSON.stringify(policy))
  index = index.replaceAll('import.meta.url', JSON.stringify(indexUrl.href))
  return import(moduleUrl(index))
}
const { apply } = await loadGate()
const marker = 'FIXTURE_MARKER harmless controlled data\n'

function fixture() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-filetool-secret-'))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside')
  const state = join(root, 'state')
  for (const path of [workspace, outside, join(state, 'home')]) mkdirSync(path, { recursive: true })
  let guard
  let invocations = 0
  const definitions = new Map()
  apply({ tools: {
    guard(value) { guard = value },
    get(name) { if (!definitions.has(name)) definitions.set(name, {}); return definitions.get(name) },
  }, get() { return undefined } }, {
    auraDir: join(state, 'home', 'aura-actions'), dshHome: join(state, 'home'), home: root,
    supportRoot: join(root, 'support'), repoRoots: [], releaseRoots: [], readRoots: [outside],
    defaultWorkspace: workspace, confineReads: true, allowLoopback: false, networkAllow: [],
  })
  assert.equal(typeof guard, 'function', 'the actual plugin must register its global tool guard')
  const call = (name, args, cwd = workspace) => {
    const refusal = guard({ name, arguments: args, agent: { id: 'fixture-A', session: { header: { cwd } } } })
    if (refusal !== undefined) return { refusal, invoked: false }
    invocations++
    // A harmless file body proves a refused call never reaches content IO.
    // This transport is a fixture, not an attestation of installed DSH tools.
    if (name === 'grep') {
      const path = args.path ?? cwd
      return { invoked: true, value: execFileSync(rgBinary, ['--hidden', '--no-ignore', '--follow', 'FIXTURE_MARKER', path], { encoding: 'utf8', cwd: cwd ?? workspace }) }
    }
    const raw = args.file_path ?? args.path ?? args.files?.[0]?.path
    const path = raw.startsWith('~/') ? resolve(root, raw.slice(2)) : resolve(cwd, raw)
    return { invoked: true, value: readFileSync(path, 'utf8') }
  }
  const put = path => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, marker); return path }
  return { root, workspace, outside, put, call, count: () => invocations }
}

const spellings = ['.credentials.yaml', 'launch-url.json', 'auma.key', 'nostr/identity.json']
const fileCalls = path => [
  ['read', { file_path: path }], ['read_image', { file_path: path }],
  ['present', { files: [{ path }] }], ['str_replace_editor', { command: 'view', path }],
  ['grep', { path, pattern: 'FIXTURE_MARKER' }],
]
const refused = (result, label) => {
  assert.equal(result.invoked, false, `${label}: protected fixture reached the file body`)
  assert.match(result.refusal, /key-material:|host-secret:|read:hardlink|search:unqualified/u, label)
}

test('all four secret classes stop at the actual global guard across file tools', () => {
  const f = fixture()
  for (const spelling of spellings) {
    const path = f.put(join(f.workspace, 'nested', spelling))
    for (const [name, args] of fileCalls(path)) refused(f.call(name, args), `${name} ${spelling}`)
  }
  assert.equal(f.count(), 0)
})

test('resolved symlinks, relative climbs, home aliases and renamed hardlinks cannot expose a secret', () => {
  const f = fixture()
  for (const [i, spelling] of spellings.entries()) {
    const path = f.put(join(f.outside, spelling))
    const alias = join(f.workspace, `ordinary-${i}.txt`)
    symlinkSync(path, alias)
    for (const [name, args] of fileCalls(alias)) refused(f.call(name, args), `${name} symlink ${spelling}`)
    refused(f.call('read', { file_path: `../outside/${spelling}` }), `relative ${spelling}`)
    refused(f.call('read', { file_path: `~/outside/${spelling}` }), `home ${spelling}`)
    const hardlink = join(f.workspace, `renamed-${i}.txt`)
    linkSync(path, hardlink)
    refused(f.call('read', { file_path: hardlink }), `hardlink ${spelling}`)
  }
  assert.equal(f.count(), 0)
})

test('recursive content searches inspect protected descendants and aliases even under an allowed root', () => {
  for (const spelling of spellings) {
    const f = fixture()
    f.put(join(f.workspace, 'deep', 'hidden', spelling))
    refused(f.call('grep', { path: f.workspace, pattern: 'FIXTURE_MARKER' }), `descendant ${spelling}`)
    assert.equal(f.count(), 0)
  }
  for (const kind of ['symlink', 'hardlink']) {
    const f = fixture()
    const target = f.put(join(f.outside, 'auma.key'))
    mkdirSync(join(f.workspace, 'deep'))
    const alias = join(f.workspace, 'deep', 'ordinary.txt')
    if (kind === 'symlink') symlinkSync(target, alias)
    else linkSync(target, alias)
    refused(f.call('grep', { path: f.workspace, pattern: 'FIXTURE_MARKER' }), `descendant ${kind}`)
  }
})

test('a clean workspace still supports reads, image/view/present transport and recursive search', () => {
  const f = fixture()
  const path = f.put(join(f.workspace, 'nested', 'public.txt'))
  for (const [name, args] of fileCalls(path)) {
    const result = f.call(name, args)
    assert.equal(result.invoked, true, `${name} clean file`)
    assert.ok(result.value.includes('FIXTURE_MARKER'))
  }
  assert.equal(f.call('read', { file_path: 'nested/public.txt' }).invoked, true)
  assert.equal(f.call('grep', { pattern: 'FIXTURE_MARKER' }).invoked, true)
  assert.equal(f.call('grep', { path: f.workspace, pattern: 'FIXTURE_MARKER' }, null).invoked, true)
  const unknownRoot = f.call('grep', { pattern: 'FIXTURE_MARKER' }, null)
  assert.equal(unknownRoot.invoked, false)
  assert.match(unknownRoot.refusal, /search:unbound-root/u)
})

test('grep checks the literal tilde subtree instead of substituting a clean home subtree', () => {
  const f = fixture()
  f.put(join(f.outside, 'clean', 'public.txt'))
  f.put(join(f.workspace, '~', 'outside', 'clean', 'auma.key'))
  refused(f.call('grep', { path: '~/outside/clean', pattern: 'FIXTURE_MARKER' }), 'literal tilde descendant')
  assert.equal(f.count(), 0)
})

test('unresolved links, directory cycles and depth exhaustion refuse the entire search', () => {
  const dangling = fixture()
  symlinkSync(join(dangling.outside, 'missing'), join(dangling.workspace, 'link'))
  refused(dangling.call('grep', { path: dangling.workspace }), 'dangling alias')
  const cycle = fixture()
  symlinkSync(cycle.workspace, join(cycle.workspace, 'loop'))
  refused(cycle.call('grep', { path: cycle.workspace }), 'directory cycle')
  const deep = fixture()
  deep.put(join(deep.workspace, ...Array(34).fill('nested'), 'public.txt'))
  refused(deep.call('grep', { path: deep.workspace }), 'depth budget')
})
