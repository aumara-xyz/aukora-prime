// SPDX-License-Identifier: AGPL-3.0-or-later
// Pin the gap between a path verdict and a later open; all swapped targets are disposable fixtures.
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { createGuard, readSettings } from './lib/index.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const mutant = process.env.FILE_FENCE_MUTANT
const policyUrl = new URL('./lib/policy.mjs', import.meta.url)
async function loadPolicy() {
  if (!mutant || mutant === 'no-swap') return import(policyUrl.href)
  const mutations = {
    'read-root': ["if (confineReads && kind !== 'dir') {", 'if (false) {'],
    'write-root': ['const roots = [...workspace, ...repoRoots, ...extraWritableRoots]', "const roots = ['/']"],
  }
  assert.ok(Object.hasOwn(mutations, mutant), 'unknown file-fence mutant')
  const source = readFileSync(policyUrl, 'utf8')
  const [before, after] = mutations[mutant]
  assert.equal(source.split(before).length, 2, 'mutation must remove exactly one root check')
  const changed = source.replace(before, after).replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}`)
}
const { createPolicy } = await loadPolicy()

function fixture(t, mode, component) {
  const root = realpathSync(mkdtempSync(join(here, '.file-fence-race-')))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside')
  for (const dir of [join(workspace, 'folder'), outside]) mkdirSync(dir, { recursive: true })
  const target = join(workspace, 'folder', 'note.txt')
  const escaped = join(outside, 'note.txt')
  writeFileSync(target, 'inside fixture')
  // The parent write case also exercises a newly created destination.
  const original = mode === 'write' && component === 'parent' ? null : 'outside fixture'
  if (original !== null) writeFileSync(escaped, original)
  const settings = readSettings({
    home: root, supportRoot: join(root, 'support'), dshHome: join(root, 'state', 'home'),
    auraDir: join(root, 'aura'), repoRoots: [], releaseRoots: [], extraWritableRoots: [],
    readRoots: [], defaultWorkspace: workspace, confineReads: true,
    networkAllow: [], allowLoopback: false,
  })
  function swap() {
    if (mutant === 'no-swap') return
    const path = component === 'leaf' ? target : dirname(target)
    renameSync(path, `${path}.held`)
    symlinkSync(component === 'leaf' ? escaped : outside, path)
  }
  const call = { tool: mode, args: { file_path: target, content: 'changed fixture' }, workspace }
  const exec = { name: mode, arguments: call.args, agent: { session: { header: { cwd: workspace } } } }
  return { settings, target, escaped, original, call, exec, swap }
}

for (const mode of ['read', 'write']) {
  for (const component of ['leaf', 'parent']) {
    test(`${mode}: existing ${component} symlink outside the root is refused`, t => {
      const f = fixture(t, mode, component)
      const policy = createPolicy(f.settings)
      assert.equal(policy.judge(f.call).decision, 'allow')
      f.swap()
      assert.equal(policy.judge(f.call).rule, `${mode}:outside-workspace`)
    })

    test(`${mode}: ${component} swap after the real guard allows redirects a later open`, async t => {
      const f = fixture(t, mode, component)
      const guard = createGuard({ settings: f.settings })
      assert.equal(guard(f.exec), undefined, 'the real guard and receipt path allow the original file')
      // A deterministic interleaving: verdict and receipt finish, another actor swaps an entry,
      // then the synthetic consumer opens the same pathname. No harness runtime is exercised.
      f.swap()
      let result
      if (mode === 'read') result = readFileSync(f.target, 'utf8')
      else writeFileSync(f.target, f.call.args.content)
      const after = existsSync(f.escaped) ? readFileSync(f.escaped, 'utf8') : null
      assert.match(guard(f.exec), new RegExp(`\\[${mode}:outside-workspace\\]`), 'a fresh check would refuse')
      if (mode === 'read') assert.equal(result, f.original, 'the later read reached the outside fixture')
      else assert.equal(after, f.call.args.content, 'the later write changed or created the outside fixture')
      await t.test('known-failing: the allowed operation stays inside the checked root', {
        todo: 'The guard returns a verdict, not an open descriptor; a later pathname open follows the swapped symlink.',
      }, () => {
        if (mode === 'read') assert.equal(result, 'inside fixture')
        else assert.equal(after, f.original)
      })
    })
  }
}
