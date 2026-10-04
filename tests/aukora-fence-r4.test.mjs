// SPDX-License-Identifier: AGPL-3.0-or-later
// One focused source-policy regression. Only harmless synthetic files and
// in-memory verdicts are used; no command, live tool or credential is opened.
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
async function loadPolicy() {
  if (!process.env.FENCE_R4_MUTANT) return import(policyUrl.href)
  assert.equal(process.env.FENCE_R4_MUTANT, 'whole-path')
  let source = readFileSync(policyUrl, 'utf8')
  const original = source
  // Remove only the whole-argument guard, restoring r3 substring discovery.
  source = source.replace('if (wholePathTraversal(raw)) return true', "if (raw.includes('../')) return true")
  assert.notEqual(source, original, 'the requested guard must actually be removed')
  source = source.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}
const { createPolicy } = await loadPolicy()

test('whole paths: embedded prose traversal stays text while actual paths retain refusal', () => {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-fence-r4-'))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside folder')
  const state = join(root, 'state')
  const spacedDirectory = join(workspace, 'folder with spaces')
  for (const dir of [workspace, outside, spacedDirectory, join(state, 'home')]) mkdirSync(dir, { recursive: true })
  const publicFile = join(workspace, 'public.txt')
  const outsideFile = join(outside, 'public file.txt')
  const protectedFile = join(spacedDirectory, '.credentials.yaml')
  for (const path of [publicFile, outsideFile, protectedFile]) writeFileSync(path, 'public synthetic fixture\n')
  const policy = createPolicy({
    home: root, supportRoot: join(root, 'support'), dshHome: join(state, 'home'),
    auraDir: join(state, 'home', 'aura-actions'), repoRoots: [], releaseRoots: [],
    extraWritableRoots: [], readRoots: [], defaultWorkspace: workspace,
    networkAllow: [], allowLoopback: false, mainBranch: 'main', confineReads: true,
  })
  const judge = (tool, args) => policy.judge({ tool, args, workspace })
  // session_probe is a synthetic approved-family name, not a live registration.
  const prose = [
    'Please discuss ../.credentials.yaml',
    'Please explain ../../../outside/not-created.txt without opening it.',
    'The text docs/../../../outside/file is an example, not a request.',
    'An ordinary sentence contains ../ and continues.',
  ]
  for (const message of prose) {
    assert.equal(judge('session_probe', { message }).decision, 'allow', 'embedded traversal must stay prose')
    assert.equal(judge('session_probe', { envelope: [{ details: { message } }] }).decision, 'allow')
    assert.equal(judge('read', { file_path: publicFile, message }).decision, 'allow', 'known-tool extra text stays prose too')
  }
  for (const path of [
    '../outside folder/not-created file.txt',
    '../outside folder/not-created file.txt ',
    './folder with spaces/../../outside folder/not-created file.txt',
    'folder/../../outside/not-created.txt',
  ]) {
    assert.equal(judge('session_probe', { envelope: [{ arbitrary: path }] }).rule, 'read:outside-workspace',
      'whole traversal paths, including explicit paths with spaces, remain candidates even when absent')
  }
  assert.equal(judge('session_probe', { arbitrary: outsideFile }).rule, 'read:outside-workspace',
    'absolute existing paths with spaces remain discoverable')
  assert.equal(judge('session_probe', { arbitrary: 'folder with spaces/.credentials.yaml' }).rule,
    'host-secret:provider-credentials', 'bare relative existing paths with spaces remain discoverable')
  const declaredPath = 'missing folder/../../outside folder/not-created file.txt'
  assert.equal(judge('read', { file_path: declaredPath }).rule, 'read:outside-workspace',
    'the schema-specific read field is judged without the discovery heuristic')
  assert.equal(judge('session_probe', { location: declaredPath }).rule, 'read:outside-workspace',
    'explicit path aliases retain their existing meaning')
  assert.equal(judge('session_probe', { arbitrary: './folder with spaces/../public.txt' }).decision, 'allow',
    'a genuine traversal path landing inside the workspace remains allowed')
  assert.equal(judge('session_probe', { message: 'ordinary metadata' }).decision, 'allow')
})
