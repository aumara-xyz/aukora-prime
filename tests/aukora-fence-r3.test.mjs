// SPDX-License-Identifier: AGPL-3.0-or-later
// Two bounded source-policy checks with harmless synthetic files. No command,
// live tool, credential, sandbox, inode-alias enumeration or runtime is used.
import assert from 'node:assert/strict'
import { linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
const mutant = process.env.FENCE_R3_MUTANT
async function loadPolicy() {
  if (!mutant) return import(policyUrl.href)
  let source = readFileSync(policyUrl, 'utf8')
  const original = source
  if (mutant === 'workspace-hardlinks') {
    source = source.replace('analysis.links.checked && analysis.links.nlink > 1', 'false')
  } else if (mutant === 'generic-paths') {
    source = source.replace('path || discoveredPath(value, discovery)', 'path')
  } else throw new Error('unknown focused mutant')
  assert.notEqual(source, original, 'the requested guard must actually be removed')
  // Load the mutant in memory, retaining the real module dependencies.
  source = source.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}
const { createPolicy } = await loadPolicy()

function fixture() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-fence-r3-'))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside')
  const state = join(root, 'state')
  for (const dir of [workspace, outside, join(state, 'home')]) mkdirSync(dir, { recursive: true })
  const settings = {
    home: root, supportRoot: join(root, 'support'), dshHome: join(state, 'home'),
    auraDir: join(state, 'home', 'aura-actions'), repoRoots: [], releaseRoots: [],
    extraWritableRoots: [], readRoots: [], defaultWorkspace: workspace,
    networkAllow: [], allowLoopback: false, mainBranch: 'main', confineReads: true,
  }
  const policy = createPolicy(settings)
  const judge = (tool, args) => policy.judge({ tool, args, workspace })
  return { root, workspace, outside, settings, judge }
}

test('workspace hardlinks: a real external alias defeats no workspace exception', () => {
  const { workspace, outside, settings } = fixture()
  // Disable read confinement so only the inode guard can refuse this read.
  const policy = createPolicy({ ...settings, confineReads: false })
  const judge = path => policy.judge({ tool: 'read', args: { file_path: path }, workspace })
  const publicFile = join(workspace, 'public.txt')
  const externalAlias = join(outside, 'public-alias.txt')
  writeFileSync(publicFile, 'public synthetic fixture\n')
  linkSync(publicFile, externalAlias)
  const inside = lstatSync(publicFile)
  const external = lstatSync(externalAlias)
  assert.equal(inside.dev, external.dev)
  assert.equal(inside.ino, external.ino, 'the external name must actually name the workspace inode')
  assert.equal(inside.nlink, 2)
  assert.equal(judge(publicFile).rule, 'read:hardlink')
  assert.equal(judge(externalAlias).rule, 'read:hardlink')

  const internalFile = join(workspace, 'internal.txt')
  writeFileSync(internalFile, 'public synthetic fixture\n')
  linkSync(internalFile, join(workspace, 'internal-alias.txt'))
  assert.equal(judge(internalFile).rule, 'read:hardlink', 'workspace-only links are conservatively refused too')
  const singleton = join(workspace, 'single.txt')
  writeFileSync(singleton, 'public synthetic fixture\n')
  assert.equal(judge(singleton).decision, 'allow')
  assert.equal(judge(workspace).decision, 'allow', 'directory nlink is not a regular-file alias count')
})

test('generic paths: unlisted argument keys discover whole existing paths and literal traversal', () => {
  const { workspace, outside, judge } = fixture()
  const publicFile = join(workspace, 'public.txt')
  const outsideFile = join(outside, 'public.txt')
  const protectedFile = join(workspace, '.credentials.yaml')
  for (const path of [publicFile, outsideFile, protectedFile]) writeFileSync(path, 'public synthetic fixture\n')
  // session_probe is a synthetic approved-family name, not a claimed live tool.
  assert.equal(judge('session_probe', { arbitrary: { values: [outsideFile] } }).rule, 'read:outside-workspace')
  assert.equal(judge('session_probe', { arbitrary: protectedFile }).rule, 'host-secret:provider-credentials')
  assert.equal(judge('session_probe', { arbitrary: '.credentials.yaml' }).rule, 'host-secret:provider-credentials')
  assert.equal(judge('session_probe', { arbitrary: '../outside/not-created.txt' }).rule, 'read:outside-workspace')
  assert.equal(judge('read', { file_path: publicFile, arbitrary: [outsideFile] }).rule, 'read:outside-workspace',
    'switch-known tools also scan unlisted keys after their specific path check')
  const alias = join(workspace, 'outside-alias')
  symlinkSync(outsideFile, alias)
  assert.equal(judge('session_probe', { arbitrary: alias }).rule, 'read:outside-workspace')
  assert.equal(judge('session_probe', { arbitrary: publicFile }).decision, 'allow')
  assert.equal(judge('session_probe', { arbitrary: 'public.txt' }).decision, 'allow')
  assert.equal(judge('session_probe', { arbitrary: 'ordinary metadata' }).decision, 'allow')
  assert.equal(judge('session_probe', { arbitrary: join(outside, 'not-created.txt') }).decision, 'allow',
    'an unlisted nonexistent whole string without ../ is not discovered')
  assert.equal(judge('session_probe', { arbitrary: `prose containing ${outsideFile}` }).decision, 'allow',
    'discovery does not tokenize prose or shell text')
  let deep = { arbitrary: outsideFile }
  for (let i = 0; i < 34; i++) deep = { nested: deep }
  assert.equal(judge('session_probe', deep).rule, 'path:unresolvable')
  assert.equal(judge('session_probe', { values: Array(4100).fill(null) }).rule, 'path:unresolvable')
  const cycle = {}; cycle.nested = cycle
  assert.equal(judge('session_probe', cycle).rule, 'path:unresolvable')
})
