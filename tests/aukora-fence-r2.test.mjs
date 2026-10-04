// SPDX-License-Identifier: AGPL-3.0-or-later
// Three bounded policy checks. Commands are judged, never executed; all inode
// fixtures are public synthetic files. No sandbox, key or live service is used.
import assert from 'node:assert/strict'
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const policyUrl = new URL('../plugins/aukora-action-gate/lib/policy.mjs', import.meta.url)
const mutant = process.env.FENCE_R2_MUTANT
async function loadPolicy() {
  if (!mutant) return import(policyUrl.href)
  let source = readFileSync(policyUrl, 'utf8')
  const original = source
  if (mutant === 'command-mentions') {
    source = source.replace(/^    if \(hostMention !== undefined\).*\n/mu, '')
  } else if (mutant === 'hardlinks') {
    source = source.replace('analysis.links.checked && analysis.links.nlink > 1', 'false')
  } else if (mutant === 'path-aliases') {
    source = source.replace('paths?|locations?|worktree', 'paths?|worktree')
  } else throw new Error('unknown focused mutant')
  assert.notEqual(source, original, 'the requested guard must actually be removed')
  // Mutate only an in-memory module; leave source, dependencies and checks intact.
  source = source.replace(/from (['"])(\.[^'"]+)\1/gu,
    (_match, _quote, relative) => `from ${JSON.stringify(new URL(relative, policyUrl).href)}`)
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
}
const { createPolicy } = await loadPolicy()

function fixture() {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'aukora-fence-r2-'))
  const workspace = join(root, 'workspace')
  const alternate = join(root, 'alternate')
  const repository = join(root, 'repository')
  const release = join(root, 'release')
  const readable = join(root, 'readable')
  const worktreesRoot = join(root, 'worktrees')
  const state = join(root, 'state')
  for (const dir of [workspace, alternate, repository, release, readable, worktreesRoot, join(state, 'home')]) {
    mkdirSync(dir, { recursive: true })
  }
  const settings = {
    home: root, supportRoot: join(root, 'support'), dshHome: join(state, 'home'),
    auraDir: join(state, 'home', 'aura-actions'), repoRoots: [repository], releaseRoots: [release],
    extraWritableRoots: [readable, worktreesRoot], readRoots: [readable], defaultWorkspace: workspace,
    worktreesRoot, networkAllow: [], allowLoopback: false, mainBranch: 'main',
    // Deliberately isolate the new guards from the existing outside-root fence.
    confineReads: false,
  }
  const policy = createPolicy(settings)
  const judge = (tool, args, trustedWorkspace = workspace) => policy.judge({ tool, args, workspace: trustedWorkspace })
  return { root, workspace, alternate, repository, release, readable, worktreesRoot, policy, judge }
}

test('command mentions: Linux file-fence secrets are refused before execution', () => {
  const { workspace, judge } = fixture()
  const names = [
    '/synthetic/.credentials.yaml', '/synthetic/launch-url.json',
    '/home/aukora-gate/owner-secret.json', '/home/aukora-gate/gate.db',
    '/home/aukora-gate/receipt-ed25519.pem', '/run/aukora-gate/owner.sock',
    '/var/lib/aukora-boundary/targets/example', '/etc/aukora-example/config',
    '/proc/self/environ', '/proc/42/environ', '/proc/42/task/7/environ',
    '/proc/self/mem', '/proc/self/cmdline', '/etc/shadow', '/etc/gshadow', '/etc/sudoers',
  ]
  for (const path of names) {
    for (const [tool, args] of [
      ['bash', { command: `cat '${path}'`, workdir: workspace }],
      ['run_code', { code: `readFile(${JSON.stringify(path)})` }],
      ['terminal_send', { text: `cat '${path}'` }],
    ]) {
      const verdict = judge(tool, args)
      assert.equal(verdict.decision, 'deny', `${tool} must refuse the named secret`)
      assert.equal(verdict.rule, 'host-secret:mentioned')
    }
  }
  for (const operator of ['|', '&&', '>', '<', ';']) {
    const verdict = judge('bash', { command: `cat /proc/self/environ${operator}public.txt` })
    assert.equal(verdict.rule, 'host-secret:mentioned', 'plain shell operators delimit the named process file')
  }
  assert.equal(judge('bash', { command: "printf 'public fixture\\n'" }).decision, 'allow')
  assert.equal(judge('bash', { command: 'cat gate.db' }).decision, 'allow', 'a public workspace basename is not a gate-home path')
})

test('hardlinks: multiply-linked regular files are refused in every configured root', () => {
  const { workspace, alternate, repository, release, readable, policy, judge } = fixture()
  for (const dir of [workspace, repository, release, readable]) {
    writeFileSync(join(dir, 'public.txt'), 'public fixture\n')
    linkSync(join(dir, 'public.txt'), join(dir, 'second.txt'))
  }
  assert.equal(judge('read', { file_path: join(workspace, 'second.txt') }).rule, 'read:hardlink')
  assert.equal(policy.judge({ tool: 'read', args: { file_path: join(workspace, 'second.txt') } }).rule, 'read:hardlink')
  for (const dir of [repository, release, readable]) {
    const path = join(dir, 'second.txt')
    for (const [tool, args] of [
      ['read', { file_path: path }], ['read_image', { file_path: path }],
      ['str_replace_editor', { command: 'view', path }], ['session_read', { location: path }],
    ]) {
      const verdict = judge(tool, args)
      assert.equal(verdict.decision, 'deny', 'configured host roots are not workspace ownership')
      assert.equal(verdict.rule, 'read:hardlink')
    }
  }
  const inactive = judge('read', { file_path: join(workspace, 'second.txt') }, alternate)
  assert.equal(inactive.rule, 'read:hardlink', 'default workspace is not an exception while another session workspace is active')
  const forged = judge('session_read', { location: join(readable, 'second.txt'), workspace: readable })
  assert.equal(forged.rule, 'read:hardlink', 'model arguments cannot change the trusted workspace')
  writeFileSync(join(readable, 'single.txt'), 'public fixture\n')
  assert.equal(judge('read', { file_path: join(readable, 'single.txt') }).decision, 'allow')
  assert.equal(judge('glob', { path: readable }).decision, 'allow', 'directory nlink is not a file hard link')
})

test('path aliases: location and enabled aliases survive nested extraction', () => {
  const { workspace, worktreesRoot, judge } = fixture()
  const path = join(workspace, '.credentials.yaml')
  // No credential bytes: policy matches this synthetic spelling only.
  // session_read is a synthetic approved-family probe here. The confirmed DSH
  // pin has no registered session_read schema; this does not attest a live tool.
  for (const args of [
    { location: path }, { wrapper: [{ locations: [{ primary: path }] }] },
    { first: { second: { third: { fourth: { locations: [path] } } } } },
  ]) {
    const verdict = judge('session_read', args)
    assert.equal(verdict.decision, 'deny')
    assert.equal(verdict.rule, 'host-secret:provider-credentials')
  }
  for (const key of ['retained', 'presented', 'state']) {
    assert.equal(judge('aura_association', { [key]: path }).rule, 'host-secret:provider-credentials')
  }
  assert.equal(judge('aura_association', { retained: 'relative.txt', presented: 'another.txt' }).rule, 'path:unresolvable')
  const worktree = join(worktreesRoot, 'proposal')
  mkdirSync(worktree)
  assert.equal(judge('aukora_self_change', { worktree: 'proposal', paths: ['.credentials.yaml'] }).rule,
    'host-secret:provider-credentials', 'paths resolve in the existing validated worktree')
  assert.equal(judge('aukora_self_change', { worktree, paths: ['public.txt'] }).decision, 'allow')
  assert.equal(judge('session_read', { location: join(workspace, 'public.txt') }).decision, 'allow')
  let tooDeep = { location: path }
  for (let i = 0; i < 34; i++) tooDeep = { nested: tooDeep }
  assert.equal(judge('session_read', tooDeep).rule, 'path:unresolvable')
  assert.equal(judge('session_read', { values: Array(4100).fill(null) }).rule, 'path:unresolvable')
  const cycle = {}; cycle.nested = cycle
  assert.equal(judge('session_read', cycle).rule, 'path:unresolvable')
})
