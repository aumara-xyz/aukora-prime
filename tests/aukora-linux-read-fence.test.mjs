/**
 * The Linux read fence on Auma's file tools (2026-10-04).
 *
 * Red-team on the Nebius pilot at 7ae564b: the `read` tool, running as the backend user, read the provider
 * credential (`<state>/home/.credentials.yaml`) and the launch token (`<state>/launch-url.json`) because that user
 * owns them; the gate fenced only writes. This court drives the action gate's real policy and fails if either half
 * of the fence is removed: the host-secret patterns (unconditional) or the fail-closed read confinement.
 * It reads no secret: every path is judged, none is opened.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readSettings } from '../plugins/aukora-action-gate/lib/index.mjs'
import { createPolicy } from '../plugins/aukora-action-gate/lib/policy.mjs'

const root = mkdtempSync(join(tmpdir(), 'aukora-read-fence-'))
const state = join(root, 'genesis', 'state')
const dshHome = join(state, 'home')
const workspace = join(state, 'workspace')
const release = join(root, 'release')
for (const dir of [dshHome, workspace, release, join(dshHome, 'aura-actions')]) mkdirSync(dir, { recursive: true })
writeFileSync(join(workspace, 'notes.txt'), 'ok\n')
writeFileSync(join(release, 'README.md'), 'release\n')
symlinkSync(join(dshHome, '.credentials.yaml'), join(workspace, 'innocent.txt'))

const policyWith = extra => createPolicy(readSettings({
  auraDir: join(dshHome, 'aura-actions'), dshHome, home: root, releaseRoots: [release], defaultWorkspace: workspace, ...extra,
}))
const fenced = policyWith({ confineReads: true })
const open = policyWith({ confineReads: false })
const judge = (policy, tool, args) => policy.judge({ tool, args, workspace })

let n = 0
const expect = (policy, tool, args, decision, rulePrefix, label) => {
  const v = judge(policy, tool, args)
  assert.equal(v.decision, decision, `${label}: expected ${decision}, got ${v.decision} [${v.rule}]`)
  if (rulePrefix) assert.ok(v.rule.startsWith(rulePrefix), `${label}: expected rule ${rulePrefix}*, got ${v.rule}`)
  n++
}

// ── THE RED-TEAM PATHS: refused whichever way they are asked. ─────────────────────────────────────────────────
const secrets = [
  [join(dshHome, '.credentials.yaml'), 'host-secret:provider-credentials', 'a credentials'],
  [join(state, 'launch-url.json'), 'host-secret:launch-token', 'b launch token'],
  ['/home/aukora-gate/owner-secret.json', 'host-secret:gate-home', 'c owner secret'],
  ['/home/aukora-gate/gate.db', 'host-secret:gate-home', 'c gate ledger'],
  ['/var/lib/aukora-boundary/targets/plugins/auma-theme/theme.json', 'host-secret:gate-targets', 'c theme target'],
  ['/home/aukora-gate/receipt-ed25519.pem', 'host-secret:gate-home', 'd signing key'],
  ['/proc/self/environ', 'host-secret:proc-environ', 'e self environ'],
  ['/proc/197859/environ', 'host-secret:proc-environ', 'e backend environ'],
  ['/proc/self/mem', 'host-secret:proc-mem', 'e mem'],
  ['/proc/self/cmdline', 'host-secret:proc-cmdline', 'e cmdline'],
  ['/proc/self/task/1/environ', 'host-secret:proc-environ', 'e thread environ'],
  ['/etc/sudoers.d/aukora-boundary', 'host-secret:sudoers-d', 'f sudoers.d'],
  ['/etc/sudoers', 'host-secret:sudoers', 'f sudoers'],
  ['/etc/shadow', 'host-secret:shadow', 'shadow'],
  ['/etc/aukora-boundary/x.conf', 'host-secret:aukora-config', 'etc/aukora*'],
  ['/root/.bashrc', 'host-secret:root-home', 'root home'],
  ['/home/ubuntu/.ssh/id_ed25519', 'key-material:ssh', 'ssh'],
  ['/run/aukora-gate/owner.sock', 'host-secret:gate-sockets', 'owner socket'],
]
for (const policy of [fenced, open]) {
  for (const [path, rule, label] of secrets) {
    expect(policy, 'read', { file_path: path }, 'deny', rule, `read ${label}`)
    expect(policy, 'read_image', { file_path: path }, 'deny', rule, `read_image ${label}`)
    expect(policy, 'str_replace_editor', { command: 'view', path }, 'deny', rule, `view ${label}`)
    expect(policy, 'write', { file_path: path }, 'deny', '', `write ${label}`)
    expect(policy, 'edit', { file_path: path }, 'deny', '', `edit ${label}`)
  }
}

// ── THE FAIL-CLOSED HALF: everything outside the workspace and named roots. ──────────────────────────────────
expect(fenced, 'read', { file_path: '/etc/hostname' }, 'deny', 'read:outside-workspace', 'read /etc/hostname')
expect(fenced, 'read', { file_path: '/etc/passwd' }, 'deny', 'read:outside-workspace', 'read /etc/passwd')
expect(fenced, 'read', { file_path: '/sys/class/net/eth0/address' }, 'deny', 'read:outside-workspace', 'read /sys')
expect(fenced, 'read', { file_path: '/proc/cpuinfo' }, 'deny', 'read:outside-workspace', 'read /proc/cpuinfo')
expect(fenced, 'read', { file_path: join(dshHome, 'sessions', 'other.jsonl') }, 'deny', 'host-secret:harness-state', 'read another session')
expect(fenced, 'read', { file_path: '../launch-url.json' }, 'deny', 'host-secret:launch-token', 'relative climb to token')
expect(fenced, 'read', { file_path: '../home/notes' }, 'deny', 'host-secret:harness-state', 'relative climb into state')
expect(fenced, 'read', { file_path: 'innocent.txt' }, 'deny', 'host-secret:provider-credentials', 'symlink in workspace to credential')
expect(fenced, 'glob', { pattern: '**/*', path: '/home' }, 'deny', '', 'glob /home')
expect(fenced, 'grep', { pattern: 'key', path: state }, 'deny', 'host-secret:harness-state', 'grep the state root')
expect(fenced, 'grep', { pattern: 'x', path: '/etc' }, 'deny', 'read:outside-workspace', 'grep /etc')
expect(fenced, 'write', { file_path: '/tmp/aukora-redteam-write' }, 'deny', 'write:outside-workspace', 'write /tmp')

// ── WHAT STAYS OPEN: the agent's own workspace and the release she runs from. ───────────────────────────────
expect(fenced, 'read', { file_path: join(workspace, 'notes.txt') }, 'allow', 'allow:', 'read workspace file')
expect(fenced, 'read', { file_path: 'notes.txt' }, 'allow', 'allow:', 'read workspace-relative file')
expect(fenced, 'read', { file_path: join(release, 'README.md') }, 'allow', 'allow:', 'read release file')
expect(fenced, 'glob', { pattern: '*.txt' }, 'allow', 'allow:', 'glob the workspace')
expect(fenced, 'write', { file_path: join(workspace, 'out.txt') }, 'allow', 'allow:', 'write workspace file')

// ── THE BREAK TEST, IN-FILE: the confinement is what refuses /etc/hostname (it is open when switched off). ──
expect(open, 'read', { file_path: '/etc/hostname' }, 'allow', 'allow:', 'unfenced control: /etc/hostname')

// ── AND LINUX DEFAULTS TO FENCED when the row does not say otherwise. ───────────────────────────────────────
if (process.platform === 'linux') {
  expect(policyWith({}), 'read', { file_path: '/etc/hostname' }, 'deny', 'read:outside-workspace', 'linux default is fenced')
}

console.log(`aukora-linux-read-fence: ${n}/${n} PASS`)
