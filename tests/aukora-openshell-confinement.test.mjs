// L1 on Linux: Auma's one-shot bash through OpenShell as `auma` (plugins/aukora-openshell-confinement + sbx-exec).
// Source checks of the join; the installed behaviour (refusals, timeout, detached children, cancel) is observed on the
// pilot and recorded in the commit, not claimed here.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { readSettings, validateConfinementInfo, validateRequest, prepareLabTransport } from '../plugins/aukora-openshell-confinement/lib/transport.mjs'
import { guestSpec, guestBashExecutor } from '../plugins/aukora-openshell-confinement/lib/index.mjs'
import { sandboxArgv } from '../packages/boundary-gate/src/sandbox.mjs'
import { resolveLayout } from '../packages/boundary-gate/src/layout.mjs'

const root = new URL('../', import.meta.url)
const read = p => readFileSync(new URL(p, root), 'utf8')
const HOST = '/home/aukora-host/genesis/state/workspace'
const settings = readSettings({ workspaceRoot: '/sandbox', hostWorkspaceRoot: HOST, timeoutSeconds: 60 })
const pol = (workspaceRoot, mode = 'workspace-write') => ({ mode, workspaceRoot, sessionId: 's1' })
const refuses = (fn, reason) => assert.throws(fn, e => e.code === 'SANDBOX_UNAVAILABLE' && (!reason || e.reason === reason))

test('only the EXACT session workspace maps to the guest /sandbox', () => {
  const mapped = guestSpec({ command: 'pwd', workdir: HOST, sandboxPolicy: pol(HOST) }, settings)
  assert.equal(mapped.workdir, '/sandbox')
  assert.deepEqual(mapped.sandboxPolicy, pol('/sandbox'))
  validateRequest(['bash', '-c', 'pwd'], mapped.sandboxPolicy, settings)
  refuses(() => guestSpec({ command: 'x', workdir: HOST + '/sub', sandboxPolicy: pol(HOST) }, settings), 'WORKSPACE')
  // another root is not mapped, and validateRequest then refuses it
  const other = guestSpec({ command: 'x', workdir: '/home/aukora-host', sandboxPolicy: pol('/home/aukora-host') }, settings)
  refuses(() => validateRequest(['bash', '-c', 'x'], other.sandboxPolicy, settings), 'WORKSPACE')
  // an escalated mode keeps its mode through the mapping and refuses
  const esc = guestSpec({ command: 'x', workdir: HOST, sandboxPolicy: pol(HOST, 'danger-full-access') }, settings)
  refuses(() => validateRequest(['bash', '-c', 'x'], esc.sandboxPolicy, settings), 'POLICY')
  refuses(() => validateRequest(['bash', '-c', 'x'], pol('/sandbox', 'read-only'), settings), 'POLICY')
  // without a declared mapping nothing is mapped
  const plain = readSettings({})
  assert.equal(guestSpec({ workdir: HOST, sandboxPolicy: pol(HOST) }, plain).workdir, HOST)
  for (const bad of ['/', 'rel', HOST + '/', '/a/../b', '/sandbox', '/a//b']) refuses(() => readSettings({ hostWorkspaceRoot: bad }), 'CONFIG')
})

test('run_code, terminals and alternate argv refuse before any transport', () => {
  refuses(() => validateRequest(['node', '/x/bootstrap.mjs'], pol('/sandbox'), settings), 'RUN_CODE_CONTROL_CHANNEL')
  refuses(() => validateRequest(['/bin/bash', '--noprofile', '--norc', '-i'], pol('/sandbox'), settings), 'TERMINAL_TRANSPORT')
  refuses(() => validateRequest(['sh', '-c', 'id'], pol('/sandbox'), settings), 'TERMINAL_TRANSPORT')
})

test('the guest executor maps, spawns its runner at host /, and refuses background, stdin and env', async () => {
  const seen = []
  class Base {
    resolve(req) { return { command: req.command, workdir: req.workdir ?? '/sandbox', sandboxPolicy: req.sandboxPolicy } }
    async run(spec) { seen.push(spec); return { ok: true } }
    async start() { return 'started' }
  }
  const Guest = guestBashExecutor(Base, settings)
  const g = new Guest()
  const spec = g.resolve({ command: 'ls', workdir: HOST, sandboxPolicy: pol(HOST) })
  assert.equal(spec.workdir, '/sandbox')
  await g.run({ ...spec, dshEnv: { DSH_HOME: '/home/aukora-host/genesis/state/home' } })
  assert.equal(seen[0].workdir, '/')
  assert.equal(seen[0].dshEnv, undefined)
  await assert.rejects(g.start(spec), e => e.reason === 'BACKGROUND')
  refuses(() => g.resolve({ command: 'ls', stdin: 'x', sandboxPolicy: pol(HOST) }), 'TRANSPORT')
  refuses(() => g.resolve({ command: 'ls', env: { A: '1' }, sandboxPolicy: pol(HOST) }), 'TRANSPORT')
})

test('the transport is the boundary runner: env -i, sudo -n -u auma sbx-exec, quoted command in /sandbox', () => {
  const t = prepareLabTransport(['bash', '-c', "echo 'hi'"], pol('/sandbox'), settings, sandboxArgv, resolveLayout())
  assert.deepEqual(t.argv.slice(0, 9), ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', '/usr/bin/sudo', '-n', '-u', 'auma', '/usr/local/lib/aukora-boundary/sbx-exec'])
  assert.equal(t.argv[9], '60')
  assert.match(t.argv[10], /^cd -- '\/sandbox' \|\|/)
  assert.ok(t.argv[10].endsWith(`exec 'bash' '-c' 'echo '\\''hi'\\'''`))
})

test('the wrapper envelope format is what the adapter accepts, and nothing weaker', () => {
  const e = { version: 1, openshell_version: '0.1.2', sandbox: 'auma-ws', state: 'Ready', instance_id: '3cdf6774-267d-4a67-b680-91d998b89cdd',
    policy_revision: 1, applied_revision: 1, workspace_root: '/sandbox', network_mode: 'none',
    policy: { filesystem_policy: { include_workdir: false, read_only: ['/bin', '/usr', '/lib', '/lib64', '/etc', '/proc', '/dev/urandom'], read_write: ['/sandbox', '/tmp', '/dev/null'] },
      landlock: { compatibility: 'hard_requirement' }, version: 1, network_policies: {} } }
  validateConfinementInfo(e)
  for (const f of [x => { x.policy.landlock.compatibility = 'best_effort' }, x => { x.policy.filesystem_policy.include_workdir = true },
    x => { x.network_mode = 'bridge' }, x => { x.applied_revision = 0 }, x => { x.policy.filesystem_policy.read_write.push('/home') },
    x => { x.policy.network_policies = { any: {} } }]) {
    const c = structuredClone(e); f(c); refuses(() => validateConfinementInfo(c))
  }
})

test('sbx-exec re-checks the applied policy under its lock before every command, with no forgeable marker', () => {
  const w = read('packages/boundary-gate/host/sbx-exec')
  assert.ok(!w.includes('SKSBX'), 'argv-marker exemption is gone')
  const lock = w.indexOf('/usr/bin/flock -w'), check = w.indexOf('info check || exit 125'), run = w.indexOf('aukora-boundary exec "$2"')
  assert.ok(lock > 0 && check > lock && run > check, 'lock -> applied-policy check -> exec')
  assert.match(w, /if \[ "\$\{1:-\}" = --confinement-info \]; then\n  \[ "\$#" -eq 1 \] \|\| exit 2/)
  assert.match(w, /'landlock'\) == \{'compatibility': 'hard_requirement'\}/)
  assert.match(w, /fs\.get\('include_workdir'\) is False/)
  assert.match(w, /env\['network_mode'\] == 'none'/)
  assert.match(w, /names\.count\(cname\) != 1/)
  assert.match(w, /trap on_cancel TERM INT HUP/)
  const s = read('packages/boundary-gate/host/openshell/ensure-sandbox.sh')
  assert.equal((s.match(/--policy "\$POLICY"/g) || []).length, 3, 'every create passes the hard startup policy')
  assert.match(s, /policy_ok \|\| \{ echo "REFUSING/)
  assert.match(read('packages/boundary-gate/host/openshell/sandbox-policy.yml'), /compatibility: hard_requirement/)
})

test('Linux-only wiring: the patch swaps Seatbelt and bash-sandbox for the adapter, the release carries it', () => {
  const p = read('overlays/linux-openshell.patch.yml')
  assert.match(p, /^- id: aukora-seatbelt\n  disabled: true$/m)
  assert.match(p, /^- id: bash-sandbox\n  disabled: true$/m)
  assert.match(p, /- id: aukora-openshell-confinement\n {6}name: \.\/plugins\/aukora-openshell-confinement\/lib\/index\.mjs/)
  assert.match(p, /hostWorkspaceRoot: !!js process\.cwd\(\)/)
  const m = read('scripts/materialize-aukora-release.py')
  assert.match(m, /'aukora-openshell-confinement',/)
  assert.match(m, /target \/ 'linux-openshell\.patch\.yml'/)
  assert.match(m, /for module in \('sandbox\.mjs', 'layout\.mjs'\):/)
  assert.ok(JSON.parse(read('plugins/aukora-composition-gate/policy.json')).pluginSet.includes('aukora-openshell-confinement'))
  assert.match(read('packages/boundary-gate/host/systemd/aukora-genesis.service'), /--patch \S+\/linux-openshell\.patch\.yml$/m)
  // the shared composition (macOS too) must not mount it
  assert.ok(!/aukora-openshell-confinement/.test(read('overlays/action-gate.patch.yml')))
})

test('the caged worker refuses on Linux before any filesystem work or spawn', () => {
  const i = read('plugins/aukora-caged-worker/lib/index.mjs'), r = read('plugins/aukora-caged-worker/lib/run.mjs')
  const g = i.indexOf("process.platform === 'linux'"); assert.ok(g > 0 && g < i.indexOf('mkdirSync(workspace'))
  const h = r.indexOf("process.platform === 'linux'"); assert.ok(h > 0 && h < r.indexOf('captureWorkspacePatchArgs(input)', r.indexOf('export async function runPatch')))
})
