// L1 on Linux: Auma's one-shot bash through OpenShell as `auma` (plugins/aukora-openshell-confinement + sbx-exec).
// Source/protocol checks use synthetic Linux metadata and disposable files.
// They do not establish actual kernel mounts, EROFS, network containment or runtime qualification.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { readSettings, readConfinementInfo, validateConfinementInfo, parseConfinementInfoJson, validateRequest, prepareLabTransport } from '../plugins/aukora-openshell-confinement/lib/transport.mjs'
import { guestSpec, guestBashExecutor } from '../plugins/aukora-openshell-confinement/lib/index.mjs'
import { sandboxArgv } from '../packages/boundary-gate/src/sandbox.mjs'
import { resolveLayout } from '../packages/boundary-gate/src/layout.mjs'

const root = new URL('../', import.meta.url)
const read = p => readFileSync(new URL(p, root), 'utf8')
const HOST = '/synthetic/registered/workspace'
const settings = readSettings({ workspaceRoot: '/sandbox', hostWorkspaceRoot: HOST, timeoutSeconds: 60 })
const pol = (workspaceRoot, mode = 'workspace-write') => ({ mode, workspaceRoot, sessionId: 's1' })
const refuses = (fn, reason) => assert.throws(fn, e => e.code === 'SANDBOX_UNAVAILABLE' && (!reason || e.reason === reason))
const canonical = value => Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']' :
  value !== null && typeof value === 'object' ? '{' + Object.keys(value).sort().map(key =>
    JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}' : JSON.stringify(value)
const digest = value => 'sha256:' + createHash('sha256').update(canonical(value), 'utf8').digest('hex')
const reseal = value => {
  value.inventory_digest = digest(value.mount_inventory)
  value.supervisor_inventory_digest = digest(value.supervisor_inventory)
  value.mountinfo_digest = digest(value.mountinfo)
  return value
}
const kernelMount = (mount_id, parent_id, device, root, mountpoint, writable, filesystem, source) => ({
  mount_id, parent_id, device, root, mountpoint, options: [writable ? 'rw' : 'ro'], optional: [],
  filesystem, source, super_options: [writable ? 'rw' : 'ro'],
})
function mountinfo() {
  return [kernelMount('1', '0', '0:40', '/', '/', false, 'overlay', 'overlay'),
    kernelMount('2', '1', '8:1', HOST, '/sandbox', true, 'ext4', '/dev/synthetic'),
    kernelMount('3', '2', '8:1', HOST + '/.git', '/sandbox/.git', false, 'ext4', '/dev/synthetic'),
    kernelMount('4', '1', '0:41', '/', '/tmp', true, 'tmpfs', 'tmpfs'),
    kernelMount('5', '1', '8:2', '/synthetic/volumes/channel/_data', '/.openshell/channel', true, 'ext4', '/dev/channel'),
    kernelMount('6', '1', '8:1', '/synthetic/runtime/openshell-sandbox', '/opt/openshell/bin/openshell-sandbox', false, 'ext4', '/dev/synthetic'),
    kernelMount('7', '1', '0:43', '/', '/proc', false, 'proc', 'proc')]
}
function envelope() {
  const channel = { Type: 'volume', Name: 'synthetic-channel', Source: '/synthetic/volumes/channel/_data',
    Destination: '/.openshell/channel', Driver: 'local', Mode: 'nosuid,nodev',
    Options: ['nosuid', 'nodev'], RW: true, Propagation: 'rprivate' }
  const isolation = { uid: 166535, uid_map: [{ container_id: 0, host_id: 165536, size: 65536 }],
    gid_map: [{ container_id: 0, host_id: 165536, size: 65536 }], cap_eff: '0000000000000000',
    cap_prm: '0000000000000000', cap_bnd: '0000000000000000', no_new_privs: 1, seccomp: 2,
    process_start_time: 12345, workload_binary_digest: 'sha256:' + 'a'.repeat(64) }
  const supervisor = { ...structuredClone(isolation), uid_map: [{ container_id: 0, host_id: 0, size: 4294967295 }],
    gid_map: [{ container_id: 0, host_id: 0, size: 4294967295 }] }
  delete supervisor.workload_binary_digest
  return reseal({ version: 3, openshell_version: '0.1.2', sandbox: 'auma-ws', state: 'Ready',
    instance_id: 'synthetic-instance', policy_revision: 1, applied_revision: 1, workspace_root: '/sandbox', network_mode: 'none',
    policy: { filesystem_policy: { include_workdir: false,
      read_only: ['/bin', '/usr', '/lib', '/lib64', '/etc', '/proc', '/dev/urandom'],
      read_write: ['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx'] },
      landlock: { compatibility: 'hard_requirement' }, version: 1, network_policies: {} },
    mount_inventory: [channel,
      { Type: 'bind', Source: '/synthetic/runtime/openshell-sandbox', Destination: '/opt/openshell/bin/openshell-sandbox',
        Driver: '', Mode: 'ro', Options: ['ro'], RW: false, Propagation: 'rprivate' },
      { Type: 'bind', Source: HOST, Destination: '/sandbox', Driver: '', Mode: 'nosuid,nodev',
        Options: ['nosuid', 'nodev'], RW: true, Propagation: 'rprivate' },
      { Type: 'bind', Source: HOST + '/.git', Destination: '/sandbox/.git', Driver: '', Mode: 'ro,nosuid,nodev',
        Options: ['ro', 'nosuid', 'nodev'], RW: false, Propagation: 'rprivate' }],
    profile_digest: 'sha256:' + 'b'.repeat(64), isolation,
    supervisor_inventory: [{ ...structuredClone(channel), RW: false, Mode: 'ro,nosuid,nodev' }],
    supervisor_isolation: supervisor, mountinfo: mountinfo(),
    workspace_binding: { workspace_source: HOST, git_source: HOST + '/.git', workspace_device: '8:1',
      workspace_inode: '2001', git_device: '8:1', git_inode: '2002', mount_namespace: 'mnt:[4000]' } })
}

function helperFixture() {
  const e = envelope(), sid = '11111111-2222-4333-8444-555555555555'
  const workloadConfig = { Tmpfs: { '/run/openshell-supervisor-ca': 'rw,noexec,nosuid,nodev,mode=0777,size=1m,rprivate,tmpcopyup',
    '/tmp': 'rw,nosuid,nodev,mode=1777' }, Devices: [],
    IpcMode: 'shareable', PidMode: 'private', ReadonlyRootfs: true }
  const supervisorConfig = { Tmpfs: {}, Devices: [], IpcMode: 'shareable', PidMode: 'private', ReadonlyRootfs: false }
  const profile = { version: 1, expected_mounts: structuredClone(e.mount_inventory),
    expected_supervisor_mounts: structuredClone(e.supervisor_inventory),
    workload_binary_digest: e.isolation.workload_binary_digest,
    uid_ranges: [{ host_id: 165536, size: 65536 }], gid_ranges: [{ host_id: 165536, size: 65536 }],
    forbidden_host_ids: [1001], expected_workload_config: workloadConfig, expected_supervisor_config: supervisorConfig }
  const container = { Name: 'openshell-default--auma-ws-' + sid, Id: '1'.repeat(64),
    State: { Pid: 4321, Running: true }, Mounts: structuredClone(e.mount_inventory),
    HostConfig: { Privileged: false, SecurityOpt: ['no-new-privileges'], NetworkMode: 'none', ...workloadConfig } }
  const supervisor = { Name: 'openshell-supervisor-' + sid, Id: '2'.repeat(64),
    State: { Pid: 4322, Running: true }, Mounts: structuredClone(e.supervisor_inventory),
    HostConfig: { Privileged: false, SecurityOpt: ['no-new-privileges'], NetworkMode: 'host', ...supervisorConfig } }
  const process = { pid: 4321, start_time: 12345, uid: 166536, uid_map: structuredClone(e.isolation.uid_map),
    gid_map: structuredClone(e.isolation.gid_map), cap_eff: e.isolation.cap_eff, cap_prm: e.isolation.cap_prm,
    cap_bnd: e.isolation.cap_bnd, no_new_privs: 1, seccomp: 2 }
  const supervisorProcess = { ...structuredClone(process), pid: 4322,
    uid_map: structuredClone(e.supervisor_isolation.uid_map), gid_map: structuredClone(e.supervisor_isolation.gid_map) }
  const registration = { version: 1, workspace_id: sid, workspace_source: HOST, git_source: HOST + '/.git' }
  return { e, sid, profile, container, supervisor, process, supervisor_process: supervisorProcess, registration,
    host_tmp_device: '9:1' }
}

function helperPython(code, fixture = helperFixture()) {
  const prelude = `
import copy, importlib.util, json, subprocess, sys
def forbidden_process(*a, **kw):
    raise AssertionError('unmocked process launch in disposable source test')
subprocess.Popen = forbidden_process
spec = importlib.util.spec_from_file_location('inventory', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
f = json.load(sys.stdin)
def refusal(fn):
    try: fn()
    except (ValueError, KeyError, TypeError, IndexError): return
    raise AssertionError('unsafe fixture accepted')
def protocol_refusal(fn):
    try: fn()
    except ValueError: return
    raise AssertionError('unsafe protocol fixture accepted')
`
  return execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', prelude + '\n' + code,
    fileURLToPath(new URL('packages/boundary-gate/host/openshell/sandbox-inventory.py', root))],
  { input: JSON.stringify(fixture), encoding: 'utf8', timeout: 3000, maxBuffer: 64 * 1024 })
}

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

test('direct ctx.sandbox accepts only the declared byte-exact host policy and preserves guest transport and guards', () => {
  const argv = ['bash', '-c', 'pwd']
  const policy = Object.freeze(pol(HOST))
  const before = JSON.stringify(policy)
  validateRequest(argv, policy, settings)
  const hostTransport = prepareLabTransport(argv, policy, settings, sandboxArgv, resolveLayout())
  const guestTransport = prepareLabTransport(argv, Object.freeze(pol('/sandbox')), settings, sandboxArgv, resolveLayout())
  assert.deepEqual(hostTransport, guestTransport)
  assert.match(hostTransport.argv.at(-1), /^cd -- '\/sandbox' \|\|/)
  assert.ok(!hostTransport.argv.at(-1).includes(HOST))
  assert.equal(JSON.stringify(policy), before, 'the resolved immutable host policy is not rewritten')

  // No filesystem lookup or path normalization turns an alias into this mapping.
  const alias = '/synthetic/workspace-alias'
  for (const root of [undefined, '', '/', '/home/aukora-host', HOST + '/sub', HOST + '/sub/..',
    HOST + '/../workspace', HOST + '/', HOST + '//', alias]) {
    const bad = Object.freeze(pol(root))
    refuses(() => validateRequest(argv, bad, settings), 'WORKSPACE')
    refuses(() => prepareLabTransport(argv, bad, settings, sandboxArgv, resolveLayout()), 'WORKSPACE')
  }
  for (const unmapped of [readSettings({}), readSettings({ hostWorkspaceRoot: undefined })]) {
    refuses(() => validateRequest(argv, policy, unmapped), 'WORKSPACE')
    refuses(() => prepareLabTransport(argv, policy, unmapped, sandboxArgv, resolveLayout()), 'WORKSPACE')
    refuses(() => validateRequest(argv, pol(undefined), unmapped), 'WORKSPACE')
  }
  for (const mode of ['read-only', 'danger-full-access']) {
    const bad = Object.freeze(pol(HOST, mode)), original = JSON.stringify(bad)
    refuses(() => validateRequest(argv, bad, settings), 'POLICY')
    refuses(() => prepareLabTransport(argv, bad, settings, sandboxArgv, resolveLayout()), 'POLICY')
    assert.equal(JSON.stringify(bad), original)
  }
  refuses(() => validateRequest(argv, { ...policy, sessionId: '' }, settings), 'POLICY')
  refuses(() => validateRequest(['node', '/synthetic/bootstrap.mjs'], policy, settings), 'RUN_CODE_CONTROL_CHANNEL')
  refuses(() => validateRequest(['sh', '-c', 'pwd'], policy, settings), 'TERMINAL_TRANSPORT')
  refuses(() => prepareLabTransport(['bash', '-i'], policy, settings, sandboxArgv, resolveLayout()), 'TERMINAL_TRANSPORT')
  const reason = new Error('synthetic cancellation'), signal = AbortSignal.abort(reason)
  assert.throws(() => validateRequest(argv, policy, settings, signal), error => error === reason)
  assert.throws(() => prepareLabTransport(argv, policy, settings, sandboxArgv, resolveLayout(), signal), error => error === reason)
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
  const e = envelope()
  validateConfinementInfo(e)
  for (const f of [x => { x.policy.landlock.compatibility = 'best_effort' }, x => { x.policy.filesystem_policy.include_workdir = true },
    x => { x.network_mode = 'bridge' }, x => { x.applied_revision = 0 }, x => { x.policy.filesystem_policy.read_write.push('/home') },
    x => { x.policy.network_policies = { any: {} } }, x => { x.version = 1 },
    x => { x.policy.filesystem_policy.read_only.push('/home') },
    x => { x.policy.filesystem_policy.read_only[0] = '/usr' },
    x => { x.policy.filesystem_policy.read_only = ['/usr'] },
    x => { x.policy.filesystem_policy.extra = false },
    x => { x.policy.process = { run_as_user: 'sandbox' } },
    x => { x.policy.process = { run_as_user: 'sandbox', run_as_group: 'sandbox', extra: true } },
    x => { x.policy.process = { run_as_user: '', run_as_group: 'sandbox' } }]) {
    const c = structuredClone(e); f(c); refuses(() => validateConfinementInfo(c))
  }
  const process = envelope(); process.policy.process = { run_as_user: 'sandbox', run_as_group: 'sandbox' }
  validateConfinementInfo(process)
})

test('v3 readback binds the entire closed mount records and companion channel inventory', () => {
  // Frozen independent Python json.dumps(sort_keys=True, separators=(',', ':'),
  // ensure_ascii=False) vectors cover compact UTF8 canonicalization.
  const vector = envelope()
  assert.equal(vector.inventory_digest, 'sha256:e8d1965dd453e52169f7163104ecfc8740f65d3612bf49d81dea0d71b2f0e275')
  vector.mount_inventory[1].Source = '/synthetic/runtime/é-sandbox'
  vector.inventory_digest = 'sha256:80f1a7cea61d2867a5c617f609b22e4dbe34184ac31b4309da4b6e06b761a255'
  validateConfinementInfo(vector)
  for (const mutate of [
    x => { x.extra = true }, x => { delete x.profile_digest },
    x => { x.profile_digest = 'sha256:' + 'A'.repeat(64) },
    x => { x.mount_inventory.pop() }, x => { x.mount_inventory.reverse() },
    x => { delete x.mount_inventory[1] },
    x => { x.mount_inventory[0].Destination = '/unexpected' },
    x => { x.mount_inventory[2].Type = 'volume'; x.mount_inventory[2].Name = 'unapproved-workspace' },
    x => { x.mount_inventory[1].RW = true },
    x => { x.mount_inventory[1].Name = 'unapproved-bind-name' },
    x => { delete x.mount_inventory[0].Driver },
    x => { x.mount_inventory[0].unknown = true },
    x => { x.mount_inventory[0].Options.push('nodev') },
    x => { x.mount_inventory[0].Options = 'nodev' },
    x => { x.mount_inventory[0].Options = [''] },
    x => { delete x.mount_inventory[0].Options[0] },
    x => { x.mount_inventory[0].Source = '/synthetic/../escape' },
    x => { x.mount_inventory[0].Source = 'relative' },
    x => { x.mount_inventory[0].Source = '/synthetic//alias' },
    x => { x.mount_inventory[0].Propagation = {} },
    x => { x.supervisor_inventory[0].RW = true },
    x => { x.supervisor_inventory[0].Source = '/synthetic/different-source' },
    x => { x.supervisor_inventory[0].Options = ['ro'] },
    x => { x.supervisor_inventory.push(structuredClone(x.supervisor_inventory[0])) },
  ]) {
    const e = envelope(); mutate(e); reseal(e); refuses(() => validateConfinementInfo(e))
  }
  for (const mutate of [
    x => { x.mount_inventory[1].Source = '/synthetic/changed-binary' },
    x => { x.mount_inventory[2].Options.push('extra') },
    x => { x.supervisor_inventory[0].Mode = 'changed-mode' },
    x => { x.inventory_digest = 'sha256:' + '0'.repeat(64) },
    x => { x.supervisor_inventory_digest = 'sha256:' + '0'.repeat(64) },
  ]) {
    const e = envelope(); mutate(e); refuses(() => validateConfinementInfo(e), 'SANDBOX_INVENTORY')
  }
  // A digest corroborates received bytes. Exact approval of those Source/Options
  // bytes is a separate protected host-profile comparison, not a guest assertion.
  const reorderedKeys = JSON.parse(JSON.stringify(envelope()), (key, value) => value)
  validateConfinementInfo(reorderedKeys)
})

test('v3 readback refuses host-user mappings, map overlaps, capability bits and weakened process isolation', () => {
  for (const mutate of [
    x => { delete x.isolation }, x => { x.isolation.extra = true },
    x => { x.isolation.uid = true }, x => { x.isolation.uid = 1001 },
    x => { x.isolation.uid_map[0].host_id = 1001 },
    x => { x.isolation.uid_map[0].host_id = 0; x.isolation.uid_map[0].size = 231072 },
    x => { x.isolation.gid_map[0].host_id = 1001 },
    x => { x.isolation.uid_map[0].host_id = 165535 },
    x => { x.isolation.uid_map[0].size = 65537 },
    x => { x.isolation.uid_map[0].container_id = 1 },
    x => { x.isolation.uid_map[0].size = 0 },
    x => { x.isolation.uid_map[0].size = true },
    x => { x.isolation.uid_map[0].size = 2 ** 32 },
    x => { x.isolation.uid_map[0].container_id = 2 ** 32 - 1; x.isolation.uid_map[0].size = 2 },
    x => { x.isolation.uid_map.push({ container_id: 1, host_id: 165537, size: 1 }) },
    x => { x.isolation.uid_map[0].extra = 1 },
    x => { x.isolation.cap_eff = '0000000000000001' },
    x => { x.isolation.cap_prm = '0000000000000001' },
    x => { x.isolation.cap_bnd = '0000000000000001' },
    x => { x.isolation.cap_eff = '0' },
    x => { x.isolation.no_new_privs = 0 },
    x => { x.isolation.no_new_privs = true },
    x => { x.isolation.seccomp = 0 },
    x => { x.isolation.process_start_time = 0 },
    x => { x.isolation.process_start_time = Number.MAX_SAFE_INTEGER + 1 },
    x => { x.isolation.workload_binary_digest = 'mutable-tag' },
    x => { x.supervisor_isolation.cap_bnd = '0000000000000001' },
    x => { x.supervisor_isolation.uid = 0 },
    x => { x.supervisor_isolation.uid = 4294967295 },
    x => { x.supervisor_isolation.uid_map.push({ container_id: 1, host_id: 4294967295, size: 1 }) },
    x => { x.supervisor_isolation.workload_binary_digest = 'sha256:' + 'a'.repeat(64) },
  ]) {
    const e = envelope(); mutate(e); refuses(() => validateConfinementInfo(e))
  }
})

test('textual readback rejects duplicate keys, unsafe numbers, invalid Unicode and oversized/deep JSON', () => {
  validateConfinementInfo(parseConfinementInfoJson(JSON.stringify(envelope())))
  for (const source of [
    '{"version":1,"version":2}', '{"version":1,"\\u0076ersion":2}',
    '{"nested":{"source":1,"source":2}}', '{"__proto__":1,"__proto__":2}',
    '{"value":1e999}', '{"value":9007199254740992}', '{"value":"\\ud800"}',
    '{"value":NaN}', '{"value":01}', '{"value":true,}', '{"value":1} trailing',
    '['.repeat(34) + '0' + ']'.repeat(34), ' '.repeat(65537),
  ]) refuses(() => parseConfinementInfoJson(source), 'POLICY_READBACK')
  const parsed = parseConfinementInfoJson('{"__proto__":{"polluted":true}}')
  assert.equal(Object.getPrototypeOf(parsed), null)
  assert.equal({}.polluted, undefined)
})

test('protected profile helper is effect-free and rejects altered full policy, mounts and process facts', () => {
  const result = JSON.parse(helperPython(`
m.validate_policy(f['e']['policy'])
good = m.validate_snapshot(f['container'], f['process'], f['profile'], workload_binary_digest=f['profile']['workload_binary_digest'])
assert good['inventory_digest'] == f['e']['inventory_digest']
assert set(good['isolation']) == set(f['e']['isolation'])
m.validate_supervisor(f['supervisor'], f['supervisor_process'], f['profile'])
for edit in [lambda p: p['filesystem_policy']['read_only'].append('/extra'),
             lambda p: p['filesystem_policy']['read_only'].pop(),
             lambda p: p['filesystem_policy']['read_write'].append('/extra'),
             lambda p: p.update(process={'run_as_user':'sandbox'}),
             lambda p: p['filesystem_policy'].update(include_workdir=True)]:
    p = copy.deepcopy(f['e']['policy']); edit(p); refusal(lambda: m.validate_policy(p))
for edit in [lambda p: p.update(extra=True), lambda p: p.pop('expected_mounts'),
             lambda p: p.update(forbidden_host_ids=[]),
             lambda p: p.update(uid_ranges=[{'host_id':165535,'size':65536}]),
             lambda p: p.update(gid_ranges=[{'host_id':165536,'size':65537}]),
             lambda p: p['expected_workload_config'].update(Devices=[{}]),
             lambda p: p['expected_workload_config'].update(IpcMode='host'),
             lambda p: p['expected_workload_config'].update(PidMode='host'),
             lambda p: p['expected_workload_config']['Tmpfs'].update({'relative':'rw'})]:
    p = copy.deepcopy(f['profile']); edit(p)
    refusal(lambda: m.validate_snapshot(f['container'], f['process'], p, workload_binary_digest=f['profile']['workload_binary_digest']))
for edit in [lambda c: c['Mounts'].append(copy.deepcopy(c['Mounts'][0])),
             lambda c: c['Mounts'].pop(), lambda c: c['Mounts'][0].pop('Options'),
             lambda c: c['Mounts'][0].update(Options=['different']),
             lambda c: c['Mounts'][0].update(Propagation='different'),
             lambda c: c['Mounts'][0].update(Name='different'),
             lambda c: c['Mounts'][0].update(Source='/synthetic/different'),
             lambda c: c['HostConfig']['Tmpfs'].update({'/extra':'rw'}),
             lambda c: c['HostConfig'].update(Devices=[{}]),
             lambda c: c['HostConfig'].update(ReadonlyRootfs=False),
             lambda c: c['HostConfig'].update(Privileged=True),
             lambda c: c['HostConfig'].update(SecurityOpt=[]),
             lambda c: c['State'].update(Pid=9999)]:
    c = copy.deepcopy(f['container']); edit(c)
    refusal(lambda: m.validate_snapshot(c, f['process'], f['profile'], workload_binary_digest=f['profile']['workload_binary_digest']))
refusal(lambda: m.validate_snapshot(f['container'], f['process'], f['profile'], workload_binary_digest='sha256:'+'0'*64))
for edit in [lambda p: p['uid_map'][0].update(host_id=1001),
             lambda p: p['gid_map'][0].update(host_id=1001),
             lambda p: p['uid_map'][0].update(host_id=0,size=231072),
             lambda p: p['uid_map'][0].update(container_id=1),
             lambda p: p['uid_map'][0].update(size=65537),
             lambda p: p['uid_map'][0].update(size=True),
             lambda p: p['uid_map'][0].update(container_id=4294967295,size=2),
             lambda p: p['uid_map'].append({'container_id':1,'host_id':165537,'size':1}),
             lambda p: p.update(uid=1001), lambda p: p.update(cap_eff='0000000000000001'),
             lambda p: p.update(cap_prm='0000000000000001'), lambda p: p.update(cap_bnd='0000000000000001'),
             lambda p: p.update(no_new_privs=0), lambda p: p.update(no_new_privs=True),
             lambda p: p.update(seccomp=0), lambda p: p.update(start_time=0)]:
    p = copy.deepcopy(f['process']); edit(p)
    refusal(lambda: m.validate_snapshot(f['container'], p, f['profile'], workload_binary_digest=f['profile']['workload_binary_digest']))
for edit in [lambda c: c['Mounts'][0].update(RW=True),
             lambda c: c['Mounts'][0].update(Source='/synthetic/different'),
             lambda c: c['HostConfig'].update(NetworkMode='none'),
             lambda c: c['HostConfig'].update(Devices=[{}])]:
    c = copy.deepcopy(f['supervisor']); edit(c)
    refusal(lambda: m.validate_supervisor(c, f['supervisor_process'], f['profile']))
for raw in ['{"value":1,"value":2}', '{"value":NaN}', '{"value":"\\\\ud800"}']:
    refusal(lambda: m.strict_json(raw))
print(json.dumps({'ok':True,'profile_digest':good['profile_digest']}))
`))
  assert.equal(result.ok, true)
  assert.match(result.profile_digest, /^sha256:[0-9a-f]{64}$/)
})

test('tmpfs readback keeps exactly the two producer roles even when profile and observation agree on an extra writable path', () => {
  helperPython(`
assert len(f['container']['Mounts']) == 4
m.validate_snapshot(f['container'], f['process'], f['profile'], workload_binary_digest=f['profile']['workload_binary_digest'])
for edit in [lambda t: t.update({'/sandbox2':'rw,nosuid,nodev,mode=1777'}),
             lambda t: t.pop('/tmp'), lambda t: t.pop('/run/openshell-supervisor-ca'),
             lambda t: t.update({'/tmp':True}), lambda t: t.update({'/tmp':[]} ),
             lambda t: t.update({'/tmp':'rw,nosuid,nodev,mode=1777,rw'}),
             lambda t: t.update({'/tmp':'ro,nosuid,nodev,mode=1777'}),
             lambda t: t.update({'/tmp':'rw,nosuid,nodev,mode=1777,exec'}),
             lambda t: t.update({'/tmp':'rw,nodev,mode=1777'}),
             lambda t: t.update({'/run/openshell-supervisor-ca':'rw,nosuid,nodev,mode=0777,size=1m'})]:
    p, c = copy.deepcopy(f['profile']), copy.deepcopy(f['container'])
    edit(p['expected_workload_config']['Tmpfs'])
    c['HostConfig']['Tmpfs'] = copy.deepcopy(p['expected_workload_config']['Tmpfs'])
    refusal(lambda: m.validate_snapshot(c, f['process'], p, workload_binary_digest=p['workload_binary_digest']))
for kind in ['bind', 'tmpfs']:
    c = copy.deepcopy(f['container'])
    c['Mounts'].append({'Type':kind, 'Source':'/synthetic/extra', 'Destination':'/sandbox2',
        'Driver':'', 'Mode':'rw', 'Options':['rw'], 'RW':True, 'Propagation':'rprivate'})
    refusal(lambda: m.validate_snapshot(c, f['process'], f['profile'], workload_binary_digest=f['profile']['workload_binary_digest']))
`)
})

test('binary evidence binds the observed source and actual process executable without a fallback', () => {
  const result = JSON.parse(helperPython(`
from types import SimpleNamespace
from unittest.mock import patch
info = SimpleNamespace(st_dev=8,st_ino=9,st_mode=0o100755)
with patch.object(m.os,'O_PATH',0o10000000,create=True), patch.object(m,'_anchored_file',return_value=(41,info)), patch.object(m,'_binary_fd_digest',side_effect=['sha256:'+'a'*64,'sha256:'+'a'*64]) as hashed, patch.object(m.os,'open',side_effect=[42,43]) as opened, patch.object(m.os,'fstat',return_value=info), patch.object(m.os,'close') as closed:
    assert m.binary_digest('/synthetic/code',999999999,4321)=='sha256:'+'a'*64
    assert opened.call_args_list[0].args[0]=='/proc/4321/exe'
    assert opened.call_args_list[0].args[1] & m.os.O_PATH
    assert hashed.call_args_list[1].args[0]==43
    closed.assert_called_once_with(42)
with patch.object(m.os,'O_PATH',0o10000000,create=True), patch.object(m,'_anchored_file',return_value=(41,info)), patch.object(m,'_binary_fd_digest',side_effect=['sha256:'+'a'*64,'sha256:'+'b'*64]), patch.object(m.os,'open',side_effect=[42,43]), patch.object(m.os,'fstat',return_value=info), patch.object(m.os,'close'):
    refusal(lambda:m.binary_digest('/synthetic/code',999999999,4321))
with patch.object(m.os,'O_PATH',0o10000000,create=True),patch.object(m,'_anchored_file',return_value=(41,info)), patch.object(m,'_binary_fd_digest',return_value='sha256:'+'a'*64), patch.object(m.os,'open',side_effect=PermissionError('synthetic proc authority absent')):
    try:m.binary_digest('/synthetic/code',999999999,4321)
    except PermissionError:pass
    else:raise AssertionError('missing proc authority accepted')
special = SimpleNamespace(st_dev=8,st_ino=9,st_mode=0o20600)
with patch.object(m.os,'O_PATH',0o10000000,create=True),patch.object(m.os,'open',side_effect=[51,52,53]) as opened,patch.object(m.os,'fstat',return_value=special),patch.object(m.os,'close'):
    refusal(lambda:m._anchored_file('/synthetic/special'))
    assert opened.call_count==3 and opened.call_args.args[1] & m.os.O_PATH
    assert all(not call.args[0].startswith('/proc/') for call in opened.call_args_list)
print(json.dumps({'ok':True}))
`))
  assert.equal(result.ok, true)
})

const admissionMockPrelude = `
names = [f['container']['Name'], f['supervisor']['Name']]
policy = {'policy':f['e']['policy'],'status':'effective','scope':'sandbox','policy_source':'sandbox','config_revision':1,'sandbox':'auma-ws','active_version':1,'hash':'d'*64}
sandbox = {'id':f['sid'],'name':'auma-ws','phase':'Ready','current_policy_version':1,
           'conditions':[{'type':'Ready','status':'True'},{'type':'ConfigurationReady','status':'True'}],
           'configuration_admission':{'state':'accepted','policy_hash':'d'*64,'policy_version':1,'config_revision':1,'provider_env_revision':0},
           'annotations':{'internal.openshell.ai/runtime-generation':'synthetic-instance'}}
scenario = 'good'; counts = {}
def query(argv, deadline):
    route = tuple(argv); counts[route] = counts.get(route,0)+1
    if scenario == 'nonzero_query': raise ValueError('mocked nonzero read-only query')
    if route == ('/usr/bin/openshell','policy','get','auma-ws','--full','-o','json'):
        if scenario == 'malformed': return '{'
        if scenario == 'duplicate': return '{"policy":{},"policy":{}}'
        p = copy.deepcopy(policy)
        if scenario == 'changed_policy' and counts[route] > 1: p['hash'] = 'changed'
        if scenario == 'missing_hash': p.pop('hash')
        if scenario == 'bool_active': p['active_version'] = True
        if scenario == 'global_policy': p['policy_source']='global'
        if scenario == 'global_revision': p['global_policy_version']=1
        if scenario == 'missing_config_revision': p.pop('config_revision')
        if scenario == 'bool_config_revision': p['config_revision']=True
        return json.dumps(p)
    if route == ('/usr/bin/openshell','--version'): return 'openshell 0.1.2'
    if route == ('/usr/bin/openshell','sandbox','get','auma-ws','-o','json'):
        s = copy.deepcopy(sandbox)
        if scenario == 'changed_sandbox' and counts[route] > 1: s['current_policy_version'] = 2
        if scenario == 'missing_hash': s['configuration_admission'].pop('policy_hash')
        if scenario == 'bool_admission': s['configuration_admission']['policy_version'] = True
        if scenario == 'different_config_revision': s['configuration_admission']['config_revision']=2
        if scenario == 'missing_provider_revision': s['configuration_admission'].pop('provider_env_revision')
        if scenario == 'changed_provider_revision' and counts[route]>1: s['configuration_admission']['provider_env_revision']=1
        return json.dumps(s)
    if route == ('/usr/bin/podman','ps','--format','{{.Names}}'): return '\\n'.join(names)
    if route == ('/usr/bin/podman','inspect',*names):
        c = copy.deepcopy([f['container'],f['supervisor']])
        if scenario == 'replaced_pid' and counts[route] > 1: c[0]['State']['Pid'] = 9999
        if scenario == 'changed_mount' and counts[route] > 1: c[0]['Mounts'][0]['Source'] = '/synthetic/different'
        if scenario == 'volatile_health' and counts[route] > 1: c[0]['State']['Healthcheck'] = {'Status':'changed'}
        return json.dumps(c)
    raise AssertionError('unexpected mocked query')
profile_calls = 0
def profile():
    global profile_calls
    profile_calls += 1; p = copy.deepcopy(f['profile'])
    if scenario == 'changed_profile' and profile_calls > 1: p['expected_mounts'][0]['Mode'] = 'changed'
    if scenario == 'late_profile_change' and workspace_calls > 1: p['expected_mounts'][0]['Mode'] = 'changed'
    return p
stat_calls = {}
def proc_read(pid,leaf):
    p = f['process'] if pid == 4321 else f['supervisor_process']
    if leaf == 'stat':
        stat_calls[pid] = stat_calls.get(pid,0)+1
        stamp = p['start_time'] + (1 if scenario == 'reused_pid' and stat_calls[pid] > 2 else 0)
        return str(pid)+' (synthetic) '+' '.join(['S']+['0']*18+[str(stamp)])
    if leaf in ('uid_map','gid_map'):
        return '\\n'.join(' '.join(str(row[key]) for key in ('container_id','host_id','size')) for row in p[leaf])
    if leaf == 'status':
        uid = p['uid']; gids = [uid]*4; groups = [uid]
        if scenario == 'saved_gid' and pid == 4321: gids[2] = 1001
        if scenario == 'supplementary_group' and pid == 4321: groups.append(1001)
        return '\\n'.join(['Uid: '+ ' '.join([str(uid)]*4),'Gid: '+' '.join(map(str,gids)),
                          'Groups: '+' '.join(map(str,groups)),
                          'CapEff: '+p['cap_eff'],'CapPrm: '+p['cap_prm'],'CapBnd: '+p['cap_bnd'],
                          'NoNewPrivs: '+str(p['no_new_privs']),'Seccomp: '+str(p['seccomp'])])
    raise AssertionError('unexpected mocked proc leaf')
m.query, m.read_profile, m.proc_read = query, profile, proc_read
m.binary_digest = lambda path, deadline, pid: f['profile']['workload_binary_digest']
registration_calls = 0
def registration():
    global registration_calls
    registration_calls += 1; r = copy.deepcopy(f['registration'])
    if scenario == 'changed_registration' and registration_calls > 1: r['workspace_id'] = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    return r
workspace_calls = 0
def workspace(container, profile, deadline):
    global workspace_calls
    workspace_calls += 1
    result = {key:copy.deepcopy(f['e'][key]) for key in ('mountinfo','mountinfo_digest','workspace_binding')}
    if scenario == 'changed_namespace' and workspace_calls > 1: result['workspace_binding']['mount_namespace'] = 'mnt:[4001]'
    if scenario == 'changed_workspace_inode' and workspace_calls > 1: result['workspace_binding']['workspace_inode'] = '2003'
    return result
m.read_workspace_registration, m.observe_workspace = registration, workspace
`

test('mocked fresh admission emits the exact v3 envelope and refuses replaced or ambiguous observations', () => {
  const result = JSON.parse(helperPython(admissionMockPrelude + `
good = m.admission('auma-ws','print')
assert good['version'] == 3 and good['inventory_digest'] == f['e']['inventory_digest']
for case in ('malformed','duplicate','nonzero_query','replaced_pid','changed_mount','reused_pid',
             'changed_profile','changed_policy','changed_sandbox','saved_gid','supplementary_group',
             'missing_hash','bool_active','bool_admission','global_policy','global_revision',
             'missing_config_revision','bool_config_revision','different_config_revision','missing_provider_revision','changed_provider_revision',
             'changed_registration','changed_namespace','changed_workspace_inode','late_profile_change'):
    scenario = case; counts.clear(); stat_calls.clear(); profile_calls = registration_calls = workspace_calls = 0
    if case in ('changed_registration','changed_namespace','changed_workspace_inode','late_profile_change'):
        protocol_refusal(lambda: m.admission('auma-ws','print'))
    else:refusal(lambda: m.admission('auma-ws','print'))
scenario = 'volatile_health'; counts.clear(); stat_calls.clear(); profile_calls = registration_calls = workspace_calls = 0
m.admission('auma-ws','print')
print(json.dumps(good,separators=(',',':'),ensure_ascii=False))
`))
  validateConfinementInfo(result)
  assert.equal(result.isolation.uid, 166536)
  assert.equal(result.supervisor_inventory.length, 1)
})

test('mocked profile generation requires protected pin and ranges and never adopts stale installed volume identities', () => {
  const fixture = helperFixture()
  fixture.generation_schema = JSON.parse(read('packages/boundary-gate/host/openshell/inventory-generation-schema.json'))
  fixture.generation_pin = JSON.parse(read('packages/boundary-gate/host/openshell/workload-pin.json')).workload_binary_digest
  const result = JSON.parse(helperPython(admissionMockPrelude + `
schema, pin = f['generation_schema'], f['generation_pin']
old_profile = copy.deepcopy(f['profile'])
def mounts(constraints):
    out = []
    for constraint in constraints:
        row = copy.deepcopy(constraint)
        if row['Destination'] == '/sandbox': row['Source'] = f['registration']['workspace_source']
        elif row['Destination'] == '/sandbox/.git': row['Source'] = f['registration']['git_source']
        else: row['Source'] = '/synthetic/new-generation/' + ('binary' if row['Type']=='bind' else row['Destination'].rsplit('/',1)[1])
        if row['Type'] == 'volume': row['Name'] = 'synthetic-new-uuid-' + row['Destination'].rsplit('/',1)[1]
        out.append(row)
    return out
f['container']['Mounts'] = mounts(schema['workload_mount_constraints'])
f['supervisor']['Mounts'] = mounts(schema['supervisor_mount_constraints'])
f['container']['HostConfig'].update(copy.deepcopy(schema['expected_workload_config']))
f['supervisor']['HostConfig'].update(copy.deepcopy(schema['expected_supervisor_config']))
inputs = (pin, schema['uid_ranges'], schema['gid_ranges'], 1001, schema, f['registration'])
m.read_generation_inputs = lambda: copy.deepcopy(inputs)
def missing_profile(): raise ValueError('synthetic missing installed profile')
m.read_profile = missing_profile
m.binary_digest = lambda path, deadline, pid: pin
assert m.admission('auma-ws','bootstrap') is None
good = m.admission('auma-ws','generate')
assert set(good) == set(old_profile) and len(good) == 9
assert good['workload_binary_digest'] == pin
assert good['expected_mounts'] != old_profile['expected_mounts']
assert all('/synthetic/new-generation/' in row['Source'] for row in good['expected_mounts'] if row['Destination'] not in ('/sandbox','/sandbox/.git'))
assert next(row for row in good['expected_mounts'] if row['Destination']=='/sandbox')['Source']==f['registration']['workspace_source']
assert next(row for row in good['expected_mounts'] if row['Destination']=='/sandbox/.git')['Source']==f['registration']['git_source']
refusal(lambda: m.admission('auma-ws','print'))
m.read_profile = lambda: copy.deepcopy(old_profile)
refusal(lambda: m.admission('auma-ws','print'))
saved = copy.deepcopy(f['process'])
f['process']['uid_map'][0]['host_id'] = 1001
refusal(lambda: m.admission('auma-ws','generate'))
f['process'] = saved
m.binary_digest = lambda path, deadline, pid: 'sha256:'+'0'*64
refusal(lambda: m.admission('auma-ws','generate'))
m.binary_digest = lambda path, deadline, pid: pin
for bad_inputs in [('sha256:'+'0'*64,inputs[1],inputs[2],1001,schema,inputs[5]),
                   (pin,[{'host_id':1001,'size':65536}],inputs[2],1001,schema,inputs[5]),
                   (pin,inputs[1],[{'host_id':165536,'size':65537}],1001,schema,inputs[5]),
                   (pin,inputs[1],inputs[2],1002,schema,inputs[5]),
                   (pin,inputs[1],inputs[2],1001,schema,{**inputs[5],'workspace_source':'/synthetic/other','git_source':'/synthetic/other/.git'})]:
    m.read_generation_inputs = lambda: copy.deepcopy(bad_inputs)
    refusal(lambda: m.admission('auma-ws','generate'))
m.read_generation_inputs = lambda: copy.deepcopy(inputs)
print(json.dumps({'ok':True,'profile':good}))
`, fixture))
  assert.equal(result.ok, true)
  assert.equal(Object.keys(result.profile).length, 9)
})

test('explicit bootstrap checks protected inputs then refuses; ordinary preparation is admission-only under the lock', () => {
  const source = read('packages/boundary-gate/host/openshell/ensure-sandbox.sh')
  const profile = source.indexOf('"$INVENTORY" auma-ws profile'), bootstrap = source.indexOf('"$INVENTORY" auma-ws bootstrap')
  const refusal = source.indexOf('REFUSING: registered workspace requires a qualified mount producer and fresh reviewed inventory')
  const exit = source.indexOf('exit 7', refusal), lock = source.indexOf('/usr/bin/flock -w'), check = source.indexOf('"$INVENTORY" auma-ws check')
  assert.ok(bootstrap > 0 && bootstrap < refusal && refusal < exit && exit < profile && profile < lock && lock < check)
  assert.match(source, /if \[ "\$bootstrap" = 1 \]; then[\s\S]*auma-ws bootstrap[\s\S]*exit 7\nfi/)
  assert.match(source, /auma-ws profile \|\| \{[\s\S]*exit 7\n\}/)
  assert.match(source, /auma-ws check \|\| \{[\s\S]*exit 7\n\}/)
  // The former four managed-volume create paths are removed: applying their
  // archive restore/chown to a host bind would alter the registered workspace.
  assert.ok(!/openshell (?:sandbox (?:create|delete)|gateway register)|podman volume|snapshot_workspace|restore_workspace|ln -sfn|mkdir -p "\$P"/.test(source))
})

test('generation input files reject altered pins and ranges, and candidate output is private and exclusive', () => {
  const fixture = helperFixture()
  fixture.generation_schema = JSON.parse(read('packages/boundary-gate/host/openshell/inventory-generation-schema.json'))
  fixture.generation_pin = JSON.parse(read('packages/boundary-gate/host/openshell/workload-pin.json')).workload_binary_digest
  const result = JSON.parse(helperPython(`
import os, stat, tempfile
from types import SimpleNamespace
pin = {'version':1,'workload_binary_digest':f['generation_pin']}
files = {m.PIN_PATH:json.dumps(pin),m.GENERATION_SCHEMA_PATH:json.dumps(f['generation_schema']),
         m.WORKSPACE_REGISTRATION_PATH:json.dumps(f['registration']),
         '/etc/subuid':'auma:165536:65536\\n','/etc/subgid':'auma:165536:65536\\n'}
m._read_protected = lambda path: files[path]
m.pwd.getpwnam = lambda name: SimpleNamespace(pw_uid=1001,pw_name='auma')
assert m.read_generation_inputs()[0] == f['generation_pin']
for bad in [{'version':True,'workload_binary_digest':f['generation_pin']},
            {'version':1,'workload_binary_digest':'sha256:'+'0'*64},
            {'version':1,'workload_binary_digest':f['generation_pin'],'extra':True}]:
    files[m.PIN_PATH] = json.dumps(bad); refusal(m.read_generation_inputs)
files[m.PIN_PATH] = json.dumps(pin)
for path in ('/etc/subuid','/etc/subgid'):
    saved = files[path]
    for raw in ('auma:1001:65536\\n','auma:165536:65537\\n','auma:165536:65536\\nauma:165536:65536\\n','malformed'):
        files[path] = raw; refusal(m.read_generation_inputs)
    files[path] = saved
m.pwd.getpwnam = lambda name: SimpleNamespace(pw_uid=1002,pw_name='auma')
refusal(m.read_generation_inputs)
m.pwd.getpwnam = lambda name: SimpleNamespace(pw_uid=1001,pw_name='auma')
for edit in (lambda r:r.update(version=True), lambda r:r.update(extra=True),
             lambda r:r.update(workspace_id='not-an-id'), lambda r:r.update(workspace_source='/'),
             lambda r:r.update(workspace_source='/synthetic/../alias'),
             lambda r:r.update(git_source='/synthetic/other/.git')):
    registration=copy.deepcopy(f['registration']);edit(registration)
    files[m.WORKSPACE_REGISTRATION_PATH]=json.dumps(registration)
    protocol_refusal(m.read_generation_inputs)
files[m.WORKSPACE_REGISTRATION_PATH]=json.dumps(f['registration'])
assert m.read_generation_inputs()[5]==f['registration']
for protected in (m.PROFILE_PATH,m.PIN_PATH,m.GENERATION_SCHEMA_PATH,m.WORKSPACE_REGISTRATION_PATH):
    protocol_refusal(lambda:m.write_candidate(protected,f['profile']))
with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as parent:
    path = parent+'/candidate.json'
    previous = os.umask(0)
    try: m.write_candidate(path,f['profile'])
    finally: os.umask(previous)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path,'rb') as stream: original = stream.read()
    assert json.loads(original) == f['profile']
    try: m.write_candidate(path,f['profile'])
    except FileExistsError: pass
    else: raise AssertionError('existing candidate overwritten')
    with open(path,'rb') as stream: assert stream.read() == original
    os.symlink(path,parent+'/leaf-link')
    try: m.write_candidate(parent+'/leaf-link',f['profile'])
    except FileExistsError: pass
    else: raise AssertionError('symlink output followed')
    os.mkdir(parent+'/directory'); os.symlink(parent+'/directory',parent+'/directory-link')
    try: m.write_candidate(parent+'/directory-link/new.json',f['profile'])
    except OSError: pass
    else: raise AssertionError('symlink ancestor followed')
    assert not os.path.exists(parent+'/directory/new.json')
    assert not any(name.startswith('.openshell-inventory-') for name in os.listdir(parent))
print(json.dumps({'ok':True}))
`, fixture))
  assert.equal(result.ok, true)
})

test('sbx-exec re-checks the applied policy under its lock before every command, with no forgeable marker', () => {
  const w = read('packages/boundary-gate/host/openshell/custody/sbx_exec_body.sh')
  assert.ok(!w.includes('SKSBX'), 'argv-marker exemption is gone')
  const lock = w.indexOf('/usr/bin/flock -w'), check = w.indexOf('info check || exit 125'), run = w.indexOf('aukora-boundary exec "$2"')
  assert.ok(lock > 0 && check > lock && run > check, 'lock -> applied-policy check -> exec')
  assert.match(w, /if \[ "\$\{1:-\}" = --confinement-info \]; then\n  \[ "\$#" -eq 1 \] \|\| exit 2/)
  assert.match(w, /\/usr\/bin\/python3 -I -S \/usr\/local\/lib\/aukora-boundary\/openshell\/sandbox-inventory\.py "\$SB" "\$1"/)
  assert.match(w, /trap on_cancel TERM INT HUP/)
  const s = read('packages/boundary-gate/host/openshell/ensure-sandbox.sh')
  assert.equal((s.match(/openshell sandbox create/g) || []).length, 0, 'preparation cannot auto-create an unqualified host binding')
  assert.match(s, /auma-ws check \|\| \{[\s\S]*echo "REFUSING/)
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

test('PTY grant (2026-10-04): exactly /dev/pts + /dev/ptmx join the writable roots, in all four places, and nothing broader', () => {
  const want = ['/dev/null', '/dev/ptmx', '/dev/pts', '/sandbox', '/tmp']
  const yml = read('packages/boundary-gate/host/openshell/sandbox-policy.yml').match(/^\s*read_write: \[([^\]]*)\]$/m)
  assert.ok(yml, 'policy file names read_write')
  assert.deepEqual(yml[1].split(',').map(s => s.trim()).sort(), want)
  assert.match(read('packages/boundary-gate/host/openshell/sandbox-inventory.py'), /["']\/dev\/ptmx["']/)
  const ensure = read('packages/boundary-gate/host/openshell/ensure-sandbox.sh')
  assert.match(ensure, /INVENTORY=\/usr\/local\/lib\/aukora-boundary\/openshell\/sandbox-inventory\.py/)
  assert.match(ensure, /\/usr\/bin\/python3 -I -S "\$INVENTORY" auma-ws profile/)
  assert.match(ensure, /\/usr\/bin\/python3 -I -S "\$INVENTORY" auma-ws check/)
  assert.ok(read('plugins/aukora-openshell-confinement/lib/transport.mjs').includes("['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx']"))
  const e = envelope(); e.policy.filesystem_policy.read_write = [...want]
  validateConfinementInfo(e)
  for (const f of [x => { x.policy.filesystem_policy.read_write = ['/sandbox', '/tmp', '/dev/null', '/dev', '/dev/ptmx'] },
    x => { x.policy.filesystem_policy.read_write = ['/sandbox', '/tmp', '/dev/null', '/dev/pts'] },
    x => { x.policy.filesystem_policy.read_write.push('/dev/tty') }]) {
    const c = structuredClone(e); f(c); refuses(() => validateConfinementInfo(c))
  }
})

test('v3 kernel metadata refuses C1/C2/C4/C5, malformed topology and an unbound session source', () => {
  const corruptions = [
    ['C1 git writable', e => { e.mountinfo[2].options = ['rw']; e.mountinfo[2].super_options = ['rw'] }],
    ['C2 host temporary bind', e => { Object.assign(e.mountinfo[3], { filesystem: 'ext4', root: '/synthetic/host-tmp', source: '/dev/host' }) }],
    ['C4 protected extra mount', e => { e.mountinfo.push(kernelMount('8', '1', '8:3', '/synthetic/protected', '/genesis', false, 'ext4', '/dev/protected')) }],
    ['C5 second writable workspace', e => { e.mountinfo.push(kernelMount('8', '1', '8:1', HOST, '/sandbox2', true, 'ext4', '/dev/synthetic')) }],
    ['root writable', e => { e.mountinfo[0].options = ['rw']; e.mountinfo[0].super_options = ['rw'] }],
    ['git missing', e => { e.mountinfo.splice(2, 1) }],
    ['temporary mount missing', e => { e.mountinfo.splice(3, 1) }],
    ['private proc missing', e => { e.mountinfo.splice(6, 1) }],
    ['git not child', e => { e.mountinfo[2].parent_id = '1' }],
    ['duplicate kernel ID', e => { e.mountinfo[3].mount_id = '2' }],
    ['duplicate kernel path', e => { e.mountinfo[3].mountpoint = '/sandbox' }],
    ['disconnected mount', e => { e.mountinfo[5].parent_id = '999' }],
    ['cyclic hierarchy', e => { e.mountinfo[0].parent_id = '2' }],
    ['self parent', e => { e.mountinfo[2].parent_id = '3' }],
    ['device mismatch', e => { e.mountinfo[1].device = '8:9' }],
    ['unknown field', e => { e.mountinfo[0].extra = true }],
    ['numeric kernel ID', e => { e.mountinfo[0].mount_id = 1 }],
    ['aliased kernel ID', e => { e.mountinfo[0].mount_id = '01' }],
    ['overflow kernel ID', e => { e.mountinfo[0].mount_id = '4294967296' }],
    ['duplicate options', e => { e.mountinfo[1].options = ['rw', 'rw'] }],
    ['unsorted options', e => { e.mountinfo[1].options = ['rw', 'nodev'] }],
    ['ambiguous access', e => { e.mountinfo[1].options = ['ro', 'rw'] }],
    ['unavailable super access', e => { e.mountinfo[1].super_options = [] }],
    ['namespace absent', e => { delete e.workspace_binding.mount_namespace }],
    ['namespace malformed', e => { e.workspace_binding.mount_namespace = 'mnt:[0]' }],
    ['inode aliased', e => { e.workspace_binding.git_inode = e.workspace_binding.workspace_inode }],
    ['inode unsafe', e => { e.workspace_binding.git_inode = '18446744073709551616' }],
    ['git source escaped', e => { e.workspace_binding.git_source = HOST + '/elsewhere/.git' }],
    ['workspace source altered', e => { e.workspace_binding.workspace_source = '/synthetic/other' }],
  ]
  const invalid = []
  for (const [name, edit] of corruptions) {
    const e = envelope(); edit(e); reseal(e)
    assert.throws(() => validateConfinementInfo(e, HOST), error => error.reason === 'WORKSPACE_BINDING', name)
    invalid.push({ name, e })
  }
  const fixture = helperFixture(); fixture.invalid = invalid
  assert.equal(JSON.parse(helperPython(`
m.validate_mountinfo(f['e']['mountinfo'],f['e']['workspace_binding'],f['container']['Mounts'],host_tmp_device=f['host_tmp_device'])
for case in f['invalid']:
    e=case['e']
    protocol_refusal(lambda:m.validate_mountinfo(e['mountinfo'],e['workspace_binding'],e['mount_inventory'],host_tmp_device=f['host_tmp_device']))
print(json.dumps({'rejected':len(f['invalid'])}))
`, fixture)).rejected, corruptions.length)
  const stale = envelope(); stale.mountinfo.reverse()
  refuses(() => validateConfinementInfo(stale, HOST), 'WORKSPACE_BINDING')
  reseal(stale); validateConfinementInfo(stale, HOST)
  const other = envelope(), source = '/synthetic/other'
  other.workspace_binding.workspace_source = other.mount_inventory[2].Source = other.mountinfo[1].root = source
  other.workspace_binding.git_source = other.mount_inventory[3].Source = other.mountinfo[2].root = source + '/.git'
  reseal(other); validateConfinementInfo(other)
  refuses(() => validateConfinementInfo(other, HOST), 'WORKSPACE_BINDING')
})

test('host network and an added payload root fail before admission; missing trusted workspace fails before a reader can spawn', async () => {
  const fixture = helperFixture()
  fixture.container.HostConfig.NetworkMode = 'host'
  assert.equal(JSON.parse(helperPython(`
protocol_refusal(lambda:m.validate_snapshot(f['container'],f['process'],f['profile'],workload_binary_digest=f['profile']['workload_binary_digest']))
f['container']['HostConfig']['NetworkMode']='none'
f['container']['Mounts'].append({**f['container']['Mounts'][2],'Destination':'/sandbox2'})
protocol_refusal(lambda:m.validate_snapshot(f['container'],f['process'],f['profile'],workload_binary_digest=f['profile']['workload_binary_digest']))
print(json.dumps({'ok':True}))
`, fixture)).ok, true)
  const e = envelope(); e.network_mode = 'host'
  refuses(() => validateConfinementInfo(e), 'APPLIED_POLICY')
  // An inaccessible layout is safe here only because absence/aliases are refused
  // before readConfinementInfo obtains any field used to launch its owned reader.
  const noReader = new Proxy({}, { get() { assert.fail('reader path reached without a trusted workspace') } })
  for (const source of [undefined, '/', 'relative', HOST + '/../alias', HOST + '/']) {
    await assert.rejects(readConfinementInfo(noReader, undefined, source), error => error.reason === 'WORKSPACE_BINDING')
  }
})

test('actual mountinfo parser preserves ordered records and refuses unsupported escapes and ambiguous kernel fields', () => {
  const result = JSON.parse(helperPython(`
def raw(rows):
    return '\\n'.join(' '.join([r['mount_id'],r['parent_id'],r['device'],r['root'],r['mountpoint'],','.join(r['options']),*r['optional']])+ ' - '+ ' '.join([r['filesystem'],r['source'],','.join(r['super_options'])]) for r in rows)
table=raw(f['e']['mountinfo'])
assert m.parse_mountinfo(table)==f['e']['mountinfo']
escaped='7 1 8:1 /synthetic/with\\\\040space /space ro - ext4 /dev/synthetic ro'
assert m.parse_mountinfo(escaped)[0]['root']=='/synthetic/with space'
for source in ('',table+' - malformed','1 0 8:1 / / ro - overlay overlay',
               '1 0 8:1 /bad\\\\041escape / ro - overlay overlay ro'):
    protocol_refusal(lambda:m.parse_mountinfo(source))
private=copy.deepcopy(f['e']['mountinfo']);private[3]['device']=f['host_tmp_device']
protocol_refusal(lambda:m.validate_mountinfo(private,f['e']['workspace_binding'],f['container']['Mounts'],host_tmp_device=f['host_tmp_device']))
protocol_refusal(lambda:m.validate_mountinfo(f['e']['mountinfo'],f['e']['workspace_binding'],f['container']['Mounts']))
print(json.dumps({'ok':True}))
`))
  assert.equal(result.ok, true)
})

test('actual workspace collector refuses PID, namespace, mount-table and inode races without a guest-exec fallback', () => {
  const result = JSON.parse(helperPython(`
from unittest.mock import patch
def raw(rows):
    return '\\n'.join(' '.join([r['mount_id'],r['parent_id'],r['device'],r['root'],r['mountpoint'],','.join(r['options']),*r['optional']])+ ' - '+ ' '.join([r['filesystem'],r['source'],','.join(r['super_options'])]) for r in rows)
table=raw(f['e']['mountinfo']); identities=(('8:1','2001'),('8:1','2002'))
def collect(case):
    times=[12345,12346] if case=='pid' else [12345,12345]
    namespaces=['mnt:[4000]','mnt:[4001]'] if case=='namespace' else ['mnt:[4000]','mnt:[4000]']
    sources=[identities,(('8:1','2003'),identities[1])] if case=='source_inode' else [identities,identities]
    kernels=[(('8:1','2003'),identities[1])] if case=='wrong_initial_inode' else [identities,identities]
    changed=copy.deepcopy(f['e']['mountinfo']);changed.append({**changed[1],'mount_id':'8','mountpoint':'/sandbox2'})
    tables=[table,raw(changed)] if case=='table' else [table,table]
    host_namespace='mnt:[4000]' if case=='host_namespace' else 'mnt:[9000]'
    kernel_args={'side_effect':PermissionError('synthetic authority missing')} if case=='proc_authority' else {'side_effect':kernels}
    with patch.object(m,'prove_private_proc',return_value=None,create=True) as private_proc,patch.object(m,'start_time',side_effect=times),patch.object(m,'_mount_namespace',side_effect=namespaces),patch.object(m.os,'readlink',return_value=host_namespace),patch.object(m,'_source_directory_identities',side_effect=sources),patch.object(m,'_kernel_directory_identities',**kernel_args),patch.object(m,'proc_read',side_effect=tables),patch.object(m,'_open_directory',return_value=41),patch.object(m,'_directory_identity',return_value=(f['host_tmp_device'],'9001')),patch.object(m.os,'close'):
        observed=m.observe_workspace(f['container'],f['profile'],999999999)
        assert private_proc.call_count==2
        assert all(call.args==(4321,12345) for call in private_proc.call_args_list)
        return observed
good=collect('good')
assert good=={key:f['e'][key] for key in ('mountinfo','mountinfo_digest','workspace_binding')}
for case in ('pid','namespace','source_inode','wrong_initial_inode','table','host_namespace'):
    protocol_refusal(lambda:collect(case))
try:collect('proc_authority')
except PermissionError:pass
else:raise AssertionError('missing proc authority accepted')
protocol_refusal(lambda:m.observe_workspace(f['container'],f['profile'],0))
print(json.dumps({'ok':True,'refused':8}))
`))
  assert.equal(result.ok, true)
  assert.equal(result.refused, 8)
})

test('actual source-directory anchoring rejects symlink workspace, symlink ancestors, .git aliases and linked-worktree files', () => {
  assert.equal(JSON.parse(helperPython(`
import errno,os,tempfile
with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as parent:
    workspace=parent+'/workspace';os.mkdir(workspace);os.mkdir(workspace+'/.git')
    actual=m._source_directory_identities(workspace)
    assert actual[0]!=actual[1]
    os.symlink(workspace,parent+'/workspace-link')
    os.mkdir(parent+'/ancestor');os.symlink(workspace,parent+'/ancestor/workspace-link')
    for source in (parent+'/workspace-link',parent+'/ancestor/workspace-link'):
        try:m._source_directory_identities(source)
        except OSError as error:assert error.errno in (errno.ELOOP,errno.ENOTDIR)
        else:raise AssertionError('workspace alias followed')
    os.symlink(parent,parent+'/ancestor-link')
    try:m._source_directory_identities(parent+'/ancestor-link/workspace')
    except OSError as error:assert error.errno in (errno.ELOOP,errno.ENOTDIR)
    else:raise AssertionError('ancestor alias followed')
    os.rmdir(workspace+'/.git');os.mkdir(parent+'/external-git');os.symlink(parent+'/external-git',workspace+'/.git')
    try:m._source_directory_identities(workspace)
    except OSError as error:assert error.errno in (errno.ELOOP,errno.ENOTDIR)
    else:raise AssertionError('metadata alias followed')
    os.unlink(workspace+'/.git')
    with open(workspace+'/.git','w') as stream:stream.write('gitdir: '+parent+'/external-git\\n')
    try:m._source_directory_identities(workspace)
    except OSError as error:assert error.errno in (errno.ELOOP,errno.ENOTDIR)
    else:raise AssertionError('linked-worktree gitdir file accepted')
print(json.dumps({'ok':True}))
`)).ok, true)
})

test('C1-C5 source controls expose acceptance only when their production validation guard is removed', async () => {
  const source = read('plugins/aukora-openshell-confinement/lib/transport.mjs')
  const mutate = async (before, after) => {
    assert.equal(source.split(before).length, 2, 'mutation must identify exactly one production guard')
    const changed = source.replace(before, after)
    return import('data:text/javascript;base64,' + Buffer.from(changed, 'utf8').toString('base64'))
  }
  const c1 = envelope(); c1.mountinfo[2].options = c1.mountinfo[2].super_options = ['rw']; reseal(c1)
  refuses(() => validateConfinementInfo(c1, HOST), 'WORKSPACE_BINDING')
  const noPayloadAccess = await mutate('if (writable !== payload.RW || row.optional.length !== 0 ||',
    'if (false || row.optional.length !== 0 ||')
  noPayloadAccess.validateConfinementInfo(envelope(), HOST)
  noPayloadAccess.validateConfinementInfo(c1, HOST)

  const tmpStart = source.indexOf("    if (path === '/tmp') {")
  assert.ok(tmpStart > 0)
  const guardStart = source.indexOf('      if (!writable', tmpStart)
  const guardEnd = source.indexOf('return false;', guardStart) + 'return false;'.length
  assert.ok(guardStart > tmpStart && guardEnd > guardStart)
  const noPrivateTmp = await mutate(source.slice(guardStart, guardEnd), '      if (false) return false;')
  const c2 = envelope(); Object.assign(c2.mountinfo[3], { filesystem: 'ext4', root: '/synthetic/host-tmp', source: '/dev/host' }); reseal(c2)
  refuses(() => validateConfinementInfo(c2, HOST), 'WORKSPACE_BINDING')
  noPrivateTmp.validateConfinementInfo(envelope(), HOST)
  noPrivateTmp.validateConfinementInfo(c2, HOST)

  const c3 = envelope(); c3.network_mode = 'host'
  refuses(() => validateConfinementInfo(c3, HOST), 'APPLIED_POLICY')
  const noNetworkGuard = await mutate("info.network_mode !== 'none'", 'false')
  noNetworkGuard.validateConfinementInfo(envelope(), HOST)
  noNetworkGuard.validateConfinementInfo(c3, HOST)

  const noUnknownMountGuard = await mutate('if (!role || row.filesystem !== role[0] || writable !== role[1]) return false;',
    'if (!role) continue; if (row.filesystem !== role[0] || writable !== role[1]) return false;')
  noUnknownMountGuard.validateConfinementInfo(envelope(), HOST)
  for (const extra of [kernelMount('8', '1', '8:3', '/synthetic/protected', '/genesis', false, 'ext4', '/dev/protected'),
    kernelMount('8', '1', '8:1', HOST, '/sandbox2', true, 'ext4', '/dev/synthetic')]) {
    const e = envelope(); e.mountinfo.push(extra); reseal(e)
    refuses(() => validateConfinementInfo(e, HOST), 'WORKSPACE_BINDING')
    noUnknownMountGuard.validateConfinementInfo(e, HOST)
  }
})

test('approved infrastructure mount shapes still bind device, source, root, topology and private propagation', () => {
  const valid = envelope()
  valid.mountinfo.push(kernelMount('8', '1', '0:42', '/', '/dev', true, 'tmpfs', 'tmpfs'),
    kernelMount('9', '7', '0:43', '/sys', '/proc/sys', false, 'proc', 'proc'),
    kernelMount('10', '8', '0:44', '/', '/dev/pts', true, 'devpts', 'devpts'),
    kernelMount('11', '7', '0:42', '/null', '/proc/kcore', true, 'tmpfs', 'tmpfs'),
    kernelMount('12', '1', '0:45', '/', '/run/openshell-supervisor-ca', true, 'tmpfs', 'tmpfs'),
    kernelMount('13', '8', '0:46', '/', '/dev/shm', true, 'tmpfs', 'tmpfs'))
  reseal(valid); validateConfinementInfo(valid, HOST)
  const invalid = []
  for (const edit of [e => { e.mountinfo[8].device = '8:9' },
    e => { e.mountinfo[8].source = '/dev/host-secret' }, e => { e.mountinfo[8].root = '/different' },
    e => { e.mountinfo[8].parent_id = '1' }, e => { e.mountinfo[6].source = '/dev/host' },
    e => { e.mountinfo[6].root = '/host-proc' }, e => { e.mountinfo[10].device = '0:99' },
    e => { e.mountinfo[10].source = '/dev/host-secret' }, e => { e.mountinfo[10].root = '/' },
    e => { e.mountinfo[11].source = '/synthetic/host' }, e => { e.mountinfo[11].device = '0:41' },
    e => { e.mountinfo[11].device = '0:42' }, e => { e.mountinfo[11].device = '0:40' },
    e => { e.mountinfo[3].device = '0:40' }, e => { e.mountinfo[3].device = '8:1' },
    e => { e.mountinfo[7].device = '0:40'; e.mountinfo[10].device = '0:40' },
    e => { e.mountinfo[12].device = '0:42' }, e => { e.mountinfo[12].device = '0:41' },
    e => { e.mountinfo[12].device = '0:40' }, e => { e.mountinfo[12].device = '8:1' },
    e => { e.mountinfo[1].optional = ['shared:1'] }, e => { e.mountinfo[3].optional = ['shared:1'] },
    e => { e.workspace_binding.mount_namespace = 'mnt:[18446744073709551616]' },
    e => { e.mountinfo.push(kernelMount('14', '1', '8:3', '/synthetic/secret', '/etc/hosts', false, 'ext4', '/dev/host')) }]) {
    const e = structuredClone(valid); edit(e); reseal(e)
    refuses(() => validateConfinementInfo(e, HOST), 'WORKSPACE_BINDING')
    invalid.push(e)
  }
  const fixture = helperFixture(); fixture.e = valid; fixture.invalid = invalid
  assert.equal(JSON.parse(helperPython(`
m.validate_mountinfo(f['e']['mountinfo'],f['e']['workspace_binding'],f['container']['Mounts'],host_tmp_device=f['host_tmp_device'])
for e in f['invalid']:
    protocol_refusal(lambda:m.validate_mountinfo(e['mountinfo'],e['workspace_binding'],e['mount_inventory'],host_tmp_device=f['host_tmp_device']))
print(json.dumps({'rejected':len(f['invalid'])}))
`, fixture)).rejected, invalid.length)
})

test('actual private-proc proof binds retained namespace descriptors, guest PID1 and NSpid with before/after fences', () => {
  const result = JSON.parse(helperPython(`
from unittest.mock import patch
def stat(pid,stamp=12345):
    return str(pid)+' (synthetic ) name) '+' '.join(['S']+['0']*18+[str(stamp)])
assert m._stat_identity(stat(4321))==(4321,12345)
assert m._nspid('Name: synthetic\\nNSpid: 4321 51 1\\n')==(4321,51,1)
for raw in ('','NSpid: 4321 1\\nNSpid: 4321 1','NSpid: 4321 0','NSpid: 4321 01','NSpid: 4321 4294967296'):
    protocol_refusal(lambda:m._nspid(raw))
for raw in ('4321 malformed','0 (name) '+ ' '.join(['S']+['0']*18+['12345']),stat(4321,0),stat(4321,9007199254740992)):
    protocol_refusal(lambda:m._stat_identity(raw))
for namespace in ('pid:[0]','pid:[18446744073709551616]','pid:[01]','pid:[1]\\n'):
    protocol_refusal(lambda:m._pid_namespace(namespace))
def proof(case):
    opened=[]; reads={};links={}
    destinations={(10,'root'):11,(11,'proc'):12,(12,'1'):13,(10,'ns'):14,(13,'ns'):15}
    def open_at(path,flags,*,dir_fd):
        assert (dir_fd,path) in destinations
        assert flags&m.os.O_DIRECTORY and flags&m.os.O_CLOEXEC
        assert bool(flags&m.os.O_NOFOLLOW)==(path!='root')
        if case=='directory_authority' and path=='proc':raise PermissionError('synthetic authority absent')
        result=destinations[dir_fd,path];opened.append(result);return result
    def link(path,*,dir_fd=None):
        key=(dir_fd,path);links[key]=links.get(key,0)+1
        if path=='/proc/self/ns/pid':
            assert dir_fd is None
            return 'pid:[4000]' if case=='host_namespace' else 'pid:[9001]' if case=='collector_race' and links[key]>1 else 'pid:[9000]'
        assert path=='pid' and dir_fd in (14,15)
        if case=='namespace_race' and links[key]>1:return 'pid:[4001]'
        return 'pid:[4001]' if case=='wrong_guest_namespace' and dir_fd==15 else 'pid:[4000]'
    def metadata(fd,leaf):
        key=(fd,leaf);reads[key]=reads.get(key,0)+1
        if case=='metadata_authority':raise PermissionError('synthetic metadata authority absent')
        if leaf=='stat':
            assert fd in (10,13)
            pid=4321 if fd==10 else 1
            if case=='host_pid' and fd==10:pid=4322
            if case=='guest_pid' and fd==13:pid=2
            stamp=12346 if case=='start_time' or (case=='stat_race' and reads[key]>1) else 12345
            return stat(pid,stamp)
        assert (fd,leaf)==(10,'status')
        if case=='nspid_first':return 'NSpid: 4322 1'
        if case=='nspid_last':return 'NSpid: 4321 2'
        if case=='nspid_missing':return 'Name: synthetic'
        if case=='nspid_race' and reads[key]>1:return 'NSpid: 4321 52 1'
        return 'NSpid: 4321 51 1'
    with patch.object(m,'_open_directory',return_value=10) as anchor,patch.object(m.os,'open',side_effect=open_at),patch.object(m.os,'readlink',side_effect=link),patch.object(m,'_read_proc_at',side_effect=metadata),patch.object(m.os,'close') as closed:
        try:m.prove_private_proc(4321,12345)
        finally:
            anchor.assert_called_once_with('/proc/4321')
            assert sorted(call.args[0] for call in closed.call_args_list)==sorted([10,*opened])
proof('good')
for case in ('host_namespace','wrong_guest_namespace','host_pid','guest_pid','start_time',
             'nspid_first','nspid_last','nspid_missing','namespace_race','collector_race','stat_race','nspid_race'):
    protocol_refusal(lambda:proof(case))
for case in ('directory_authority','metadata_authority'):
    try:proof(case)
    except PermissionError:pass
    else:raise AssertionError('missing private proc authority accepted')
with patch.object(m.os,'open',return_value=41) as opened,patch.object(m,'_read_fd',return_value=b'NSpid: 4321 1') as read,patch.object(m.os,'close') as closed:
    assert m._read_proc_at(10,'status')=='NSpid: 4321 1'
    assert opened.call_args.args[0]=='status' and opened.call_args.args[1]&m.os.O_NOFOLLOW
    assert opened.call_args.kwargs=={'dir_fd':10}
    read.assert_called_once_with(41,m.MAX_READ_BYTES);closed.assert_called_once_with(41)
    protocol_refusal(lambda:m._read_proc_at(10,'environ'))
print(json.dumps({'ok':True,'refused':14}))
`))
  assert.equal(result.ok, true)
  assert.equal(result.refused, 14)
})
