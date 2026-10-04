// L1 on Linux: Auma's one-shot bash through OpenShell as `auma` (plugins/aukora-openshell-confinement + sbx-exec).
// Source checks of the join; the installed behaviour (refusals, timeout, detached children, cancel) is observed on the
// pilot and recorded in the commit, not claimed here.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { readSettings, validateConfinementInfo, parseConfinementInfoJson, validateRequest, prepareLabTransport } from '../plugins/aukora-openshell-confinement/lib/transport.mjs'
import { guestSpec, guestBashExecutor } from '../plugins/aukora-openshell-confinement/lib/index.mjs'
import { sandboxArgv } from '../packages/boundary-gate/src/sandbox.mjs'
import { resolveLayout } from '../packages/boundary-gate/src/layout.mjs'

const root = new URL('../', import.meta.url)
const read = p => readFileSync(new URL(p, root), 'utf8')
const HOST = '/home/aukora-host/genesis/state/workspace'
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
  return value
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
  return reseal({ version: 2, openshell_version: '0.1.2', sandbox: 'auma-ws', state: 'Ready',
    instance_id: 'synthetic-instance', policy_revision: 1, applied_revision: 1, workspace_root: '/sandbox', network_mode: 'none',
    policy: { filesystem_policy: { include_workdir: false,
      read_only: ['/bin', '/usr', '/lib', '/lib64', '/etc', '/proc', '/dev/urandom'],
      read_write: ['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx'] },
      landlock: { compatibility: 'hard_requirement' }, version: 1, network_policies: {} },
    mount_inventory: [channel,
      { Type: 'bind', Source: '/synthetic/runtime/openshell-sandbox', Destination: '/opt/openshell/bin/openshell-sandbox',
        Driver: '', Mode: 'ro', Options: ['ro'], RW: false, Propagation: 'rprivate' },
      { Type: 'volume', Name: 'synthetic-workspace', Source: '/synthetic/volumes/workspace/_data',
        Destination: '/sandbox', Driver: 'local', Mode: 'nosuid,nodev', Options: ['nosuid', 'nodev'], RW: true, Propagation: 'rprivate' }],
    profile_digest: 'sha256:' + 'b'.repeat(64), isolation,
    supervisor_inventory: [{ ...structuredClone(channel), RW: false, Mode: 'ro,nosuid,nodev' }],
    supervisor_isolation: supervisor })
}

function helperFixture() {
  const e = envelope(), sid = '11111111-2222-4333-8444-555555555555'
  const workloadConfig = { Tmpfs: { '/run': 'rw,nosuid,nodev,size=65536k' }, Devices: [],
    IpcMode: 'shareable', PidMode: 'private', ReadonlyRootfs: false }
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
  return { e, sid, profile, container, supervisor, process, supervisor_process: supervisorProcess }
}

function helperPython(code) {
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
`
  return execFileSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', prelude + '\n' + code,
    fileURLToPath(new URL('packages/boundary-gate/host/openshell/sandbox-inventory.py', root))],
  { input: JSON.stringify(helperFixture()), encoding: 'utf8', timeout: 3000, maxBuffer: 64 * 1024 })
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

test('v2 readback binds the entire closed mount records and companion channel inventory', () => {
  // Frozen independent Python json.dumps(sort_keys=True, separators=(',', ':'),
  // ensure_ascii=False) vectors cover compact UTF8 canonicalization.
  const vector = envelope()
  assert.equal(vector.inventory_digest, 'sha256:4c53a9a999ebab88dd48e51daae676c2c90bdf9f6be4a23cc0fe885ab9b81f8f')
  vector.mount_inventory[1].Source = '/synthetic/runtime/é-sandbox'
  vector.inventory_digest = 'sha256:80e5262b9023749370dc3d0c118d4b75cb64b4a3721bcb0a9e84480e20e2d463'
  validateConfinementInfo(vector)
  for (const mutate of [
    x => { x.extra = true }, x => { delete x.profile_digest },
    x => { x.profile_digest = 'sha256:' + 'A'.repeat(64) },
    x => { x.mount_inventory.pop() }, x => { x.mount_inventory.reverse() },
    x => { delete x.mount_inventory[1] },
    x => { x.mount_inventory[0].Destination = '/unexpected' },
    x => { x.mount_inventory[2].Type = 'bind' },
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

test('v2 readback refuses host-user mappings, map overlaps, capability bits and weakened process isolation', () => {
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
             lambda c: c['HostConfig'].update(ReadonlyRootfs=True),
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

test('mocked fresh admission emits the exact v2 envelope and refuses replaced or ambiguous observations', () => {
  const result = JSON.parse(helperPython(`
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
good = m.admission('auma-ws','print')
assert good['version'] == 2 and good['inventory_digest'] == f['e']['inventory_digest']
for case in ('malformed','duplicate','nonzero_query','replaced_pid','changed_mount','reused_pid',
             'changed_profile','changed_policy','changed_sandbox','saved_gid','supplementary_group',
             'missing_hash','bool_active','bool_admission','global_policy','global_revision',
             'missing_config_revision','bool_config_revision','different_config_revision','missing_provider_revision','changed_provider_revision'):
    scenario = case; counts.clear(); stat_calls.clear(); profile_calls = 0
    refusal(lambda: m.admission('auma-ws','print'))
scenario = 'volatile_health'; counts.clear(); stat_calls.clear(); profile_calls = 0
m.admission('auma-ws','print')
print(json.dumps(good,separators=(',',':'),ensure_ascii=False))
`))
  validateConfinementInfo(result)
  assert.equal(result.isolation.uid, 166536)
  assert.equal(result.supervisor_inventory.length, 1)
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
  assert.equal((s.match(/--policy "\$POLICY"/g) || []).length, 4, 'every create passes the hard startup policy')
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

test('PTY grant (2026-10-04): exactly /dev/pts + /dev/ptmx join the writable roots, in all four places, and nothing broader', () => {
  const want = ['/dev/null', '/dev/ptmx', '/dev/pts', '/sandbox', '/tmp']
  const yml = read('packages/boundary-gate/host/openshell/sandbox-policy.yml').match(/^\s*read_write: \[([^\]]*)\]$/m)
  assert.ok(yml, 'policy file names read_write')
  assert.deepEqual(yml[1].split(',').map(s => s.trim()).sort(), want)
  assert.match(read('packages/boundary-gate/host/openshell/sandbox-inventory.py'), /["']\/dev\/ptmx["']/)
  const ensure = read('packages/boundary-gate/host/openshell/ensure-sandbox.sh')
  assert.match(ensure, /INVENTORY=\/usr\/local\/lib\/aukora-boundary\/openshell\/sandbox-inventory\.py/)
  assert.match(ensure, /\/usr\/bin\/python3 -I -S "\$INVENTORY" auma-ws policy/)
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
