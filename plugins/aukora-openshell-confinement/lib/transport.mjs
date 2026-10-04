// SPDX-License-Identifier: AGPL-3.0-or-later
// Exact Bash transport for the guest filesystem namespace. Admission requires
// a genuine applied-policy readback from the root-owned boundary wrapper.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
export const GUEST_WORKSPACE = '/sandbox';
export const MAX_COMMAND_BYTES = 256 * 1024;
export const CONFINEMENT_INFO_VERSION = 3;
export const CONFINEMENT_INFO_KEYS = Object.freeze(['version', 'openshell_version', 'sandbox', 'state',
  'instance_id', 'policy_revision', 'applied_revision', 'workspace_root', 'network_mode', 'policy',
  'mount_inventory', 'inventory_digest', 'profile_digest', 'isolation', 'supervisor_inventory',
  'supervisor_inventory_digest', 'supervisor_isolation', 'mountinfo', 'mountinfo_digest', 'workspace_binding']);
const WRITABLE_ROOTS = Object.freeze(['/sandbox', '/tmp', '/dev/null', '/dev/pts', '/dev/ptmx']);
const READ_ONLY_ROOTS = Object.freeze(['/bin', '/usr', '/lib', '/lib64', '/etc', '/proc', '/dev/urandom']);
const MAX_INFO_BYTES = 64 * 1024;

export function unavailable(reason, message) {
  return Object.assign(new Error(`aukora-openshell-confinement: ${message}`), {
    code: 'SANDBOX_UNAVAILABLE', reason,
  });
}

function text(value) {
  return typeof value === 'string' && !value.includes('\0') &&
    Buffer.from(value, 'utf8').toString('utf8') === value;
}

export function readSettings(input = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).some(key => !['workspaceRoot', 'timeoutSeconds', 'hostWorkspaceRoot'].includes(key))) {
    throw unavailable('CONFIG', 'unsupported configuration');
  }
  const workspaceRoot = input.workspaceRoot ?? GUEST_WORKSPACE;
  const timeoutSeconds = input.timeoutSeconds ?? 60;
  // The trusted session workspace must match the protected wrapper's observed
  // /sandbox bind source. A configured name alone is not a mount or its proof.
  const hostWorkspaceRoot = input.hostWorkspaceRoot;
  if (hostWorkspaceRoot !== undefined && (!text(hostWorkspaceRoot) || !hostWorkspaceRoot.startsWith('/') ||
      hostWorkspaceRoot === '/' || hostWorkspaceRoot.length > 1024 || hostWorkspaceRoot.endsWith('/') ||
      hostWorkspaceRoot.split('/').some(part => part === '.' || part === '..') || hostWorkspaceRoot.includes('//') ||
      hostWorkspaceRoot === GUEST_WORKSPACE)) {
    throw unavailable('CONFIG', 'hostWorkspaceRoot must be a normalized absolute host path');
  }
  // No host-to-guest mapping is inferred. The existing wrapper only knows /sandbox.
  if (workspaceRoot !== GUEST_WORKSPACE) {
    throw unavailable('WORKSPACE', 'only the explicit guest workspace /sandbox can be prepared');
  }
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 300) {
    throw unavailable('TIMEOUT', 'timeoutSeconds must be an integer from 1 to 300');
  }
  return Object.freeze({ workspaceRoot, timeoutSeconds, ...(hostWorkspaceRoot === undefined ? {} : { hostWorkspaceRoot }) });
}

export function validateRequest(argv, policy, settings, signal) {
  signal?.throwIfAborted();
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy) ||
      Object.keys(policy).some(key => !['mode', 'workspaceRoot', 'sessionId'].includes(key))) {
    throw unavailable('POLICY', 'a resolved confined policy is required');
  }
  if (policy.mode !== 'workspace-write') {
    throw unavailable('POLICY', 'the existing wrapper cannot enforce the requested file-effect policy');
  }
  // An explicit host identity routes to the guest; it grants no host access.
  // Compare exact identities, without normalizing or resolving path aliases.
  const mappedHost = settings.hostWorkspaceRoot !== undefined &&
    policy.workspaceRoot === settings.hostWorkspaceRoot;
  if (policy.workspaceRoot !== settings.workspaceRoot && !mappedHost) {
    throw unavailable('WORKSPACE', 'the guest or exact configured host workspace is required');
  }
  if (policy.sessionId !== undefined &&
      (!text(policy.sessionId) || policy.sessionId.length === 0 || policy.sessionId.length > 256)) {
    throw unavailable('POLICY', 'invalid session identity');
  }
  // No terminal, PowerShell, native SDK or run_code compatibility is inferred.
  if (!Array.isArray(argv) || argv.length !== 3 || argv[0] !== 'bash' ||
      argv[1] !== '-c' || !text(argv[2])) {
    const executable = Array.isArray(argv) && typeof argv[0] === 'string'
      ? argv[0].split('/').at(-1) : undefined;
    if (executable === 'node' || executable === 'node.exe') {
      throw unavailable('RUN_CODE_CONTROL_CHANNEL', 'run_code requires an unsupported guest FD7 control transport');
    }
    if (['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'pwsh', 'powershell'].includes(executable)) {
      throw unavailable('TERMINAL_TRANSPORT', 'interactive and alternate shell argv require an unsupported guest terminal transport');
    }
    throw unavailable('ARGV', 'only the exact Bash command argv shape is supported by this transport');
  }
  signal?.throwIfAborted();
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function identity(value) {
  return text(value) && /^[A-Za-z0-9_.:-]{1,256}$/.test(value);
}

function closed(value, keys) {
  return object(value) && Object.keys(value).length === keys.length &&
    Object.keys(value).every(key => keys.includes(key));
}

function exactSet(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    new Set(value).size === expected.length && Array.from(value).every(item => expected.includes(item));
}

function absolutePath(value) {
  return text(value) && value.startsWith('/') && value.length <= 4096 &&
    (value === '/' || !value.endsWith('/')) && !value.includes('//') &&
    !value.split('/').some(part => part === '.' || part === '..');
}

function digest(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (object(value)) return '{' + Object.keys(value).sort().map(key =>
    JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  return JSON.stringify(value);
}

function inventoryDigest(value) {
  return 'sha256:' + createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export const MOUNTINFO_KEYS = Object.freeze(['mount_id', 'parent_id', 'device', 'root', 'mountpoint',
  'options', 'optional', 'filesystem', 'source', 'super_options']);
export const WORKSPACE_BINDING_KEYS = Object.freeze(['workspace_source', 'git_source', 'workspace_device',
  'workspace_inode', 'git_device', 'git_inode', 'mount_namespace']);
// Keep these proposed required infrastructure shapes aligned with sandbox-inventory.py.
// Actual runtime sources still require qualification by the protected collector;
// an unlisted mount, including a second writable workspace, is unavailable.
const INFRASTRUCTURE_MOUNTS = Object.freeze({
  '/proc': ['proc', false],
  '/dev': ['tmpfs', true],
  '/dev/pts': ['devpts', true],
  '/dev/shm': ['tmpfs', true],
  '/dev/mqueue': ['mqueue', true],
  '/sys': ['sysfs', false],
  '/sys/fs/cgroup': ['cgroup2', false],
  '/proc/bus': ['proc', false],
  '/proc/fs': ['proc', false],
  '/proc/irq': ['proc', false],
  '/proc/sys': ['proc', false],
  '/proc/sysrq-trigger': ['proc', false],
  '/proc/acpi': ['tmpfs', false],
  '/proc/scsi': ['tmpfs', false],
  '/sys/firmware': ['tmpfs', false],
  '/sys/devices/virtual/powercap': ['tmpfs', false],
  '/proc/kcore': ['tmpfs', true],
  '/proc/keys': ['tmpfs', true],
  '/proc/timer_list': ['tmpfs', true],
  '/proc/latency_stats': ['tmpfs', true],
  '/proc/sched_debug': ['tmpfs', true],
});
const MASKED_PROC_FILES = new Set(['/proc/kcore', '/proc/keys', '/proc/timer_list',
  '/proc/latency_stats', '/proc/sched_debug']);

function decimal(value, positive, ceiling) {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]*)(?![\s\S])/.test(value) &&
    value.length <= 20 && BigInt(value) >= (positive ? 1n : 0n) && BigInt(value) < ceiling;
}

function device(value) {
  return typeof value === 'string' && /^(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)(?![\s\S])/.test(value) &&
    value.split(':').every(part => decimal(part, false, 1n << 32n));
}

function workspaceBinding(value) {
  return closed(value, WORKSPACE_BINDING_KEYS) &&
    absolutePath(value.workspace_source) && value.workspace_source !== '/' &&
    absolutePath(value.git_source) && value.git_source === value.workspace_source + '/.git' &&
    device(value.workspace_device) && device(value.git_device) &&
    decimal(value.workspace_inode, true, 1n << 64n) && decimal(value.git_inode, true, 1n << 64n) &&
    typeof value.mount_namespace === 'string' && /^mnt:\[[1-9][0-9]*\](?![\s\S])/.test(value.mount_namespace) &&
    decimal(value.mount_namespace.slice(5, -1), true, 1n << 64n) &&
    (value.workspace_device !== value.git_device || value.workspace_inode !== value.git_inode);
}

function sortedOptions(value) {
  // UTF-8 lexical order matches the Python producer's Unicode codepoint order.
  return Array.isArray(value) && value.length <= 256 &&
    Array.from(value).every(option => text(option) && option.length > 0) && new Set(value).size === value.length &&
    value.every((option, index) => index === 0 ||
      Buffer.compare(Buffer.from(value[index - 1], 'utf8'), Buffer.from(option, 'utf8')) < 0);
}

function kernelMounts(rows, binding, mounts, claimedDigest) {
  if (!workspaceBinding(binding) || !Array.isArray(rows) || rows.length < 1 || rows.length > 512 ||
      !digest(claimedDigest) || inventoryDigest(rows) !== claimedDigest) return false;
  const byPath = new Map();
  const byId = new Map();
  for (const row of rows) {
    if (!closed(row, MOUNTINFO_KEYS) || !decimal(row.mount_id, true, 1n << 32n) ||
        !decimal(row.parent_id, false, 1n << 32n) || row.mount_id === row.parent_id ||
        !device(row.device) || !absolutePath(row.root) || !absolutePath(row.mountpoint) ||
        byPath.has(row.mountpoint) || byId.has(row.mount_id) ||
        !text(row.filesystem) || row.filesystem.length === 0 || !text(row.source) || row.source.length === 0 ||
        !['options', 'optional', 'super_options'].every(key => sortedOptions(row[key])) ||
        !['options', 'super_options'].every(key =>
          row[key].includes('ro') !== row[key].includes('rw'))) return false;
    byPath.set(row.mountpoint, row);
    byId.set(row.mount_id, row);
  }
  const expected = new Map(mounts.map(mount => [mount.Destination, mount]));
  const root = byPath.get('/');
  if (!root || !['overlay', 'fuse.overlayfs', 'fuse-overlayfs'].includes(root.filesystem) ||
      !root.options.includes('ro') || !byPath.has('/tmp') || !byPath.has('/proc') ||
      mounts.some(mount => !byPath.has(mount.Destination))) return false;
  for (const row of rows) {
    const visited = new Set();
    let current = row;
    while (byId.has(current.parent_id)) {
      if (visited.has(current.mount_id)) return false;
      visited.add(current.mount_id);
      current = byId.get(current.parent_id);
    }
    if (current !== root) return false;
    const path = row.mountpoint;
    const writable = row.options.includes('rw');
    if (path === '/') continue;
    // Every visible child belongs to its closest visible mounted ancestor.
    // Merely naming the root (or /sandbox for .git) is not sufficient topology.
    let ancestor = path.slice(0, path.lastIndexOf('/')) || '/';
    while (!byPath.has(ancestor)) ancestor = ancestor.slice(0, ancestor.lastIndexOf('/')) || '/';
    if (row.parent_id !== byPath.get(ancestor).mount_id) return false;
    const payload = expected.get(path);
    if (payload) {
      if (writable !== payload.RW || row.optional.length !== 0 ||
          (path === '/sandbox' && row.device !== binding.workspace_device) ||
          (path === '/sandbox/.git' && row.device !== binding.git_device)) return false;
      continue;
    }
    if (path === '/tmp') {
      if (!writable || row.filesystem !== 'tmpfs' || row.root !== '/' || row.source !== 'tmpfs' ||
          row.optional.length !== 0 || row.device === binding.workspace_device ||
          row.device === binding.git_device || row.device === byPath.get('/dev')?.device) return false;
      // The protected collector also compares this device with host /tmp and
      // proves host/guest inode equality. Structural JSON cannot observe either.
      continue;
    }
    if (path === '/run/openshell-supervisor-ca') {
      if (!writable || row.filesystem !== 'tmpfs' || row.root !== '/' || row.source !== 'tmpfs' ||
          row.optional.length !== 0 || row.device === binding.workspace_device ||
          row.device === binding.git_device || row.device === byPath.get('/dev')?.device ||
          row.device === root.device || row.device === byPath.get('/tmp').device) return false;
      continue;
    }
    if (['/etc/hosts', '/etc/hostname', '/etc/resolv.conf'].includes(path)) {
      // No exact externally anchored engine-file identity is in this contract.
      // Read-only alone cannot distinguish configuration from a host secret.
      return false;
    }
    const role = Object.hasOwn(INFRASTRUCTURE_MOUNTS, path) ? INFRASTRUCTURE_MOUNTS[path] : undefined;
    if (!role || row.filesystem !== role[0] || writable !== role[1]) return false;
    if (row.filesystem === 'proc') {
      const proc = byPath.get('/proc');
      const expectedRoot = path === '/proc' ? '/' : path.slice('/proc'.length);
      if (!proc || row.source !== 'proc' || row.root !== expectedRoot || row.device !== proc.device) return false;
    }
    if (row.filesystem === 'tmpfs') {
      if (row.source !== 'tmpfs' || row.optional.length !== 0) return false;
      if (MASKED_PROC_FILES.has(path)) {
        if (row.root !== '/null' || row.device !== byPath.get('/dev')?.device) return false;
      } else if (row.root !== '/' || row.device === binding.workspace_device ||
          row.device === binding.git_device) return false;
    }
  }
  const workspace = byPath.get('/sandbox');
  const git = byPath.get('/sandbox/.git');
  if (git.mount_id === workspace.mount_id || git.parent_id !== workspace.mount_id) return false;
  const distinct = new Set([binding.workspace_device, binding.git_device, root.device]);
  const temporaryDevice = byPath.get('/tmp').device;
  if (distinct.has(temporaryDevice)) return false;
  const dev = byPath.get('/dev');
  if (dev) {
    if (distinct.has(dev.device) || dev.device === temporaryDevice) return false;
    for (const path of ['/dev/shm', '/run/openshell-supervisor-ca']) {
      const row = byPath.get(path);
      if (row && (distinct.has(row.device) || row.device === dev.device || row.device === temporaryDevice)) return false;
    }
  }
  return true;
}

function validMount(record) {
  const keys = ['Type', 'Source', 'Destination', 'Driver', 'Mode', 'Options', 'RW', 'Propagation'];
  if (record?.Type === 'volume') keys.push('Name');
  return closed(record, keys) && ['volume', 'bind'].includes(record.Type) &&
    (record.Type !== 'volume' || identity(record.Name)) &&
    absolutePath(record.Source) && absolutePath(record.Destination) &&
    text(record.Driver) && record.Driver.length <= 128 &&
    text(record.Mode) && record.Mode.length <= 512 &&
    Array.isArray(record.Options) && record.Options.length <= 128 &&
    Array.from(record.Options).every(option => text(option) && option.length > 0 && option.length <= 512) &&
    new Set(record.Options).size === record.Options.length && typeof record.RW === 'boolean' &&
    text(record.Propagation) && record.Propagation.length <= 128;
}

function mountInventory(value, roles, claimedDigest) {
  if (!Array.isArray(value) || value.length !== roles.length || !digest(claimedDigest) ||
      roles.some(([destination, type, writable], index) => !validMount(value[index]) ||
        value[index].Destination !== destination || value[index].Type !== type || value[index].RW !== writable)) return false;
  return inventoryDigest(value) === claimedDigest;
}

const UINT32_END = 2 ** 32;
function idMap(value, subordinate) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 128) return false;
  for (const row of value) {
    if (!closed(row, ['container_id', 'host_id', 'size']) ||
        !['container_id', 'host_id', 'size'].every(key => Number.isSafeInteger(row[key]) &&
          row[key] >= 0 && row[key] < UINT32_END) || row.size === 0 ||
        row.container_id + row.size > UINT32_END || row.host_id + row.size > UINT32_END ||
        (subordinate && (row.host_id < 165536 || row.host_id + row.size > 231072))) return false;
  }
  if (!value.some(row => row.container_id === 0)) return false;
  for (let index = 0; index < value.length; index++) {
    for (let other = index + 1; other < value.length; other++) {
      for (const key of ['container_id', 'host_id']) {
        if (value[index][key] < value[other][key] + value[other].size &&
            value[other][key] < value[index][key] + value[index].size) return false;
      }
    }
  }
  return true;
}

function isolation(value, subordinate) {
  const keys = ['uid', 'uid_map', 'gid_map', 'cap_eff', 'cap_prm', 'cap_bnd',
    'no_new_privs', 'seccomp', 'process_start_time'];
  if (subordinate) keys.push('workload_binary_digest');
  return closed(value, keys) && Number.isSafeInteger(value.uid) && value.uid > 0 &&
    value.uid < UINT32_END && idMap(value.uid_map, subordinate) && idMap(value.gid_map, subordinate) &&
    value.uid_map.some(row => row.host_id <= value.uid && value.uid < row.host_id + row.size) &&
    ['cap_eff', 'cap_prm', 'cap_bnd'].every(key => value[key] === '0000000000000000') &&
    value.no_new_privs === 1 && value.seccomp === 2 &&
    Number.isSafeInteger(value.process_start_time) && value.process_start_time > 0 &&
    (!subordinate || digest(value.workload_binary_digest));
}

/** Bounded textual ingress: JSON.parse alone silently accepts duplicate keys. */
export function parseConfinementInfoJson(source) {
  if (!text(source) || Buffer.byteLength(source, 'utf8') > MAX_INFO_BYTES) {
    throw unavailable('POLICY_READBACK', 'invalid applied-policy JSON encoding or size');
  }
  let offset = 0;
  let nodes = 0;
  const fail = () => { throw unavailable('POLICY_READBACK', 'invalid or ambiguous applied-policy JSON'); };
  const space = () => { while (offset < source.length && /[\t\r\n ]/.test(source[offset])) offset++; };
  const string = () => {
    const start = offset++;
    while (offset < source.length) {
      const char = source[offset++];
      if (char === '"') {
        try {
          const value = JSON.parse(source.slice(start, offset));
          if (!text(value)) fail();
          return value;
        } catch { fail(); }
      }
      if (char === '\\') offset++;
    }
    fail();
  };
  const parse = depth => {
    if (depth > 32 || ++nodes > 4096) fail();
    space();
    const char = source[offset];
    if (char === '"') return string();
    if (char === '{' || char === '[') {
      const array = char === '[';
      const value = array ? [] : Object.create(null);
      const seen = new Set();
      const end = array ? ']' : '}';
      offset++;
      space();
      if (source[offset] === end) { offset++; return value; }
      for (;;) {
        space();
        let key;
        if (!array) {
          if (source[offset] !== '"') fail();
          key = string();
          if (seen.has(key)) fail();
          seen.add(key);
          space();
          if (source[offset++] !== ':') fail();
        }
        const item = parse(depth + 1);
        if (array) value.push(item); else value[key] = item;
        space();
        const separator = source[offset++];
        if (separator === end) return value;
        if (separator !== ',') fail();
      }
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(literal, offset)) { offset += literal.length; return value; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(offset));
    if (!number) fail();
    offset += number[0].length;
    const value = Number(number[0]);
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) fail();
    return value;
  };
  const value = parse(0);
  space();
  if (offset !== source.length) fail();
  return value;
}

/** Validate full readback. The protected host profile comparator establishes
 * approved source/options identities; a self-supplied digest is not that proof. */
export function validateConfinementInfo(info, expectedWorkspace) {
  if (!closed(info, CONFINEMENT_INFO_KEYS) || info.version !== CONFINEMENT_INFO_VERSION ||
      info.openshell_version !== '0.1.2' ||
      info.sandbox !== 'auma-ws' || info.state !== 'Ready' || !identity(info.instance_id) ||
      !Number.isSafeInteger(info.policy_revision) || info.policy_revision < 1 ||
      info.applied_revision !== info.policy_revision || info.workspace_root !== GUEST_WORKSPACE ||
      info.network_mode !== 'none') {
    throw unavailable('APPLIED_POLICY', 'the running sandbox policy is unavailable or unapplied');
  }
  const policy = info.policy;
  const filesystem = policy?.filesystem_policy;
  if (!object(policy) || policy.version !== 1 ||
      !closed(filesystem, ['include_workdir', 'read_only', 'read_write']) ||
      filesystem.include_workdir !== false || !exactSet(filesystem.read_only, READ_ONLY_ROOTS) ||
      !exactSet(filesystem.read_write, WRITABLE_ROOTS) ||
      !object(policy.landlock) || Object.keys(policy.landlock).length !== 1 ||
      policy.landlock.compatibility !== 'hard_requirement' ||
      !object(policy.network_policies) || Object.keys(policy.network_policies).length !== 0 ||
      Object.keys(policy).some(key => !['version', 'filesystem_policy', 'landlock',
        'process', 'network_policies', 'network_middlewares'].includes(key)) ||
      (policy.process !== undefined && (!closed(policy.process, ['run_as_user', 'run_as_group']) ||
        !text(policy.process.run_as_user) || policy.process.run_as_user.length < 1 || policy.process.run_as_user.length > 128 ||
        !text(policy.process.run_as_group) || policy.process.run_as_group.length < 1 || policy.process.run_as_group.length > 128)) ||
      (policy.network_middlewares !== undefined &&
        (!object(policy.network_middlewares) || Object.keys(policy.network_middlewares).length !== 0))) {
    throw unavailable('FILE_POLICY', 'the applied sandbox does not enforce the exact supported filesystem policy');
  }
  if (!digest(info.profile_digest) ||
      !mountInventory(info.mount_inventory, [
        ['/.openshell/channel', 'volume', true],
        ['/opt/openshell/bin/openshell-sandbox', 'bind', false],
        ['/sandbox', 'bind', true],
        ['/sandbox/.git', 'bind', false],
      ], info.inventory_digest) ||
      !mountInventory(info.supervisor_inventory, [['/.openshell/channel', 'volume', false]],
        info.supervisor_inventory_digest) ||
      !isolation(info.isolation, true) || !isolation(info.supervisor_isolation, false)) {
    throw unavailable('SANDBOX_INVENTORY', 'the exact sandbox inventory or process isolation is unavailable');
  }
  const channel = info.mount_inventory[0];
  const supervisorChannel = info.supervisor_inventory[0];
  if (Object.keys(channel).some(key => !['RW', 'Mode'].includes(key) &&
      canonicalJson(channel[key]) !== canonicalJson(supervisorChannel[key]))) {
    throw unavailable('SANDBOX_INVENTORY', 'the supervisor channel identity does not match the workload');
  }
  const binding = info.workspace_binding;
  if (!kernelMounts(info.mountinfo, binding, info.mount_inventory, info.mountinfo_digest) ||
      info.mount_inventory[2].Source !== binding.workspace_source ||
      info.mount_inventory[3].Source !== binding.git_source ||
      (expectedWorkspace !== undefined && (!absolutePath(expectedWorkspace) || expectedWorkspace === '/' ||
        expectedWorkspace !== binding.workspace_source))) {
    throw unavailable('WORKSPACE_BINDING', 'the exact workspace bind and read-only metadata mount are unavailable');
  }
  return info;
}

/** Preparation-only read: never launch the proposed command or inherit env. */
export async function readConfinementInfo(layout, signal, expectedWorkspace) {
  signal?.throwIfAborted();
  // Real preparation must bind the root-custody readback to its trusted session
  // workspace. A source supplied only by that readback cannot appoint itself.
  if (!absolutePath(expectedWorkspace) || expectedWorkspace === '/') {
    throw unavailable('WORKSPACE_BINDING', 'a trusted host workspace is required for policy readback');
  }
  try {
    const stdout = await new Promise((accept, reject) => {
      let settled = false;
      let timer;
      const finish = (error, output) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        if (error !== undefined && error !== null) reject(error);
        else accept(output);
      };
      const stopReader = () => {
        child.kill('SIGKILL');
        child.stdout?.destroy();
        child.stderr?.destroy();
      };
      const abort = () => { stopReader(); finish(signal.reason); };
      const child = execFile('/usr/bin/sudo',
        ['-n', '-u', layout.users.agent, layout.sbxExec, '--confinement-info'], {
          cwd: '/', env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' },
          encoding: 'utf8', maxBuffer: MAX_INFO_BYTES, killSignal: 'SIGKILL',
        }, (error, output) => finish(error, output));
      // Settlement does not wait indefinitely for inherited child pipes.
      // The root-owned INFO path must separately bound its own backend queries.
      timer = setTimeout(() => {
        stopReader();
        finish(unavailable('POLICY_READBACK', 'the applied-policy readback timed out'));
      }, 5000);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
    });
    signal?.throwIfAborted();
    return validateConfinementInfo(parseConfinementInfoJson(stdout), expectedWorkspace);
  } catch (error) {
    signal?.throwIfAborted();
    if (error?.code === 'SANDBOX_UNAVAILABLE') throw error;
    // Raw child diagnostics can contain operator paths or command contents.
    throw unavailable('POLICY_READBACK', 'the boundary wrapper supplied no valid applied-policy readback');
  }
}

export function quoteGuestArg(value) {
  if (!text(value)) throw unavailable('ARGV', 'invalid argument encoding');
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

export function buildGuestCommand(argv) {
  const command = "cd -- '/sandbox' || { printf '%s\\n' " +
    "'aukora-openshell-confinement: guest-workspace-unavailable' >&2; exit 125; }; exec " +
    argv.map(quoteGuestArg).join(' ');
  if (Buffer.byteLength(command, 'utf8') > MAX_COMMAND_BYTES) {
    throw unavailable('ARGV', 'encoded command exceeds the boundary wrapper limit');
  }
  return command;
}

// The selected wrapper's file-denial dialect has not been qualified.
// Do not classify arbitrary guest errors as sandbox denial evidence.
export const DENIAL_SIGNATURES = Object.freeze([]);
export const RUNNER_FAILURE_RULES = Object.freeze([
  Object.freeze({
    allowedExitCodes: Object.freeze([125]),
    fatalSignatures: Object.freeze(['aukora-openshell-confinement: guest-workspace-unavailable']),
  }),
  Object.freeze({
    fatalSignatures: Object.freeze([
      'sudo: a password is required',
      'sudo: unknown user auma',
      'sudo: unable to execute /usr/local/lib/aukora-boundary/sbx-exec',
      'aukora-openshell-confinement: applied-policy-unavailable',
      'aukora-openshell-confinement: sandbox-unavailable',
    ]),
  }),
]);

/** Prepare argv; confine returns it only after validating the applied policy. */
export function prepareLabTransport(argv, policy, settings, sandboxArgv, layout, signal) {
  validateRequest(argv, policy, settings, signal);
  if (layout.users?.host !== 'aukora-host' || layout.users?.agent !== 'auma' ||
      layout.users?.gate !== 'aukora-gate' || layout.sandbox !== 'auma-ws' ||
      layout.sbxExec !== '/usr/local/lib/aukora-boundary/sbx-exec') {
    throw unavailable('BACKEND', 'the selected wrapper requires the exact lab layout');
  }
  const command = buildGuestCommand(argv);
  const [program, args] = sandboxArgv(command, settings.timeoutSeconds, layout);
  if (program !== '/usr/bin/sudo' || !Array.isArray(args) || args.length !== 6 ||
      args[0] !== '-n' || args[1] !== '-u' || args[2] !== 'auma' ||
      args[3] !== layout.sbxExec || args[4] !== String(settings.timeoutSeconds) || args[5] !== command) {
    throw unavailable('BACKEND', 'the boundary runner returned an incompatible argv');
  }
  signal?.throwIfAborted();
  return Object.freeze({
    // No caller-controlled host shell or inherited loader environment.
    argv: ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', program, ...args],
    denialSignatures: DENIAL_SIGNATURES,
    runnerFailureRules: RUNNER_FAILURE_RULES,
  });
}
