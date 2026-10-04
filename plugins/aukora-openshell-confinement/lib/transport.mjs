// SPDX-License-Identifier: AGPL-3.0-or-later
// Exact Bash transport for the guest filesystem namespace. Admission requires
// a genuine applied-policy readback from the root-owned boundary wrapper.
import { execFile } from 'node:child_process';
export const GUEST_WORKSPACE = '/sandbox';
export const MAX_COMMAND_BYTES = 256 * 1024;
const WRITABLE_ROOTS = Object.freeze(['/sandbox', '/tmp', '/dev/null']);

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
      Object.keys(input).some(key => !['workspaceRoot', 'timeoutSeconds', 'nodeExecutable', 'bootstrapPath',
        'startupTimeoutMs', 'cleanupTimeoutMs'].includes(key))) {
    throw unavailable('CONFIG', 'unsupported configuration');
  }
  const workspaceRoot = input.workspaceRoot ?? GUEST_WORKSPACE;
  const timeoutSeconds = input.timeoutSeconds ?? 60;
  // No host-to-guest mapping is inferred. The existing wrapper only knows /sandbox.
  if (workspaceRoot !== GUEST_WORKSPACE) {
    throw unavailable('WORKSPACE', 'only the explicit guest workspace /sandbox can be prepared');
  }
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 300) {
    throw unavailable('TIMEOUT', 'timeoutSeconds must be an integer from 1 to 300');
  }
  const { nodeExecutable, bootstrapPath } = input;
  for (const path of [nodeExecutable, bootstrapPath]) {
    if (path !== undefined && (!text(path) || !path.startsWith('/') || path.split('/').includes('..') || path.length > 4096)) {
      throw unavailable('CONFIG', 'guest executable and bootstrap paths must be explicit absolute paths');
    }
  }
  const startupTimeoutMs = input.startupTimeoutMs ?? 5000;
  const cleanupTimeoutMs = input.cleanupTimeoutMs ?? 10000;
  if (![startupTimeoutMs, cleanupTimeoutMs].every(value => Number.isSafeInteger(value) && value >= 1000 && value <= 30000)) {
    throw unavailable('CONFIG', 'invalid bounded carrier deadline');
  }
  return Object.freeze({ workspaceRoot, timeoutSeconds, nodeExecutable, bootstrapPath,
    startupTimeoutMs, cleanupTimeoutMs });
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
  if (policy.workspaceRoot !== settings.workspaceRoot) {
    throw unavailable('WORKSPACE', 'host and guest workspace identities cannot be substituted');
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

/** Validate observed startup policy, including runtime-added writable roots. */
export function validateConfinementInfo(info) {
  const keys = ['version', 'openshell_version', 'sandbox', 'state', 'instance_id', 'policy_revision',
    'applied_revision', 'workspace_root', 'network_mode', 'policy'];
  if (!object(info) || Object.keys(info).length !== keys.length ||
      Object.keys(info).some(key => !keys.includes(key)) || info.version !== 1 ||
      info.openshell_version !== '0.1.2' ||
      info.sandbox !== 'auma-ws' || info.state !== 'Ready' || !identity(info.instance_id) ||
      !Number.isSafeInteger(info.policy_revision) || info.policy_revision < 1 ||
      info.applied_revision !== info.policy_revision || info.workspace_root !== GUEST_WORKSPACE ||
      info.network_mode !== 'none') {
    throw unavailable('APPLIED_POLICY', 'the running sandbox policy is unavailable or unapplied');
  }
  const policy = info.policy;
  const filesystem = policy?.filesystem_policy;
  if (!object(policy) || policy.version !== 1 || !object(filesystem) ||
      Object.keys(filesystem).some(key => !['include_workdir', 'read_only', 'read_write'].includes(key)) ||
      filesystem.include_workdir !== false || !Array.isArray(filesystem.read_only) ||
      filesystem.read_only.length > 256 || filesystem.read_only.some(path =>
        !text(path) || !path.startsWith('/') || path.includes('..') || path.length > 4096) ||
      !Array.isArray(filesystem.read_write) || filesystem.read_write.length !== WRITABLE_ROOTS.length ||
      new Set(filesystem.read_write).size !== WRITABLE_ROOTS.length ||
      filesystem.read_write.some(path => !WRITABLE_ROOTS.includes(path)) ||
      !object(policy.landlock) || Object.keys(policy.landlock).length !== 1 ||
      policy.landlock.compatibility !== 'hard_requirement' ||
      !object(policy.network_policies) || Object.keys(policy.network_policies).length !== 0 ||
      Object.keys(policy).some(key => !['version', 'filesystem_policy', 'landlock',
        'process', 'network_policies', 'network_middlewares'].includes(key)) ||
      (policy.network_middlewares !== undefined &&
        (!object(policy.network_middlewares) || Object.keys(policy.network_middlewares).length !== 0))) {
    throw unavailable('FILE_POLICY', 'the applied sandbox does not enforce the supported writable roots');
  }
  return info;
}

/** Preparation-only read: never launch the proposed command or inherit env. */
export async function readConfinementInfo(layout, signal) {
  signal?.throwIfAborted();
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
          encoding: 'utf8', maxBuffer: 16 * 1024, killSignal: 'SIGKILL',
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
    return validateConfinementInfo(JSON.parse(stdout));
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
