// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure argv preparation for the existing boundary-gate wrapper. This is not
// admission: index.mjs refuses execution while policy/lifecycle gaps remain.
export const GUEST_WORKSPACE = '/sandbox';
export const MAX_COMMAND_BYTES = 256 * 1024;
export const WRAPPER_LIMITS = Object.freeze([
  'read-only file effects are not enforced',
  'the guest workspace is not the host filesystem workspace',
  'caller workdir and remaining deadline are absent from confine()',
  'guest absence after cancellation is not established',
  'cleanup exempts an agent-controlled argv marker',
]);

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
      Object.keys(input).some(key => !['workspaceRoot', 'timeoutSeconds'].includes(key))) {
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
  return Object.freeze({ workspaceRoot, timeoutSeconds });
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
    throw unavailable('ARGV', 'only the exact Bash command argv shape is supported by this transport');
  }
  signal?.throwIfAborted();
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
    ]),
  }),
]);

/** Prepare a partial transport only; this result is never returned by confine(). */
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
    enforcement: 'partial',
    denialSignatures: DENIAL_SIGNATURES,
    runnerFailureRules: RUNNER_FAILURE_RULES,
  });
}
