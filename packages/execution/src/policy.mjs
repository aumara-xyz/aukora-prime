// SPDX-License-Identifier: AGPL-3.0-or-later
// Adapted from Genesis 1cde243 plugins/aukora-openshell/lib/runner.mjs.
import { resolve } from "node:path"
const GUEST_WORKDIR = "/sandbox"
const MAX_OUTPUT = 1_048_576
const ENV = Object.freeze({ PATH: "/usr/bin:/bin", NO_COLOR: "1", TERM: "dumb", PAGER: "cat", GIT_PAGER: "cat" })
const READS = ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc", "/dev/urandom"]

export function refused(message, code = 'AUKORA_OPENSHELL_UNAVAILABLE') {
  return Object.assign(new Error(`aukora-openshell: ${message}`), { code })
}

export function validateSpec(spec, settings) {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw refused('resolved Bash spec required')
  const policy = spec.sandboxPolicy
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)
    || Object.keys(policy).some(key => !['mode', 'workspaceRoot', 'sessionId'].includes(key))
    || !['read-only', 'workspace-write'].includes(policy.mode)
    || typeof policy.workspaceRoot !== 'string' || !policy.workspaceRoot.startsWith('/')
    || resolve(policy.workspaceRoot) !== policy.workspaceRoot || /[\x00-\x1f\x7f]/u.test(policy.workspaceRoot)) {
    throw refused('read-only or workspace-write with one absolute logical workspaceRoot required', 'AUKORA_CONFINEMENT_POLICY')
  }
  if (spec.workdir !== policy.workspaceRoot || (settings && spec.workdir !== settings.workspaceRoot)) {
    throw refused('workdir and approved logical workspaceRoot must agree; host subdirectory and mount joins are unavailable', 'AUKORA_OPENSHELL_WORKDIR')
  }
  if (typeof spec.command !== 'string' || spec.command.includes('\0') || Buffer.byteLength(spec.command) > 262_144) {
    throw refused('Bash command must be a bounded string without NUL', 'AUKORA_CONFINEMENT_ARGV')
  }
  for (const [key, max] of [['timeoutMs', 600_000], ['stdoutMaxBytes', MAX_OUTPUT]]) {
    if (!Number.isSafeInteger(spec[key]) || spec[key] <= 0 || spec[key] > max) throw refused(`invalid ${key}`)
  }
  if (spec.stdin !== undefined && (typeof spec.stdin !== 'string' || Buffer.byteLength(spec.stdin) > 4_194_304)) {
    throw refused('stdin exceeds the pinned CLI 4 MiB limit')
  }
  if (policy.sessionId !== undefined && (typeof policy.sessionId !== 'string' || policy.sessionId.length === 0)) {
    throw refused('invalid policy session identity', 'AUKORA_CONFINEMENT_POLICY')
  }
  for (const key of ['env', 'dshEnv']) {
    if (spec[key] !== undefined && (!spec[key] || typeof spec[key] !== 'object' || Array.isArray(spec[key]))) {
      throw refused(`invalid ${key} map`, 'AUKORA_OPENSHELL_ENV')
    }
  }
  if (spec.signal !== undefined && (typeof spec.signal?.throwIfAborted !== 'function'
    || typeof spec.signal.addEventListener !== 'function' || typeof spec.signal.removeEventListener !== 'function')) {
    throw refused('invalid cancellation signal')
  }
  return policy
}

/** Translate the policy to Linux guest paths; never mount or upload a host path. */
export function guestPolicy(mode) {
  if (!['read-only', 'workspace-write'].includes(mode)) throw refused('unconfined mode is unavailable', 'AUKORA_CONFINEMENT_POLICY')
  return {
    version: 1,
    filesystem_policy: { include_workdir: mode === 'workspace-write',
      read_only: mode === 'read-only' ? [...READS, GUEST_WORKDIR, '/tmp'] : [...READS],
      read_write: mode === 'workspace-write' ? ['/tmp', '/dev/null'] : ['/dev/null'] },
    landlock: { compatibility: 'hard_requirement' }, process: { run_as_user: '1000', run_as_group: '1000' },
    network_policies: {},
  }
}

/** Closed guest environment. Host authentication homes and contributor URLs are never forwarded. */
export function guestEnvironment(spec) {
  validateSpec(spec)
  const env = { ...ENV }
  for (const [key, value] of Object.entries(spec.env ?? {})) {
    if (!Object.hasOwn(ENV, key) || value !== ENV[key]) throw refused('ordinary environment entry has no approved guest translation', 'AUKORA_OPENSHELL_ENV')
  }
  for (const [key, value] of Object.entries(spec.dshEnv ?? {})) {
    if (typeof value !== 'string' || value.includes('\0')) throw refused('invalid managed environment entry', 'AUKORA_OPENSHELL_ENV')
    if (key === 'DSH_HOME' && value.startsWith('/')) env.DSH_HOME = '/sandbox/.dsh'
    else if (key === 'DSH_SHELL' && value === '1') env.DSH_SHELL = '1'
    else if (key === 'DSH_SESSION_ID' && /^[a-zA-Z0-9_.-]{1,128}$/.test(value)) env.DSH_SESSION_ID = value
    else throw refused('managed environment contributor has no approved guest translation', 'AUKORA_OPENSHELL_ENV')
  }
  return env
}
