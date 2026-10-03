// Host layout of the harness-to-agent boundary (distilled from the Genesis SKUNKWORKS boundary lab).
// Three Linux principals and one shared group:
//   host  (aukora-host) runs the harness; it may PROPOSE to the gate and run sandbox commands via one sudo rule
//   agent (auma)        owns rootless Podman, the OpenShell gateway and the sandbox; no host tools
//   gate  (aukora-gate) owns proposals, the signed ledger, the receipt key and the allowlisted target files
//   group (skgate)      = host + gate; only the gate's PROPOSE socket is group-accessible
// Paths are operator configuration. Nothing here creates users, files or sockets.
import path from 'node:path'

export const DEFAULT_LAYOUT = Object.freeze({
  users: Object.freeze({ host: 'aukora-host', agent: 'auma', gate: 'aukora-gate', group: 'skgate' }),
  sandbox: 'auma-ws',
  gatewayPort: 17690,
  libexec: '/usr/local/lib/aukora-boundary',
  root: '/srv/aukora-boundary',
  run: '/run/aukora-boundary-gate',
})

const NAME = /^[a-z_][a-z0-9_-]{0,31}$/
const SANDBOX = /^[a-z0-9][a-z0-9-]{0,62}$/

function absolute(label, value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value || value.length > 1024 || value === '/')
    throw new TypeError(`layout: ${label} must be a normalized absolute path`)
  return value
}

// Returns a frozen, validated layout plus derived paths. Unknown keys refuse.
export function resolveLayout(overrides = {}) {
  const allowed = new Set(Object.keys(DEFAULT_LAYOUT))
  for (const k of Object.keys(overrides)) if (!allowed.has(k)) throw new TypeError(`layout: unknown key ${k}`)
  const l = { ...DEFAULT_LAYOUT, ...overrides, users: { ...DEFAULT_LAYOUT.users, ...(overrides.users ?? {}) } }
  for (const [role, name] of Object.entries(l.users)) if (!NAME.test(String(name))) throw new TypeError(`layout: invalid ${role} user/group name`)
  if (new Set([l.users.host, l.users.agent, l.users.gate]).size !== 3) throw new TypeError('layout: host, agent and gate must be three distinct Linux users')
  if (!SANDBOX.test(String(l.sandbox))) throw new TypeError('layout: invalid sandbox name')
  if (!Number.isInteger(l.gatewayPort) || l.gatewayPort < 1024 || l.gatewayPort > 65535) throw new TypeError('layout: gatewayPort must be an unprivileged port')
  for (const k of ['libexec', 'root', 'run']) absolute(k, l[k])
  return Object.freeze({
    ...l,
    users: Object.freeze(l.users),
    sbxExec: path.join(l.libexec, 'sbx-exec'),
    gateHome: path.join(l.root, 'gate'),
    targetRoot: path.join(l.root, 'targets'),
    appRoot: path.join(l.root, 'app'),
    proposeSocket: path.join(l.run, 'gate.sock'),
    ownerSocket: path.join(l.run, 'owner.sock'),
  })
}

// The single sudo rule: the harness user may run exactly the root-owned wrapper as the agent user.
export function sudoersRule(layout = resolveLayout()) {
  return `${layout.users.host} ALL=(${layout.users.agent}) NOPASSWD: ${layout.sbxExec}\n`
}
