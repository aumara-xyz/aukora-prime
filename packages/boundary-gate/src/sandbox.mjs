// Harness-side runner for the agent's hands: every command goes through the root-owned sbx-exec wrapper as
// the agent user (one sudo rule), never through a host shell. Output is capped per stream; a timeout or an
// abort kills the sudo child. The probe script below is run INSIDE the sandbox by the fail-closed self-check.
import { spawn } from 'node:child_process'
import os from 'node:os'
import { resolveLayout } from './layout.mjs'

export const OUT_CAP = 64 * 1024
export const MAX_TIMEOUT_S = 300

export function clampTimeout(seconds) {
  const n = Math.floor(Number(seconds))
  if (!Number.isFinite(n)) return 60
  return Math.max(1, Math.min(MAX_TIMEOUT_S, n))
}

export function sandboxArgv(command, timeoutS = 60, layout = resolveLayout()) {
  if (typeof command !== 'string' || command.length === 0 || command.length > 256 * 1024 || command.includes('\0'))
    throw new TypeError('sandbox: command must be a non-empty string without NUL (<=256 KiB)')
  return ['/usr/bin/sudo', ['-n', '-u', layout.users.agent, layout.sbxExec, String(clampTimeout(timeoutS)), command]]
}

// spawnImpl is injectable for checks; production uses node:child_process spawn with a minimal environment.
export function runInSandbox(command, { timeoutS = 60, signal, layout = resolveLayout(), spawnImpl = spawn, graceS = 15 } = {}) {
  const [file, args] = sandboxArgv(command, timeoutS, layout)
  const t = clampTimeout(timeoutS)
  return new Promise((resolve) => {
    const child = spawnImpl(file, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin' } })
    let out = Buffer.alloc(0), err = Buffer.alloc(0), killed = null
    const take = (buf, d) => buf.length >= OUT_CAP ? buf : Buffer.concat([buf, d]).subarray(0, OUT_CAP)
    child.stdout.on('data', d => { out = take(out, d) })
    child.stderr.on('data', d => { err = take(err, d) })
    const kill = (why) => { killed ??= why; try { child.kill('SIGKILL') } catch {} }
    const onAbort = () => kill('aborted')
    if (signal?.aborted) onAbort(); else signal?.addEventListener('abort', onAbort, { once: true })
    const timer = setTimeout(() => kill('timeout'), (t + graceS) * 1000)
    child.on('error', (e) => { err = take(err, Buffer.from(`sandbox spawn failed: ${e.code ?? e.message}\n`)) })
    child.on('close', (code, sig) => {
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort)
      resolve({ exit_code: code ?? -1, signal: sig ?? null, killed, stdout: out.toString('utf8'), stderr: err.toString('utf8') })
    })
  })
}

const q = (s) => "'" + String(s).replace(/'/g, `'\\''`) + "'"
const HOSTPORT = /^[A-Za-z0-9.:\[\]-]{1,253}:[0-9]{1,5}$/

// Egress / host-reach probe run INSIDE the sandbox; any success makes it fail. `targets` are host:port pairs
// supplied by the operator (public resolvers, the model API, the cloud metadata service, the podman bridge
// gateway, ...). The harness and gateway ports on loopback and on every host interface are always added.
export function egressProbeScript({ targets = [], hostPorts = [3091, 17690, 22], visiblePaths = [], dnsNames = [], interfaces = os.networkInterfaces() } = {}) {
  const hostIps = Object.values(interfaces).flat().filter(a => a && a.family === 'IPv4').map(a => a.address)
  const all = [...new Set([...targets, 'localhost:3091', 'localhost:17690', 'host.containers.internal:3091', 'host.containers.internal:17690',
    ...hostIps.flatMap(ip => hostPorts.map(p => `${ip}:${p}`))])]
  for (const t of all) if (!HOSTPORT.test(t)) throw new TypeError(`probe target refused: ${String(t).slice(0, 80)}`)
  const paths = ['/run/podman/podman.sock', '/var/run/docker.sock', ...visiblePaths]
  for (const n of dnsNames) if (!/^[A-Za-z0-9.-]{1,253}$/.test(n)) throw new TypeError('probe dns name refused')
  return `fail=0
for t in ${all.map(q).join(' ')}; do h=\${t%:*}; p=\${t##*:}
  if timeout 4 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then echo "REACHABLE $t"; fail=1; else echo "blocked $t"; fi; done
for s in ${paths.map(q).join(' ')} /run/user/*/podman/podman.sock; do if [ -e "$s" ]; then echo "VISIBLE $s"; fail=1; else echo "absent $s"; fi; done
# OpenShell's in-sandbox DNS stub answers every name with a synthetic sinkhole address in the RFC 2544 benchmarking range; a real address = fail
for n in ${dnsNames.map(q).join(' ')}; do ip=$(getent hosts "$n" | awk '{print $1; exit}'); case "$ip" in ""|198.18.*|198.19.*) echo "dns $n -> \${ip:-none} (sinkhole/none)";; *) echo "DNS REAL ADDRESS $n -> $ip"; fail=1;; esac; done
if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then echo "SUDO works"; fail=1; else echo "no sudo"; fi
echo "routes: $(awk 'NR>1' /proc/net/route | wc -l)"
echo "PROBE_DONE fail=$fail"`
}

export function probePassed(result) {
  return result.exit_code === 0 && /PROBE_DONE fail=0\s*$/.test(result.stdout) &&
    !/^(REACHABLE|VISIBLE|DNS REAL|SUDO works)/m.test(result.stdout)
}
