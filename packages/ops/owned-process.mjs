import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'

const TOKEN = /(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key|access[_-]?token|authorization|password|secret)\s*["']?\s*[=:]\s*["']?[^\s,"'}]+)/ig
export function sanitized(text) { return String(text).replace(TOKEN, '[REDACTED]') }

/** Only this direct child is signalled. Descendant cleanup requires H/F or a cgroup. */
export function runOwned(command, args = [], options = {}) {
  if (!Array.isArray(args) || args.some(v => typeof v !== 'string')) throw new Error('INVALID_ARGV')
  const { cwd, timeoutMs = 30_000, signal, maxOutputBytes = 1024 * 1024 } = options
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) throw new Error('INVALID_TIMEOUT')
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1 || maxOutputBytes > 8 * 1024 * 1024) throw new Error('INVALID_OUTPUT_BUDGET')
  const id = randomUUID()
  const env = { PATH: '/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin', LANG: 'C.UTF-8',
    HOME: options.home ?? cwd, TMPDIR: options.tmpdir ?? cwd,
    AUKORA_PRIME_PAID_INFERENCE: 'disabled', AUKORA_PRIME_GPU: 'disabled',
    ...options.env }
  // Shell expansion, inherited credentials and caller-selected process IDs are absent.
  return new Promise(resolve => {
    let child, stdout = '', stderr = '', timedOut = false, cancelled = false, overflow = false, tokenLeak = false
    let rawOut = '', rawErr = '', completed = false, observedExit = null
    const cancel = () => { cancelled = true; child?.kill('SIGTERM') }
    const capture = (kind, chunk) => {
      const data = chunk.toString('utf8')
      const remaining = Math.max(0, maxOutputBytes - Buffer.byteLength(rawOut) - Buffer.byteLength(rawErr))
      if (kind === 'stdout') rawOut += data.slice(0, remaining)
      else rawErr += data.slice(0, remaining)
      if (Buffer.byteLength(data) > remaining) {
        overflow = true; child?.kill('SIGTERM')
      }
    }
    if (signal?.aborted) { resolve({ owner_id: id, cancelled: true, exit_code: null, completion: 'NOT_STARTED', stdout: '', stderr: '' }); return }
    try { child = spawn(command, args, { cwd, env, shell: false, detached: false, stdio: ['ignore', 'pipe', 'pipe'] }) }
    catch { resolve({ owner_id: id, exit_code: null, completion: 'NOT_STARTED', error: 'SPAWN_ERROR', stdout: '', stderr: '' }); return }
    child.stdout.on('data', c => capture('stdout', c))
    child.stderr.on('data', c => capture('stderr', c))
    signal?.addEventListener('abort', cancel, { once: true })
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM') }, timeoutMs)
    // Owned direct child only; never pkill, process-name matching or negative PID signals.
    let escalation
    const scheduleEscalation = () => { escalation ??= setTimeout(() => {
      child.kill('SIGKILL')
      child.stdout.destroy(); child.stderr.destroy()
      finish(observedExit?.code ?? null, observedExit?.signal ?? null, undefined, 'OUTPUT_DRAIN_UNKNOWN')
    }, 500) }
    const poll = setInterval(() => { if (timedOut || cancelled || overflow) scheduleEscalation() }, 50)
    const finish = (code, exitSignal, error, completion) => {
      if (completed) return
      completed = true
      clearTimeout(timer); clearTimeout(escalation); clearInterval(poll)
      signal?.removeEventListener('abort', cancel)
      stdout = sanitized(rawOut); stderr = sanitized(rawErr)
      tokenLeak = stdout !== rawOut || stderr !== rawErr
      resolve({ owner_id: id, pid: child.pid ?? null, exit_code: code, signal: exitSignal,
        completion: completion ?? (error ? 'NOT_STARTED' : 'DIRECT_CHILD_CLOSED'), error,
        timed_out: timedOut, cancelled, output_overflow: overflow, token_leak: tokenLeak,
        stdout: stdout.slice(0, maxOutputBytes), stderr: stderr.slice(0, maxOutputBytes),
        descendant_cleanup: 'NOT_VERIFIED' })
    }
    child.on('error', () => finish(null, null, 'SPAWN_ERROR'))
    child.on('exit', (code, s) => { observedExit = { code, signal: s } })
    child.on('close', (code, s) => finish(code, s, undefined))
  })
}
