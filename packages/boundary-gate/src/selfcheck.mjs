// Fail-closed start-up self-check ("teeth twin"), run as the harness user. Every forbidden action MUST fail
// and the in-sandbox egress probe MUST pass, otherwise every agent tool stays refused. Extra probes (the gate's
// owner channel, approval on the propose channel) are added by the gate package as `extraProbes`.
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { resolveLayout } from './layout.mjs'
import { runInSandbox, egressProbeScript, probePassed } from './sandbox.mjs'

const sudoDenied = (args) => () => { if (spawnSync('/usr/bin/sudo', ['-n', ...args, '/bin/true']).status === 0) return 'SUDO_OK'; throw Object.assign(new Error('denied'), { code: 'DENIED' }) }

// Each probe returns normally only if the forbidden action SUCCEEDED.
export function forbiddenProbes(layout = resolveLayout()) {
  const theme = path.join(layout.targetRoot, 'plugins/auma-theme/theme.json')
  return [
    ['write gate-owned target', () => fs.openSync(theme, 'r+')],
    ['create file next to target', () => fs.openSync(path.join(path.dirname(theme), '.selfcheck-probe'), 'wx')],
    ['read gate receipt key', () => fs.readFileSync(path.join(layout.gateHome, 'receipt-ed25519.pem'))],
    ['open gate ledger db', () => fs.openSync(path.join(layout.gateHome, 'gate.db'), 'r')],
    ['read gate owner secret', () => fs.readFileSync(path.join(layout.gateHome, 'owner-secret.json'))],
    ['drop file into harness plugins dir', () => fs.openSync(path.join(layout.appRoot, 'plugins', '.selfcheck-probe.js'), 'wx')],
    [`sudo to ${layout.users.gate}`, sudoDenied(['-u', layout.users.gate])],
    ['sudo to root', sudoDenied([])],
    [`sudo to ${layout.users.agent} outside sbx-exec`, sudoDenied(['-u', layout.users.agent])],
  ]
}

export function runForbidden(probes) {
  const results = []; let ok = true
  for (const [action, fn] of probes) {
    let succeeded = false, why = ''
    try { const r = fn(); succeeded = true; if (typeof r === 'number' && r > 2) { try { fs.closeSync(r) } catch {} } } catch (e) { why = e.code ?? e.message }
    results.push({ action, result: succeeded ? 'SUCCEEDED (BAD)' : `refused (${why})` })
    if (succeeded) ok = false
  }
  return { ok, results }
}

export async function selfCheck({ layout = resolveLayout(), probes = forbiddenProbes(layout), extraProbes = [], egress = {}, run = runInSandbox } = {}) {
  const forbidden = runForbidden(probes)
  const extra = []
  for (const [action, fn] of extraProbes) {
    const r = await fn().then(() => 'SUCCEEDED (BAD)', e => `refused (${String(e?.code ?? e?.message ?? e).slice(0, 60)})`)
    extra.push({ action, result: r })
  }
  const r = await run(egressProbeScript(egress), { timeoutS: 120, layout })
  const egressOk = probePassed(r)
  const ok = forbidden.ok && extra.every(x => !x.result.startsWith('SUCC')) && egressOk
  return {
    ok, state: ok ? 'passed' : 'FAILED', at: new Date().toISOString(),
    forbidden: [...forbidden.results, ...extra],
    egress: { passed: egressOk, exit: r.exit_code, reachable: r.stdout.match(/^(REACHABLE|VISIBLE|DNS REAL|SUDO works).*$/gm) ?? [], stderr: r.stderr.slice(0, 300) },
  }
}
