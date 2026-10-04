#!/usr/bin/env node
// Fail-closed boundary self-check for a deployed host, run AS THE HARNESS USER (aukora-host):
//   node selfcheck.mjs --run /run/aukora-gate --gate-home /home/aukora-gate --target-root /var/lib/aukora-boundary/targets \
//        --release-parent /opt/aukora-genesis [--forbid-write <path>]...
// Every forbidden action must FAIL (write a gate-owned target, read the gate key/ledger/owner secret, write into any
// release's plugins dir, sudo to the gate user/root/agent outside sbx-exec, reach the owner socket, approve on the
// propose socket, write any --forbid-write path), and the in-sandbox egress probe must PASS. The result is recorded as
// a signed `selfcheck` entry in the gate ledger. Exit 0 only if the check passed AND it was recorded; otherwise 1, so
// systemd's ExecStartPre refuses to start the runtime and the periodic timer stops it (OnFailure).
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { resolveLayout } from '../src/layout.mjs'
import { forbiddenProbes, selfCheck } from '../src/selfcheck.mjs'
import { gateProbes } from '../src/gate-client.mjs'
import { runInSandbox } from '../src/sandbox.mjs'
import { call } from '../src/server.mjs'

const ABS = (v, k) => { if (typeof v !== 'string' || !path.isAbsolute(v) || path.normalize(v) !== v || v === '/') throw new Error(`${k} must be a normalized absolute path`); return v }

export function parseArgs(argv) {
  const o = { forbidWrite: [] }; const keys = { '--run': 'run', '--gate-home': 'gateHome', '--target-root': 'targetRoot', '--release-parent': 'releaseParent' }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = argv[i + 1]
    if (a === '--forbid-write') { o.forbidWrite.push(ABS(v, a)); i++ }
    else if (Object.hasOwn(keys, a)) { if (o[keys[a]]) throw new Error(`${a} given twice`); o[keys[a]] = ABS(v, a); i++ }
    else throw new Error(`unknown argument ${String(a).slice(0, 40)}`)
  }
  for (const k of Object.values(keys)) if (!o[k]) throw new Error(`missing --${k.replace(/[A-Z]/g, m => '-' + m.toLowerCase())}`)
  return o
}

export function hostLayout(o) {
  const base = resolveLayout({ run: o.run })
  return Object.freeze({ ...base, gateHome: o.gateHome, targetRoot: o.targetRoot, appRoot: o.releaseParent })
}

export function hostProbes(o, layout = hostLayout(o), readdir = fs.readdirSync) {
  // forbiddenProbes covers one appRoot/plugins; on a host with several releases every release's plugins dir is probed.
  const probes = forbiddenProbes(layout).filter(([action]) => action !== 'drop file into harness plugins dir')
  const releases = readdir(o.releaseParent).filter(n => /^release-[0-9a-f]{7,40}$/.test(n)).sort()
  if (releases.length === 0) throw new Error(`no release-* directory under ${o.releaseParent}`)
  for (const r of releases) probes.push([`drop file into ${r}/plugins`, () => fs.openSync(path.join(o.releaseParent, r, 'plugins', '.selfcheck-probe.js'), 'wx')])
  for (const p of o.forbidWrite) probes.push([`write ${p}`, () => fs.openSync(p, 'r+')])
  return probes
}

export async function main(argv, { run = runInSandbox, rpc = call, probesFor = hostProbes, out = s => process.stdout.write(s) } = {}) {
  let o
  try { o = parseArgs(argv) } catch (e) { out(`selfcheck: REFUSED ${e.message}\n`); return 2 }
  const layout = hostLayout(o)
  let result
  try { result = await selfCheck({ layout, probes: probesFor(o, layout), extraProbes: gateProbes(layout), run }) }
  catch (e) { result = { ok: false, state: 'FAILED', at: new Date().toISOString(), error: String(e?.message ?? e).slice(0, 300) } }
  let recorded = false
  try { await rpc(layout.proposeSocket, 'selfcheck', { result }); recorded = true } catch (e) { out(`selfcheck: could not record in the gate ledger (${String(e?.message ?? e).slice(0, 120)})\n`) }
  out(JSON.stringify({ ...result, recorded }) + '\n')
  const ok = result.ok === true && recorded
  out(`selfcheck: ${ok ? 'PASSED' : 'FAILED (fail closed)'}\n`)
  return ok ? 0 : 1
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2))
