#!/usr/bin/env node
// RELEASE FLOOR CHECK, run by aukora-genesis.service as ExecStartPre from the root-owned gate install. Trusted code only:
// the candidate release is read as DATA (.dsh-build JSON), its installed approval is verified against the root pin with
// src/plugin-set-canon.mjs, it must name exactly this release, and its gate-signed applied_at must not predate the floor.
//   check --release-dir /opt/aukora-genesis/release-xxxxxxx --approval-state-root /etc/aukora-approvals/<sha>/state [--floor FILE]
//   show  [--floor FILE]
import fs from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { installedRelease } from '../src/targets.mjs'
import { verifyGateSetApproval } from '../src/plugin-set-canon.mjs'
import { FLOOR_FILE, readFloor, checkFloor } from '../src/release-floor.mjs'

const { values: o, positionals: [cmd] } = parseArgs({ allowPositionals: true, strict: true, options: {
  'release-dir': { type: 'string' }, 'approval-state-root': { type: 'string' }, floor: { type: 'string', default: FLOOR_FILE } } })
const die = (m) => { console.error(`release-floor: REFUSED: ${m}`); process.exit(1) }
const rootOwned = (p) => { const st = fs.lstatSync(p); if (st.isSymbolicLink() || st.uid !== 0 || (st.mode & 0o022) !== 0) die(`${p} is not root-owned, go-w and a real path`) }

if (cmd === 'show') { console.log(JSON.stringify(readFloor(o.floor), null, 2)); process.exit(0) }
if (cmd !== 'check') die('usage: release-floor.mjs check --release-dir DIR --approval-state-root DIR [--floor FILE] | show')
const relDir = o['release-dir'], root = o['approval-state-root']
if (!relDir || !path.isAbsolute(relDir) || !root || !path.isAbsolute(root)) die('--release-dir and --approval-state-root must be absolute')
try {
  const gs = path.join(root, 'gate-state')
  for (const p of [root, gs, path.join(gs, 'plugin-set-approval.json'), path.join(gs, 'plugin-set-approver.json')]) rootOwned(p)
  const floor = readFloor(o.floor, { requireRoot: true })
  const on = installedRelease(path.dirname(relDir), path.basename(relDir))
  const record = JSON.parse(fs.readFileSync(path.join(relDir, '.dsh-build/plugin-set.json'), 'utf8'))
  const approval = JSON.parse(fs.readFileSync(path.join(gs, 'plugin-set-approval.json'), 'utf8'))
  const pin = JSON.parse(fs.readFileSync(path.join(gs, 'plugin-set-approver.json'), 'utf8'))
  const v = verifyGateSetApproval({ record, approval, pin })
  if (v.release !== on.release || v.release_dir !== on.release_dir || v.record !== on.record) die(`the installed approval names ${v.release_dir}, not ${on.release_dir}`)
  const r = checkFloor(floor, v)
  console.log(`release-floor: OK ${r.release} (owner-approved ${v.appliedAt}) >= floor ${r.floor} (${floor.applied_at})`)
} catch (e) { die(e.message) }
