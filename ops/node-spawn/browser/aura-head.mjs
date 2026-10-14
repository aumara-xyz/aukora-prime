// SPDX-License-Identifier: AGPL-3.0-or-later
// Read verified gate and memory heads without returning ledger records.
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { readGateSnapshot } from '../../../scripts/aura/gate-snapshot.mjs'
import { readMemoryLedgerHead } from '../../../plugins/aukora-kira/lib/continuity-head.mjs'

const HEX64 = /^[0-9a-f]{64}$/u
const need = (condition, code) => { if (!condition) throw new Error('BROWSER_AURA_' + code) }

export function readBrowserGateHead({ dbPath, publicKeyPath, expectedKeySha256 }) {
  const value = readGateSnapshot({ dbPath, publicKeyPem: readFileSync(publicKeyPath, 'utf8'),
    expectedKeySha256, sourceId: 'gate-ledger' })
  need(value.ok === true, 'GATE_READ_INVALID')
  return { head: value.selected_head.hash, entries: value.selected_head.position }
}

export function readBrowserKiraHead({ stateDir }) {
  const value = readMemoryLedgerHead({ stateDir })
  need(value.head === null
    ? value.entries === 0 && ['kira-ledger-missing', 'kira-ledger-empty'].includes(value.absence)
    : HEX64.test(value.head) && Number.isSafeInteger(value.entries) && value.entries > 0 && value.absence === null,
  'KIRA_READ_INVALID')
  return value
}

function main() {
  const [kind, pin] = process.argv.slice(2)
  need(process.version === 'v24.11.1' && (kind === 'gate' && process.argv.length === 4 && HEX64.test(pin)
    || kind === 'kira' && process.argv.length === 3), 'READ_USAGE')
  const value = kind === 'gate' ? readBrowserGateHead({ dbPath: '/home/aukora-gate/gate.db',
    publicKeyPath: '/run/aukora-gate/receipt-ed25519.pub', expectedKeySha256: pin })
    : readBrowserKiraHead({ stateDir: '/home/aukora-host/genesis/state/home/kira-memory' })
  console.log(JSON.stringify(value))
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try { main() } catch (error) {
    console.error('REFUSED ' + (/^BROWSER_AURA_[A-Z_]+$/u.test(error.message) ? error.message : 'BROWSER_AURA_READ_REFUSED'))
    process.exitCode = 1
  }
}
