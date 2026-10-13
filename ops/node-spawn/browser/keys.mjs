// Generate fresh node-local gate keys and their public signer epoch.
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import { loadOwnerSecret } from '/opt/aukora-boundary-gate/src/secrets.mjs'
import { loadOrCreateKey } from '/opt/aukora-boundary-gate/src/ledger.mjs'

const home = '/home/aukora-gate'
process.umask(0o077)
for (const name of ['owner-secret.json', 'receipt-ed25519.pem', 'signer-epochs.json']) {
  if (fs.existsSync(`${home}/${name}`)) throw Error('BROWSER_GATE_KEYS_EXIST')
}
loadOwnerSecret(home)
const key = loadOrCreateKey(home)
const digest = createHash('sha256').update(key.pub.export({ type: 'spki', format: 'der' })).digest('hex')
fs.writeFileSync(`${home}/signer-epochs.json`, JSON.stringify({ version: 1,
  kind: 'aukora-signer-epochs/v1', epochs: [{ epoch: 1, gate_pubkey_sha256: digest }] }) + '\n',
{ mode: 0o600, flag: 'wx' })
