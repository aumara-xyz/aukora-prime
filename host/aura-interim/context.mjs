// INTERIM trusted collector context (root-owned, 0644). Owner/controller keys are INTERIM and must be
// replaced by Peter's Touch ID owner root (G) when native custody lands.
import { readFileSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
const REL = process.env.AUKORA_RELEASE_DIR
if (!/^\/opt\/aukora-genesis\/release-[0-9a-f]{7}$/u.test(REL ?? '')) throw new Error('release-dir-invalid')
const records = await import(`${REL}/aukora-nostr/lib/records.mjs`)
const { createNostrCollectorCodec } = await import(`${REL}/scripts/aura/collect-gate.mjs?context`)
const { gatePublicKeySha256 } = await import(`${REL}/scripts/aura/gate-snapshot.mjs`)
const pub = JSON.parse(readFileSync('/etc/aukora-aura/public.json', 'utf8'))
const publicKeyPem = readFileSync('/etc/aukora-aura/gate-receipt-ed25519.pub', 'utf8')
export const INTERIM_OWNER_PUBKEY_HEX = pub.ownerPubkeyHex
export async function collectorContext() {
  const codec = await createNostrCollectorCodec({ records,
    authorSecretKeyHex: readFileSync('/etc/aukora-aura/author-INTERIM.key', 'utf8').trim(),
    binding: pub.binding, controllerKeyHex: pub.controllerKeyHex, ownerSubject: pub.ownerSubject,
    authorPubkeyHex: pub.authorPubkeyHex, ownerPubkeyHex: pub.ownerPubkeyHex })
  return { storeDir: '/var/lib/aukora-aura/store', codec, pythonExecutable: '/usr/bin/python3',
    snapshotOptions: { dbPath: process.env.AURA_SNAPSHOT ?? '/var/lib/aukora-aura/snapshot/gate.db',
      sourceId: 'aukora-gate-pilot', publicKeyPem, expectedKeySha256: readFileSync('/etc/aukora-aura/gate-key.sha256', 'utf8').trim() },
    anchors: JSON.parse(readFileSync('/etc/aukora-aura/anchors.json', 'utf8')) }
}
