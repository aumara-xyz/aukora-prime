// INTERIM Aura collector keys (Grok install 2026-10-04). Run as root ON the pilot only.
// Replace with Peter's Touch ID owner root (G) when native custody lands. No key leaves the pilot.
import { generateKeyPairSync, sign, createHash, createPublicKey } from 'node:crypto'
import { writeFileSync, existsSync } from 'node:fs'
const REL = process.env.AUKORA_RELEASE_DIR
const ev = await import(`${REL}/aukora-nostr/lib/event.mjs`)
const identity = await import(`${REL}/aukora-nostr/lib/identity.mjs`)
const D = '/etc/aukora-aura'
if (existsSync(`${D}/author-INTERIM.key`)) { console.log('keys exist, not regenerating'); process.exit(0) }
const authorSecretKeyHex = ev.randomSecretKey(), ownerSecretKeyHex = ev.randomSecretKey()
const authorPubkeyHex = ev.publicKeyOf(authorSecretKeyHex), ownerPubkeyHex = ev.publicKeyOf(ownerSecretKeyHex)
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const controllerKeyHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex')
const ownerSubject = `aukora:1:${createHash('sha256').update(`aukora-INTERIM-owner:${ownerPubkeyHex}`).digest('hex')}`
const statement = { subject: ownerSubject, npub: identity.npubEncode(authorPubkeyHex), nostrPubkeyHex: authorPubkeyHex,
  handle: 'aura-collector-INTERIM', createdAt: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), safetyVersion: 2 }
const binding = { domain: identity.NOSTR_BINDING_DOMAIN, statement,
  signature: sign(null, identity.bindingPreimage(statement), privateKey).toString('hex'),
  approvalKeyDid: `did:key:${controllerKeyHex}`, label: 'INTERIM' }
const w = (f, s, mode) => writeFileSync(`${D}/${f}`, s, { mode, flag: 'wx' })
w('author-INTERIM.key', authorSecretKeyHex + '\n', 0o640)        // group aukora-aura (signs records)
w('owner-INTERIM.key', ownerSecretKeyHex + '\n', 0o600)          // root only, never used by the collector
w('controller-INTERIM.pem', privateKey.export({ type: 'pkcs8', format: 'pem' }), 0o600) // root only
w('public.json', JSON.stringify({ label: 'INTERIM', note: 'Replace with the Touch ID owner root (G) when native custody lands',
  ownerSubject, authorPubkeyHex, ownerPubkeyHex, controllerKeyHex, binding }, null, 2) + '\n', 0o644)
console.log('INTERIM keys generated; owner', ownerSubject.slice(0, 24) + '…')
