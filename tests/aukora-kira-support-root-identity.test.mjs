/**
 * Kira's installed identity is found under AUKORA_SUPPORT_ROOT, the root the launcher actually forwards
 * (2026-10-04, Nebius pilot: with only AUKORA_STATE consulted, Kira refused field-missing and never mounted).
 * Fails if the support root is ignored for an installed lookup, or read for a complete explicit composition.
 */
import assert from 'node:assert/strict'
import { resolveMemoryIdentity, UNLINKED_MEMORY_SUBJECT } from '../plugins/aukora-kira/lib/memory-identity.mjs'

const SUBJECT = `aukora:1:${'ef'.repeat(32)}`
const overlay = `- id: aukora-kira\n  config:\n    memoryOwner:\n      stateDir: /srv/genesis/state/home/kira-memory\n      subject: ${SUBJECT}\n`
let readFrom
const readText = path => { readFrom = path; return overlay }
const env = { AUKORA_SUPPORT_ROOT: '/srv/genesis/support' }

const got = resolveMemoryIdentity({ platform: 'linux', env, subject: UNLINKED_MEMORY_SUBJECT, stateDir: '/srv/genesis/state/home/kira-memory',
  installed: true, allowLegacyPlaceholder: true, readText })
assert.equal(got.subject, SUBJECT, 'installed lookup resolves the real subject from the support root')
assert.equal(readFrom, '/srv/genesis/support/kira-deployment-overlay.patch.yml', 'the overlay is read from AUKORA_SUPPORT_ROOT')

readFrom = undefined
const explicit = resolveMemoryIdentity({ platform: 'linux', env, subject: SUBJECT, stateDir: '/x/kira-memory', installed: false,
  readText: () => { throw new Error('must not read') } })
assert.equal(explicit.subject, SUBJECT, 'explicit composition resolves without the support root')

readFrom = undefined
resolveMemoryIdentity({ platform: 'linux', env: { ...env, AUKORA_STATE: '/srv/genesis/state' }, subject: UNLINKED_MEMORY_SUBJECT,
  stateDir: '/srv/genesis/state/home/kira-memory', installed: true, allowLegacyPlaceholder: true, readText })
assert.equal(readFrom, '/srv/genesis/state/kira-deployment-overlay.patch.yml', 'AUKORA_STATE still wins when set')
console.log('aukora-kira-support-root-identity: 5/5 PASS')
