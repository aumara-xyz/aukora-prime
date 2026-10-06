// SPDX-License-Identifier: AGPL-3.0-or-later
// Bind D's source readiness profile to independently protected current public host data.
// This host check supplies no retained-proof verifier, enrollment or success fallback.
import { createHash } from 'node:crypto'
import { SIGNER_EPOCHS_FILE, validateSignerEpochs } from '../src/vendor/signer-epochs.mjs'
import { readOwnerState } from './owner-state.mjs'
import { readProtectedPublicText } from './protected-public-data.mjs'

const FIELDS = Object.freeze(['version', 'kind', 'ready', 'checked_at_ms', 'gate_pubkey_sha256',
  'owner_state_sha256', 'owner_subject', 'owner_root_id', 'owner_epoch', 'registry_sha256',
  'activation_sha256', 'ledger', 'consumed_effects'])
const OWNER_FIELDS = Object.freeze(['owner_subject', 'owner_root_id', 'owner_epoch', 'registry_sha256', 'activation_sha256'])
const EFFECT_FIELDS = Object.freeze(['retained', 'unresolved', 'applying', 'incomplete', 'conflict'])
const BINDINGS = new WeakSet()
const WINDOW_MS = 5000
const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex')
const safeInteger = value => Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0
const hash = value => typeof value === 'string' && value.length === 64 && /^[0-9a-f]{64}$/u.test(value)
const refuse = () => { throw new Error('gate-readiness:unavailable') }

function closed(supplied, fields) {
  if (supplied === null || typeof supplied !== 'object' || Array.isArray(supplied)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(supplied))) refuse()
  for (let prototype = supplied; prototype !== null; prototype = Object.getPrototypeOf(prototype)) {
    const then = Object.getOwnPropertyDescriptor(prototype, 'then')
    if (then && (!Object.hasOwn(then, 'value') || typeof then.value === 'function')) refuse()
  }
  const descriptors = Object.getOwnPropertyDescriptors(supplied), keys = Reflect.ownKeys(descriptors)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string' || !fields.includes(key))) refuse()
  const result = Object.create(null)
  for (const field of fields) {
    const descriptor = descriptors[field]
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) refuse()
    result[field] = descriptor.value
  }
  return result
}

/** Current normalized owner state and latest explicit signer epoch; neither pin comes from D's reply. */
export function readGateReadinessBinding() {
  try {
    const owner_state = readOwnerState()
    const text = readProtectedPublicText(SIGNER_EPOCHS_FILE, 16384)
    const registry = validateSignerEpochs(JSON.parse(text)), latest = registry.epochs.at(-1)
    if (!safeInteger(latest.epoch) || latest.epoch < 1 || !hash(latest.gate_pubkey_sha256)) refuse()
    const binding = Object.freeze({ owner_state, owner_state_sha256: sha256(JSON.stringify(owner_state)),
      gate_pubkey_sha256: latest.gate_pubkey_sha256, signer_epoch: latest.epoch, signer_registry_sha256: sha256(text) })
    BINDINGS.add(binding)
    return binding
  } catch { refuse() }
}

/** Full closed D profile only. A coarse {ok:true}, asynchronous or accessor profile cannot establish readiness. */
export function validateGateReadiness(supplied, binding, { startedAtMs, finishedAtMs } = {}) {
  try {
    if (!BINDINGS.has(binding) || !safeInteger(startedAtMs) || !safeInteger(finishedAtMs)
      || finishedAtMs < startedAtMs || finishedAtMs - startedAtMs > WINDOW_MS) refuse()
    const profile = closed(supplied, FIELDS)
    if (profile.version !== 1 || profile.kind !== 'aukora-boundary-gate-readiness/v1' || profile.ready !== true
      || !safeInteger(profile.checked_at_ms) || profile.checked_at_ms < startedAtMs || profile.checked_at_ms > finishedAtMs
      || profile.gate_pubkey_sha256 !== binding.gate_pubkey_sha256
      || profile.owner_state_sha256 !== binding.owner_state_sha256
      || OWNER_FIELDS.some(field => profile[field] !== binding.owner_state[field])) refuse()
    const ledger = closed(profile.ledger, ['entries', 'head'])
    if (!safeInteger(ledger.entries) || (ledger.entries === 0 ? ledger.head !== 'GENESIS' : !hash(ledger.head))) refuse()
    const effects = closed(profile.consumed_effects, EFFECT_FIELDS)
    if (EFFECT_FIELDS.some(field => !safeInteger(effects[field]))
      || ['unresolved', 'applying', 'incomplete', 'conflict'].some(field => effects[field] !== 0)) refuse()
    return Object.freeze({ ...profile, ledger: Object.freeze(ledger), consumed_effects: Object.freeze(effects) })
  } catch { refuse() }
}

/** Fresh protected owner/pin reads bracket a synchronous host-owned core call; any binding drift refuses. */
export function checkGateReadiness(call) {
  try {
    if (typeof call !== 'function') refuse()
    const startedAtMs = Date.now(), before = readGateReadinessBinding()
    const profile = call()
    const after = readGateReadinessBinding(), finishedAtMs = Date.now()
    if (JSON.stringify(before) !== JSON.stringify(after)) refuse()
    return validateGateReadiness(profile, after, { startedAtMs, finishedAtMs })
  } catch { refuse() }
}
