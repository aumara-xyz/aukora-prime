// SPDX-License-Identifier: AGPL-3.0-or-later
// Bind D's source readiness profile to independently protected current public host data.
// This host check supplies no retained-proof verifier, enrollment or success fallback.
import { createHash, createPublicKey } from 'node:crypto'
import { SIGNER_EPOCHS_FILE, validateSignerEpochs } from '../src/vendor/signer-epochs.mjs'
import { readOwnerState } from './owner-state.mjs'
import { readProtectedPublicText } from './protected-public-data.mjs'

const FIELDS = Object.freeze(['version', 'kind', 'ready', 'checked_at_ms', 'gate_pubkey_sha256',
  'owner_state_sha256', 'owner_subject', 'owner_root_id', 'owner_epoch', 'registry_sha256',
  'activation_sha256', 'ledger', 'consumed_effects'])
const OWNER_FIELDS = Object.freeze(['owner_subject', 'owner_root_id', 'owner_epoch', 'registry_sha256', 'activation_sha256'])
const EFFECT_FIELDS = Object.freeze(['retained', 'unresolved', 'applying', 'incomplete', 'conflict'])
const MANIFEST_FILE = '/etc/aukora-boundary-gate/gate-package-manifest.json'
const CONFIGURATION_FILE = '/etc/aukora-boundary-gate/aura-context.json'
const CONFIGURATION_FIELDS = Object.freeze(['version', 'kind', 'owner_subject', 'store_dir', 'source', 'nostr', 'anchors', 'python_executable'])
const SOURCE_FIELDS = Object.freeze(['db_path', 'source_id', 'public_key_pem', 'key_sha256', 'max_rows', 'max_bytes', 'max_record_bytes'])
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

function ownData(supplied, field) {
  if (supplied === null || typeof supplied !== 'object' || Array.isArray(supplied)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(supplied))) refuse()
  const descriptor = Object.getOwnPropertyDescriptor(supplied, field)
  if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) refuse()
  return descriptor.value
}

// Secondary host binding only: mandatory bootstrap strict parsing and complete BootIdentity
// verification precede Node dispatch. This bounded record read cannot replace those checks.
function readReadinessCarrier(ownerState, gatePin) {
  const manifestText = readProtectedPublicText(MANIFEST_FILE, 2 * 1024 * 1024)
  const manifest = closed(JSON.parse(manifestText), ['version', 'kind', 'package', 'entry', 'files', 'external_files', 'profiles'])
  if (manifest.version !== 2 || manifest.kind !== 'aukora-gate-package/v2'
    || manifest.package !== '/opt/aukora-boundary-gate' || manifest.entry !== 'bin/gate.mjs') refuse()
  const boot = closed(ownData(manifest.profiles, 'boot'), ['kind', 'files', 'digest'])
  if (boot.kind !== 'aukora-prime-boot-identity/v1' || typeof boot.digest !== 'string'
    || !/^sha256:[0-9a-f]{64}$/u.test(boot.digest)) refuse()
  const reference = closed(ownData(boot.files, CONFIGURATION_FILE), ['source', 'source_sha256', 'sha256'])
  if (reference.source !== 'operator-data:aura-context/v1' || !hash(reference.source_sha256)
    || !hash(reference.sha256) || reference.source_sha256 !== reference.sha256) refuse()
  const configurationText = readProtectedPublicText(CONFIGURATION_FILE, 1024 * 1024)
  // The expected bytes come from the protected reviewed manifest, never from this carrier or D's reply.
  if (sha256(configurationText) !== reference.sha256) refuse()
  const configuration = closed(JSON.parse(configurationText), CONFIGURATION_FIELDS)
  const source = closed(configuration.source, SOURCE_FIELDS)
  if (configuration.version !== 1 || configuration.kind !== 'aukora-aura-context/v1'
    || configuration.owner_subject !== ownerState.owner_subject || source.key_sha256 !== gatePin
    || typeof source.public_key_pem !== 'string' || source.public_key_pem.length > 1024
    || !/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\r?\n?$/u.test(source.public_key_pem)) refuse()
  const publicKey = createPublicKey({ key: source.public_key_pem, type: 'spki', format: 'pem' })
  if (publicKey.asymmetricKeyType !== 'ed25519'
    || sha256(publicKey.export({ type: 'spki', format: 'der' })) !== gatePin) refuse()
  return { readiness_manifest_sha256: sha256(manifestText), readiness_configuration_sha256: sha256(configurationText) }
}

/** Current owner/latest signer pins and independently manifest-pinned public carrier; no pin comes from D's reply. */
export function readGateReadinessBinding() {
  try {
    const owner_state = readOwnerState()
    const text = readProtectedPublicText(SIGNER_EPOCHS_FILE, 16384)
    const registry = validateSignerEpochs(JSON.parse(text)), latest = registry.epochs.at(-1)
    if (!safeInteger(latest.epoch) || latest.epoch < 1 || !hash(latest.gate_pubkey_sha256)) refuse()
    const carrier = readReadinessCarrier(owner_state, latest.gate_pubkey_sha256)
    const binding = Object.freeze({ owner_state, owner_state_sha256: sha256(JSON.stringify(owner_state)),
      gate_pubkey_sha256: latest.gate_pubkey_sha256, signer_epoch: latest.epoch, signer_registry_sha256: sha256(text), ...carrier })
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

/** Fresh protected owner/pin/manifest/carrier reads bracket a synchronous core call; any binding drift refuses. */
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
