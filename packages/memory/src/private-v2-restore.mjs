// SPDX-License-Identifier: AGPL-3.0-or-later
// Qualified snapshot/control preparation for the explicit private-v2 composition.
import { canonicalJSON } from '../genesis/plugins/aukora-kira/lib/record.mjs'
import { types } from 'node:util'
import { requireMemory, sha256, MAX_BYTES } from './codecs.mjs'
import { inspectSnapshot } from './snapshot.mjs'
import { memoryTarget, memoryStateVersion } from './authorization.mjs'
import { assertPrivateHost, assertPrivateProfile, detachPrivateData, decodeControlV3, assertForwardControlV3,
  assertLineageCompletionsV2 } from './private-v2-control.mjs'
import { assertRetentionV2, isPrivateV2FileRetentionReader } from './private-v2-retention.mjs'
import { isPrivateV2Participant } from './private-v2-participant.mjs'
import { isPrivateV2RecordAccess } from './private-v2-records.mjs'

export const PRIVATE_V2_COLD_SCHEMA = 'aukora-prime-memory-cold-bundle/v3'
const KEYS = ['schema', 'owner_id', 'owner_subject', 'snapshot', 'published_lineage', 'pending',
  'prepared_candidates', 'manifest_sha256']
const bodyOf = bundle => Object.fromEntries(KEYS.filter(key => key !== 'manifest_sha256').map(key => [key, bundle[key]]))
const same = (left, right) => canonicalJSON(left) === canonicalJSON(right)
const digest = body => sha256(Buffer.from('aukora-prime.memory-cold-bundle.v3\0' + canonicalJSON(body)))
const factories = new WeakSet()
const check = (condition, suffix) => requireMemory(condition, 'memory:private-v2-restore-' + suffix)

/**
 * Validate every edge, including intermediate journal/phase transitions. This only
 * checks the supplied exact bytes; protected reader custody establishes publication.
 */
function lineage(input, host, {profile, contracts}) {
  check(Array.isArray(input) && input.length > 0 && input.length <= 10000, 'lineage-required')
  const checked = input.map(envelope => assertRetentionV2(envelope, host, {profile, contracts, pastEpoch: true}))
  const hashes = new Set()
  for (const envelope of checked) {
    check(!hashes.has(envelope.checkpoint_sha256), 'lineage-cycle')
    hashes.add(envelope.checkpoint_sha256)
  }
  for (let index = 0; index < checked.length - 1; index++) {
    const next = checked[index], previous = checked[index + 1]
    check(next.previous_checkpoint_sha256 === previous.checkpoint_sha256 && next.sequence === previous.sequence + 1,
      'lineage-predecessor-mismatch')
    check(previous.authorization_epoch <= next.authorization_epoch, 'lineage-epoch-regression')
    assertForwardControlV3(previous.control_state, next.control_state,
      {...host, authorization_epoch: next.authorization_epoch}, {profile, contracts})
  }
  const oldest = checked[checked.length - 1]
  check(oldest.sequence === 1 && oldest.previous_checkpoint_sha256 === null, 'lineage-baseline-missing')
  check(checked[0].authorization_epoch === host.authorization_epoch, 'current-epoch-mismatch')
  assertLineageCompletionsV2(checked, host, {profile, contracts})
  return checked
}

/**
 * Offline byte/correlation verification. A copied generation or this result cannot
 * authenticate a published pointer, select a restore anchor, or authorize an effect.
 */
export function inspectPrivateV2ColdBundle(input, rawHost, {profile: rawProfile, contracts} = {}) {
  const host = assertPrivateHost(rawHost), profile = assertPrivateProfile(rawProfile), bundle = detachPrivateData(input)
  check(bundle && typeof bundle === 'object' && !Array.isArray(bundle) && Object.keys(bundle).length === KEYS.length
    && KEYS.every(key => Object.hasOwn(bundle, key)), 'cold-fields-invalid')
  check(bundle.schema === PRIVATE_V2_COLD_SCHEMA && bundle.owner_id === host.owner_id
    && bundle.owner_subject === host.owner_subject, 'cold-owner-schema-mismatch')
  check(typeof bundle.manifest_sha256 === 'string' && /^[0-9a-f]{64}$/.test(bundle.manifest_sha256)
    && digest(bodyOf(bundle)) === bundle.manifest_sha256, 'cold-manifest-mismatch')
  check(Buffer.byteLength(canonicalJSON(bundle)) <= MAX_BYTES, 'cold-bytes-limit')
  // Successful export only describes the complete published state with no pending.
  // Diagnostic pending/candidate material is never accepted as a restore bundle.
  check(bundle.pending === null && Array.isArray(bundle.prepared_candidates) && bundle.prepared_candidates.length === 0,
    'cold-pending-unavailable')
  const published = lineage(bundle.published_lineage, host, {profile, contracts})
  const retained = decodeControlV3(published[0].control_state, host, {profile, contracts})
  const snapshot = inspectSnapshot(bundle.snapshot, host.owner_subject, {expectedHeads: retained.heads})
  check(same(bundle.snapshot.heads, retained.heads), 'cold-heads-mismatch')
  check(snapshot.quarantine.length === 0, 'cold-quarantine-forbidden')
  return Object.freeze({bundle, published_lineage: published, control: retained,
    structurally_valid: true, publication_verified: false, grants_authority: false})
}

export const isPrivateV2Restore = value => Boolean(value && factories.has(value))

/** No caller-selected anchor or record-writing callback is accepted. */
export function createPrivateV2Restore(input = {}) {
  check(input && typeof input === 'object' && !Array.isArray(input) && !types.isProxy(input)
    && [Object.prototype, null].includes(Object.getPrototypeOf(input)), 'configuration-invalid')
  const descriptors = Object.getOwnPropertyDescriptors(input), keys = ['participant', 'reader', 'profile', 'contracts', 'records']
  check(Reflect.ownKeys(descriptors).length === keys.length && keys.every(key => descriptors[key]
    && Object.hasOwn(descriptors[key], 'value') && descriptors[key].enumerable), 'configuration-invalid')
  const {participant, reader, profile: rawProfile, contracts, records} = Object.fromEntries(keys.map(key => [key, descriptors[key].value]))
  check(isPrivateV2Participant(participant) && isPrivateV2FileRetentionReader(reader)
    && isPrivateV2RecordAccess(records), 'owned-source-capabilities-required')
  const profile = detachPrivateData(assertPrivateProfile(rawProfile))
  check(participant.coordinator?.reader === reader, 'reader-mismatch')
  check(same(participant.profile, profile), 'profile-mismatch')
  check(contracts && typeof contracts === 'object' && !types.isProxy(contracts), 'contracts-required')
  const contractDescriptors = Object.getOwnPropertyDescriptors(contracts)
  check(['validateContract', 'operationDigest', 'canonicalJson'].every(key => contractDescriptors[key]
    && Object.hasOwn(contractDescriptors[key], 'value') && typeof contractDescriptors[key].value === 'function'), 'contracts-required')

  async function verifiedBundle(host, input, current, published) {
    const checked = inspectPrivateV2ColdBundle(input, host, {profile, contracts})
    check(same(checked.published_lineage, published) && same(checked.published_lineage[0], current),
      'cold-protected-lineage-mismatch')
    return checked
  }

  async function exportColdBundle(rawHost, options = {}) {
    const host = assertPrivateHost(rawHost)
    options = detachPrivateData(options)
    check(options && typeof options === 'object' && !Array.isArray(options)
      && Object.keys(options).every(key => key === 'full') && (options.full === undefined || typeof options.full === 'boolean'),
    'export-options-invalid')
    return participant.withVerifiedControl(host, async (client, actual, current) => {
      const published = await reader.readPublishedLineage(host, {checkpoint_sha256: null})
      check(same(published[0], current), 'export-current-changed')
      const snapshot = await records.exportSnapshot(client, host, {full: options.full !== false})
      const retained = decodeControlV3(actual, host, {profile, contracts})
      check(same(snapshot.heads, retained.heads), 'export-heads-changed')
      await records.preflight(client, host, snapshot, retained)
      const body = {schema: PRIVATE_V2_COLD_SCHEMA, owner_id: host.owner_id, owner_subject: host.owner_subject,
        snapshot, published_lineage: published, pending: null, prepared_candidates: []}
      const bundle = {...body, manifest_sha256: digest(body)}
      inspectPrivateV2ColdBundle(bundle, host, {profile, contracts})
      return bundle
    })
  }

  async function verifyColdBundle(rawHost, input) {
    const host = assertPrivateHost(rawHost), frozen = detachPrivateData(input)
    return participant.withVerifiedRestoreControl(host, async (_client, _actual, current, published) => {
      const checked = await verifiedBundle(host, frozen, current, published)
      return Object.freeze({manifest_sha256: checked.bundle.manifest_sha256,
        checkpoint_sha256: current.checkpoint_sha256, control_sha256: current.control_state.control_sha256,
        authorization_epoch: current.authorization_epoch, structurally_valid: true,
        publication_verified: true, grants_authority: false})
    })
  }

  async function prepareRestoreBinding(rawHost, input) {
    const host = assertPrivateHost(rawHost), frozen = detachPrivateData(input)
    return participant.withVerifiedRestoreControl(host, async (client, actual, current, published) => {
      const checked = await verifiedBundle(host, frozen, current, published)
      const retained = decodeControlV3(current.control_state, host, {profile, contracts})
      await records.preflight(client, host, checked.bundle.snapshot, retained)
      const local = decodeControlV3(actual, host, {profile, contracts})
      return {target_identity: memoryTarget(host.owner_subject), state_version: memoryStateVersion(local.heads),
        canonical_parameters: {manifest_sha256: checked.bundle.snapshot.manifest_sha256, mode: 'prime-restore',
          heads: checked.bundle.snapshot.heads, retained_heads: retained.heads,
          control_anchor_sha256: current.control_state.control_sha256,
          retention_checkpoint_sha256: current.checkpoint_sha256, retention_epoch: current.authorization_epoch}}
    })
  }

  async function restoreSnapshot() {
    // C's real retained restore reservation/dispatch/effect-receipt join is still v1.
    // A physical restore helper or lineage digest supplies no replacement permission.
    check(false, 'authority-join-unavailable')
  }
  const adapter = Object.freeze({exportColdBundle, verifyColdBundle, prepareRestoreBinding, restoreSnapshot})
  factories.add(adapter)
  return adapter
}
