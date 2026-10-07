// SPDX-License-Identifier: AGPL-3.0-or-later
// The lab flow behind aukora_id_emit: one relay-post-shaped operation through the
// vendored AUKORA ID stack, in-process: identity chain -> policy commitments ->
// certificates -> checkpoint -> emission request -> owner-signed approval (lab root)
// -> consumed BEFORE dispatch -> fixed LOCAL sink. Disposable lab keys per state dir;
// never real key material; the caller's text is never dispatched (the variable-payload
// adapter profile is unfrozen). No platform gate here — the plugin wrapper gates it.
import { randomBytes } from 'node:crypto'
import { mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ID = new URL('../../../vendor/aukora-id/src/', import.meta.url).pathname

export async function runLabEmit(stateDir) {
  const bytes = await import(`${ID}/bytes/index.mjs`)
  const keys = await import(`${ID}/keys/index.mjs`)
  const apertureMod = await import(`${ID}/aperture/index.mjs`)
  const profile = await import(`${ID}/aperture/local-profile.mjs`)
  const { openJournal } = await import(`${ID}/journal/index.mjs`)
  const { verifyEvent } = await import(`${ID}/verifier/index.mjs`)
  const { createFixedLocalSink, fixedPayloadBytes } = await import(`${ID}/local-sink/index.mjs`)
  const registry = JSON.parse(readFileSync(`${ID}/../spec/layer0-v1/registry.json`, 'utf8'))

  const freshId = () => randomBytes(32).toString('hex')
  const json = v => Buffer.from(JSON.stringify(v))
  const disposable = () => {
    const secret = keys.generateDisposableKey()
    return { secret, descriptor: JSON.parse(Buffer.from(keys.descriptorBytes(secret)).toString()),
      id: bytes.keyId(keys.descriptorBytes(secret)).toString('hex') }
  }
  const root = disposable(), appendKey = disposable(), human = disposable(), apertureKey = disposable()
  const subject = freshId(), chain = freshId(), now = Math.floor(Date.now() / 1000)
  const events = []
  const policies = Object.values(registry.policy_documents)
    .map(({ digest, document }) => ({ digest, document: profile.trustedBytes(document).toString('base64url') }))
    .sort((a, b) => a.digest.localeCompare(b.digest))
  const journalDir = join(stateDir, 'id-lab')
  mkdirSync(journalDir, { recursive: true, mode: 0o700 })
  let observer = null
  const source = openJournal({ directory: journalDir,
    bootstrapBytes: profile.trustedBytes({ subject_id: subject, chain_id: chain, now }) })
  try {
    let genesisId = null, anchor = null
    const create = (kind, body, role, signer, cert, expires = null, refs = null, version = 'v1', position = null) => {
      refs = refs === null ? (cert ? [cert] : []) : refs
      const record = { schema: 'aukora.record.v1', profile: profile.CLASSICAL_PROFILE, domain: registry.record_domains[kind],
        kind, subject_id: subject, chain_id: chain, epoch: '0',
        sequence: position ? String(BigInt(position.sequence) + 1n) : String(events.length),
        previous_event: position ? position.head : events.length ? bytes.parseEvent(events.at(-1)).event.id : null,
        issued_at: now, not_before: now, expires, authority_refs: [...new Set(refs)].sort(),
        outer_context: { pubkey: (kind === 'identity' ? root : appendKey).descriptor.bip340_public_key,
          created_at: now, kind: 8790, tags: [['aukora', 'l0-v1']] },
        signer_plan: [{ role, key_id: signer.id, key_source: kind === 'identity' ? 'genesis_root' : 'certificate',
          certificate_ref: kind === 'identity' ? null : cert, algorithms: ['bip340'] }], consent_context: null, body }
      if (version === 'v2') {
        record.schema = 'aukora.record.v2'
        record.domain = `aukora.${kind.replaceAll('_', '-')}.v2`
        record.outer_context.tags = [['aukora', 'l0-v2'], ['prev', record.previous_event], ['seq', record.sequence]]
      }
      currentKind = kind
      try {
      return keys.constructEvent(keys.signRecord(profile.trustedBytes(record), profile.trustedBytes([
        { key_id: signer.id, secret_key: signer.secret.toString('base64url') }])), (kind === 'identity' ? root : appendKey).secret)
      } catch (e) { throw new Error(`create(${kind}) threw: ${e.code} ${e.message}`) }
    }
    let currentKind = '?'
    const appendChecked = eventBytes => {
      const { event, record } = bytes.parseEvent(eventBytes)
      if (!genesisId) {
        genesisId = event.id
        anchor = { expected_subject_id: subject, expected_chain_id: chain,
          expected_genesis: genesisId, expected_root_key_id: root.id }
      }
      const context = json({ schema: 'aukora.verify-context.v1', purpose: 'historical_integrity',
        ...anchor, expected_profile: profile.CLASSICAL_PROFILE, expected_kind: record.kind,
        expected_signers: record.signer_plan.map(({ role, key_id }) => ({ role, key_id })),
        policy_pins: policies.map(p => p.digest), control: null, additional_anchors: [], additional_control: [] })
      const evidence = json({ schema: 'aukora.evidence.v1', events: [...events]
        .sort((a, b) => bytes.parseEvent(a).event.id.localeCompare(bytes.parseEvent(b).event.id))
        .map(e => e.toString('base64url')), policies, control_state: null, artifacts: [] })
      let result
      try { result = verifyEvent(eventBytes, context, evidence) }
      catch (e) { throw new Error(`lab chain THREW at ${record.kind}: ${e.code} ${e.message}`) }
      if (result.verdict !== 'valid') throw new Error(`lab chain build refused: ${record.kind}: ${JSON.stringify(result)}`)
      source.withWriterLock(writer => writer.appendVerified(eventBytes)); events.push(eventBytes); return event.id
    }

    appendChecked(create('identity', { root_key: root.descriptor, initial_append_key: appendKey.descriptor,
      ...Object.fromEntries(['succession', 'recovery', 'algorithm', 'persona'].map(name => [`${name}_policy_digest`, registry.policy_documents[name].digest])) },
      'root', root, null))
    const policyRefs = []
    for (const name of ['algorithm', 'scope', 'time', 'control', 'custody']) policyRefs.push(appendChecked(create('policy_commitment', {
      policy_type: name, policy_version: 1, policy_digest: registry.policy_documents[name].digest,
      effective_sequence: String(events.length) }, 'root', root, genesisId)))
    const ceiling = [{ unit: 'bytes', maximum: '18', currency: null }, { unit: 'requests', maximum: '1', currency: null }]
    const bind = (key, role, restriction) => appendChecked(create('key_binding', {
      key_id: key.id, descriptor: key.descriptor, role, parent_key_id: root.id, parent_certificate_ref: genesisId,
      valid_from_epoch: '0', valid_through_epoch: '0',
      restriction: { subject_id: subject, chain_id: chain, ...restriction },
      custody_policy_digest: registry.policy_documents.custody.digest, binding_purpose: 'enroll', device_assertion_policy_digest: null },
      'root', root, genesisId, now + 1000, [genesisId, ...policyRefs]))
    const humanCertificate = bind(human, 'human_approval', { record_kinds: ['emission_request'], emission_scopes: [profile.LOCAL_SCOPE], budget_ceiling: ceiling })
    const apertureCertificate = bind(apertureKey, 'aperture_authority', { adapter_profiles: [profile.LOCAL_SCOPE.adapter_profile], emission_scopes: [profile.LOCAL_SCOPE], budget_ceiling: ceiling })
    observer = disposable()
    const { STATEMENT_PROFILE } = await import(`${ID}/aperture/observation.mjs`)
    const observerCertificate = bind(observer, 'aperture_observer', { adapter_profiles: [profile.LOCAL_SCOPE.adapter_profile], statement_profiles: [STATEMENT_PROFILE] })
    const basis = source.withWriterLock(writer => ({ snapshot: writer.snapshot(), heads: writer.projections() }))
    const checkpointId = appendChecked(create('coherence_checkpoint', {
      basis_event: basis.snapshot.head, basis_sequence: basis.snapshot.sequence, basis_epoch: basis.snapshot.epoch,
      previous_checkpoint: null, heads: basis.heads, control_state_digest: basis.snapshot.control_state_digest,
      evidence_complete: true, missing_evidence: [] }, 'journal_append', appendKey, genesisId))

    openSync(join(journalDir, 'observer-notices.log'), 'a') // retained lab notice log
    // The v2 host config carries the LAB secrets in-process (this process is the
    // trusted host in the lab); they are zeroed in the finally below.
    const configBytes = profile.trustedBytes({ schema: 'aukora.local-host.v2', mode: 'LOCAL_TEST', directory: journalDir, anchor,
      request_signers: [{ role: 'human_approval', key_id: human.id }],
      append: { certificate_ref: genesisId, secret_key: appendKey.secret.toString('base64url') },
      aperture: { certificate_ref: apertureCertificate, secret_key: apertureKey.secret.toString('base64url') } })
    const observerNoticeFd = openSync(join(journalDir, 'observer-channel.log'), 'a')
    const { createLocalHost } = await import(`${ID}/host/index.mjs`)
    const noticeFd = openSync(join(journalDir, 'observer-notices.log'), 'a')
    const host = createLocalHost(configBytes, { observerFd: noticeFd })

    const fixedPayload = fixedPayloadBytes()
    const salt = randomBytes(32)
    const commitment = bytes.hashDomain('aukora.payload.v1', Buffer.concat([salt, fixedPayload])).toString('hex')
    const operation = freshId()
    const requestBytes = create('emission_request', {
      operation_id: operation, nonce: freshId(), requester_subject: anchor.expected_subject_id,
      requester_key_id: human.id, agent_card_ref: null, scope: profile.LOCAL_SCOPE, payload_commitment: commitment,
      budget: profile.LOCAL_BUDGET, expected_control_checkpoint: checkpointId,
    }, 'human_approval', human, humanCertificate, now + 100, [humanCertificate, checkpointId])
    const request = bytes.parseEvent(requestBytes)
    const humanSigners = profile.trustedBytes([{ role: 'human_approval', key_id: human.id }])
    host.appendVerified(requestBytes, humanSigners)
    const position = host.snapshot()
    const approvalBytes = create('owner_approval', {
      operation_id: request.record.body.operation_id, nonce: request.record.body.nonce,
      request_ref: request.event.id, requester_key_id: request.record.body.requester_key_id,
      scope: request.record.body.scope,
      payload_sha256: bytes.sha256(fixedPayload).toString('hex'),
      payload_commitment: request.record.body.payload_commitment, journal_head: position.head,
    }, 'root', root, genesisId, now + 100, [genesisId, request.event.id], 'v2', position)
    const rootSigners = profile.trustedBytes([{ role: 'root', key_id: anchor.expected_root_key_id }])
    const admitted = host.admitCurrent(approvalBytes, rootSigners)
    if (!admitted.appended) throw new Error(`lab approval refused: ${JSON.stringify(admitted)}`)
    const payloadEvidenceBytes = profile.trustedBytes({ operation_id: operation,
      salt: salt.toString('base64url'), payload: fixedPayload.toString('base64url') })
    const result = host.submitLocal(requestBytes, payloadEvidenceBytes)
    // The replay arm: the SAME operation submitted again must refuse REPLAY —
    // the consumed-before-dispatch record is the thing being proven.
    const replayed = host.submitLocal(requestBytes, payloadEvidenceBytes)
    salt.fill(0); fixedPayload.fill(0)
    const inspected = host.inspect()
    host.close?.()
    return { state: result.state, reason_codes: result.reason_codes, intent_ref: result.intent_ref,
      receipt_ref: result.receipt_ref, counters: inspected.counters, replay_arm: replayed.reason_codes ?? replayed.reasons,
      completion_evidence: inspected.completion_evidence,
      note: 'LAB SEAM: owner-signed approval consumed before dispatch to the fixed LOCAL sink; caller text was NOT dispatched (variable-payload adapter profile unfrozen)' }
  } finally {
    source.close()
    for (const key of [root, appendKey, human, apertureKey, observer].filter(Boolean)) key.secret.fill(0)
  }
}
