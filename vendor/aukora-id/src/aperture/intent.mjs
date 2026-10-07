import { randomBytes } from 'node:crypto';
import { hashDomain } from '../bytes/index.mjs';
import { trustedBytes, LOCAL_ADAPTER, refuse } from './local-profile.mjs';

// This assembler grants no authority and has no signing/storage handles. Call it
// only after the separate verifier + LOCAL effect policy succeeds under the lock.
export function prepareIntent({ request, requestRef, snapshot, aperture, append, policyRefs, approval = null }) {
  const body = request.body;
  const signer = {
    role: 'aperture_authority', key_id: aperture.key_id,
    key_source: 'certificate', certificate_ref: aperture.certificate_ref,
    algorithms: ['bip340'],
  };
  const authorityRef = body.agent_card_ref ?? request.signer_plan.find(
    (entry) => entry.role === 'human_approval' && entry.key_id === body.requester_key_id,
  )?.certificate_ref;
  if (!authorityRef) refuse('WRONG_AUTHORITY');
  if (snapshot.now_lower !== snapshot.now_upper) refuse('TIME_UNCERTAINTY');
  if (BigInt(snapshot.sequence) >= 18446744073709551615n) refuse('LIMIT_EXCEEDED');
  if (approval && (approval.event.id !== snapshot.head || approval.record.kind !== 'owner_approval')) refuse('INCONSISTENT_HEAD');
  const reservationId = randomBytes(32).toString('hex');
  const descriptor = {
    subject_id: request.subject_id, chain_id: request.chain_id, epoch: snapshot.epoch,
    operation_id: body.operation_id, nonce: body.nonce, reservation_id: reservationId,
    request_ref: requestRef, actor_key_id: aperture.key_id, authority_ref: authorityRef,
    scope: body.scope, payload_commitment: body.payload_commitment, budget: body.budget,
    control_checkpoint_ref: body.expected_control_checkpoint,
    not_before: snapshot.now_lower, expires: approval ? Math.min(request.expires, approval.record.expires) : request.expires,
  };
  const commitment = Buffer.from(hashDomain('aukora.reservation.v1', trustedBytes(descriptor))).toString('hex');
  const record = {
    schema: approval ? 'aukora.record.v2' : 'aukora.record.v1', profile: request.profile, domain: approval ? 'aukora.intent.v2' : 'aukora.intent.v1', kind: 'intent',
    subject_id: request.subject_id, chain_id: request.chain_id, epoch: snapshot.epoch,
    sequence: (BigInt(snapshot.sequence) + 1n).toString(), previous_event: snapshot.head,
    issued_at: snapshot.now_lower, not_before: descriptor.not_before, expires: descriptor.expires,
    authority_refs: [...new Set([...request.authority_refs, ...policyRefs, requestRef,
      authorityRef, aperture.certificate_ref, append.certificate_ref, ...(approval ? [approval.event.id] : [])])].sort(),
    outer_context: { pubkey: append.public_key, created_at: snapshot.now_lower, kind: 8790,
      tags: approval ? [['aukora','l0-v2'],['prev',snapshot.head],['seq',(BigInt(snapshot.sequence)+1n).toString()]] : [['aukora', 'l0-v1']] },
    signer_plan: [signer], consent_context: null,
    body: {
      operation_id: body.operation_id, nonce: body.nonce, request_ref: requestRef,
      requester_key_id: body.requester_key_id, actor_key_id: aperture.key_id,
      scope: body.scope, payload_commitment: body.payload_commitment, authority_ref: authorityRef,
      budget: body.budget, control_checkpoint_ref: body.expected_control_checkpoint,
      reservation_id: reservationId, consumption_commitment: commitment, adapter_profile: LOCAL_ADAPTER,
    },
  };
  return { recordBytes: trustedBytes(record), descriptorBytes: trustedBytes(descriptor) };
}

// Enumerate the complete no-onward-delegation budget ancestry *after* W2 has
// validated it. No independently authored signature/role/currentness verifier.
export function budgetCeilings(request, apertureCertificateRef, recordsById) {
  const grants = new Map();
  const addCertificate = (ref) => {
    const certificate = recordsById.get(ref);
    if (!certificate || certificate.kind !== 'key_binding') refuse('MISSING_EVIDENCE');
    const ceiling = certificate.body.restriction.budget_ceiling;
    if (!Array.isArray(ceiling)) refuse('WRONG_AUTHORITY');
    grants.set(ref, ceiling);
  };
  addCertificate(apertureCertificateRef);
  if (request.body.agent_card_ref !== null) {
    const card = recordsById.get(request.body.agent_card_ref);
    if (!card || card.kind !== 'agent_card') refuse('MISSING_EVIDENCE');
    grants.set(request.body.agent_card_ref, card.body.budget);
    if (card.schema === 'aukora.record.v2') {
      if (card.signer_plan.length !== 1 || card.signer_plan[0].role !== 'root') refuse('WRONG_AUTHORITY');
    } else {
      const human = card.signer_plan.filter((p) => p.role === 'human_approval');
      if (human.length !== 1 || !human[0].certificate_ref) refuse('WRONG_AUTHORITY');
      addCertificate(human[0].certificate_ref);
    }
  } else {
    const human = request.signer_plan.filter((p) => p.role === 'human_approval');
    if (human.length !== 1 || !human[0].certificate_ref) refuse('WRONG_AUTHORITY');
    addCertificate(human[0].certificate_ref);
  }
  return [...grants.entries()].sort(([a], [b]) => a.localeCompare(b)).flatMap(([grant_ref, ceilings]) =>
    request.body.budget.map((item) => {
      const ceiling = ceilings.find((c) => c.unit === item.unit && c.currency === item.currency);
      if (!ceiling || BigInt(ceiling.maximum) < BigInt(item.maximum)) refuse('WRONG_AUTHORITY');
      return { grant_ref, unit: item.unit, currency: item.currency,
        maximum: ceiling.maximum, amount: item.maximum };
    }));
}
