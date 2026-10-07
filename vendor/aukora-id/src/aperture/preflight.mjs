import { parseRecord } from '../bytes/index.mjs';
import { refuse } from './local-profile.mjs';

// W2 currently charges every supplied envelope and every resolved application
// proof within its unchanged 64-signature limit. The complete current prefix is
// required for ancestry/control reconstruction: do not drop old records here.
// Run after W2 has validated that prefix but BEFORE either intent signature.
export function preflightIntentWork(recordBytes, verifiedEvents, { reserveReceipt = false, verifiedPrefix = false } = {}) {
  const record = parseRecord(recordBytes);
  if (record.kind !== 'intent') refuse('WRONG_DOMAIN');
  const ids = new Set(verifiedEvents.map(({ event }) => event.id));
  for (const ref of [record.previous_event, ...record.authority_refs, record.body.request_ref,
    record.body.authority_ref, record.body.control_checkpoint_ref,
    ...record.signer_plan.map(signer => signer.certificate_ref)]) {
    if (!ids.has(ref)) refuse('MISSING_EVIDENCE');
  }
  const retainedChecks = verifiedPrefix ? 0 : verifiedEvents.reduce((total, { proofs }) => total + 1 + proofs.length, 0);
  const intentChecks = 1 + record.signer_plan.length;
  // A configured observer needs one additional application + envelope proof.
  // Reserving that work does not attest any observation or allow a done receipt.
  if (retainedChecks + intentChecks + (reserveReceipt ? 2 : 0) > 64) refuse('LIMIT_EXCEEDED');
}
