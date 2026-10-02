// SPDX-License-Identifier: AGPL-3.0-or-later
// Compile-only consumer check: run with strict NodeNext, noEmit, and skipLibCheck=false.
// This file must never be executed; the declared inputs model independently observed data.
import type { ApprovalProof, ConsumedGrant, Digest, JsonValue, OperationProposal } from '@aukora-prime/contracts';
import {
  ExternalDeepSeekGateway, SpendLedger,
  inferenceBudgetState, normalizeTotalBudget, totalBudgetBinding, totalBudgetPolicyDigest,
  type DispatchAdmission, type DispatchBinding, type LocalRoute, type LocalTask,
  type ProviderReply, type ProviderRequest, type SourceCitation, type TotalTestingBudget,
} from '@aukora-prime/inference';
import {
  SeparatedCredentialService, type SeparatedServiceOptions,
  type WorkerReviewedApproval, type WorkerClaimInput, type WorkerIntentLookup,
  type WorkerSettlementLookup, type WorkerSettlementMethod,
  type WorkerIntent as ServiceWorkerIntent,
  type WorkerClaimReply as ServiceWorkerClaimReply,
  type WorkerSettlementPayload as ServiceWorkerSettlementPayload,
  type WorkerSettlementReply as ServiceWorkerSettlementReply,
} from '@aukora-prime/inference/credential-service';
import {
  inferenceBudgetState as subpathBudgetState,
  totalBudgetBinding as subpathBudgetBinding,
} from '@aukora-prime/inference/budget-binding';
import {
  createWorkerEvidence, validateWorkerClaimReply, validateWorkerSettlementReply,
  type WorkerIntent, type WorkerPhase, type WorkerReceipt, type WorkerClaimReply,
  type WorkerSettlementPayload, type WorkerSettlementReply, type PendingWorkerSettlement,
} from './src/worker-evidence.mjs';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends
  (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
type RequiredKeys<T> = { [K in keyof T]-?: object extends Pick<T, K> ? never : K }[keyof T];
type AdmissionKeys = 'owner_id' | 'task_id' | 'conversation_id' | 'request_uuid' |
  'body_sha256' | 'binding_hash' | 'citations_sha256' | 'config_digest' |
  'reserved_tokens' | 'reserved_cost_microusd' | 'credential_generation' |
  'total_budget_id' | 'operation' | 'consumed_grant' | 'request_digest';
type AdmissionHasExactly15Fields = Assert<Equal<keyof DispatchAdmission, AdmissionKeys>>;
type AdmissionRequiresAll15Fields = Assert<Equal<RequiredKeys<DispatchAdmission>, AdmissionKeys>>;
type AdmissionOperationIsFrozenContract = Assert<Equal<DispatchAdmission['operation'], OperationProposal>>;
type AdmissionGrantIsFrozenContract = Assert<Equal<DispatchAdmission['consumed_grant'], ConsumedGrant>>;
type AdmissionDigestIsTagged = Assert<Equal<DispatchAdmission['request_digest'], Digest>>;
type RequestAdmissionIsOptionalExactAdmission = Assert<Equal<ProviderRequest['admission'], DispatchAdmission | undefined>>;
type IntentFields = Assert<Equal<keyof WorkerIntent,
  'operation' | 'consumed_grant' | 'request_id' | 'request_digest' | 'binding' |
  'task' | 'route' | 'total_budget' | 'input_bound' | 'max_output_tokens' | 'citations'>>;
type IntentRequiredFields = Assert<Equal<RequiredKeys<WorkerIntent>, keyof WorkerIntent>>;
type ClaimFields = Assert<Equal<keyof WorkerClaimReply,
  'ok' | 'status' | 'consumed_grant' | 'request_id' | 'request_digest'>>;
type ReceiptFields = Assert<Equal<keyof WorkerReceipt,
  'version' | 'kind' | 'operation_id' | 'operation_digest' | 'grant_id' | 'request_id' |
  'request_digest' | 'owner_subject' | 'task_id' | 'conversation_id' | 'route_id' |
  'config_digest' | 'credential_generation' | 'total_budget_id' | 'body_sha256' |
  'outcome' | 'result_digest' | 'usage' | 'reservation_retained' | 'observed_at'>>;
type SettlementPayloadFields = Assert<Equal<keyof WorkerSettlementPayload,
  'operation' | 'consumed_grant' | 'request_id' | 'request_digest' | 'receipt' | 'receipt_digest'>>;
type SettlementReplyFields = Assert<Equal<keyof WorkerSettlementReply,
  'ok' | 'status' | 'request_id' | 'request_digest' | 'receipt_digest' |
  'idempotent' | 'reconciliation_required'>>;
type SettlementReplyStatuses = Assert<Equal<WorkerSettlementReply['status'], 'COMPLETED' | 'OUTCOME_UNKNOWN'>>;
type ReceiptOutcomes = Assert<Equal<WorkerReceipt['outcome'], 'completed' | 'outcome_unknown'>>;
type WorkerPhases = Assert<Equal<WorkerPhase,
  'intent_committed' | 'claim_started' | 'claimed' | 'http_started' | 'outcome_recorded'>>;
type PendingMethods = Assert<Equal<PendingWorkerSettlement['method'], 'settleInference' | 'reconcileInferenceSettlement'>>;
type ExportedIntent = Assert<Equal<ServiceWorkerIntent, WorkerIntent>>;
type ExportedClaim = Assert<Equal<ServiceWorkerClaimReply, WorkerClaimReply>>;
type ExportedSettlement = Assert<Equal<ServiceWorkerSettlementPayload, WorkerSettlementPayload>>;
type ExportedSettlementReply = Assert<Equal<ServiceWorkerSettlementReply, WorkerSettlementReply>>;
type BudgetStateSubpathMatches = Assert<Equal<typeof subpathBudgetState, typeof inferenceBudgetState>>;
type BudgetBindingSubpathMatches = Assert<Equal<typeof subpathBudgetBinding, typeof totalBudgetBinding>>;
type ReviewedCallback = Assert<Equal<SeparatedServiceOptions['getReviewedApproval'],
  (binding: DispatchBinding) => Promise<WorkerReviewedApproval>>>;
type DispatchCallback = Assert<Equal<SeparatedServiceOptions['withDispatch'],
  (input: WorkerClaimInput) => Promise<ProviderReply>>>;
type ClaimInputFields = Assert<Equal<keyof WorkerClaimInput,
  'operation' | 'consumed_grant' | 'request_id' | 'request_digest'>>;
type IntentLookupFields = Assert<Equal<keyof WorkerIntentLookup,
  'owner_id' | 'task_id' | 'operation_digest' | 'request_uuid' | 'request_digest'>>;
type SettlementLookupFields = Assert<Equal<keyof WorkerSettlementLookup,
  keyof WorkerIntentLookup | 'receipt_digest'>>;
type SettlementMethods = Assert<Equal<WorkerSettlementMethod, PendingWorkerSettlement['method']>>;
type LegacyVerifierRemoved = Assert<Equal<Extract<keyof SeparatedServiceOptions, 'verifyDispatchAdmission'>, never>>;
type SettleCallback = Assert<Equal<SeparatedServiceOptions['settleInference'],
  (input: WorkerSettlementPayload) => Promise<WorkerSettlementReply>>>;
type ReconcileCallback = Assert<Equal<SeparatedServiceOptions['reconcileInferenceSettlement'],
  (input: WorkerSettlementPayload) => Promise<WorkerSettlementReply>>>;
type EvidenceCallback = Assert<Equal<SeparatedServiceOptions['getReconciliationEvidence'],
  ((input: { evidence_id: string; intent: WorkerIntent }) => Promise<ProviderReply>) | undefined>>;

declare const operation: OperationProposal;
declare const proof: ApprovalProof;
declare const grant: ConsumedGrant;
declare const digest: Digest;
declare const binding: DispatchBinding;
declare const route: LocalRoute;
declare const task: LocalTask;
declare const descriptor: TotalTestingBudget;
declare const citations: SourceCitation[];
declare const providerReply: ProviderReply;
declare const rawAuthorityReply: unknown;
declare const baseServiceOptions: Omit<SeparatedServiceOptions,
  'getReviewedApproval' | 'withDispatch' | 'settleInference' | 'reconcileInferenceSettlement' | 'getReconciliationEvidence'>;

const admission: DispatchAdmission = {
  ...binding, operation, consumed_grant: grant, request_digest: digest,
};
// @ts-expect-error Boolean authorization cannot replace an exact admission.
const booleanAdmission: DispatchAdmission = true;
// @ts-expect-error A consumed grant alone cannot replace the 15-field admission.
const grantOnlyAdmission: DispatchAdmission = grant;
// @ts-expect-error An untagged string cannot become the request digest.
const invalidDigest: DispatchAdmission = { ...admission, request_digest: 'untagged' };

const normalized: TotalTestingBudget = normalizeTotalBudget(descriptor);
const budgetDigest: Digest = totalBudgetPolicyDigest(normalized);
const budgetBinding = totalBudgetBinding(normalized);
const budgetState = inferenceBudgetState({
  owner: { owner_id: task.owner_id, subject: 'aukora:1:synthetic-owner' },
  route, total_budget: normalized, credential_generation: 1,
});
// Assign the actual helper outputs, without casts, spreading, or JSON round-trips.
const target: OperationProposal['target_identity'] = budgetState.target_identity;
const directBudgetParameters: OperationProposal['canonical_parameters'] = budgetBinding;
const canonicalParameters: OperationProposal['canonical_parameters'] = {
  total_budget: budgetState.total_budget,
};
const targetJson: JsonValue = budgetState.target_identity;
const budgetJson: JsonValue = budgetBinding;
const stateDigest: Digest = budgetState.state_version;
const boundOperation: OperationProposal = {
  ...operation, target_identity: target, canonical_parameters: canonicalParameters,
  expected_state_version: stateDigest,
};

const intent: WorkerIntent = {
  operation: boundOperation, consumed_grant: grant, request_id: binding.request_uuid,
  request_digest: digest, binding, task, route, total_budget: normalized,
  input_bound: 12, max_output_tokens: 24, citations,
};
const claim: WorkerClaimReply = {
  ok: true, status: 'DISPATCHED', consumed_grant: grant,
  request_id: intent.request_id, request_digest: intent.request_digest,
};
// @ts-expect-error A boolean acknowledgement is not an authority claim reply.
const booleanClaim: WorkerClaimReply = true;
// @ts-expect-error A partial claim reply cannot authorize HTTP.
const partialClaim: WorkerClaimReply = { ok: true, status: 'DISPATCHED' };
// @ts-expect-error Claimed status must use the frozen uppercase authority spelling.
const invalidClaimStatus: WorkerClaimReply = { ...claim, status: 'claimed' };
const evidence = createWorkerEvidence(intent, providerReply, '2030-01-01T00:00:00.000Z');
const unknownEvidence = createWorkerEvidence(intent, null, '2030-01-01T00:00:00.000Z');
const receipt: WorkerReceipt = evidence.receipt;
const payload: WorkerSettlementPayload = evidence.payload;
const checkedClaim: WorkerClaimReply = validateWorkerClaimReply(intent, rawAuthorityReply);
const checkedSettlement: WorkerSettlementReply = validateWorkerSettlementReply(payload, rawAuthorityReply);
const settlement: WorkerSettlementReply = {
  ok: true, status: 'COMPLETED', request_id: payload.request_id,
  request_digest: payload.request_digest, receipt_digest: payload.receipt_digest,
  idempotent: false, reconciliation_required: false,
};
// @ts-expect-error A worker receipt alone is not an authority settlement acknowledgement.
const receiptAsSettlement: WorkerSettlementReply = receipt;
// @ts-expect-error Dispatch status cannot acknowledge a settlement.
const invalidSettlementStatus: WorkerSettlementReply = { ...settlement, status: 'DISPATCHED' };
// @ts-expect-error Outcome-unknown evidence still requires a receipt and receipt digest.
const partialSettlementPayload: WorkerSettlementPayload = {
  operation, consumed_grant: grant, request_id: intent.request_id, request_digest: digest,
};

const options: SeparatedServiceOptions = {
  ...baseServiceOptions,
  getReviewedApproval: async observedBinding => {
    const exactBinding: DispatchBinding = observedBinding;
    return { operation, approval_proof: proof };
  },
  withDispatch: async input => {
    const originalOperation: OperationProposal = input.operation;
    const originalGrant: ConsumedGrant = input.consumed_grant;
    const requestDigest: Digest = input.request_digest;
    return providerReply;
  },
  settleInference: async input => {
    const exactPayload: WorkerSettlementPayload = input;
    return settlement;
  },
  reconcileInferenceSettlement: async input => ({
    ...settlement, request_id: input.request_id, request_digest: input.request_digest,
    receipt_digest: input.receipt_digest,
  }),
  getReconciliationEvidence: async ({ evidence_id, intent: originalIntent }) => {
    const originalOperation: OperationProposal = originalIntent.operation;
    const evidenceId: string = evidence_id;
    return providerReply;
  },
};
// @ts-expect-error Boolean authorization is not the completed dispatch continuation.
const booleanContinuation: SeparatedServiceOptions['withDispatch'] = async () => true;
// @ts-expect-error A claim reply alone cannot replace HTTP and durable evidence continuation.
const claimOnlyContinuation: SeparatedServiceOptions['withDispatch'] = async () => claim;
// @ts-expect-error A review needs the operation and actual approval proof, not an approval boolean.
const booleanReview: SeparatedServiceOptions['getReviewedApproval'] = async () => true;
// @ts-expect-error The removed claim-only callback is not part of the service options.
type RemovedVerifier = SeparatedServiceOptions['verifyDispatchAdmission'];
// @ts-expect-error Private settlement callback must return the authority acknowledgement.
const receiptSettler: SeparatedServiceOptions['settleInference'] = async () => receipt;
const service = new SeparatedCredentialService(options);
const reviewed: Promise<WorkerReviewedApproval> = service.getReviewedApproval(binding);
const lookup: WorkerIntentLookup = {
  owner_id: task.owner_id, task_id: task.task_id, operation_digest: digest,
  request_uuid: intent.request_id, request_digest: intent.request_digest,
};
const continued: Promise<ProviderReply> = service.withCommittedIntent(lookup, async committedAdmission => {
  const exactAdmission: DispatchAdmission = committedAdmission;
  return service.dispatchCommitted(exactAdmission, claim);
});
const delivered: Promise<WorkerSettlementReply> = service.withCommittedSettlement(
  'settleInference', { ...lookup, receipt_digest: payload.receipt_digest }, async committedPayload => {
    const exactPayload: WorkerSettlementPayload = committedPayload;
    return options.settleInference(exactPayload);
  });
const reconciled: Promise<string> = service.withCommittedSettlement(
  'reconcileInferenceSettlement', { ...lookup, receipt_digest: payload.receipt_digest },
  async committedPayload => committedPayload.request_id);
// @ts-expect-error Intent lookup requires the original operation digest.
service.withCommittedIntent({ owner_id: task.owner_id, task_id: task.task_id,
  request_uuid: intent.request_id, request_digest: digest }, async () => providerReply);
// @ts-expect-error Committed intent consumer must be awaited; a synchronous result is not accepted.
service.withCommittedIntent(lookup, () => providerReply);
// @ts-expect-error A boolean claim cannot start the private committed dispatch.
service.dispatchCommitted(admission, true);
// @ts-expect-error Settlement replay must select an exact committed receipt digest.
service.withCommittedSettlement('settleInference', lookup, async () => settlement);
// @ts-expect-error Settlement callbacks cannot invoke a fresh dispatch method.
service.withCommittedSettlement('withDispatch', { ...lookup, receipt_digest: digest }, async () => settlement);
const ledger = new SpendLedger('/synthetic/compile-only', { total_budget: normalized });
const reservedIntent: WorkerIntent = ledger.reserveWorkerIntent(intent);
const recovered = ledger.workerIntent(task.owner_id, task.task_id, intent.request_id);
const recoveredClaim: WorkerClaimReply | null = recovered.claim_reply;
const recoveredPhase: WorkerPhase = recovered.phase;
const pending: PendingWorkerSettlement = ledger.recordWorkerEvidence(
  task.owner_id, task.task_id, intent.request_id, null, '2030-01-01T00:00:00.000Z');
ledger.acknowledgeWorkerSettlement(task.owner_id, task.task_id, intent.request_id, digest, settlement);
const gateway = new ExternalDeepSeekGateway({
  route, ledger, request_home: '/synthetic/compile-only',
  provider: { mode: 'production', generate: async () => providerReply },
  authorize_dispatch: async observedBinding => ({
    ...observedBinding, operation, consumed_grant: grant, request_digest: digest,
  }),
});
