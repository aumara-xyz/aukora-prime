# Unknown outcome recovery — design awaiting review

This document adds no API, permission, disposition, device revocation or execution behavior. Current `OUTCOME_UNKNOWN` records retain consumed approval IDs, PREPARED effects, the grant, dispatch identity, receipts, settlement outbox and reconciliation obligation. C and F must not relaunch their original request. Owner login or acknowledgment does not establish that no effect occurred.

## Evidence-backed reconciliation

Only the authenticated private owner of the original executor/memory ledger may submit factual evidence. Evidence must bind the original store identity, operation/grant/request, runtime/deployment/ledger identity and exact receipt bytes. Existing `reconcileSettlement` may monotonically refine an execution outcome after a genuinely drained typed result and qualified cleanup evidence; `settleMemory` may resend the identical committed D receipt. Missing/corrupt state requires history recovery first. A result-retrieval route, if introduced, needs trusted SDK/control-plane provenance bound to that original job/request. Stdout, ordinary logs, owner belief and sandbox absence do not establish external effect success or absence.

Unknown cleanup, possible late creation, RPC uncertainty or unresolved ledger ownership remain obligations. The disappearance of a sandbox cannot undo external effects it may already have caused. Completion evidence can be recorded after approval/session/epoch expiry because it records an already dispatched effect rather than authorizing another effect.

## Owner review annotation

A future annotation could record that the owner reviewed the remaining uncertainty. It would require an authenticated matching owner session and fresh single-use step-up approval, bound to the exact current evidence. Required bindings include store ID, owner ID/subject/current authorization epoch, original operation ID/digest, consumed grant ID/digest, request ID/digest, current receipt digest (or explicit null), and a literal acknowledgment that the outcome remains unknown and external effects may have occurred. Evidence changes between challenge and commit must refuse completion.

The annotation must preserve factual `OUTCOME_UNKNOWN` and `reconciliation_required:true`. It must never fabricate an ExecutionReceipt, write “no effect,” remove consumed IDs/prepared effects, return the job to PREPARED, reuse its grant/nonce/request, retry dispatch, create compensation, or hide uncertainty. No annotation endpoint exists in this checkpoint.

## Possible independently approved admission disposition

F proposed a future distinct action `execution.abandon_unknown`. Its sole possible purpose would be to allow independently approved fresh operations while retaining the original unknown job and every original launch/replay fence. This needs a separate design and owner approval; it is not implemented or part of the current policy/worker route.

In addition to the annotation bindings, a proposed disposition must bind independently observed confirmed absence, the exact cleanup and late-create fence evidence, the immutable deployment/ledger identity, and the requested admission-only disposition. It must refuse if creation/cleanup/ownership obligations remain uncertain or evidence cannot rule out a late owned sandbox. A drained/terminal control-plane create record may supply relevant evidence; a point-in-time empty inventory alone cannot prove no late creation. The owner must explicitly accept the residual unknown external-effect risk.

Disposition would be stored separately from factual receipts and consumed state. It would never turn the original job into successful/failed/cancelled, clear its reconciliation history, release its grant, or permit execution of that job again. Each independent future operation would require its own exact proposal, current state check and fresh owner proof. Compensation would be another separately reviewed operation, never an automatic retry.

## Provisioning, recovery and revocation

Missing state with a retained witness must restore the verified original store ID and history at or above both retained heads. New-store setup cannot reset, replace or manufacture that history. Same-UID rewriting of both state and witness remains outside the source guarantee until qualified deployed separation.

Device revocation and authorization-epoch changes remain unavailable until their explicit authentication, recovery and concurrency design is reviewed. Seven-word root recovery remains parked; it supplies no alternate login or acknowledgment authority.
