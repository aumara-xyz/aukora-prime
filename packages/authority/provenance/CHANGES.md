# Lane C provenance and pending changes

Selected source is Genesis commit `645d3213b8aede3b544269b4224ae09df06b0a42`, from the integrator's clean read-only donor snapshot. The authority kernel source pin is `def297fc146bf3c448df4d0f4e78358d65345436`, AGPL-3.0-or-later. No installed `b7` tree or prototype/lab forest is included.

The kernel, its source reference/conformance, pinned Noble dependencies, `approval-state-store.mjs`, and `trusted-state-store.mjs` are byte-for-byte donor copies. Copied Aumlok verification/request/receipt helpers and the strict JSON reader retain their notices. Root Genesis LICENSE/NOTICE are preserved as historical donor material; their references to other Genesis packages do not imply those packages are copied here. Prime's own LICENSE repeats the donor AGPL terms.

Only one donor file is modified: `upstream/scripts/aukora/decide.mjs`.

1. Replace the broad Aumlok index import with Prime's narrow verifier facade so root phrase, custody, ceremonies, and unrelated plugin features are absent from the import closure.
2. Accept trusted injected `witnessDirectory`, existing-store subclass, and before-prepare hook. The service always supplies its explicit owned paths. Wire requests cannot select a clock, path, policy, verifier, or store.
3. Run the hook after the original store has loaded state under its writer lock; preserve named Prime refusal results.
4. Add a trusted verified-passkey adapter that uses the same existing kernel and store transaction after C re-verifies the persisted exact owner assertion. It maps to local-write/authorization:null and never creates an Ed25519 signature or claims the hybrid kernel profile.

`upstream/plugins/aukora-aumlok/lib/prime-verifier.mjs` is new Prime code, explicitly marked as such. All `src/**`, `check.mjs`, package metadata, and this documentation are new Prime adapter/service code. They are not represented as original donor bytes. The manifest records original and copied hashes separately and names this modification.

The plan's related fixes are individually accounted for:

| Fix | Status and evidence |
|---|---|
| Closed exact operation/digest/nonce/expiry/audience/epoch | Implemented at contract ingress, immutable review, completion, reservation, and dispatch; mutation/refusal fixtures |
| Authenticated owner approval before authority use | Implemented: valid schema alone refuses, exact durable review and valid signature/assertion required |
| Durable consumption before ALLOW | Existing kernel/stores retained; fixture observes PREPARED and consumed ID before success |
| Durable denial, epoch, and old-state refusal | Broker lifecycle in the same store plus retained revision; restart/restore fixtures |
| Owner passkey login, no email/fallback | Default passkey-only; actual ES256 verifier, pinned public credentials, UP/UV, RP/origin/challenge/counter checks |
| Browser review preimage consistency | B/C domain/canonical-byte match confirmed; golden approval SHA256 `7ccb05303887594810bfdd031f739e90e6c00a6c29b4f444f252cae9d4208bd2` |
| Owner enrollment and credential origin | Pending separate owner action and registration verification; no real keys or credentials created |
| Seven-word recovery/root ceremony | Retained design, parked; no recovery or weak root-login endpoint |
| Deployed IPC/UID/witness separation | Not performed or verified; same-UID rewrite limitation remains |
| Executor effect settlement/uncertainty | Core reserves/claims once; F/H execute/reconcileOwned integration remains, no effect run here |
| Kernel hybrid profile | Not implemented by these local-write adapters; no hybrid claim |
| Installed application activation | Outside authorized source-only lane; running unchanged |

Library transfer attempts in this lane returned `library file transfer failed: download failed` and created no local file. The integrator subsequently materialized the master v1.2 and inventory files and supplied the clean donor snapshot. A read-only remote clone attempt failed with `Could not resolve host: github.com`; no network/resource/security change was made. No new safety refusal occurred, and no previously refused sequence was retried.


## Owner-relayed Opus repair checkpoint

Base Prime source commit: `6ba58235338d2997ca649743675018c120e3bc49`. Added independent proof/row/op digest guards in the service and same modified donor `decide.mjs` passkey boundary, and derive grants from verified proof. The original kernel and two donor stores remain unchanged. Prime subclass now persists random new-store identity, binds witnesses to it, refuses missing history witnesses and symlink ancestors, and retains same-UID limitations. Structured authenticated Task admission, owner-scoped operation IDs, expiry pruning and explicit quotas replace bare true/guest-claim acceptance. Private C/F claim/cancel/idempotent settle/explicit reconcile and actual C/D memory receipt settlement share the existing journal/consumption path. Minimal authenticateSession returns only durable owner data; epoch mutation is disabled pending auth design review. Exact localhost pilot is optional trusted config with production HTTPS default.

Targeted proof includes normal synthetic owner-key and ES256 approval, changed parameters after removing the earlier row guard, all-digest-guards mutant caught, moved/restored state with retained store-identity witness, missing witness for kernel or broker-only history, symlink prefix, structured-task negatives, 2,000 challenge calls with bounded state, real prepared-effect dispatch corroboration, idempotent/request-digest/receipt/conflict negatives, uncertain cancellation/cleanup, post-epoch factual settlement, genuine D receipt/result digest, and explicit localhost positive/alias/port/RP negatives. F reported joined PASS7 against actual C service, normal synthetic approval and original kernel/stores, no raw PREPARED seeding. No real signing/enrollment/deployment/forbidden fixture occurred. H reported browser `net::ERR_BLOCKED_BY_CLIENT`; localhost actual support remains unverified and no bypass was attempted.

## Owner-relayed Claude da260 repair

Repair base is `1be5ccc2d93b4657a6fe7de63ec4d6757c73b114`. `propose` now requires the closed `{session_token,operation}` envelope, matching durable owner session and independent trusted Task; bridge accepted this API before edits. Pending quotas count only active unconsumed proposals, with expiry/TTL pruning and separately bounded unconsumed denials. Consumed IDs, PREPARED/dispatch/unknown duties and settled replay history never prune or count toward a lifetime admission cap. Physical store byte exhaustion remains fail closed pending capacity/archival work.

Normal methods no longer inherit automatic creation from `provisionTrustedState:true`. The separate setup-only export `provisionNewAuthorityStore` requires genuinely absent state and a pristine dedicated witness namespace; missing state with any retained witness file/heads refuses before a new ID or enrollment. Existing empty owner metadata never re-enrolls. Bridge accepted explicit fixture bootstrap and confirmed the helper has no worker/public route.

New direct kernel-only replay/high-water fixtures and disposable guard mutants use the pure reducer and original-default TrustedStateStore, without broker guards. New admission/provision fixtures use synthetic keys and disposable paths. Original kernel, stores, Noble dependencies and all donor bytes are unchanged from the prior checkpoint; no new donor modification. Unknown recovery is separately documented design only: evidence-backed reconciliation, owner review annotation, and a possible independent-admission disposition never unconsume or retry. Epoch/device revoke remains unavailable. No real provisioning, signing/enrollment, runtime, database, UID or security-setting action occurred here.
