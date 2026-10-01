# Prime authority service core

Source-only lane C package, licensed AGPL-3.0-or-later. It imports Prime's sibling `packages/contracts/src/runtime.mjs` and carries its selected Genesis authority closure locally. It needs Node 24+, no package installation, network access, user repository paths, signing service, or private key at build/runtime.

## Reused authority path

`createAuthorityService().reserve()` → adapted Genesis `decide.mjs` → copied `ApprovalStateStore` → copied `TrustedStateStore.authorizeAndPrepare()` → unchanged kernel `decide()` → fsynced `PREPARED` and retained witness → `ALLOW`.

The kernel and two original stores are copied from Genesis `645d3213b8aede3b544269b4224ae09df06b0a42`. The kernel's original source pin is `def297fc146bf3c448df4d0f4e78358d65345436`. The ten runtime kernel modules, source reference, conformance vectors, licenses, provenance, and required pinned Noble dependency closure are retained. This is the existing decision engine. The Prime layer verifies the authenticated owner's exact operation and maintains broker lifecycle metadata in the existing store transaction.

The Ed25519 v1 adapter uses `ring: 'local-write'`, `humanClearance: false`, and `authorization: null`. The passkey adapter verifies the actual assertion, then uses the same mapping and durable kernel transaction. Neither adapter supplies the kernel's hybrid authorization profile or fabricates an Ed25519 signature. An authenticator assertion does not prove comprehension.

## Trusted configuration

`createAuthorityService(options)` accepts configuration from the trusted provisioner. None of these options is a guest request or a transport field:

```js
{
  statePath: '/absolute/owned/state/authority.json',
  stateRoot: '/absolute/owned/state',
  witnessDir: '/absolute/retained/witness',
  audience: 'prime:deployment-audience',
  identities: [{
    owner_id, subject, approval_key_did, control_digest, authorization_epoch
  }],
  policy: {
    version, actions: ['memory.save'], agents: ['allowed-agent'],
    data_scope: ['public'], maximum_cost: {currency: 'USD', amount: '0'}
  },
  // Default is ['passkey']. No automatic owner-key fallback.
  loginKinds: ['passkey'],
  provisionTrustedState: false,
  authorizeTask(operation) { /* return {authenticated:true, task: trustedFrozenTask} */ },
  observeTarget(operation) { /* current exact target_identity + state_version */ },
  webauthn: {
    rp_id: 'prime.example.test',
    origins: ['https://prime.example.test'],
    credentials: [{
      owner_id, credential_id, public_key_hex, user_handle,
      sign_count: 0, backup_eligible: false
    }]
  }
}
```

All identity fields are public. `subject` is `aukora:1:<64 lowercase hex>`, the Ed25519 public DID and control digest are pinned, and the initial epoch is a nonnegative safe integer. Identity provenance must be independently authenticated during owner-approved enrollment. Public identity loading is not enrollment or proof of owner presence.

`authorizeTask` must synchronously return the closed `{authenticated:true, task:<frozen Task>}` from the authenticated host context/registry. C checks exact task/owner/agent, active task status, data classes and task spend ceiling; bare `true` refuses. Host context must also bind audience and permitted route/provider/region. It is a trusted integration callback, not a guest assertion. `observeTarget` must synchronously return `{target_identity, state_version}` from the current trusted target; missing observation or a mismatch refuses. The immutable policy separately bounds action, agent, data classes, cost, version, epoch, and operation expiry. The reviewed digest binds every frozen OperationProposal field.

Normal service methods require existing state, even when `provisionTrustedState:true` remains in trusted configuration. Fresh setup is the separate local export `provisionNewAuthorityStore(trustedOptions)`: explicitly set that flag, use absent state and a pristine dedicated witness namespace, and call it once before `createAuthorityService`. It returns `{ok:true,status:'PROVISIONED',store_id}`. Existing state refuses `STORE_ALREADY_PROVISIONED`; missing state with any retained witness file/keys (including count zero) refuses `RECONCILIATION_REQUIRED` before generating another identity. Empty owner metadata in an existing store never triggers enrollment. Do not expose the setup helper on any transport route.

Recovery restores the verified original history and store ID at or above both retained heads; it cannot use fresh setup, reset a witness, or discard consumed/uncertain duties. An interrupted fresh setup that retained its witness but lost state remains blocked rather than automatically restarting with another ID. Shared witness namespaces cannot establish which absent history is missing, so fresh setup refuses there. Multi-history provisioning would require a separately reviewed retained registry. The fixtures provision disposable directories only. Production ownership, enrollment and protected setup remain separately authorized deployment work. The service factory opens no file or listener until an API method is called.

Passkey credentials are explicitly enrolled ES256/P-256 credentials. `public_key_hex` is a validated uncompressed SEC1 P-256 public key (`04` plus 128 lowercase hex digits). Credential ID and user handle are canonical base64url; the counter is uint32. Origins must be exact HTTPS origins under the configured RP ID. No email login, registration endpoint, credential generation, root ceremony, or recovery login is provided. Seven-word recovery remains parked design. Unknown credentials and missing verifier/enrollment return `UNAVAILABLE` or `UNAUTHORIZED` without fallback.

The default public login mode is passkey. The source-only Ed25519 checks explicitly select `loginKinds: ['owner_key', 'passkey']` using disposable keys. Do not enable another mode as an implicit passkey fallback.

## API and browser join

Methods return synchronous `{ok: true, ...}` results or `{ok: false, error_code, reason}` refusals. The service exports no signer, private-key custody, or executor.

| Method | Input | Successful result |
|---|---|---|
| `propose` | `{session_token, operation}` | authenticated matching owner plus trusted Task; `operation`, `operation_digest`, `status: 'PROPOSED'` |
| `loginChallenge` | `{owner_id, kind}` | `challenge`, plus `public_key` for configured passkey |
| `loginComplete` | `{challenge, material}` | `session_token`, `owner_id`, `expiry` |
| `approvalChallenge` | `{session_token, operation}` | full operation, digest, `approval_request`, `proof_template`, optional `public_key` |
| `approvalComplete` | `{session_token, proof}` | `approval_proof`, `status: 'APPROVED'` |
| `declineApproval` | `{session_token, operation_id}` | `status: 'DENIED'` with bounded unconsumed denial retention |
| `reserve` | `{operation, approval_proof}` | durable `status: 'PREPARED'`, frozen `consumed_grant`, kernel receipt draft, explicit adapter profile |
| `claimDispatch` | `{operation, consumed_grant, request_id, request_digest}` | durable `status: 'DISPATCHED'`, exact request binding |
| `advanceAuthorizationEpoch` | `{session_token}` | `UNAVAILABLE`: epoch-change authentication design awaits review |
| `authenticateSession` | `{session_token}` | read-only durable owner ID, subject, epoch and expiry |
| `status` | `{session_token, operation_id}` | owner-scoped lifecycle, digest, reconciliation flag |
| `requestCancel` | `{operation, consumed_grant, request_id, reason}` | durable intent only; late terminal result preserved |
| `settle` / `reconcileSettlement` | `{operation, consumed_grant, request_id, request_digest, receipt, receipt_digest}` | bound idempotent executor evidence; explicit unknown reconciliation |
| `markOutcomeUnknown` | exact dispatch binding | retains consumption and marks uncertainty without fabricated evidence |
| `settleMemory` | exact dispatch binding plus genuine D `receipt` | durable idempotent applied-memory evidence |

Login challenge is the exact closed record `{version:1, owner_id, audience, challenge, issued_at, expiry, authorization_epoch}`. The login bytes are UTF-8 `aukora-prime.owner-login.v1\0` plus frozen sorted compact canonical JSON of that record. Login owner-key material is exactly `{kind:'owner_key', signature:<128 lowercase hex>}`.

Approval request is the copied donor's exact `{domain:'aukora:owner-approval-request:v1', subject, activeControlDigest, operationDigest, challenge, issuedAt, expiresAt}`. `operationDigest` is the raw SHA-256 hex of the frozen full operation. Approval signing bytes are UTF-8 `aukora:owner-approval-signature:v1\0` plus donor canonical JSON of that request. Donor and frozen shared canonical JSON agree for these closed string/safe-integer fields. Approval owner-key material is exactly `{kind:'owner_key', request:<that exact request>, signature:<128 lowercase hex>}`.

The proof template binds operation ID, prefixed operation digest, owner, audience, and epoch. Its nonce is a fresh review challenge, and its expiry is `min(operation expiry rounded down to seconds, issuedAt + 120 seconds)`. The operation's original nonce and expiry are already bound by the digest; they need not equal the separate review nonce/expiry. The owner client must freeze and compare the entire presentation and returned envelope before requesting the authenticator. The proof template's placeholder material is not a valid assertion or signature.

Passkey `public_key` is transport-safe `{challenge:<base64url SHA256 of the exact signing bytes>, rpId, allowCredentials:[{type:'public-key',id:<base64url>}], userVerification:'required', timeout:60000}`. B converts the byte fields for `navigator.credentials.get()` and returns exactly:

```js
{
  kind: 'passkey', credential_id,
  client_data_json, authenticator_data, signature, user_handle
}
```

Binary fields are canonical base64url. `user_handle` can be null for a known-owner allowCredentials assertion, otherwise it must equal the pinned handle. C parses strict UTF-8/duplicate-free client data; verifies challenge, exact origin, RP hash, UP/UV, flags, backup eligibility, and ES256 DER signature using the pinned `@noble/curves@2.2.0`; and commits credential counters with the existing state. Assertions with unrequested extensions or trailing authenticator bytes are refused. Counter increases are mandatory if either counter is nonzero; zero/zero authenticators remain subject to durable challenge one-use. Registration/attestation validation is not implemented here.

## Durability and execution boundary

Guest-valid schema is insufficient: an exact persisted review and authenticated owner's valid proof are required before reservation. The service rechecks immutable policy, durable epoch, live target state, exact operation/proof, and expiry under the **original store's held writer lock** immediately before the unchanged kernel decides.

The copied store atomically journals broker metadata and kernel consumption/prepared effects. A second retained high-water counter covers denial, session changes, and epoch increments even when the kernel receipt count is unchanged. Restored older state with a retained newer witness refuses. An interrupted write can be retained for reconciliation; it does not grant permission to reset state, witness, consumption IDs, or retry an uncertain effect. Missing matching broker reservation for consumed authority returns `RECONCILIATION_REQUIRED`.

F must verify its exact OperationProposal and ConsumedGrant and successfully call `claimDispatch` before the one owned executor call. Dispatch is consumed durably before that call. A second claim refuses. Prepared/dispatched uncertainty needs `reconcileOwned`; it must not fall back, create fresh authority, retry execution, or unconsume the grant. This package durably settles genuine executor and memory evidence through private worker joins; it executes no operation itself. Runtime qualification and transport are separate integration work. Target observation still needs the executor's own compare-and-apply semantics to close changes after observation.

The source witness lies outside the selected state restore boundary, but the same UID can rewrite both. A separate UID alone would also leave a signing oracle if authenticated owner proof were omitted. This core checks owner proof and holds no signing keys; unavoidable IPC/process/UID isolation and deployed witness ownership remain unverified deployment requirements. Mount only with immutable verifier/owner configuration, authenticated harness transport, and explicit C owner sessions. A harness bearer token is not owner approval.

## Scoped checks

From a Prime tree containing its frozen contracts:

```sh
node packages/authority/check.mjs
node packages/authority/check-admission.mjs
node packages/authority/check-kernel-guards.mjs
node packages/authority/upstream/vendor/authority/conformance.mjs
```

The first command uses only in-process synthetic Ed25519/P-256 keys and disposable local paths; it cleans them in `finally`. It checks authenticated review, exact-operation mutations, input ambiguity, passkey assertions and refusals, counters, replay across restart, concurrent reservation, durable denial/epoch/restore fences, dispatch one-use, injected fsync interruption, and real elapsed expiry. It runs no inference, external service, OpenShell fixture, owner enrollment, old app, or activation sequence. Injected fsync interruption is not a physical power-loss proof.

The full check also invokes the two standalone checks. Admission checks exercise authenticated proposal ingress, pending/denial pruning, repeated genuine reserve/dispatch/settled saves beyond the old lifetime limits, and deleted-state provisioning refusal. Kernel guard checks import the pure reducer and original-default `TrustedStateStore` without broker/subclass guards. Removing the actual replay guard must fail its pure/store replay assertions; removing the original store's high-water comparison must fail its direct rollback assertion. A pin/import refusal never counts as killing those mutants.

The unchanged kernel conformance checks its retained 354 file pins and 37 cases. `provenance/donor-files.json` records exact donor source and copied hashes, local symlinks, and changed files. `provenance/CHANGES.md` accounts for every donor modification. Running-app delivery is not verified by these source checks.


## Review repairs and private effect joins

The digest is independently checked at the service bind and verified-passkey adapter boundary: `proof.operation_digest === row.operation_digest === operationDigest(op)`. Grants take their digest from the verified proof. The focused mutant removes the earlier exact-row check and still refuses changed synthetic parameters; disabling all downstream digest boundaries is caught by the regression.

NEW stores persist random `broker.store_id` before successful admission. Retained kernel and broker witness keys derive from that identity, never the state path. Existing state without an identity has no implicit migration. A missing witness entry with any kernel receipt or broker revision refuses before rebaseline. All state/root/witness symlink ancestors refuse, and their device/inode identities are rechecked after open; Node's lack of atomic openat still leaves the documented same-UID syscall race. Same-UID forging of all metadata/witness remains outside this source claim. Real provisioning or migration requires separate owner approval.

Default trusted quotas are 32 live login challenges and 16 sessions per owner, 128 active unconsumed pending proposals per owner/256 total, and 32 retained unconsumed denials per owner/64 total. Pending admission requires an authenticated matching C owner session and the independently trusted Task. These are temporary occupancy limits, not lifetime operation counts. New unreviewed proposals have a default maximum five-minute TTL; an actual authenticated review sets their deadline to its exact approval expiry (at most 120 seconds, also bounded by operation expiry). A custom `pending_ttl_ms` controls unreviewed drafts, not the subsequent review window. Expired unconsumed pending/approved/denied rows prune, and excess unconsumed denials prune by bounded retention. A fresh authenticated review is required to reuse an expired unconsumed proposal; old proof material cannot authorize its new challenge. Denials do not occupy pending admission slots.

Any grant/dispatch, consumed approval ID, or matching kernel prepared effect excludes a row from pruning, including interrupted preparation and unknown outcomes. Completed/failed/consumed rows never occupy the pending count, so ordinary settled saves can continue beyond 128/256 while replay history stays intact. The remaining 64 KiB proposal and 16 MiB store byte limits are resource bounds: storage exhaustion refuses without losing history and requires trusted capacity/archival work, never replay-history eviction. Quota refusals do not append state. The 2,000-call disposable challenge case stays at <=32 live challenges and <32 KiB state, including expiry turnover.

`claimDispatch` requires original kernel consumption and a prepared effect matching the reservation/content digest, then atomically records the UUID request ID and request digest before success. Request digest is SHA256 of `aukora-prime.executor-request.v1` + NUL + canonical full OwnedExecutorRequest excluding AbortSignal. Receipt digest uses `aukora-prime.execution-receipt.v1` + NUL + exact frozen ExecutionReceipt JSON. F must call this actual private method once before create/execute, never a static true callback. Lost replies stay fenced; no reclaim/relaunch. C settlement validates the immutable operation/grant/request and receipt, is durable/idempotent, and can accept factual results after approval/epoch expiry. It does not reauthorize the effect.

Unknown cleanup, lost RPC, or uncertain outcome stays `OUTCOME_UNKNOWN`, even after guest absence. Cancellation is intent only. `CANCELLED` requires recorded cancellation, confirmed absence/not-created, `rpc_completion:'not_started'`, `started_at:null`, and no typed exit. A drained typed result wins over a late abort. Unknown -> later evidence uses explicit `reconcileSettlement` with stable IDs/sandbox/prior typed result/output; conflicting evidence refuses. No cancellation unconsumes authority.

D's actual committed memory receipt is separately closed: `{version:1,kind:'prime-memory-effect/v1',operation_id,operation_digest,grant_id,request_id,request_digest,owner_subject,action_type,status:'applied',result_digest,result}`. Result digest domain is `aukora-prime.memory-result.v1`; full receipt domain is `aukora-prime.memory-receipt.v1`, each NUL + frozen canonical JSON. `settleMemory` uses the same existing broker dispatch lifecycle and checks actual target owner/action/result bytes. D commits its SQL effect and receipt first and resends identical evidence on reconciliation. No sandbox/RPC receipt is fabricated for DB effects. These methods belong only to authenticated private worker IPC, never HTTP guest receipt input.

Owner epoch changes are disabled until their exact authentication design is reviewed. Disposable regressions change only synthetic store counters through the real store to verify revocation/restore fences. A login token alone grants no new admin power.

Safe owner acknowledgment/abandonment of an unknown outcome is design only in [docs/unknown-recovery-design.md](docs/unknown-recovery-design.md). No acknowledgment, clear, abandon, retry, device-revoke or admission-disposition endpoint is implemented. An owner's acknowledgment never proves no effect or releases consumed authority.

## Explicit localhost pilot (source-only)

Default WebAuthn profile is `https`. Only an explicit trusted `profile:'localhost-pilot-v1'`, `rp_id:'localhost'`, `origins:['http://localhost:18731']` permits HTTP. IP aliases, subdomains, trailing dots and other ports refuse. The browser binding separately pins `{profile,origin,rp_id}`, exact location origin, secure-context status and WebAuthn API availability. WebAuthn officially permits the localhost HTTP origin with a domain RP ID; IP hosts are excluded. See [WebAuthn RP rules](https://www.w3.org/TR/webauthn-3/#rp-id) and [Secure Contexts localhost](https://www.w3.org/TR/secure-contexts/#localhost).

H's actual in-app-browser navigation to the pilot returned `net::ERR_BLOCKED_BY_CLIENT`. It was not retried or bypassed. Actual browser support is NOT VERIFIED. This source profile creates no listener, DNS/TLS resource, credential, enrollment, or persistent configuration. Owner enrollment/action, exact origin verification, process/UID/witness separation and runtime qualification remain separately approved work.
