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
  authorizeTask(operation) { /* authenticated task/agent/route/provider/region binding */ },
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

`authorizeTask` must synchronously return **exactly `true`** for the authenticated task, agent, audience, and permitted route/provider/region. It is a trusted integration callback, not a guest assertion. `observeTarget` must synchronously return `{target_identity, state_version}` from the current trusted target; missing observation or a mismatch refuses. The immutable policy separately bounds action, agent, data classes, cost, version, epoch, and operation expiry. The reviewed digest binds every frozen OperationProposal field.

`provisionTrustedState: true` initializes public identities only in an empty state. The included fixtures use it in disposable directories. Production mounting/provisioning, persistent state ownership, owner enrollment, and credential changes require the separately authorized deployment work. The factory opens no file or listener until an API method is called.

Passkey credentials are explicitly enrolled ES256/P-256 credentials. `public_key_hex` is a validated uncompressed SEC1 P-256 public key (`04` plus 128 lowercase hex digits). Credential ID and user handle are canonical base64url; the counter is uint32. Origins must be exact HTTPS origins under the configured RP ID. No email login, registration endpoint, credential generation, root ceremony, or recovery login is provided. Seven-word recovery remains parked design. Unknown credentials and missing verifier/enrollment return `UNAVAILABLE` or `UNAUTHORIZED` without fallback.

The default public login mode is passkey. The source-only Ed25519 checks explicitly select `loginKinds: ['owner_key', 'passkey']` using disposable keys. Do not enable another mode as an implicit passkey fallback.

## API and browser join

Methods return synchronous `{ok: true, ...}` results or `{ok: false, error_code, reason}` refusals. The service exports no signer, private-key custody, or executor.

| Method | Input | Successful result |
|---|---|---|
| `propose` | exact OperationProposal | `operation`, `operation_digest`, `status: 'PROPOSED'` |
| `loginChallenge` | `{owner_id, kind}` | `challenge`, plus `public_key` for configured passkey |
| `loginComplete` | `{challenge, material}` | `session_token`, `owner_id`, `expiry` |
| `approvalChallenge` | `{session_token, operation}` | full operation, digest, `approval_request`, `proof_template`, optional `public_key` |
| `approvalComplete` | `{session_token, proof}` | `approval_proof`, `status: 'APPROVED'` |
| `declineApproval` | `{session_token, operation_id}` | durable `status: 'DENIED'` |
| `reserve` | `{operation, approval_proof}` | durable `status: 'PREPARED'`, frozen `consumed_grant`, kernel receipt draft, explicit adapter profile |
| `claimDispatch` | `{operation, consumed_grant}` | durable `status: 'DISPATCHED'` |
| `advanceAuthorizationEpoch` | `{session_token}` | incremented durable `authorization_epoch`; old sessions/proofs refuse |
| `status` | `{session_token, operation_id}` | owner-scoped lifecycle, digest, reconciliation flag |

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

F must verify its exact OperationProposal and ConsumedGrant and successfully call `claimDispatch` before the one owned executor call. Dispatch is consumed durably before that call. A second claim refuses. Prepared/dispatched uncertainty needs `reconcileOwned`; it must not fall back, create fresh authority, retry execution, or unconsume the grant. Completion/settlement and executor reconciliation are integration work; this package executes no operation itself. Target observation still needs the executor's own compare-and-apply semantics to close changes after observation.

The source witness lies outside the selected state restore boundary, but the same UID can rewrite both. A separate UID alone would also leave a signing oracle if authenticated owner proof were omitted. This core checks owner proof and holds no signing keys; unavoidable IPC/process/UID isolation and deployed witness ownership remain unverified deployment requirements. Mount only with immutable verifier/owner configuration, authenticated harness transport, and explicit C owner sessions. A harness bearer token is not owner approval.

## Scoped checks

From a Prime tree containing its frozen contracts:

```sh
node packages/authority/check.mjs
node packages/authority/upstream/vendor/authority/conformance.mjs
```

The first command uses only in-process synthetic Ed25519/P-256 keys and disposable local paths; it cleans them in `finally`. It checks authenticated review, exact-operation mutations, input ambiguity, passkey assertions and refusals, counters, replay across restart, concurrent reservation, durable denial/epoch/restore fences, dispatch one-use, injected fsync interruption, and real elapsed expiry. It runs no inference, external service, OpenShell fixture, owner enrollment, old app, or activation sequence. Injected fsync interruption is not a physical power-loss proof.

The unchanged kernel conformance checks its retained 354 file pins and 37 cases. `provenance/donor-files.json` records exact donor source and copied hashes, local symlinks, and changed files. `provenance/CHANGES.md` accounts for every donor modification. Running-app delivery is not verified by these source checks.
