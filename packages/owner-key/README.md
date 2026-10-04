# Owner key: source-only P-256 certificate boundary

## Separate owner authorization

`@aukora/owner-key/authorization` is a separate protocol for Peter's exact
operation authorization. A scoped-key certificate cannot be used as an approval.
The fixed `aukora-owner-authorization/v1` kind means authorize ONE `allowed-once`
application of the gate's stored `change` or `revert`; it has no arbitrary-signing,
delegation, rejection or approval-boolean mode. The owner signs domain-prefixed
bytes, independently of the later gate receipt:

```text
UTF8("aukora:owner-authorization:v1" + NUL + canonical sorted JSON)
```

The closed scalar object has exactly these sorted fields:
`after_sha256`, `before_sha256`, `challenge`, `expires_at_ms`, `gate`,
`issued_at_ms`, `kind`, `operation`, `owner_epoch`, `owner_root_id`,
`owner_subject`, `proposal_id`, `target`, `version`.
`before_sha256` is lower-case SHA256 or the literal `absent`; `after_sha256` is
SHA256. `gate` is the FULL SHA256 of the independently pinned gate SPKI DER,
not the current 16-character display fingerprint. Challenge is 32-byte lower-case
hex; proposal ID is the gate's canonical UUIDv4. Times are safe-integer milliseconds,
with at most 120000 ms between dedicated challenge issuance and expiry. Proposal
`created` and Mac time cannot substitute for gate-recorded `issued_at_ms`.
Owner epoch/root/subject must be independently enrolled and currently active.
Target formatting is checked here; the actual allowlist belongs to the gate.

Proof is `{algorithm:"p256-ecdsa-sha256", authorization, signature_base64}`.
`verifyOwnerAuthorization` requires an independent root SPKI, every exact object
field and `authorization_digest` from the gate's stored pending review. It checks
the signature, exact body, expiry (`now >= expiry` refuses) and pins, and returns
`grants_authority:false` with native activation still `UNPERFORMED`.
There is no seed read, generated key, default signer, HMAC substitution or software
authorization fallback. This public verifier cannot attest the origin of a signature.

The gate-signed receipt must contain:

```json
{"owner_authorization":{"version":1,"kind":"aukora-owner-authorization-ref/v1","authorization_id":"<body digest>","proof_sha256":"<exact proof digest>"}}
```

`authorization_id` is SHA256 of the domain-prefixed unsigned object;
`proof_sha256` is SHA256 of `aukora:owner-authorization-proof:v1` + NUL +
the fixed-order canonical proof JSON. Binding both prevents substitution of
different valid signatures or object bodies. The object does not reference the
later receipt, avoiding a circular signature dependency. Exact proof bytes must
be retained as a separate immutable object and resolvable from that reference.
`verifyOwnerAuthorizationReference` compares the reference to a verified live
object; it does NOT authenticate a gate receipt. An authenticated receipt verifier
must check the receipt's own operation/proposal/target/before/after/gate fields
against this object, plus the gate's signed reference. No caller-provided reference
or self-anchored gate key is sufficient.

`consumeOwnerAuthorization` hands the entire frozen proof/object/reference to a
trusted host's atomic durable callback. That transaction must recheck its CURRENT
clock, live challenge, active owner epoch, pending proposal, allowlisted target and
current before-state; retain the proof/reference and spend the challenge with
`pending -> applying` BEFORE any effect. Replay uses gate/challenge/proposal and
body identity, not a changeable ECDSA signature. Unknown consumption refuses and
must be reconciled without an automatic retry. Gate apply still rechecks stored
bytes and after-state. Hashes do not distinguish an A -> B -> A history; a target
revision would require a separate agreed contract if that distinction is needed.

H's current gate source implements durable review/consumption and a v3 receipt.
The actual G caller is checked against a captured, explicitly pinned H source closure
using disposable SQLite and published fixture keys. That check qualifies source
compatibility only. Grok owns merge/deploy/release switching; production registration,
native custody and old-v2 receipt consumer migration remain pending. G changes no gate
policy or existing receipt consumer. D/E cold readers need authenticated retained consumption/epoch
and receipt evidence; they must not use a self-selected timestamp to bypass live
challenge expiry. That archival API and exact H/D/E mapping remain unjoined.

`createOwnerAuthorizationBridge` in the reserved Mac bridge freezes the complete
displayed object and refuses changed replies, cancellation, expiry, missing native
presentation and approval/seed flags. It is a host seam; the native component remains
custody-unavailable and performs no signing. Peter's keyboard is NOT YET needed.

`createGateOwnerAuthorizationCaller` executes H's actual `review` and `decide_review`
grammar through the injected host-only `callGateOwner(op,args)`. It requires a separately
trusted synchronous `readOwnerState()` (closed eight-field active registry) and full
Ed25519 gate SPKI. It reconstructs the v3 review's exact 14-field authorization and
checks content hash, complete content/diff, dedicated issuance time and ledger issue
coordinate and binds the returned row to the original requested proposal before presenting.
Allowed-once sends the exact owner proof in
`owner_authorization_proof`; rejection sends only the old five fields without a proof.
Cancellation/disposal, visibility, epoch/state and expiry are rechecked around native
presentation. Each local question is spent before any dispatch; sent uncertainty returns
`unknown` with `applied:null`, with no retry. Authenticated v3 acknowledgements preserve
the receipt's original JSON signing order, verify the independently pinned gate signature
before using its signed acceptance time, and bind the exact transition, issue, owner object
and proof reference. This acknowledgement is not archival ledger/epoch verification.
There is no default transport or signer. The existing airlock/host registration writer
is outside G's allocated files and remains unassigned.

The reserved Swift authorization preview now takes `reviewedContent` and `reviewedDiff`,
checks their character/size bounds and content SHA256, and displays the full immutable
bytes/diff with all authorization facts. It still refuses every signing action before
any biometric or Keychain call. Native compilation and hardware qualification are unperformed.

Focused checks include `checks/authorization.test.mjs`: exact valid object and
reference, whole-body/owner/gate/challenge substitution, malformed ingress, expiry,
different signature references, concurrent replay, unknown settlement, cancellation
and missing signer. `checks/gate-caller.test.mjs` invokes H's real gate source/SQLite
with injected synthetic targets and public RFC6979/RFC8032 fixture keys. It adds six
groups for apply/proof retention, review tampering, custody unavailability/stale base,
inflight cancellation/epoch/expiry, authenticated acknowledgements and exact rejection.
The package check requires the H boundary-gate source in the integrated Prime tree;
it never discovers another repository or substitutes a mock gate. Eighteen groups passed
with zero skips; twenty guard-removal mutants were caught. These are source fixtures,
not native/OS/IPC qualification or an independent production evaluator.
`TRUSTED-PATH.json` mechanically records the four owned runtime sources, import
edges, hashes and external host callbacks. Its complete scope is G's verifier and
preview source; whole gate/deployment custody remains unqualified and unjoined.

This package implements a closed, domain-separated certificate request, P-256 public
verification, exact expected-key/subject/service/epoch/nonce binding, and a native
owner-action presentation adapter. It creates no key, enrolls nobody, changes no
Keychain/access setting, installs nothing and provides no live signing endpoint.
It is not yet the installed replacement for the collector's INTERIM owner key.

The owner root is a Secure Enclave P-256 key. Nostr BIP340 and NIP44 use secp256k1:
that recipient key is a separate scoped key. A P-256 root certificate binds its public
half; it must never be passed off as an Ed25519 controllerKeyHex or a Nostr signature.
No documented Secure Enclave secp256k1/Ed25519 interface was found. Current macOS26
CryptoKit also supports Secure Enclave ML-DSA; this package does not implement or claim
a hardware hybrid root.

## API and joins

`ownerKeyRequest`, `ownerKeyRequestText`, `parseOwnerKeyRequest`, `ownerKeyPreview`
and `ownerKeyRequestDigest` validate and snapshot the bounded scalar request. Only
canonical sorted JSON is accepted on the native wire, so duplicate-key spellings
are refused. Arbitrary sign-byte actions and approval booleans are not accepted.

`ownerRootPin` accepts canonical P-256 SPKI DER base64 and derives its SHA256 identity.
The pin must come from Peter's independently approved enrollment. A certificate's
own key, a Room message, UID, file mode, callback or `touch_id:true` is not enrollment.

`verifyOwnerKeyBinding(proof, expectations, nowSeconds)` requires the independently
pinned root, owner subject, audience, scope, epoch, predecessor, target key, request ID
and nonce plus the exact digest in the independently issued pending challenge. It
returns a public identity binding with `grants_authority:false`,
`custody:independent-enrollment-required` and `activation:UNPERFORMED`. A signature is
not remote hardware/biometric attestation and does not grant an operation.

`consumeOwnerKeyBinding` requires a trusted host callback that atomically and durably
checks expiry at commit, pending nonce/digest, initial-binding absence or exact predecessor/
next epoch, then consumes the challenge and persists the complete binding together.
It receives the complete immutable verified request and digest. No durable store is implemented here. Unknown results
refuse; host reconciliation must not turn uncertainty into a retry. Read-only B
certificate checks do not consume or activate anything. `expires_at` bounds the live
owner-action challenge. B's long-lived/cold binding reader must establish timely
activation from trusted retained registry evidence and apply its rotation/revocation
policy; it must not merely call this live-action verifier with a self-selected timestamp.
That archival/registry API is still a missing join.

The common `aukora:records` audience is proposed for D/E owner-recipient bindings;
`aukora:aura` and `aukora:recall` are also explicit permitted audiences, never wildcards.
B owns the P-256 seam in `plugins/aukora-nostr`: its current Ed25519 verifier is
incompatible. D must use the verified `owner-recipient` target as ownerPubkeyHex; E
uses D's verified deployment owner, never guest/session text. Scoped author bindings
use `aura-author` and remain identity evidence, not owner approval of each record.

An INTERIM-to-owner rotation must preserve historical recipient pins and old encrypted
records. This source neither copies the interim key to the Mac nor rewrites history.
B/D must define retained-history verification and a new-stream/rotation join before
activation. New certificate epoch/predecessor expectations come from trusted host
state; the certificate cannot choose its own current epoch.

## Reserved Mac sources

- `apps/aukora-desktop/owner-key-bridge.mjs`: host-only presentation adapter; no
  renderer approval flag, socket, subprocess or software signer.
- `apps/aukora-desktop/owner-key-touchid.swift`: native AppKit request validation and
  immutable approval preview; the secure custody/signing join is explicitly unavailable.

The native source shows fixed request facts and binds immutable canonical bytes.
It refuses BEFORE any biometric or Keychain operation because no independently approved
signed-host requirement, effective access group, Data Protection Keychain backend or
enrollment-policy evidence has been established. A public key pin alone is not custody;
CFEqual of opaque ACL objects is not documented policy attestation. There is no caller
boolean that enables signing, and no enrollment, migration, generation, regeneration,
private-key export or software fallback.

The future separately reviewed join must validate current native code against a pinned
SecRequirement and inspect its effective keychain-access-groups, then use the exact
approved Data Protection group/tag/token/public pin. It must authorize the enrolled
key's ACL through evaluateAccessControl(.useKeySign), with fresh operation-scoped
LAContext, Touch ID-only policy, zero device-unlock reuse, one exact digest-signing
call, no subsequent interaction/fallback, and invalidation on every completion/cancel.

Runtime eligibility, ACL attribute/equality behavior, signed-app/keychain access-group
custody, and actual per-action Touch ID behavior are UNPERFORMED. Same-UID callers
are not trusted. Do not attach the component to a production app before the approved
application identity/entitlement boundary and literal hardware checks are qualified.
The scoped secp256k1 Keychain secret lifecycle and its narrow encrypt/decrypt/sign
helper are also NOT IMPLEMENTED here; no software custody substitute is provided.

## Peter's next action, after A → D → E joins

Peter does not need to act during source preparation. The integrator must first present
the reviewed, signed native app identity, supported hardware/Touch ID state, intended
root/recipient custody and exact enrollment operation. Peter must then approve that
specific action while physically at the Mac. Only that separately approved operation
may create the root and scoped recipient, register the public root pin and issue the
first certificate. Rotation/retirement of the pilot INTERIM key needs a subsequent
explicitly reviewed action, with recovery/history preservation. None has happened.

## Focused acceptance

`node --test packages/owner-key/checks/owner-key.test.mjs packages/owner-key/checks/authorization.test.mjs` uses only the published
RFC6979 A.2.5 P-256 fixture in memory. It covers complete-body/pin substitution,
canonical ingress, expiry, predecessor/epoch checks, duplicate/concurrent consumption,
pending-request mutation, cancellation and rejection of fake approval/fallback.
It never touches Keychain, invokes Touch ID or generates a key. Its software fixture
signatures do not qualify hardware custody. Swift compilation and native/hardware
acceptance remain UNPERFORMED; no runtime build is authorized in this source pass.
`node packages/owner-key/checks/mutants.mjs` checks thirteen in-memory guard-removal mutants:
signature, expiry, pending digest, expected scope/pins, canonical wire, and atomic
consumption in each protocol, plus the authorization receipt reference. The loader lives under checks only; it creates no edited checkout or
dependency/runtime copy and is never imported by the package or native component.

Primary references: [Apple Security Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset),
[LAContext lifetime](https://developer.apple.com/videos/play/wwdc2022/10108/),
[new Secure Enclave PQ support](https://developer.apple.com/videos/play/wwdc2025/314/),
[NIP01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[RFC6979 fixture](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5).
