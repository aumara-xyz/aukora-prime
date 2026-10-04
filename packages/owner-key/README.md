# Owner key: source-only P-256 certificate boundary

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

`node --test packages/owner-key/checks/owner-key.test.mjs` uses only the published
RFC6979 A.2.5 P-256 fixture in memory. It covers complete-body/pin substitution,
canonical ingress, expiry, predecessor/epoch checks, duplicate/concurrent consumption,
pending-request mutation, cancellation and rejection of fake approval/fallback.
It never touches Keychain, invokes Touch ID or generates a key. Its software fixture
signatures do not qualify hardware custody. Swift compilation and native/hardware
acceptance remain UNPERFORMED; no runtime build is authorized in this source pass.
`node packages/owner-key/checks/mutants.mjs` checks six in-memory guard-removal mutants:
signature, expiry, pending digest, expected scope/pins, canonical wire, and atomic
consumption. The loader lives under checks only; it creates no edited checkout or
dependency/runtime copy and is never imported by the package or native component.

Primary references: [Apple Security Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset),
[LAContext lifetime](https://developer.apple.com/videos/play/wwdc2022/10108/),
[new Secure Enclave PQ support](https://developer.apple.com/videos/play/wwdc2025/314/),
[NIP01](https://github.com/nostr-protocol/nips/blob/master/01.md),
[RFC6979 fixture](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5).
