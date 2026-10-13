# @aukora/dsh-plugin-aumlok

The public identity/control adapter. One question, answered the same way for every consumer:
**which AUKORA subject is this, and is it still the one that was pinned?**

## C1 browser first binding (source; installation unperformed)

This adapter uses the existing v3 derivation on the node. Generated words are returned
once for the draw screen; submitted words are never echoed, logged or put in a URL.
It requires the separately provisioned HTTPS ingress and signed-in harness cookie.
It supplies no passkey enrollment, owner-state activation or release approval.

On the fresh C1 container, as its harness user, set operator inputs `C1_ORIGIN`
(exact HTTPS origin, no trailing slash), `C1_SUPPORT_ROOT`, `C1_STATE_ROOT`,
`C1_BIND_DIR` (a new, absent directory) and `C1_PATCH` (an absolute patch path).
Their parent directories must exist, belong to that user and be private.
Do not copy another node's binding, attempt database, overlay or credentials.
Set the backend's `AUKORA_SUPPORT_ROOT` to `C1_SUPPORT_ROOT` and leave
`AUKORA_STATE` unset; Kira must read the same overlay this ceremony writes.
Set `C1_STATE_ROOT` to the harness's configured `DSH_HOME`, so the generated
composition and the overlay both name its `kira-memory` directory. If this profile
uses another memory path, reconcile that composition before release approval.
From the clean reviewed checkout, with Node v24.11.1, create the patch:

```sh
node --input-type=module <<'JS'
import { writeFileSync } from 'node:fs'
import { isAbsolute } from 'node:path'
const names = ['C1_ORIGIN', 'C1_SUPPORT_ROOT', 'C1_STATE_ROOT', 'C1_BIND_DIR', 'C1_PATCH']
const [origin, supportRoot, stateRoot, directory, patch] = names.map(name => {
  const value = process.env[name]
  if (!value) throw new Error(`missing operator input: ${name}`)
  return value
})
if (new URL(origin).protocol !== 'https:' || new URL(origin).origin !== origin
  || ![supportRoot, stateRoot, directory, patch].every(isAbsolute)) throw new Error('invalid operator input')
const q = JSON.stringify
writeFileSync(patch, `- id: aukora-aumlok\n  config:\n    directory: ${q(directory)}\n`
  + `- id: aukora-face-aumlok\n  config:\n    directory: ${q(directory)}\n`
  + `    browserBinding:\n      publicOrigin: ${q(origin)}\n      supportRoot: ${q(supportRoot)}\n      stateRoot: ${q(stateRoot)}\n`,
  { flag: 'wx', mode: 0o600 })
JS
```

Add `--patch "$C1_PATCH"` to the existing reviewed harness launch command; retain
the loopback backend, public Host allowlist, secure sessions and release checks.
Disable proxy body/query logging for these routes. Then Peter signs in at the HTTPS
address, opens Aumlok, reads the cloud-derivation disclosure, chooses language and
handle, draws seven words, reveals/records/hides them, retypes all seven, checks the
acknowledgement and clicks Bind. A failed type-back spends the draw. Five failures
lock the existing attempt limiter; expiry and cancellation also require a new draw.
Browser refresh/replacement binding is refused.

As the harness user, read back the result without printing private state:

```sh
node --input-type=module <<'JS'
import { createBrowserBinding } from './plugins/aukora-aumlok/lib/browser-binding.mjs'
import { resolveMemoryIdentity } from './plugins/aukora-kira/lib/memory-identity.mjs'
const service = createBrowserBinding({ dir: process.env.C1_BIND_DIR,
  supportRoot: process.env.C1_SUPPORT_ROOT, stateRoot: process.env.C1_STATE_ROOT })
const binding = service.status()
const memory = resolveMemoryIdentity({ supportRoot: process.env.C1_SUPPORT_ROOT, installed: true })
if (!binding.ok || !binding.bound || binding.subject !== memory.subject) throw new Error('binding readback refused')
console.log('C1 verified binding and Kira overlay agree')
service.close()
JS
```

Refresh the page and repeat readback after the operator's approved restart. Kira
must subsequently mount using this support overlay; an already failed Kira mount
is not revived by writing the file. This default is lexical memory; it establishes
no semantic recall. The node retains a private attempt database
and an exclusive first-bind marker. Missing attempts, a stale marker, or a bind
that wrote the record but failed the overlay require inspection; never delete
these to retry. This source check proves neither real HTTPS/session policy,
human identity, authenticator custody, a model reply nor installed containment.

`plugins/aukora-nostr/lib/vendor/noble-curves` is canonical for the 27 payload and
licence files under this plugin's same directory. `tests/pinned-copies.test.mjs`
checks their equality; each plugin retains its own provenance manifest.

```js
import { projectPublicControl, admitPublicControl } from '@aukora/dsh-plugin-aumlok'

const projection = projectPublicControl({ genesis, activeControl, custodyClass })
// { domain, subject, epoch, activeControlDigest, revoked, approvalKeyDid, custodyClass }

const verdict = admitPublicControl({ projection, expected: pinned, signerPublicKeyPem })
// { ok: true, subject, epoch, activeControlDigest, approvalKeyDid }
// { ok: false, reason: 'aumlok:control-signer-mismatch', detail: '…' }
```

As a Cordis plugin (`exports["./service"]`), mounted from a composition row by absolute path:

```yaml
- id: aukora-aumlok
  name: "<release>/plugins/aukora-aumlok/lib/service.mjs"
  config:
    directory: "<controller-directory>"
```

It registers `ctx.aumlokControl`, injects no service (`inject = []`), and imports only its sibling
modules, never `@deepseek-ai/cordis`. See the mount note in
`scripts/aumlok/PROVENANCE.md` for why it must not import `@deepseek-ai/cordis`.

## The four facts it keeps distinct

| Field | Source | Changes when |
|---|---|---|
| `subject` | `sha256` over the content-addressed **genesis** record (a changed record yields a different subject) | a different genesis. **Never** on a key rotation. |
| `epoch` | the active control head | a control transition |
| `activeControlDigest` | digest of the active head | a rotation or a revocation |
| `revoked` | the active head's terminal state | revocation only |
| `approvalKeyDid` | `did:key` of the registered Ed25519 approval key | a rotation |

`custodyClass` and `domain` travel with them so a consumer cannot read the identity facts without
being able to read which class of custody produced them.

A fifth thing — scoped `root`/`device`/`session`/`agent` delegation claims — is *checked* here and
granted nowhere. `verifyDelegationAttenuation` returns named refusals about scope and never returns
"allowed". A matching name, a matching DID, or an unsigned claim never authorizes.

## The owner approval channel (D2)

A separate signer process on the same uid holds the registered key and signs over an exact preimage;
the broker verifies before anything settles. This is process separation, not isolation
(`OWNER_KEY_SAME_UID: true`).

```js
const session = createOwnerApprovalSession({ projection, expectation, socketPath })
await session.approve({ operationDigest, expiresAt })
// { ok: true, subject, activeControlDigest, approvalKeyDid, operationDigest, challenge, signature }
// { ok: false, reason: 'aumlok:channel-unavailable', detail: 'ENOENT: …' }
```

Each `approve()` re-admits the projection the session was opened with; it does not re-read the
controller. `approveOperation` and `settleOperation` reload and re-admit the controller on every call,
so they catch a rotation or revocation between two calls. A long-lived session does not. The signed bytes are
`'aukora:owner-approval-signature:v1' + NUL + canonicalJSON({subject, activeControlDigest,
operationDigest, challenge, issuedAt, expiresAt})`, re-derived by the verifier from **its own**
request, and verified under the key decoded back out of `approvalKeyDid` — D1's rule that the
verifier derives the DID from the key whose signature it verified.

`approve()` returns a named refusal rather than throwing. `APPROVAL_REFUSE` names ten: unavailable,
malformed, expired, channel-unavailable, channel-timeout, channel-protocol, refused, challenge-mismatch,
replayed and signature-invalid. The signer's not-ready reasons (`aumlok:unbound`, `aumlok:no-seed`) and
`aumlok:signer-socket-path-too-long` pass through under their own names. Opening a session without a
socket path throws a `TypeError`. The names are distinct because whether to restart a process, replace a
key or investigate is a different decision in each case.

The signer mandates a `review` procedure and ships no default: `signer:no-reviewer` exists so that an
unconfigured signer cannot approve by omission. `scripts/aumlok/signer.mjs` has three approver modes:
`test-all` (prints `NOT a human review`), `decline-all`, and `popup` (a native dialog that fails closed).
No court drives `popup` or `lib/approval-popup.mjs` **[CODE ONLY]**.

## The interface another lane consumes: one digest in, one artifact, one gate

`lib/operation-approval.mjs` is the NAMED surface, and `scripts/aumlok/` wraps it in three commands.
The artifact is an `aukora:approval-receipt:v1` record and nothing else — no envelope, no second copy
of the digest. `scripts/aumlok/verify-approval` runs from an empty working directory given only the
receipt and the public key. It still loads this checkout's adapter and rebuilds the signed bytes with the
functions that produced them, so it is a same-implementation check, not an independent verifier.

```
scripts/aumlok/approve-operation \
  --controller <dir> --expect-subject <aukora:1:…> --expect-control-digest <64 hex> \
  --operation <content file> --operation-digest <64 hex> \
  --signer-socket <path> --artifact-out <artifact.json> --expires-at <unix seconds> \
  [--approval-class scripted|delegated|unattributed] [--key-class B]

scripts/aumlok/settle-operation \
  --controller <dir> --expect-subject <aukora:1:…> --expect-control-digest <64 hex> \
  --operation <content file> --state <disposable dir> [--artifact <artifact.json>]
```

The digest is fixed and re-derivable by anyone holding the content — `operationDigestOf` computes it,
and there is exactly one accepted convention:

```
operationDigest = sha256( utf8("aukora:operation-content:v1") ‖ 0x00 ‖ contentBytes )
```

```js
import { operationDigestOf, approveOperation, settleOperation } from '@aukora/dsh-plugin-aumlok'
const receipt = await approveOperation({ directory, expectation, content, operationDigest, socketPath, expiresAt })
const verdict = settleOperation({ directory, expectation, artifact, content, stateDirectory })
// { ok: false, reason: 'aumlok:approval-operation-mismatch', detail: '…', results: […] }
```

Neither function throws on an operational failure and neither holds a key: approvals go to the
separate signer process over its socket, and a missing signer is `aumlok:channel-unavailable` rather than a
fallback signature. Refusals, by name:

| Refusal | The fact it names |
|---|---|
| `aumlok:settlement-no-approval` | no artifact at all: an bound identity is not an approval |
| `aumlok:approval-unavailable` | the identity is not the pinned/admitted one, or the artifact names another |
| `aumlok:approval-expired` | the window had closed at mint time or at use time |
| `aumlok:approval-key-mismatch` | the artifact names a key the pinned identity does not register |
| `aumlok:approval-operation-mismatch` | the presented content does not derive the approved digest |
| `aumlok:approval-signature-invalid` | the signature does not verify under the registered key |
| `aumlok:approval-replayed` | this challenge was already consumed once |
| `aumlok:approval-boolean-is-not-consent` | a boolean was offered as the approval |

**No boolean is an approval.** `approve-operation` has no `--confirm`/`--yes`/`--force` that produces
anything; passing one is refused by that last name, with or without a signer, and writes no artifact.

**A second invocation that presents the same challenge is refused**: an `O_EXCL` marker per challenge
in `--state`, measured on a local filesystem across two processes. The marker is written only after the
signature verifies; that ordering is code-read, and no arm yet presents a bad signature over the same
challenge and counts markers. The marker is not fsynced, so crash durability is not measured. NFS, a
second host, and a writer that rewrites the state directory are not measured either.

**An approval is not attendance.** The signer's approver is a labelled procedure, the artifact records
`attendance: reported-not-proven`, `identityBound` is `false` on every path, and the settlement record
says the gate opened — not that anything in the world was performed.

## Is the key in this record the key this record registers?

`lib/identity-correspondence.mjs` answers that over the **stored bytes**, which nothing else did: every
other reader checks the public half, and the genesis commitment covers public keys, so a record whose
`mlDsa65SecretKeyHex` was filler of the right LENGTH reads back perfectly.

```
scripts/aumlok/verify-identity --controller <dir> --read-secret-half [--expect-subject … --expect-control-digest …] [--json]
```

It proves, in one process: Ed25519 correspondence (stored private key → registered public key, DID
re-derived rather than string-matched), ML-DSA-65 correspondence (`getPublicKey(storedSecretKey)` equals
the registered public key), and an ML-DSA-65 round trip **with a negative probe**, so a verifier that
answered `true` unconditionally could not pass. It refuses by name
(`aukora:identity-ed25519-correspondence-failed`, `aukora:identity-ml-dsa-65-correspondence-failed`, …)
and prints `ML_DSA_65_CONFORMANCE: not-established`, `IDENTITY_BOUND: false`, `AUTHORITY: none` and
every ceiling on the accepting path too.

`--read-secret-half` is required: the flag is the acknowledgement that this reads private key material,
which is itself a same-uid act, not isolation. `--json` prints one machine-readable document — and
still no private material.

## What it refuses to do

* The public projection and admission path (`projectPublicControl`, `admitPublicControl`, the loader)
  does not authorize, sign, or create or rotate a controller. The package also ships the v3 ceremony
  (`bindV3`, `refreshBindingV3`), signers (the owner signer, the machine signer, the handover and
  root-class signing) and a settlement gate (`settleOperation`). Those modules do create, rotate, sign
  and open a gate, each with its own courts.
* `projectPublicControl` and the loader never return private key material (the result is built field by
  field). The ceremony exports `bindV3`, `readKeptMachineSeed` and `rootPrivateKeyOf` return seeds or
  private keys by design.
* No module in the package emits `identityBound: true` (`tests/aukora-aumlok.test.mjs` asserts it), and
  it claims no hardware custody or succession.
* It does not half-verify. The root-control suite is hybrid; a promotion refuses by name unless
  **both** halves can be verified.

`project`, `make-disposable-identity`, `verify-identity`, `approve-operation`, `settle-operation` and
`bind` print the ceilings in `lib/ceilings.mjs`, and `signer.mjs` and `diagnose` print its signer ceilings.
Courts assert them on the accepting paths of `verify-identity`, `approve-operation` and `settle-operation`
(all lines) and of `project` and `make-disposable-identity` (one line each); not for `bind`, `diagnose` or
the signer's stdout. `rehearse-rotation`, `bind-overlay` and `verify-repoint` print none. `verify-approval`
prints the ceilings carried in the receipt, which the signature does not cover.

## Offline guesses and the node limit

`derive-v3.mjs` derives both root seeds on the member's device from the normalized phrase
and `aumlok-kdf-v1` + NUL + normalized handle. An attacker with the handle and any oracle
below can repeat that computation without contacting a node. A public handle adds **zero
secret bits**; the statement in the derivation header that it raises 14.3 bits to 34.14 is
incorrect. Derivation bytes have not changed.

Two phrase sources exist. `lib/ceremony-phrase.mjs` retains the 18-anchor generator whose
header states about 14.3 bits; `lib/index.mjs` no longer exports its draw function. The desktop
uses `apps/aukora-desktop/aumlok-draw.mjs` and the shipped `data/aumlok-themes.json` instead.
`lib/themed-entropy.mjs` measures **34.142338 bits for that data's phrase alone**, with no
handle input. That estimator is a minimum-entropy calculation over bucket sizes, not a
count of equiprobable outputs or a measured attack time; duplicate removal and user choice
need their own distribution analysis. The desktop drawer should remain the supported
ceremony; the retained generator must not become a second enrollment path.

The implemented scrypt parameters are `N=2^17=131072`, `r=8`, `p=5`, output 64 bytes,
`maxmem=256*1024*1024`. The main working array is
`128*N*r = 128*131072*8 = 134217728 bytes = 128 MiB`; `maxmem=256 MiB` is an allocation
limit, not a throughput or dollar-price measurement. Five calls to the existing public
synthetic benchmark on 2026-10-12, Node **v24.11.1**, Apple M4, macOS arm64, measured
`s=1.2944057418 seconds/guess`. Reproduce without any owner's phrase or handle:

```sh
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
node --input-type=module -e 'import {measureKdfSecondsPerGuess} from "./plugins/aukora-aumlok/lib/derive-v3.mjs"; console.log(await measureKdfSecondsPerGuess({samples:5}))'
```

Expected output has `samples: 5, N: 131072, r: 8, p: 5` and a machine-dependent
`secondsPerGuess`. This measures the KDF only. With an exposed Ed25519 root key, a guess
also needs Ed25519 public-key derivation; testing only a rootId requires ML-DSA public-key
derivation too. Neither extra cost is included. These numbers do not measure optimized
attack hardware, concurrent-worker throughput, Linux performance, or rented-hardware price.

For a worker costing `c` dollars/hour: `g=1/s=0.7725552875 guesses/second`,
`g/c=0.7725552875/c guesses/second per dollar/hour of capacity`, and
`3600*g/c=2781.199035/c guesses/dollar`. Taking **c=$1/worker-hour as an illustrative
normalization, not a market price**, gives 2781.199 guesses/dollar. For `P` independent
workers at the same measured speed, divide elapsed time by `P`; total worker cost stays
constant. Memory bandwidth and hardware determine whether that scaling is achieved.

| Assumed search space | Full enumeration `M*s` | Uniform expected search `(M/2)*s` | Expected cost at illustrative $1/worker-hour |
|---|---:|---:|---:|
| Known handle, `M=2^14.3=20,171.070` phrase candidates | 26,109.549 s = 7.253 hours | 13,054.774 s = 3.626 hours | $3.626 |
| Unknown handle, **assumed** `M=2^34=17,179,869,184` phrase/handle pairs | 22,237,721,315 s = 704.671 years | 11,118,860,658 s = 352.335 years | $3,088,572.405 |

A year here is 365.25 days. These are the requested search-space scenarios, not measured
candidate distributions: min-entropy alone does not establish uniform expected search.
There is no source measurement giving an unknown handle 19.7 additional secret bits, so
`2^34` must not be claimed merely because the handle is unknown. Handles appear in public
records; discovering one removes its search dimension. The themed-data figure and the
legacy 14.3-bit figure concern different generators.

Public verification oracles in these repository formats are:

- `local-control.json` version 3 and `recordProjection()`: `publicRoot.rootId`,
  `publicRoot.ed25519` or `publicRoot.mlDsa65`; `publicRoot.handle` supplies the salt.
- Genesis `initialRootKeySetId`, the v3 public-control projection's `activeControlDigest`,
  and a v3 `aukora:approval-receipt:v1`'s `activeControlDigest`: each identifies that rootId.
- `aukora:aumlok-handover:v3`: `fromRootId`, `toRootId`, or its `signerKeyHex` and signature
  over `handoverSigningBytes`; the statement also includes the handle when present.
- Root-class `signOperation()` output: `publicKeyHex`, or its signature and the exact
  `aukora:aumlok-root-class:v3` request bytes (`act`, `subject`, `epoch`).
- Controller `machines[].{index,ed25519}` and `aukora:aumlok-machine-answer:v3`
  `by.{machineIndex,ed25519,keyId}`: derive the candidate root, then its machine Ed25519 key
  with `aumlok-machine-kdf-v1` and the index; compare the key or verify the signed bytes.
- A machine-signed `aukora:nostr-identity-binding:v1`: its `statement.handle`, document-level
  `signerKeyDid` and signature provide a check when the machine index is known or guessed (first bind is 0).

A modern subject digest alone omits the genesis nonce needed to recompute it. An independently
generated Nostr event key alone is not a phrase-root oracle. An oracle need not include a
signature when it already contains a comparable root or deterministic machine public key.

`lib/attempt-limit.mjs` is a node-side library for counting presentations per claimed subject
in a durable store. It does not run inside `derive-v3.mjs`, and this change does not mount an
enrollment endpoint. The materializer already carries this plugin's `lib` and `data` and
mounts `lib/service.mjs`, but supplies no controller directory in its default composition
row: that service reports `aumlok:adapter-unbound` until configured. Its current methods
project and admit control; they do not call the attempt limiter. A node needs an authenticated
possession challenge, a trusted enrolled-root lookup, protected attempt-state ownership, and
an endpoint that uses this limiter before recognition. Merely matching a public key is not
proof that the presenting device holds its private key. An attacker can also consume the
online allowance for another subject; recovery and denial-of-service policy remain decisions.

Owner decisions remain: increase independently generated word entropy; require a second
factor that an offline attacker cannot reconstruct; use a hardware-held signing key with a
recovery procedure; or split recovery authority across parties with a stated threshold,
collusion and loss policy. A five-guess node lockout does not replace any of these decisions.

> The arithmetic in the section above was written before new phrases became seven words from 2,048 (77 bits; see "Seven words" below). It describes the two LEGACY generators, which are no longer used to make a phrase.

## Node presentation limit (library only)

Import `lib/attempt-limit.mjs` directly under Node v24.11.1. `openAttemptLimiter({file,
rootForSubject, initialize})` uses a dedicated SQLite file; `initialize: true` explicitly
creates its schema. Reopening without that option refuses missing state. The synchronous
node-owned lookup returns the current pinned `rootId` for a canonical `aukora:1:<64 hex>`
subject, or `undefined`. It must use the stored genesis lineage and current control record,
not treat the subject suffix as the current rootId. Devices supply only `{subject, rootId}`
to `present()`; they must not choose the lookup, clock, store, or policy.

Defaults are `limit: 5`, `baseMs: 60000`, `maxMs: 3600000`. The fifth failure locks for
60 seconds; each failure after expiry doubles the interval up to one hour. Locked requests
do not extend the deadline. Successful recognition preserves failure history, because
anyone can replay a public root. Policy is stored and must match on reopen. State updates
serialize across processes and commit before a verdict; storage errors refuse. A persisted
last-seen clock prevents clock rollback from shortening an interval.

Unknown subjects, malformed roots, wrong roots, locks, and operational failures return
exactly `{ok:false, reason:'aumlok:enrollment-refused'}`, without existence, counter or
retry-time fields. Unknown subjects receive the same counters. This is response-shape
non-disclosure, not a measurement of network or lookup timing. Recognition returns
`{ok:true, recognized:true, authority:'none'}`; it creates no device or permission.

An operator can run this disposable probe as `aukora-host` from a materialized release,
using Node v24.11.1 and a writable local temporary directory:

```sh
umask 077
node --input-type=module <<'JS'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { openAttemptLimiter } from './plugins/aukora-aumlok/lib/attempt-limit.mjs'
const directory = mkdtempSync(join(tmpdir(), 'aumlok-attempt-probe-'))
const subject = 'aukora:1:' + 'a'.repeat(64), rootId = 'b'.repeat(64)
let clock = 1000000, limiter
const options = { file: join(directory, 'attempts.sqlite'), now: () => clock,
  rootForSubject: claimed => claimed === subject ? rootId : undefined }
try {
  limiter = openAttemptLimiter({ ...options, initialize: true })
  console.log('BEFORE', limiter.present({ subject, rootId }).ok)
  for (let n = 0; n < 5; n++) limiter.present({ subject, rootId: 'c'.repeat(64) })
  limiter.close()
  limiter = openAttemptLimiter(options)
  console.log('LOCKED_AFTER_REOPEN', limiter.present({ subject, rootId }).reason)
  clock += 60000
  const result = limiter.present({ subject, rootId })
  console.log('AFTER_INTERVAL', result.ok, result.authority)
} finally { limiter?.close(); rmSync(directory, { recursive: true, force: true }) }
JS
```

Expected output: `BEFORE true`, `LOCKED_AFTER_REOPEN aumlok:enrollment-refused`,
`AFTER_INTERVAL true none` (Node may also print its SQLite experimental warning).
This probe uses synthetic public values and an injected clock; it does not enroll an owner
or show that a mounted node route calls the limiter. Regression and mutation checks are
`node tests/aukora-aumlok-attempt-limit.test.mjs --mutate` from this checkout.

For a real route, provision one persistent database outside the release directory, in a
directory accessible only to its trusted node service, with umask 077. Every worker for
that node must use the same file. Do not recreate or restore older attempt state on restart.
SQLite assumes local filesystem locking and sync semantics; NFS, power-loss behavior,
same-UID tampering, malicious storage rollback, and multiple nodes sharing one allowance
are not established here. The `aukora-host` process can itself rewrite its own store; use
a separate authority process if that process is an adversary. Rate limits on total traffic
and new subjects are still needed to bound database growth. A mounted challenge and
owner-authorization route, state provisioning, operator recovery, and Linux acceptance
remain unperformed. The existing adapter should consume this library when that route is
implemented; no second identity or derivation implementation is needed.

## No build step

The modules under `lib/` are the shipped bytes. Nothing transpiles or bundles them, so the digest a
reviewer checks is the digest that runs. Every static single-quoted `from` import in the top-level
`lib/*.mjs` is a `node:*` builtin or a sibling (an arm in `tests/aukora-aumlok.test.mjs`).
`pq-generator.mjs` also dynamically imports the vendored, pinned `@noble/post-quantum` closure in
`lib/vendor/noble-ml-dsa` (see its `PROVENANCE.md`), which that arm does not scan.

## Seven words: source inventory and migration

New phrases use `lib/ceremony-phrase.mjs`: seven independent, uniform draws with replacement
from one 2,048-word BIP-39 list, using the platform CSPRNG. Thus
`7 × log2(2048) = 77 bits`; the public handle contributes no secret entropy.
The ten languages and pinned list hashes are in
[`lib/vendor/bip39-wordlists/manifest.json`](lib/vendor/bip39-wordlists/manifest.json).
They were copied offline from `@scure/bip39` 2.0.1 with its MIT license. These are
seven-word Aumlok phrases, not BIP-39 wallet mnemonics or checksums. NFKD spelling and
Japanese ideographic spaces are accepted; an unknown word is named in the refusal.

The existing v3 salt and scrypt remain `aumlok-kdf-v1`, N=131072, r=8, p=5,
64 output bytes and maxmem=256 MiB. The algorithm's memory term is `128 × N × r = 128 MiB`.
At one second per guess, a uniform phrase needs `2^76` guesses on average, about
`2.394 × 10^15` years on one such worker; multiply by the measured seconds per guess
and divide by parallel workers. This is arithmetic, not a hardware benchmark or a
77-bit claim for words chosen by a person. A local macOS run under Node 24.11.1
(three samples) measured 0.858250 seconds per guess: `2^76 × 0.858250 / 31557600 ≈
2.055 × 10^15` serial core-years on that measured worker. This does not measure an
attacker's hardware or the cost of checking any separately retained fast fingerprint.
Existing ASCII phrase/handle pairs retain
their derived keys. Old acrostics remain accepted and are labelled **legacy phrase, weak**.

The inventory below refers to the pre-change revision `2a605d3706328ae46718cfe0c836178646c67342`:

| Location at that revision | Vocabulary and selection |
|---|---|
| `lib/derive-v3.mjs:5` | Claimed about 14.3 bits for the phrase and 34.14 for the pair. A public handle does not supply the difference; these were two different generators. |
| `lib/ceremony-phrase.mjs:29–110` | 18 anchors; 94 root, 88 unite and 80 rise words, in 25 letter buckets each (2–4 words). A fixed anchor/root/root/unite/unite/rise/rise acrostic used a random byte modulo each pool length, excluded repeats, and had a fixed fallback. Enumerating its output probabilities gives 14.3401 bits of min-entropy. |
| `apps/aukora-desktop/aumlok-draw.mjs:149,236,295` | `crypto.randomInt` chose one of 150 anchors, then six words restricted by its initials and the NATURE/NATURE/PEOPLE/PEOPLE/SPIRIT/SPIRIT grammar, excluding repeats. `data/aumlok-themes.json` contained 683/1,198/677 entries. |
| `lib/themed-entropy.mjs:24,353` | Historical pool estimate `log2(150) + 26.913519 = 34.142338` bits; best alternative letter gate 36.310947. This estimate assumed uniform bucket choices and did not model rejection of repeated words. |
| `lib/ceilings.mjs:129,180`, `lib/ceremony-verify.mjs:52,59`, `lib/index.mjs:191` | Repeated the old strength estimates. Historical data provenance retains its dated figures. |
| Both face source trees, `src/client/AumlokSurface.tsx:316` | Requested a draw through `control-projection.ts:123`, `binding-bridge.ts:177`, then desktop `aumlok-bridge.mjs:618`; no separate face RNG. The mirror is `plugins/aukora-face/aumlok`. |

The older candidate files `data/theme-nature.json`, `theme-people.json` and
`theme-spirit.json` contain 8,656, 19,157 and 9,260 entries. They are historical harvest
inputs, not the active vocabulary. The EFF safety fixture contains 7,773 words and
their codes (the original 7,776 minus three removed entries). Small legacy tables
remain for compatibility validation and historical inventory; new generation does not use them.

Read-only `git log -S` and historical-source measurements in the Genesis checkout found
the remembered stronger version: `a2520b0b6` measured **60.461383 bits** over 1,364
drawable anchors, with 8,445/18,155/8,578 themed entries. It exists on
`origin/cursor/aumlok-drop-theme-c75d`, not the Genesis main revision `9572138ef`
imported by Prime's squash `c358ac7`. Subsequent commits on that branch narrowed the
pools: `4d07844b5` measured 39.718075 bits and `51e74cbeb` 33.576950.
On the older main lineage, `245990b74` measured 58.983292 and refused below its 64-bit
floor; `1118a94c5` retired that floor, then `80772f29e` applied commonness and
pleasantness filters and reached 34.142338. Earlier still, `efd97b44f` added an
independent seven-word EFF generator (`7 × log2(7776) = 90.474 bits`);
`3a5574346` removed it and both list copies in favor of the small acrostic.
These source/history findings do not establish which version was installed or used.

## Reviewing it

The seven-word changes are checked with `node --test tests/aukora-aumlok-words.test.mjs`
and `node tests/aukora-aumlok-words.test.mjs --mutate`, plus the language and UI tests.
The face source and its mirror were changed together; the compiled face bundles were
not rebuilt (this clone has no built `vendor/dsh`). No installed-app or Linux run is
claimed for this change. Historical commands below describe earlier checks.

```bash
node tests/aukora-aumlok-cold-root.test.mjs
node tests/aukora-aumlok-verify.test.mjs
node tests/aukora-aumlok-fresh-bind.test.mjs
node tests/aukora-aumlok-attempt-limit.test.mjs --mutate
```

The previously documented `aukora-aumlok`, signer, approve and mount test files are absent
from this checkout; their historical arm counts are not current results. The historical
mount suite booted a disposable DSH profile over a release,
let the **real Cordis loader** load `lib/service.mjs` from an absolute composition path, and had a
second plugin with `inject = ['aumlokControl']` consume it. Its negative control mounts the same
consumer with no aumlok row — Cordis withholds an unsatisfied dependency, so the consumer does not
activate and its report is absent. Because the mount row configures no `capabilities`, the consumer's
promotion call must come back `aumlok:ed25519-point-validator-unavailable`, which is the fail-closed
behaviour arriving in the host rather than a gap the mount fills.

`scripts/aumlok/PROVENANCE.md` records the Deep source pin, the per-module port map, the measured
compatibility mapping between Deep's hybrid root-control layer and Genesis's Ed25519 action signer,
and the two checks this closure cannot perform.
