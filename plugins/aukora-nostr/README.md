# @aukora/dsh-plugin-nostr

A Nostr identity per node, and the binding that says which AUKORA subject owns it.

The source-only [Nostr-shaped records library](RECORDS.md) adds closed record
construction, verification, NIP-44 v2 content and chain checks through `./records`.
It does not establish journal coverage, owner authority or installed collection.


## contentDigest is local; the EVENT ID is the identity

**`contentDigest` is a digest of the wire bytes THIS node retained, so two nodes holding the same
message digest it to DIFFERENT values** — a relay round trip re-serializes, and each node's
`sha256(retained bytes) == its own contentDigest` is the only equality that holds. Measured on a real
send and receive, 2026-09-24: the sending peer filed `1bf3cd65…` and the receiving node filed
`cbcd7246…` for the same event, both sound. **So never match a sent copy to a received one by
`contentDigest`.** The cross-node identity is **`eventId`** — the SHA-256 of the event's canonical
serialization, invariant under how the bytes are spelled — and it matched exactly.
That is a retained 2026-09-24 measurement. The test that originally pinned both
halves is not present in this checkout.

## What exists today

`lib/identity.mjs` — the Nostr keypair and the binding.

- **A secp256k1 / BIP-340 key** per node, stored under `<stateDir>/nostr/identity.json` at mode 0600.
  A mode check is not custody, and the verdict says so.
- **`npub` encode/decode** (bech32), with the checksum enforced: a bad npub is refused by name rather
  than decoded into bytes.
- **The binding**: `{"this npub belongs to subject X"}`, signed by the **AUMLOK ed25519** key. The
  Nostr key is the *subject* of the statement; the Aumlok key is its *signer*, and an arm refuses a
  structurally perfect binding signed by a different controller.
- **Three verifiers share `evaluateBinding`'s structural and signature checks.** `verifyBinding`
  checks against a controller **record on this machine** and answers *"did OUR controller issue
  this?"*; `verifyBindingWithKey` checks against a controller **public key given directly as hex** and
  answers *"did the key we were told to expect sign this?"*. Each of those two applies its own subject
  routing check, so that part is duplicated rather than shared. The third, `verifyBindingUnderItsSigner`
  (exported from `index.mjs`), checks a document against the key it names: it is for classification
  only and must never be used for trust. The trust verifiers answer with a NAMED refusal — `binding-domain-unknown`,
  `binding-signature-invalid`, `binding-npub-mismatch`, `binding-subject-mismatch` — never a boolean.
  Pointing the first one at a friend's binding reports a signature failure, and that is not a forgery:
  our key is genuinely not its signer.

### Contact states: what we actually know about the other end

A **contact record** is `{npub, peerControllerKey, label?}`, where `peerControllerKey` is the peer's
Aumlok ed25519 **public** key as 64 hex characters, exchanged out of band — read aloud, scanned, or on
paper. That key is the trust anchor. `resolveContact({npub, peerControllerKey, binding, expectSubject})`
verifies the binding **against it**, so the answer is "is this my friend's npub?" and not "did I issue
this?" — `controllerDir` is passed instead only for a binding this node issued itself.

Five states (corrected 2026-09-26; the code replaced a four-state model):

| state | what it means | `sas` |
| --- | --- | --- |
| `VERIFIED` | a binding verifies under this contact's recorded peer key, AND a confirmation the owner signed over this npub, this controller key and the six digits verifies | present |
| `BOUND` | the binding verifies, but nobody has confirmed it, or the confirmation is stale | present |
| `TEST` | the binding verifies and is TEST-labelled — every binding today, because the only enrolled controller is disposable | present |
| `UNBOUND` | **no binding was presented at all** | `null` |
| `FOREIGN` | a binding WAS presented and it does not attest to this contact, or a presented confirmation does not verify | `null` |

**`FOREIGN` is two facts, each with its own named reason**, because a caller may act differently on
each:

- *signed by another controller* — the signature verifies, under a key that is **not** the one this
  contact records: `signed by controller X, this contact records Y`. Someone signed for this npub and
  it was not the key we agreed to trust.
- *does not verify* — the signature fails under the contact's recorded key: a forged, corrupt or
  re-pointed document.

A contact record whose `peerControllerKey` is not 64 hex characters is refused **by name**
(`contact:peer-controller-key-malformed`), never quietly reported as `FOREIGN`: a typo in the anchor is
a different fact from a binding that fails to verify, and reporting the first as the second sends
someone hunting an attacker when they should be re-reading a key.

**The SAS, and what comparing it proves.** A short authentication string — six decimal digits, shown
as two groups of three — is derived from `sha256('aukora:nostr-sas:v1' ‖ peerControllerKey ‖ npub) mod
10^6` (the first 64 bits, reduced mod 10^6). Because **both halves are in the preimage**, a match is
evidence that both people hold the same controller key and npub, at about 20 bits. It is not a
commitment scheme: an attacker who controls the key exchange can grind a matching six digits offline in
about a million tries, so this is the weak form of the check. Two npubs under one controller differ; one
npub under two controllers differ.

**A SAS is produced for `TEST`, `BOUND` and `VERIFIED`.** `UNBOUND` and `FOREIGN` carry `sas: null`, and
`sasFor` throws `contact:no-sas-without-a-binding` or `contact:no-sas-for-a-failed-binding` rather
than returning a placeholder. Handing someone a string to compare for an unproven contact is worse
than showing nothing — it launders a guess into a ritual, and the two people come away believing they
confirmed something.

`lib/event.mjs` — NIP-01 events. The id is sha256 over the canonical
`[0, pubkey, created_at, kind, tags, content]` array, **not** over the event JSON; the signature is
BIP-340 over the id's 32 raw bytes, not over its hex text. `signEvent` refuses when the signing key is
not the key the event claims.

`lib/nip44.mjs` — the payload layer: ECDH, HKDF, padding, ChaCha20, HMAC. Interoperable, proven
against the published NIP-44 vectors.

`lib/giftwrap.mjs` — NIP-59 gift wrap and NIP-17 direct messages:

- **rumor** (kind 14) unsigned, **seal** (kind 13) signed by the real author with empty tags,
  **gift wrap** (kind 1059) signed by a **fresh random key per message** with the only `p` tag.
- **The MUST:** after unsealing, the rumor's `pubkey` is compared to the seal's. The seal proves who
  *sealed*; without this comparison any sender can claim any author, because the rumor is unsigned.
  It is a named refusal, `nostr:sender-mismatch`, checked **after** the seal's signature.
- `composeDirectMessage` produces one wrap per recipient **and one for the sender**, because there is
  no server-side history — the sender's own copy is the only record of what they sent.

### What the relay can and cannot see

In the retained historical court account, a published wrap contains neither the message text, nor the
author's pubkey, nor the inner kind. It **does** contain the recipient's `p` tag, which is the
documented limit of NIP-17 — and exactly why the spec tells relays to gate `kind:1059` behind NIP-42
AUTH. Until we only publish to relays that do, "no metadata leak" is not a claim this lane can make.

## The two vendored primitives, and why

**Node lacks two primitives this lane needs, and they fail in opposite ways.** Both are measured facts,
recorded by the historical pin court. That court is not present in this checkout.

**1. BIP-340 Schnorr — absent, and silent about it.** Measured 2026-09-22:
`crypto.sign(null, msg, {key, scheme:'schnorr'})` accepts the option, ignores it, and returns a DER
ECDSA signature (70, 71 and 72 bytes across runs, where BIP-340 is *always* exactly 64) — and
`crypto.verify(..., {scheme:'schnorr'}, sig)` returns **true**, because it verified ECDSA. A caller who
passes the option and checks only "did it verify?" ships bytes every relay rejects, late and quietly.
This is a fail-open, not a missing function.

**2. IETF ChaCha20 (RFC 8439) — absent, and loud about it.** Node's `chacha20` is the OpenSSL
*original* with a 128-bit IV. A 12-byte nonce — the size RFC 8439 and NIP-44 both specify — is rejected
outright (`ERR_CRYPTO_INVALID_IV`), and a 16-byte IV reproduces *neither* byte order of the RFC 8439
§2.4.2 ciphertext (`51448c64…`, `1a7481d7…`, where the RFC says `6e2e359a…`). `chacha20-poly1305` *is*
present and is deliberately **not** used: NIP-44 wants a bare ChaCha20 stream plus a separate
HMAC-SHA256, and the AEAD authenticates a different byte range, so AEAD payloads are unreadable by a
NIP-44 reader.

The removed pin court asserted the non-64-byte signature, the refused 12-byte
nonce, and that a 16-byte IV did not reproduce the RFC vector. Those are retained
2026-09-22 results, not assertions run by this checkout.

So `lib/vendor/` carries two **pinned, vendored** trees — on identical terms:

- `noble-curves/` — `@noble/curves@2.4.0` + `@noble/hashes@2.4.0` (both MIT). This is the static-import
  closure of `secp256k1.js`, which is **broader than `schnorr` strictly needs** — vendored whole rather
  than hand-trimmed, because a trim that missed one dynamic import would fail at a relay, not at build
  time. 25 modules, 537,716 bytes.
- `noble-ciphers/` — `@noble/ciphers@2.1.1` (MIT), zero dependencies, so the closure is four files.
  49,434 bytes.

Each tree has a manifest (`upstream-noble-*.json`) recording the **tarball sha256**, a per-file digest
and a closure digest, with the upstream licence beside the bytes.

## Relay transport, and the one rule it exists to enforce

`lib/relay.mjs` publishes and reads gift wraps over public relays, with no server of ours.

**Offline is a named state, never an empty result.** Every read returns the per-relay outcome beside
the events, and a read no relay answered is `nostr:no-relay-answered` — *not* `{ wraps: [] }`. That
distinction is the whole point: `[]` from a relay that answered means "no new messages", while `[]`
from a client that reached nobody means "you are offline", and a person waiting for a message needs to
be told which. Sends work the same way — `publishToRelays` reports which relays **accepted**, and a
send nobody accepted is `nostr:no-relay-accepted`.

Per-relay states: `relay:ok`, `relay:refused`, `relay:auth-required`, `relay:timeout`,
`relay:unreachable`, `relay:bad-reply`, `relay:closed`. `auth-required` is deliberately **not**
`refused`: a relay needing NIP-42 is one we have not authenticated to, not one that will never serve
us. `relaySummary()` renders the line a person actually reads:

```
2 asked, 1 answered: wss://relay.damus.io (ok), wss://nos.lol (unreachable: could not reach wss://nos.lol)
```

The historical court drove this over a real WebSocket against an in-process
NIP-01 mock relay. Neither that mock relay nor its court is present in this
checkout, so those handler/frame claims have no current runnable entry point here.

### The jitter trap, found only by a real relay

**Do not pass a recent `since` to a read.** NIP-17 requires the seal and gift-wrap timestamps to be
randomised into the two days before now, so a wrap is routinely many hours old the instant it is
published. Measured on the first real round trip: the wrap was dated **2310 minutes (38 hours)** in the
past, and a read with `since = now - 60` returned **zero events from two relays that had accepted and
stored it**. Nothing errored — the relays answered, `verdict` was `null`, and the message was simply
absent. That is the same silent-empty-result failure this module exists to prevent, in the time
dimension, and it is why `DEFAULT_LOOKBACK_SECONDS` exists and why arm 12 pins it.

Two further consequences of the same real run, both now handled: relays may refuse a subscription
outright with NIP-01 `CLOSED` and an `auth-required:` reason, which must not read as "nothing there"
(arm 13), and `relay.nostr.band` was unreachable while the other two served the message — a partial
result the accounting reports rather than hides.

## Re-issuing the binding on enrol day

Until the owner enrols, the only controller record on this machine is disposable, so every binding is
signed by a key that means nothing and is labelled `TEST`. Nothing about the machinery changes on
enrol day — the Nostr key is machine-generated and is never derived from the phrase — so the re-issue
is one line, run with the AUKORA shell running because the SHELL'S SIGNER is what signs:

```
node plugins/aukora-nostr/bin/reissue-binding.mjs \
  --state <stateDir> --controller <stateDir>/aumlok --subject <subject> [--handle <nip05LocalPart>]
```

**The tool holds no key.** It asks the signer's `sign-nostr-binding` operation for the signature over
one JSON line — the signer is the only thing in this product that can sign without opening a seed
file — and it never reads a seed, never uses the controller record's private half and never signs
locally. It refuses by name if the socket is unreachable, if the signer declines, or if the returned
signature does not verify, and in every one of those cases it writes **no** binding file. The label is
an unsigned note on the document (`--label`, default `TEST`); what the signature covers is the ruled
five-key statement.

It never moves, overwrites or deletes a key: `loadOrCreateNostrKey` returns the existing one, so
re-running cannot orphan a node's npub. It re-reads and re-verifies what it wrote and exits non-zero
if the verdict is not `verified`.

**Back up the controller record before you need it.** For a v2 controller record, the ML-DSA seed is
random and is not recoverable from the phrase, so a lost `local-control.json` cannot be rebuilt from it.
Under v3 (`aumlok-kdf-v1`, what `bind` writes today), both halves derive from the handle plus the seven
words; the words without the handle recover nothing. A binding signed by a lost controller cannot be re-issued, only
replaced, and replacing it is a new identity rather than a recovery.

## Current check and historical courts

```
node plugins/aukora-nostr/checks/records.mjs
```

This source-only check uses published test keys and in-memory records. It performs
no key generation, credential read, socket, relay request or installed-path check.
The seven dated Nostr courts, their mock relay, public-relay opt-in and vector file
listed by the imported README are absent from this checkout; their arm counts and
real-relay results are historical rather than runnable commands here.

Both crypto courts check **published vectors**, never a round trip: `sign` then `verify` agrees with
itself even when both halves are wrong, and a published vector does not.

That is not a theoretical worry here. `lib/nip44.mjs` passed its own smoke test — encrypt, decrypt,
compare, green — while being wrong in three independent ways (HKDF as extract+expand instead of the
spec's extract-only/expand-only split, power-of-two padding, and no extended length prefix). Run against
the published vectors, the *same* code failed 10 of 10 payload vectors and 9 of 24 padding lengths and
could not decrypt a published payload at all, while its own round trip still returned `true`. The
The historical vector file is not present in this checkout, so this retained
account does not substitute for a current published-vector check.

## Not here yet

The Messages face exists (contacts, thread, send, add-contact and confirm-contact routes, with courts:
the `aukora-messages-*` suites). What remains is relay transport, which exists but with real gaps, each
named rather than implied: **no NIP-42 AUTH, no retry, no pool, no reconnection, and no kind-10050 read** — so this node
publishes to its own `DEFAULT_RELAYS` rather than the recipient's stated inbox relays, and cannot yet
use the AUTH-gated relays that would hide the recipient's `p` tag.

A binding is **not** authorization and **not** attendance, and no control succession is consulted — a
binding does not expire when the control that signed it rotates. Everything is **TEST-labelled** until
the owner enrols.
