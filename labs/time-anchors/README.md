<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Offline quicknet round verification

`drand.mjs` exports `verifyDrandRound(round, signatureHex)`. It accepts a positive
safe integer and a 48-byte hexadecimal signature (either case), verifies the
quicknet `bls-unchained-g1-rfc9380` signature against the fixed public key, and
returns `{ ok: true, chainHash, round, signature, randomness, advisoryOnly: true,
grantsAuthority: false }`. Signature and randomness output are lowercase hex.
Randomness is SHA-256 of the decoded verified signature; no caller-supplied
randomness is trusted. Refusals are `{ ok: false, code }`, with
`drand_round_invalid`, `drand_signature_invalid`, or `drand_signature_unverified`.

Adapted from `aukora-kernel` commit `b441edc4d`,
`apps/symbiote/core/src/drandAnchor.ts` and its `tests/drandAnchor.test.ts`
(copyright 2026 Aukora, AGPL-3.0-or-later). The captured public round 30226057 is
retained from that test. BLS uses the existing pinned Noble curves 2.2.0 and
hashes 2.2.0 under `packages/authority/upstream/vendor/authority/deps/`; their MIT
notices remain there. No third-party source is copied or dependency added.

Run `node labs/time-anchors/checks/drand.mjs` with Node 24.11.1. Checks include
the donor's four offline verification cases and in-memory protection mutations.
Fetching, clock drift, ceremony integration and receipt-schema changes are
excluded. This source lab does not prove freshness, when a receipt existed,
owner approval, containment, or installed-runtime behavior. A valid old round
can be replayed; the beacon signature binds only its round number.
