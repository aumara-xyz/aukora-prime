<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# PQ hybrid source lab

This additive lab ports the membrane's receipt signature format and adds an experimental hybrid content-key wrap. It uses the already vendored Noble libraries. It is source only: no installed service, enrollment, persistent key creation, key custody, owner ceremony, receipt migration, or enforcement is provided. Both `pqcGrantsAuthority()` and `keyWrapGrantsAuthority()` return `false`.

The existing Nostr record v1 grammar, NIP-01 event identifiers and signatures, and existing Ed25519 author bindings remain unchanged. These exports are separate evidence/encryption helpers for a future explicit integration.

## Receipt signatures

`signatures.mjs` exports:

| Export | Input and result |
| --- | --- |
| `hybridSign(message, keys)` | Signs one exact lowercase 64-hex digest; returns the donor's closed five-field bundle. |
| `hybridVerify(bundle, message, pubs)` | Returns `true` only when the bundle is well formed and **both** ML-DSA-65 and Ed25519 verify. Malformed inputs return `false`. |
| `pqcGrantsAuthority()` | Always `false`. |

The caller supplies the complete keypairs to `hybridSign`:

```js
{
  mlDsa65: { publicKey: Uint8Array(1952), secretKey: Uint8Array(4032) },
  ed25519: { publicKey: Uint8Array(32), secretKey: Uint8Array(32) },
}
```

The Ed25519 private input is the 32-byte signing seed. Verification requires an independently pinned public-key pair: `{ mlDsa65: Uint8Array(1952), ed25519: Uint8Array(32) }`. A key supplied by an untrusted bundle is not a trust anchor.

The exact bundle fields are `schema`, `algorithm`, `message`, `mlDsa65`, and `ed25519`, with schema `aukora-membrane-hybrid-signature-v1` and algorithm `ml-dsa-65+ed25519`. The signature fields are lowercase hexadecimal, respectively 3309 and 64 bytes. Extra, missing, accessor, symbol, and non-enumerable fields are refused.

Both algorithms sign the UTF-8 bytes of the digest string, not decoded digest bytes. ML-DSA-65 uses the fixed context `aukora-membrane-receipt-v1`; Ed25519 signs the same bare message. This deliberate donor asymmetry is preserved, including Noble's default ZIP215 Ed25519 verification behavior. This format does not claim conformance to a standardized composite-signature profile.

The port explicitly sets ML-DSA `extraEntropy: false`, making signing deterministic rather than using the donor's default hedged signing. Message bytes, ML context, Ed25519 behavior, and bundle shape remain unchanged. Signing checks the supplied public/private correspondence and verifies both generated halves before emitting a bundle. Missing or invalid halves cannot produce an accepted bundle.

## Content-key wrapping

`key-wrap.mjs` exports:

| Export | Input and result |
| --- | --- |
| `wrapKey(dataKey, options)` | Wraps exactly 32 content-key bytes for a supplied 1216-byte recipient public key and public context. |
| `unwrapKey(envelope, options)` | Requires the independently pinned recipient public/private pair and exact expected context; returns the 32 content-key bytes or throws `pq_key_wrap_invalid`. |
| `keyWrapGrantsAuthority()` | Always `false`. |

The frozen profile is `draft-hybrid-kems-03-kitchensink-mlkem768-x25519-hpke-base-hkdf-sha256-aes256gcm`. It combines the pinned library's `KitchenSink_ml_kem768_x25519` KEM from [hybrid KEM draft 03, section 6.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-03#section-6.2) with the [RFC 9180 base-mode key schedule](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1), HKDF-SHA-256, and AES-256-GCM. The library's built-in KEM combiner binds both component secrets, encapsulations, and public keys; the lab does not substitute a new combiner.

This is an **experimental frozen draft profile**. `0xbc48` is the draft's proposed unassigned KEM identifier, not a currently registered standardized HPKE KEM. It must not be silently interpreted as a later draft, X-Wing, or another hybrid KEM. See the [HPKE registry](https://www.iana.org/assignments/hpke).

Wrapping options are `{ recipientPublicKey, context, randomness? }`. Unwrapping options are `{ recipientPrivateKey, recipientPublicKey, expectedContext }`. The private input is the pinned KitchenSink KEM's 32-byte seed; the module derives its public key and checks equality with the independently supplied public key. Context is an exact `Uint8Array` of 1–1024 bytes.

The closed envelope has five fields:

```js
{
  schema: 'aukora-prime-pq-key-wrap-v1',
  profile: 'draft-hybrid-kems-03-kitchensink-mlkem768-x25519-hpke-base-hkdf-sha256-aes256gcm',
  encapsulation: '<1120 bytes as lowercase hex>',
  wrapped_key: '<48 bytes as lowercase hex>',
  context: '<public context as lowercase hex>',
}
```

HPKE `info` and AES-GCM associated data are the same exact bytes:

```text
UTF8("aukora-prime.pq-hybrid.key-wrap.v1\0")
  || recipientPublicKey[1216] || encapsulation[1120] || context
```

The fixed key and encapsulation lengths make those boundaries unambiguous. Each wrap uses a new encapsulation and single-shot sequence-zero nonce. Production callers must **omit** optional `randomness`; the pinned library then supplies fresh CSPRNG input. The explicit 64-byte randomness option is for published fixtures and reproducible synthetic checks only. Reusing it with the same recipient/context repeats key/nonce material.

HPKE base mode does **not authenticate a sender**. The context and recipient public key must be selected outside the envelope. This helper does not establish owner approval, replay prevention, sender identity, key custody, durable one-use state, or forward secrecy against later compromise of the recipient's static private seed. Context is public authenticated data, not encrypted metadata. Private copies and derived key material are wiped on a best-effort basis; JavaScript does not provide a complete memory-erasure guarantee.

## Scoped checks

Run from the repository root with its already pinned dependency layout:

```sh
node labs/pq-hybrid/checks/hybrid.mjs
```

The fixture file contains only selected published nonsecret vectors: the first KitchenSink case in draft 03 section 11.2, and NIST ACVP ML-DSA-65 signature-verification cases 33 (valid) and 31 (invalid). Provenance and document hashes are in [PROVENANCE.md](PROVENANCE.md).

The checkscript runs 13 focused groups, including the published RFC 8032 Ed25519 empty-message vector, donor-format signature interoperability, independent Node HMAC/HKDF and AES-GCM comparison, malformed inputs, and tampering. Two in-memory downgrade mutants deliberately omit PQ signature verification or the PQ shared secret; the checks reject both. No mutated source or bypass entrypoint is written. Synthetic fixtures and passing source checks do not establish current installation, historic stored-signature validity, browser support, enrollment, FIPS validation, or a completed security audit.
