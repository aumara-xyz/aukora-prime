<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Source and fixture provenance

This lab is an additive source-only change. It imports existing vendored dependencies by repository-relative path and adds no dependency on another user-owned checkout at build or runtime. Donor signing services, filesystem custody, key-generation paths, root ceremony, bearer signing tokens, and production credentials are not copied.

## Receipt signer donor

`signatures.mjs` ports the pure signing/verifying format from [aukora-membrane/core/pqc.ts](https://github.com/aumara-xyz/aukora-membrane/blob/7283a8dd9a034e2ebac751695c57fd85c85c52e1/core/pqc.ts) at commit:

```text
7283a8dd9a034e2ebac751695c57fd85c85c52e1
```

The reviewed donor file's SHA-256 is:

```text
ae0af50f2b9db8091f32b632e7fae1c90a915e124b879d116bd9825bf8434917
```

The reference commit and reviewed local donor bytes agreed. The local donor checkout revision was `d8b17faca5f17bb6e279feb30a2ea808a1f31cb8`; it is not a runtime dependency. The donor's own header identifies earlier lineage through `aukora-one` and `aukora-evolution`; this lab does not independently revalidate that earlier lineage.

Retained donor behavior:

- Bundle schema `aukora-membrane-hybrid-signature-v1`, algorithm `ml-dsa-65+ed25519`, and exact five-field shape.
- Both algorithms sign the same UTF-8 digest string; ML-DSA uses `aukora-membrane-receipt-v1`, while Ed25519 signs the bare message.
- Both signature halves are mandatory; default Noble ZIP215 Ed25519 verification is preserved.

Port adaptations are explicit deterministic ML-DSA signing (`extraEntropy: false`), strict closed input/byte validation, supplied-key correspondence checks, generated-signature verification, and best-effort wiping of private copies. No key custody or signing oracle is introduced.

## Pinned libraries and licenses

All runtime cryptographic imports resolve to these existing paths under `packages/authority/upstream/vendor/authority/deps/`:

| Package | Version | Used modules | Package license |
| --- | --- | --- | --- |
| `@noble/post-quantum` | `0.6.1` | `ml-dsa.js`, `hybrid.js` | MIT |
| `@noble/curves` | `2.2.0` | `ed25519.js` | MIT |
| `@noble/hashes` | `2.2.0` | `hkdf.js`, `sha2.js`, `utils.js` | MIT |
| `@noble/ciphers` | `2.2.0` | `aes.js` | MIT |

The checkscript additionally uses the same pinned `ml-kem.js` and `sha3.js` for disposable fault injection and fixture derivation. Node's built-in cryptography supplies the independent wrapper reference. [RFC 8032 section 7.1 TEST 1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1) supplies its published Ed25519 seed, public key and expected signature.

These are the existing checked-in vendored packages, not an assumption that their bytes are pristine upstream tarballs. Their existing licenses, provenance, and patches are retained without edits. [The vendored dependency provenance](../../packages/authority/upstream/vendor/authority/deps/PROVENANCE.json) records their source history; this lab performs no reinstall or dependency copy.

The pinned `hybrid.js` SHA-256 is `d34a54df90fe07baf2af075aab4c046ac5f06caf3af1998f82a9b711c727a140`; its Git blob is `9c76a8f6ccbcabc3d03762b67a226c9db070c94e`. That blob was also confirmed in the target Prime source revision `524b8f52906240799ff2ff4727caed637b2dfd73`.

Primary library sources:

- [Noble post-quantum 0.6.1 hybrid implementation](https://github.com/paulmillr/noble-post-quantum/blob/0.6.1/src/hybrid.ts)
- [Noble hashes 2.2.0 HKDF implementation](https://github.com/paulmillr/noble-hashes/blob/2.2.0/src/hkdf.ts)
- [Noble ciphers 2.2.0 AES implementation](https://github.com/paulmillr/noble-ciphers/blob/2.2.0/src/aes.ts)

The signature port declares `AGPL-3.0-only`, conservatively matching the observed [donor GNU AGPL version 3 license](https://github.com/aumara-xyz/aukora-membrane/blob/7283a8dd9a034e2ebac751695c57fd85c85c52e1/LICENSE). Its reviewed package metadata and `pqc.ts` header do not independently state the later-version option; no broader donor permission is inferred. The new key-wrap module and checks declare `AGPL-3.0-or-later`, matching the existing authority package declaration. [The retained project license](../../packages/authority/LICENSE) supplies the full AGPL text; MIT dependency notices remain with their packages.

## Key-wrap construction

The KEM is the library's frozen `KitchenSink_ml_kem768_x25519`, using [draft-irtf-cfrg-hybrid-kems-03 section 6.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-03#section-6.2). Its HKDF-SHA-256 combiner binds both component secrets, ciphertexts, public keys, and the fixed KitchenSink label. The wrapper uses [RFC 9180 section 5.1](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1) base-mode labeled extract/expand with suite bytes `48504b45bc4800010002`, then AES-256-GCM.

The proposed KEM ID `0xbc48` is unassigned. This frozen composition is experimental, not a claim of current standardized HPKE or compatibility with later hybrid drafts. Base mode supplies no sender authentication. Application domain, recipient public key, encapsulation, and exact public context are bound in both HPKE `info` and AEAD associated data; no replay or authority policy is inferred.

## Selected published fixtures

`checks/vectors.json` labels each source `PUBLISHED_NONSECRET_TEST_VECTOR`. Public fixture seeds and private components are test material, not production credentials.

**KitchenSink:** first case in [draft 03 section 11.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-03.txt). The fetched document SHA-256 is:

```text
795498ca2940adae50c170316a6a0ddc4d68fd0bf2210a8e7d282a28822ccef2
```

Only that case's seed/private input, public key, 64-byte randomness, encapsulation, and shared secret are retained. Comparing those outputs tests the published KEM case; an independent wrapper comparison is separate evidence, not a published full-profile HPKE vector.

**ML-DSA-65:** selected NIST ACVP signature-verification cases from [ACVP-Server at commit `975de31eb83d87039ec88934fdc47d8c312b892d`](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204), group 3, external signature interface, pure mode. Case 33 expects `true`; case 31 expects `false`. Each case retains its exact public key, message, signature, and context.

```text
prompt.json SHA-256:
e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e
expectedResults.json SHA-256:
e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6
```

These two verification cases do not constitute a full ACVP run, ML-DSA signing known-answer validation, FIPS certification, or an audit guarantee. Full upstream vector corpora are not copied.

## Historical run evidence and its limits

A read-only metadata inspection of the donor's existing receipt chain found 20,282 rows: 19,990 carried algorithm `ml-dsa-65+ed25519` and a `signatureKey` pointer; 292 did not. Parsing reported zero errors. The inspected chain file was 14,929,142 bytes. No record bodies or private keys were imported, and no stored signature bundles were cryptographically reverified in this round.

The donor's `AUDIT-2026-08-10-full-system.md`, lines 29–31, claims that independent sample bundles matched the chain tail and describes a growing chain. That is a historical audit claim, not a new cryptographic verification or evidence of the current running program. Neither metadata counts nor source checks establish owner intent, enrolled identity, custody separation, installed enforcement, or runtime qualification.
