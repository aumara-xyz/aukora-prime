# Nostr-shaped records, version 1

**SOURCE-ONLY.** `@aukora/dsh-plugin-nostr/records` wraps the existing NIP-01,
NIP-44 v2 and Aumlok-binding primitives. It creates no keys, files, sockets or
resources and performs no journal writes or network traffic. Collection, key custody,
enrollment and owner authorization are not established by this library.
Its strict JSON dependency is the local Prime `packages/contracts/src/json.mjs`;
that module must be present inside Prime; no sibling checkout is required at runtime.

## Exports and inputs

| Export | Result |
| --- | --- |
| `buildRecord(input)` | Frozen unsigned event, including its NIP-01 `id`. |
| `signRecord(event, secretKeyHex)` | Frozen signed event; the supplied existing key must match `pubkey`. |
| `verifyRecord(event, pins)` | Frozen verified metadata, including `binding_digest` and `grants_authority:false`. |
| `encryptPrivateContent(text, {authorSecretKeyHex, ownerPubkeyHex})` | NIP-44 v2 ciphertext of literal UTF-8 text. |
| `decryptRecord(event, {...pins, ownerSecretKeyHex})` | Verified and authenticated plaintext; alternatively supply only `authorSecretKeyHex`. |
| `parseRecord(text, pins)` | Strict textual JSON ingress, then `{event, metadata}` after actual verification. |
| `verifyChain(events, {...pins, initialHead?, expectedHead?})` | `{count, initialHead, head, coverage, grants_authority:false}`. |
| `RECORD_VERSION`, `ZERO_ID`, `RECORD_KINDS`, `RECORD_LIMITS`, `RecordValidationError` | Version, genesis marker, profile constants and named validation error. |

`input` has exactly `{type,pubkey,created_at,sequence,previous_id,source,action_id,
owner_pubkey_hex,content}` plus optional `references`. `source` is exactly
`{journal_id,position,hash}`: an opaque 1–128 character token, positive safe integer
and lowercase 64-hex hash. Source position and record sequence are separate fields.
`action_id` is a token or `null`; tokens match `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`.
`created_at` is a nonnegative safe integer; sequence starts at 1. Negative zero is
refused. Keys, event IDs and hashes use lowercase 64-hex; signatures use lowercase 128-hex.

## Signed profile

`RECORD_VERSION` is 1. The experimental application kinds are ordinary events
in [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)'s 1000–9999 range,
not registered Nostr standards: `aura:8930`, `memory:8931`, `decision:8932`,
`receipt:8933`, `anchor:8934`. The closed unsigned event has exactly
`{id,pubkey,created_at,kind,tags,content}`; signing adds only `sig`.
The ID hashes `[0,pubkey,created_at,kind,tags,content]`, and the BIP-340 signature
covers the raw ID bytes. Signing proves cryptographic authorship, not authority.

The first seven tags occur exactly once in this deterministic order:

```text
["prev", previous_id], ["seq", decimal_sequence],
["src", journal_id, decimal_position, source_hash], ["act", action_id_or_empty],
["v", "1"], ["enc", "nip44-v2" or "none"], ["p", owner_pubkey_hex]
```

Genesis is sequence 1 with `previous_id === ZERO_ID` (64 zeroes); every later
sequence requires a nonzero previous ID. Optional references follow the seven tags,
at most 32, sorted lexically by tag name then value. Only exact two-element `e` and
`a` tags are accepted: `e` takes a 64-hex event ID; `a` takes
`30000..39999:64-hex-pubkey:token`. Duplicates, reordered references, extra reserved
tags and unknown tags are refused. References bind text without verifying referenced records.

Private kinds require canonical standard-base64 NIP-44 v2 payloads. Encryption
accepts 1–65,535 UTF-8 bytes of valid Unicode text, without trimming or normalization.
The owner recipient is a separately pinned Nostr secp256k1 key, not an Ed25519 key
conversion. A service encrypting to its own key reaches the owner only when those
Nostr keys are actually the same. `anchor` alone uses `enc:none` and public content:
closed canonical JSON `{head_id,head_sequence,count}`, bounded to 2,048 bytes, with
nonnegative safe integers and a zero ID exactly when head sequence is zero. Count
is producer-supplied and independent of head sequence; verification binds these
bytes, not their truth. The collector must compare them with its actual verified
source and selected head. All tags remain plaintext metadata; live anchoring is unperformed.

## Verification pins and coverage

Every verification requires exactly `{binding,controllerKeyHex,ownerSubject,
authorPubkeyHex,ownerPubkeyHex}`. The author is pinned separately from the owner
recipient. The Aumlok Ed25519 controller key and `aukora:1:64-hex` subject must come
from independently trusted configuration. The existing binding signature must
verify under that controller and bind the event's Nostr author. A binding naming
its own signer is insufficient; TEST labels are not enrollment evidence.

`verifyRecord` returns `{version,type,id,pubkey,created_at,sequence,previous_id,
source,action_id,owner_pubkey_hex,encryption,references,binding_digest,
grants_authority:false}`. This authenticates signed ciphertext bytes and their
profile, not its NIP-44 MAC or plaintext. `decryptRecord` first verifies the record
and binding, then pins exactly one owner-side or author-side secret and authenticates
the ciphertext. Supplying both secrets or neither is refused.

`verifyChain` accepts at most 4,096 records from one pinned author, enforcing every
next sequence and previous ID. Its default initial head is `{sequence:0,id:ZERO_ID}`;
a continuation head must come from a trusted verified prefix. Without `expectedHead`,
coverage is `PREFIX_ONLY`; an exact expected-head match yields `THROUGH_EXPECTED_HEAD`.
Neither result establishes completeness of the source journal. Source Ed25519
signatures, source coverage, active control, revocation and scoped custody remain
the collector/provisioner's separate obligations. Signed body text cannot grant authority.

## Collector mapping

The collector keeps its source-verification result separate from the Nostr profile.
Its private observation body may include `key_sha256`, source entry fields and the
exact signed entry-body string; this generic library does not parse or prove them.
After independently verifying the source, an abstract mapper can use:

```js
async function mapObservation(row, head, ciphertext, pins, signExisting) {
  if (!signExisting) throw new Error('collector:signer-unavailable')
  const source = { journal_id: row.source.journal_id,
    position: row.source.position, hash: row.source.hash }
  const unsigned = buildRecord({ type: 'aura', pubkey: pins.authorPubkeyHex,
    created_at: row.created_at, sequence: head.sequence + 1, previous_id: head.id,
    source, action_id: row.action_id, owner_pubkey_hex: pins.ownerPubkeyHex,
    content: ciphertext })
  const event = await signExisting(unsigned) // existing trusted signer; no fallback
  return { event, metadata: verifyRecord(event, pins) }
}
```

The mapper does not create keys or a signing authority. Production signer and key
configuration are unavailable in this source slice. Hybrid encryption/signatures,
gift wrapping, publishing, backups, restoration and independent timestamps are future joins.

## Refusals and focused check

Malformed shapes, Unicode, bounds, duplicate JSON keys, noncanonical tags/anchors,
wrong key pins, invalid signatures, bad ciphertext and broken chains throw
`RecordValidationError` with matching `code`/`reason` prefixed `nostr-record:`.
Textual ingress is bounded to 262,144 bytes and depth 16. Object snapshots are also
bounded to 10,000 nodes and reject accessors, custom prototypes, symbols, sparse
arrays and unsafe numbers.

Focused source command: `node plugins/aukora-nostr/checks/records.mjs`.
Its execution result must be reported separately; documentation is not a PASS or
installed-behavior receipt. No live traffic, credentials or key creation is needed.
