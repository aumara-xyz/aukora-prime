# Owner authorization and captured gate evidence

This is the H/D/E source interface. It describes source behavior and required trusted inputs; it does not report installed custody, owner enrollment, hardware signing, runtime containment or a mounted note-capture path. Existing receipt consumers require a separate version-3 migration before this gate source can be deployed.

## Review and one-use consumption

The gate imports the concrete G owner-authorization implementation. Source fixtures were joined against G `0e5a73b44a7c6c7007394f2f551755942cf18379` and the exact cached verifier bytes of `d23d1938f5de85f4e0e918f539efe542d165ee98` through a private test-only loader. The latter did not copy or install G files. The protected production profile pins the reviewed G verifier and index; installed-byte equality remains unperformed. A trusted, synchronous `readOwnerState()` supplies exactly:

```text
version: 1
kind: aukora-owner-state/v1
owner_subject
owner_root_spki_base64
owner_root_id
owner_epoch
registry_sha256
activation_sha256
```

The full P-256 SPKI and its SHA256 must agree. These are independently configured active-owner inputs, never values supplied by a proposal, proof or review response. A missing adapter refuses authorization. Retaining registry and activation digests records which trusted state was used; it does not independently authenticate the corresponding registry history or establish enrollment.

`review({id})` returns version 3 with the complete proposed bytes and existing presentation metadata, plus `owner_authorization`, `authorization_digest`, `review_issued_at_ms`, full `gate_pubkey_sha256`, and `review_issue:{ledger_seq,ledger_hash}`. The unsigned authorization has G's exact fourteen fields and binds the operation, proposal, target, before/after hashes, full gate SPKI hash, challenge, issue/expiry times and active owner subject/root/epoch. The durable review expires at the earlier of proposal expiry and issue time plus 120 seconds.

An allowed decision accepts exactly:

```text
{id,base_sha,new_sha,review_challenge,outcome:'allowed-once',owner_authorization_proof}
```

A rejection has the same five review fields with `outcome:'rejected'` and no proof field. Null, additional or missing proof fields refuse. Neither a bearer nor the legacy local HMAC can approve an effect.

The synchronous SQLite transaction verifies the original G proof against the retained review and independently read owner state, rechecks the proposal/base/bytes/policy, inserts immutable proof consumption, spends the review, and compares `pending` to `applying`. It rechecks active state and the current clock immediately before committing. Equality with expiry refuses. The exact canonical original proof text, active-owner state, acceptance time and signed issue/consume anchors remain retained before any target effect. The target write happens only after that commit.

The plugin-set target also retains its exact release-floor observation in the signed review-issued ledger detail. An unreadable or malformed floor makes the existing card unavailable and refuses approval; a readable rollback retains its explicit ROLLBACK line. Fresh observation equality is required before consumption, at its final commit guard and immediately before writing. An absent initial floor is valid only before any prior target bytes or retained adoption/apply history. Lost floor history cannot become a new first approval. These internal observations add no owner-proof or review-response fields.

Proof identity, proposal and gate/challenge uniqueness prevent a second consumption. Failed or ambiguous effects retain consumption and recovery fences. Startup observes existing bytes and records an incomplete, failed or conflicting result; it does not repeat an effect or invent a past apply timestamp. The gate's signed ledger and retained proof require independent pin/anchor verification by an archival consumer; database presence alone is insufficient.

## Version-3 receipt and archival verification

The gate signs the original `JSON.stringify(receipt)` bytes using its existing Ed25519 receipt key. Version 3 retains proposal/target/before/after facts and adds:

```text
gate_pubkey_sha256: full Ed25519 SPKI SHA256
owner_authorization: {version:1,kind:'aukora-owner-authorization-ref/v1',authorization_id,proof_sha256}
owner_accepted_at_ms
owner_consumption: {ledger_seq,ledger_hash,review_issue:{ledger_seq,ledger_hash}}
```

An archival verifier must authenticate the original receipt and signed issue, consume and apply rows against independently retained full gate pins/anchors; resolve the original proof and active-state evidence; recompute both G domain-separated digests; and bind every operation/root/epoch/time field across those records. It evaluates the proof's original accepted time only after authenticating that time and active-at-consumption state. Verifying at today's clock, substituting an arbitrary historical clock, accepting the receipt's own public key as a trust anchor, or checking only a short fingerprint does not establish historical authorization. A signature-valid but unanchored registry history remains an explicit unresolved qualification.

Legacy receipts remain their original bytes. They do not acquire a G proof, owner epoch or active-root history retroactively. Their owner authorization is unavailable under this profile. The existing closed version-2 plugin-set verifier rejects this new receipt grammar; no HMAC compatibility wrapper, operator bypass or silent consumer change is supplied here.

## Same-result capture

The trusted constructor's optional `journalId` must equal the collector's independently configured `source.source_id`. The selected public source configuration uses `aukora-gate-pilot`; its installed equality must be checked by the operator. There is no model/request-selected journal and no default capture identity.

Only a successful completed action, after its signed apply-row transaction commits, can produce `gate_capture`. Its closed core has these fields in this exact order:

```text
applied, state, entry, receipt, receipt_sig, ledger_seq, ledger_hash, message
```

`applied` is true and `state` is `applied`. The receipt object retains its original property order and signed JSON serialization. `gateCompletedResultDigest(core)` computes SHA256 over UTF-8 bytes of `aukora:gate-completed-result:v1`, one NUL byte, and `JSON.stringify(core)` copied in the order above. It covers this action's specific completed result, including its receipt/signature and apply-row position/hash; a later journal tip cannot substitute for it.

The additional envelope is:

```text
gate_capture: {
  capture: {
    version:1,
    kind:'aukora-gate-capture/v1',
    source:{journal_id,position:ledger_seq,hash:ledger_hash},
    proposal_id:receipt.proposal,
    gate_pubkey_sha256,
    completed_result_sha256
  },
  signature_base64
}
```

`gateCaptureSigningBytes(capture)` encodes UTF-8 `aukora:gate-capture:v1`, one NUL byte, then JSON in the shown capture order and `journal_id,position,hash` source order. The existing gate key signs those bytes after commit. Keeping this signature outside the apply row avoids a circular ledger hash. It supplies no new owner permission.

`verifyCompletedGateCapture(result,{journal_id,gate_public_key_pem,gate_pubkey_sha256})` requires a closed core plus envelope. It checks the independent full Ed25519 SPKI pin, original receipt signature, capture signature, exact completed-result digest, proposal and same source coordinate, and returns only frozen `{source}`. Invalid or absent capture refuses. This helper authenticates a gate assertion about completion; independent journal inclusion/retained-anchor checks remain separate.

The original closed core plus `gate_capture` is stored as immutable `gate_completed_results.result_text` after the signed apply transaction commits and the capture is minted, before the completed result is returned. Retention binds the original apply sequence/hash and completed-result digest; it preserves the original receipt serialization. A missing completion store detected before consumption refuses an action requiring a capture. A crash, capture-signing failure or retention failure after apply commit leaves the action applied with capture unavailable. Neither restart nor polling reconstructs or re-signs that completion.

The read-only PROPOSE operation `state({id})` returns the exact retained nine-field completed result for an applied proposal, directly accepted by `verifyCompletedGateCapture`. It validates the retained result against its original signed apply row. Later journal rows, current target bytes and current target entry metadata do not replace any retained field. Applied proposals without valid original retention return the existing status fields plus `gate_capture_status:'UNAVAILABLE'`, without a receipt or capture. Pending and other terminal proposals retain their status response. The theme PROPOSE client allowlist includes only `read`, `propose` and `state`; polling adds no approval operation.

A trusted ingestion callback may poll using the full `proposal_id` retained from the actual `proposeTheme` tool return, then verify the exact completed response with independently configured journal and full gate public pins. The old eight-character `proposal` display field remains; `proposal_id` preserves only the strictly validated UUIDv4 returned by the gate. Missing or malformed full IDs refuse. A model-supplied ID, short display prefix, invented receipt, remembered source tip or self-supplied pin cannot create the association. No host polling callback or public-pin accessor is mounted by these source changes.

D's read-only resolver can additionally find the exact signed apply row in its protected source snapshot and match that same receipt/signature and coordinate, under the same live scope and retained read grant. It must not choose an aggregate head. The optional collected `record_id` can come only from an actual matching collected record, not from the remembered ID or session sequence.

E's trusted host ingestion must retain the actual completed action result, call the verifier with host-owned pins, and bind the detached source projection to the corresponding note capture. No model parameter may supply or replace this evidence. The note association uses only `{source:{journal_id,position,hash},record_id?}`. Historical note bytes/IDs remain unchanged and association-undetermined. Failed actions, missing capture, unresolved effects and reconciliation without an original signed completion remain unavailable. These source helpers do not mount the ingestion route.

## Protected loading and remaining joins

The new bootstrap checks the complete gate package before Node. Every version-2 manifest additionally requires the six fixed protected checkout inputs beneath `/opt/aukora-genesis/src`: `scripts/launch-dsh.py`, `scripts/genesis-check.mjs`, `scripts/lib/artifact-integrity.mjs`, `scripts/lib/release-strip.mjs`, `scripts/artifacts-coverage.json` and `upstream-dsh.json`. The staging generator accepts only a separate staged checkout through `--launcher-checkout`; it reads these named inputs and refuses installed-root overlap. This profile does not cover the admission helper imported from the selected release or establish launcher execution qualification.

Its version-2 owner-key profile protects the full fixed `/opt/owner-key` package, including the concrete G verifier imports and resolution metadata. A version-1 manifest can verify legacy package custody but cannot launch this new gate's Node roles without that external closure. Actual active-owner adapter mounting, independently authenticated registry/enrollment and native custody remain unconfigured.

The selfcheck source uses an active startup latch with Genesis `BindsTo` and `After`, plus a separate periodic oneshot under the existing timer. Both checks run the protected Python bootstrap before Node and retain the fail-closed service target. The original Genesis prechecks remain. Source dependency-model checks do not establish actual systemd behavior; the operator must install the version-2 manifest, bootstrap and units together and verify the installed lifecycle.

The optional Aura profile preserves complete Prime-relative source paths beneath `/opt/aukora-aura`; it dispatches only the fixed `packages/boundary-gate/host/aura/entry.mjs` with `collect` or `verify`. Public closed configuration is fixed at `/etc/aukora-boundary-gate/aura-context.json`. Its full code, package metadata, vendor/license/provenance and configuration pins must be reviewed before Node. Missing reviewed closure or configuration refuses. Mutable DB/WAL/store/grants and existing private author material are not public source inventory entries or new provisioning actions.

D owns `context.mjs`, `entry.mjs` and `records-provider.mjs`. The provider's two methods recheck the same retained read grant and lifecycle before and after awaited calls; disposal permanently closes cached handles. Loading that provider in a separate Genesis/Cordis host still requires the host's own protected closure and lifecycle adapter. Collector bootstrap success alone does not supply that join.

Source fixtures use disposable synthetic signer/registry inputs. They do not establish installed owner-key custody, journal capture mounting, note association, provider registration, cold runtime acceptance or containment. Deployment and receipt-consumer migration remain with their explicitly allocated integrator/owners.
