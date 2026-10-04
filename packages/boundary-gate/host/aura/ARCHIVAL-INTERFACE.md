# Owner authorization and captured gate evidence

This is the H/D/E source interface. It describes source behavior and required trusted inputs; it does not report installed custody, owner enrollment, hardware signing, runtime containment or a mounted note-capture path. Existing receipt consumers require a separate version-3 migration before owner-authorization mode is activated.

## Legacy selection and durable enforcement

An undefined `readOwnerState` and no retained owner-authorization history select the original legacy review, decision and receipt grammar. Supplying any reader latches a signed, immutable enforcement marker before it can be used; that marker records required enforcement, not owner enrollment. A null, malformed, throwing or asynchronous configured reader refuses. Removing the callback after enforcement, losing its supporting tables, or retaining signed owner review/consumption history cannot restore legacy selection. This is a caller-boundary guarantee, not protection against a privileged rewrite of the entire database and its signed history.

Legacy startup and effect transitions use the same writer boundary and compare-and-set guards. A concurrently failed or completed proposal cannot be applied again. Unreadable, changed or lost plugin-set floor evidence refuses on both paths. Without a journal binding, the virgin legacy state wire remains unchanged. With the protected journal binding, a newly completed legacy action can retain a capture of its original version-2 receipt; that receipt retains its exact ten fields, property order, signature and HMAC. It supplies no G proof. Historical receipts are never reconstructed or captured retroactively.

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

The full P-256 SPKI and its SHA256 must agree. These are independently configured active-owner inputs, never values supplied by a proposal, proof or review response. A missing adapter after enforcement refuses authorization. Retaining registry and activation digests records which trusted state was used; it does not independently authenticate the corresponding registry history or establish enrollment.

`review({id})` returns version 3 with the complete proposed bytes and existing presentation metadata, plus `owner_authorization`, `authorization_digest`, `review_issued_at_ms`, full `gate_pubkey_sha256`, and `review_issue:{ledger_seq,ledger_hash}`. The unsigned authorization has G's exact fourteen fields and binds the operation, proposal, target, before/after hashes, full gate SPKI hash, challenge, issue/expiry times and active owner subject/root/epoch. The durable review expires at the earlier of proposal expiry and issue time plus 120 seconds.

An allowed decision accepts exactly:

```text
{id,base_sha,new_sha,review_challenge,outcome:'allowed-once',owner_authorization_proof}
```

A rejection has the same five review fields with `outcome:'rejected'` and no proof field. Null, additional or missing proof fields refuse. Neither a bearer nor the legacy local HMAC can approve an effect in owner-authorization mode.

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

The trusted constructor's optional `journalId` must equal the collector's independently configured `source.source_id`. The selected public source configuration uses `aukora-gate-pilot`; its installed equality must be checked by the operator. The CLI and finite bootstrap accept that exact value only as an optional, single `serve --journal-id` flag; the protected service template supplies it. Other values and roles refuse before gate-state access. There is no model/request-selected journal and no implicit capture identity.

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

The original closed core plus `gate_capture` is stored as immutable `gate_completed_results.result_text` after the signed apply transaction commits and the capture is minted, before the completed result is returned. Retention binds the original apply sequence/hash and completed-result digest; it preserves the original receipt serialization. Owner-authorization mode checks a required completion store before consumption. Legacy effect admission retains its original checks; a crash, capture-signing failure or retention failure after apply commit leaves the action applied with capture unavailable. Neither restart nor polling reconstructs or re-signs that completion.

The read-only PROPOSE operation `state({id})` returns the exact retained nine-field completed result for an applied proposal, directly accepted by `verifyCompletedGateCapture`. It validates the retained result against its original signed apply row. Later journal rows, current target bytes and current target entry metadata do not replace any retained field. Applied proposals requiring capture without valid original retention return the existing status fields plus `gate_capture_status:'UNAVAILABLE'`, without a receipt or capture. Virgin legacy without a journal preserves its original state response. Pending and other terminal proposals retain their status response. The theme PROPOSE client allowlist includes only `read`, `propose` and `state`; polling adds no approval operation.

A trusted ingestion callback may poll using the full `proposal_id` retained from the actual `proposeTheme` tool return, then verify the exact completed response with independently configured journal and full gate public pins. The old eight-character `proposal` display field remains; `proposal_id` preserves only the strictly validated UUIDv4 returned by the gate. Missing or malformed full IDs refuse. A model-supplied ID, short display prefix, invented receipt, remembered source tip or self-supplied pin cannot create the association. The default materializer selects the separate H host wrapper; actual protected loading and installed callback acceptance remain unperformed.

D's read-only resolver can additionally find the exact signed apply row in its protected source snapshot and match that same receipt/signature and coordinate, under the same live scope and retained read grant. It must not choose an aggregate head. The optional collected `record_id` can come only from an actual matching collected record, not from the remembered ID or session sequence.

E's trusted host ingestion must retain the actual completed action result, call the verifier with host-owned pins, and bind the detached source projection to the corresponding note capture. No model parameter may supply or replace this evidence. The note association uses only `{source:{journal_id,position,hash},record_id?}`. Historical note bytes/IDs remain unchanged and association-undetermined. Failed actions, missing capture, unresolved effects and reconciliation without an original signed completion remain unavailable. Source selection alone does not establish an installed ingestion route.

## Default public capture caller

The materializer selects `plugins/aukora-kira/lib/gate-capture-host.mjs` as the separate host wrapper. Its fixed Python `check-runtime-aura` preflight checks the protected gate, G source profile, launcher inputs and complete public Aura source/configuration before installed modules are imported. Functions and pins come from that host construction, never ordinary Cordis configuration or model input.

The operator explicitly selected the protected Aura configuration as the sole INTERIM mapping from the legacy `aumlok:subject:owner` alias to its canonical `owner_subject`. The wrapper detaches the existing configuration and replaces only that exact alias. It preserves the original state directory, privacy and other fields; it does not alter historical notes, IDs or subjects. E's actual normalizer must accept the resulting identity. Original owner-object identity, the typed configuration fingerprint and normalized subject/state directory are rechecked across reads and callbacks. Other aliases and an explicit conflicting canonical owner refuse capture.

D's public API loads configuration without author material. A retained read scope binds the canonical owner, full proposal UUID, exact journal position/hash/key, canonical original receipt digest, exact configuration-byte digest, release SHA and Genesis instance UUID. Root alone issues protected grants at `/etc/aukora-boundary-gate/aura-read-grants/<proposalUUID>.json`, with a maximum 300-second lifetime. The protected `/etc/aukora-boundary-gate/aura-read-lifecycle.json` binds configuration, release and actual restart instance; restart/switch hooks must change that instance. No grant can authorize an unknown future proposal or be minted by the harness.

The wrapper authenticates one detached completed DTO and validates that scope against D's fresh signed source before returning an applied state to E. Its completion verifier rechecks the same retained scope. The synchronous `isCaptureScopeLive(completedResult)` callback returns exact `true` only after those checks, creates no scope, and returns `false` on failure. E must combine it with memory identity in the existing capture write guard after awaited policy work. It must refuse a failed or mismatched capture before ordinary `remember`; accepted E `630f727` still absorbs a late verifier failure into an unassociated note, so that consumer revision is insufficient for this refusal guarantee.

R2's operator decision provides no private D archive worker. The public completion-to-note source binding can be tested separately; encrypted archive citation and private provider acceptance remain unavailable or undetermined. The existing `aura_association` model tool does not publish D's `aura.records` service. The harness never loads the private context or author key, and public capture does not establish owner enrollment or G authorization.

## Protected loading and remaining joins

The new bootstrap checks the complete gate package before Node. Every version-2 manifest additionally requires the six fixed protected checkout inputs beneath `/opt/aukora-genesis/src`: `scripts/launch-dsh.py`, `scripts/genesis-check.mjs`, `scripts/lib/artifact-integrity.mjs`, `scripts/lib/release-strip.mjs`, `scripts/artifacts-coverage.json` and `upstream-dsh.json`. The staging generator accepts only a separate staged checkout through `--launcher-checkout`; it reads these named inputs and refuses installed-root overlap. This profile does not cover the admission helper imported from the selected release or establish launcher execution qualification.

Its version-2 owner-key profile protects the full fixed `/opt/owner-key` package, including the concrete G verifier imports and resolution metadata. A version-1 manifest can verify legacy package custody but cannot launch this new gate's Node roles without that external closure. Actual active-owner adapter mounting, independently authenticated registry/enrollment and native custody remain unconfigured.

The selfcheck source uses an active startup latch with Genesis `BindsTo` and `After`, plus a separate periodic oneshot under the existing timer. Both checks run the protected Python bootstrap before Node and retain the fail-closed service target. The original Genesis prechecks remain. Source dependency-model checks do not establish actual systemd behavior; the operator must install the version-2 manifest, bootstrap and units together and verify the installed lifecycle.

The optional Aura profile preserves complete Prime-relative source paths beneath `/opt/aukora-aura`; it dispatches only the fixed `packages/boundary-gate/host/aura/entry.mjs` with `collect` or `verify`. Public closed configuration is fixed at `/etc/aukora-boundary-gate/aura-context.json`. Its full code, package metadata, vendor/license/provenance and configuration pins must be reviewed before Node. Missing reviewed closure or configuration refuses. Mutable DB/WAL/store/grants and existing private author material are not public source inventory entries or new provisioning actions.

D owns the protected context and records-provider implementation. Public preflight verifies source and configuration without opening private author material; only private collector dispatch checks that material. The provider's two methods recheck the same retained read grant and lifecycle before and after awaited calls; disposal permanently closes cached handles. Loading that provider in a separate Genesis/Cordis host still requires the host's own protected closure and lifecycle adapter. Collector bootstrap success alone does not supply that join.

Source fixtures use disposable synthetic signer/registry inputs. They do not establish installed owner-key custody, journal capture mounting, note association, provider registration, cold runtime acceptance or containment. Deployment and receipt-consumer migration remain with their explicitly allocated integrator/owners.
