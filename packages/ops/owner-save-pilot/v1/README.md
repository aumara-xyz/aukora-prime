# Reduced-guarantee owner-save pilot v1

This ops-only source packet prepares the explicitly approved interim pilot. It does not mount an application route, change credentials, initialize a store, start a service or accept a save. The original qualified factory remains closed. The original 146 evidence rows and two red rows remain frozen.

Every sidecar and preparation status carries **REDUCED-GUARANTEE** and names the missing **independent witness, second-host anchor and hardware hash display**. A digest binds metadata to bytes; it supplies none of these guarantees. No v0.3 conformance is claimed. Real owner-save acceptance and Grok review of the actual frozen bytes remain pending.

## Owned interface

`scope.mjs` exports:

- `PILOT_PROFILE`, `PILOT_PROFILE_DIGEST`: the closed literal profile and its domain-separated digest.
- `createPilotScopeBinding({deployment, operation, canonical_receipt_bytes})`: create the scope-only sidecar. `deployment` is exactly `{source_commit, release_digest, deployment_manifest_sha256}`; commit is lowercase 40hex and both byte hashes are lowercase 64hex. The caller obtains these pins from independently retained protected deployment configuration, never from the candidate's self-report. Operation and receipt inputs are both null for a status without an operation, or operation alone may be supplied before a receipt exists.
- `verifyPilotScopeBinding({binding, expected_deployment, operation, canonical_receipt_bytes})`: recompute the complete binding against independently supplied expected inputs and reject any difference. Both creation and verification are metadata operations; neither admits a receipt or proves approval/persistence.
- `createPilotPreparationStatus({phase, deployment, operation, canonical_receipt_bytes})`: a closed source-preparation status with qualification `UNPERFORMED`. Its phases are `source_preparation`, `integration_pending`, `activation_pending`, `actual_bytes_review_pending`. There is no PASS/DONE phase.
- `sha256Bytes(text)`: hash exact UTF-8 text, returning `sha256:<64hex>`.

`binding` is exactly `{scope, scope_digest}`. The scope contains `version`, `kind`, `guarantee_profile`, `scope_label`, `missing_guarantees`, `public_qualified_factory`, `v03_conformance`, `grok_review`, `profile_digest`, the three deployment fields, `operation_id`, `operation_digest`, `receipt_digest`, `canonical_receipt_bytes_sha256`. The last four values are null when their evidence is absent. A receipt requires an operation. There are no approval/authentication inputs, arbitrary status fields, allow switches or secret-bearing payloads in the output.

The helper checks the frozen OperationProposal structural contract and its digest domain. It limits this pilot to `memory.save` / `aukora-prime.memory` / a `prime-memory` owner subject. The existing twelve-field `prime-memory-effect/v1` receipt remains byte-for-byte unchanged. Scope binding requires its original canonical JSON bytes, operation/digest/owner-subject agreement and existing result/receipt digest domains. The whole input is bounded at 8 MiB to accommodate string escaping; individual operations and receipt bytes remain bounded at 2 MiB. These structural checks do not replace C, Bridge or workflow admission. The genuine application must validate the actual save reply, consumed grant, owner approval and authority settlement before presenting the corresponding receipt.

The new canonical domains are `aukora-prime.owner-save-pilot-profile.v1` and `aukora-prime.owner-save-pilot-scope.v1`, each followed by NUL and sorted compact safe-integer JSON. Existing receipt/result domains remain `aukora-prime.memory-receipt.v1` and `aukora-prime.memory-result.v1`. The canonical receipt byte SHA hashes its exact UTF-8 bytes without a domain. Expected deployment byte hashes are raw 64hex; operation, receipt, profile, scope and byte-SHA outputs have the `sha256:` prefix. No receipt bytes are printed by these helpers.

## H/Bridge/B join remains pending

This is a proposed ops sidecar interface, not an agreed application envelope. H/Bridge/B must name a separate versioned pilot assembly, authenticated client/capability boundary and envelope. Validate the sidecar and independently expected pins before giving the unchanged inner reply to existing UI adapters/workflows. Keep the validated scope in a separate read-only projection; clear it on owner/session/binding replacement. Display the label, every missing guarantee and bound digests beside each pilot receipt/status, including refusals and uncertainty.

Preserve the closed public receipt, workflow, capture-note and seven-field capability schemas. Keep `qualified-owner-memory/v1` and the retained Bridge acceptance guard closed. Do not use `requiresCapabilities:false`, remove public unavailable flags or expose a generic allow setting. The separate pilot must reuse the real owner login, native owned approval hook, exact-origin controls, C authority and genuine PG save path. Receipt hashes are not proof verification or an independent witness. A separate envelope must additionally bind the unchanged full reply bytes; this ops helper binds the receipt only and does not define that envelope.

`SETUP.md`, `operator-inputs.template.json` and `bootstrap-requirements.json` specify the proposed roles/paths, exact helper pins and missing registration, C/D bootstrap ordering, genuine D metadata/genesis, publisher transport/entrypoints and host observations. Templates are incomplete review inputs, never runtime configuration. The source packet provides no installer or bootstrap command while those helpers are absent.

## Focused source check

Use the explicitly selected frozen contracts input, or an independently materialized copy with the same three pins:

```sh
node packages/ops/owner-save-pilot/v1/check-source.mjs --contracts-root /absolute/physical/packages/contracts/src
```

The runner reads only `runtime.mjs`, `shared.mjs`, `json.mjs`, verifies their literal H251 hashes, copies them and the three named test/helper files into a new disposable directory, runs the metadata checks with the evaluator's explicit Node and scrubbed child environment, then removes that directory. It imports no module from the external source tree. Production imports resolve relative to physically owned `packages/contracts` (or composed `prime-packages/contracts`) inside Prime; no other user-owned repository is a build/runtime dependency.

The synthetic fixture is explicitly **UNAUTHENTICATED HASH METADATA ONLY**. It has no signer, approver, authority store, database, listener or effect. Checks cover changed scope/pins/operation/owner/receipt bytes, duplicate JSON keys, canonical byte identity, accessors, added fields, wrong action, missing evidence and a forbidden DONE status. Source-check PASS never becomes pilot acceptance. Real passkey + PG save, no-approval decline, tampered-approval decline and Grok actual-bytes review remain required **UNPERFORMED/PENDING**, not skipped or passed.

First-party source is AGPL-3.0-or-later under `packages/ops/LICENSE`; selected upstream source references and frozen contract pins are in `PROVENANCE.json`. No VM, credentials, installation, deployment, activation, public guard or frozen acceptance accounting is changed by this packet.
