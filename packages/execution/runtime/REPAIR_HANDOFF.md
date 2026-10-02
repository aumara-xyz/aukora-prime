# Execution repair handoff — Proposed

Source-only repair `b18b0e0546f39de244edff9ef8ea91ba781b3fc4`, parent `165fb12a45fc6e4a52e412fa5e6ef48dd978a8a8`. Import the sanitized delta patches after reviewing their base and path mapping. Do not merge old complete-history bundles. Only `packages/execution/**` was edited. H owns canonical import/mount; C owns its receipt validator. No real gateway, guest, setup, keys, security settings or deployment was used.

The repaired source keeps ambiguous exit124 unknown, verifies the complete effective configuration, and registers cleanup in the factory H already imports. Frozen operation/request/receipt envelopes, digest domains, six executor settings and private C method signatures stay unchanged. Actual runtime remains unavailable and this plan remains Proposed.

## Exact private boundaries

`createDshOpenShellExecutor({ShellExecutor,resolveSpec,executor,resolveOperation})` keeps its existing signature. The supplied context must support `effect`. A real executor must have `dispose`; H's exact `Object.freeze({capability:'unavailable',execute:refusal})` data stub is supported without one. The class registers one effect whose concurrent disposer calls share one awaited promise, including synchronous errors. No `ctx.on('dispose')` listener remains. Cordis may log a cleanup rejection and finish unloading; that never proves guest absence.

`SdkTransport` now requires the pinned raw client's existing `getSandboxConfig({workspaceScope,name},options)` method. Its `configuration(job,settings,options)` returns the exact generated readback shape declared in [sdk-transport.ts](../src/sdk-transport.ts): policy, version/hash, settings, configuration/provider revisions, policy source/global version, middleware, workspace, validation mode, extension authentication, attachment epoch and admission/instance/error fields. Raw revisions are bigint; durable equality tokens are canonical decimal strings.

[effective-policy.mjs](../src/effective-policy.mjs) implements the pinned maps-empty static protobuf identity and configuration/provider fingerprints. It compares exact full stored/effective policy, history version1, sandbox source/global version0, four unset registered settings, no providers/middleware, fail_closed mode and extensions disabled. Only matching generated metadata is tolerated; unknown semantic fields, overlays or lossy Number revisions refuse. Admission must match configuration instance, policy version/hash and both revisions; provider attachment UUID must match the spec. The durable closed fingerprint is:

```text
{version:1, workspace, policy_version:1, policy_hash,
 config_revision, provider_env_revision, provider_attachment_epoch,
 configuration_instance_id, policy_source:1, global_policy_version:0}
```

F reads at readiness, immediately before dispatch and after RPC drain. Abort, expiry and qualification are rechecked after the awaited pre-exec readback. Before launch it saves `configuration_verification:'pending'`; only a successful final readback and durable save sets `'verified'`. A crash, failed final readback or drift preserves unknown across restart, retaining typed exit/output/RPC facts and permanent launch fences. Later cleanup cannot substitute for a missing final verification.

## C-owned validator dependency

Pinned gateway timeout and genuine command124 have the same wire event. F saves separate private `gateway_exit_evidence:{exit_code:124,reason:'ambiguous_timeout_or_command_exit'}` and leaves receipt command exit null. After final trailers drain, the factual receipt has `rpc_completion:'complete'`, `status:'outcome_unknown'` and `reconciliation_required:true`. Lost trailers remain `transport_failed`. Cancellation and confirmed absence cannot prove prior command outcome.

C source `1be5ccc2d93b4657a6fe7de63ec4d6757c73b114` rejects every complete/null receipt. Until C's reviewed validator allows complete/null only for a started, conservative unknown receipt with reconciliation required, F preserves the exact pending settlement outbox and returns `RECONCILIATION_REQUIRED`. No retry, false transport status, fabricated command exit, unconsumption or C edit is made here. C's existing settlement derivation already preserves unknown. C must verify this narrow allowance using its ordinary disposable owner-key login/approval/reserve/dispatch flow, including exact duplicate delivery/restart and binding negatives; no raw PREPARED seeding.

## Evidence and remaining qualification

Node 24.11.1 checks passed: protocol14, controls19, mechanisms10, ordinary actual C1be5 approval/kernel/store join9, timeout7, effective configuration33, static effective-policy9, pinned Cordis/ShellExecutor lifecycle11. Twenty-five independent guard-removal variants were killed by 26 controls, including the durable final-verification crash guard. Actual source-built SDK 0.0.0 protobuf serialization parity, planned resource/mount round trip and strict raw-client/OwnedExecutor type compatibility passed. Encoding checks execute SDK protobuf serialization plus the pinned hash algorithm; native Rust hash/prover/runtime tests were not run. All runtime/control responses in F lifecycle tests are disposable mocks; the ordinary C join uses synthetic in-process owner keys only.

OpenShell is exact `6648bd0c290efbc41ba131ee9831ee45cd431f94`; DSH is `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`, with vendored Cordis4.0.2. Contracts remain `f4fbe48e9cbb2c751d7eb2aaa2b931a9522978d0`. The task-local SDK build manifest identifies the exact archive and compiled outputs; no runtime/build dependency on an owned donor repo is introduced.

H/C mounting and the complete/null join remain unperformed in this lane. Immutable custom workload image output, actual resource/tmpfs profile join, isolation/control credentials and observed enforcement remain prerequisites. Supervisor baseline policy enrichment must match the exact declared profile or refuse; it is not normalized away. ExecSandbox lacks an atomic configuration-revision precondition; initial/final observations cannot rule out an intermediate change. Continuous monitoring and a qualified generation fence remain Proposed. External durable deadline/termination/late-create supervision is unimplemented and requires separate setup/qualification. SDK, JS, gateway or Cordis death is not guest termination evidence.

Existing unknown-outcome facts, consumed grants, outboxes, deployment/ledger identities and fences remain retained. No acknowledgement/abandonment clearing endpoint or background/native launcher is enabled. The source repair does not authorize the setup proposal in [PILOT.md](PILOT.md).
