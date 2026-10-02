# Lifetime safeguards — disabled source increment

The subsequent [guardian process increment](GUARDIAN_PROCESS.md) adds executable
separate-process monitoring and disposable process evidence. The fixed launch
gates described here remain closed; that successor does not implement the missing
terminal target/configuration/artifact primitives or qualify a real runtime.

This increment adds durable local lifetime accounting and explicit production refusal at unsupported enforcement boundaries. It implements no guardian, independent timer, terminal create fence, atomic configuration condition or driver reclamation service. The frozen v1 operation, grant, request and receipt envelopes, their digest domains, and the private C dispatch/cancellation/settlement interfaces are unchanged.

## Implemented source behavior

[lifetime-safety.mjs](../src/lifetime-safety.mjs) fixes `PINNED_EXECUTION_SAFETY` to `unavailable` for independent expiry, late-create fencing, atomic configuration and complete owned-artifact cleanup. [owned-executor.mjs](../src/owned-executor.mjs) requires these mechanisms in addition to accepted qualification observations. A valid observation record therefore cannot make production capability, admission or availability qualified. There is no production enable callback or newly invented backend RPC in this increment.

Before reserving the local job and making the one-use C `claimDispatch`, F records the original request binding and a closed private lifetime record:

| Field | Meaning |
| --- | --- |
| `version` | Private record version `1`. |
| `request_id`, `request_digest` | Exact original frozen request binding. The full operation and consumed grant remain in the owned job. |
| `accepted_at` | Local acceptance instant before claim and create. |
| `deadline_at` | Fixed `accepted_at + wall_time_ms`, including claim delays and provisioning. |
| `last_observed_at` | Latest accepted local clock observation. |
| `wall_time_ms` | Original approved request duration; it cannot be extended during recovery. |
| `enforcement` | Always `local_accounting_only`. |

The private domain `aukora-prime.local-lifetime.v1\0` binds the immutable record fields; `last_observed_at` remains a durable observation rather than part of that immutable digest. Existing request and receipt digests retain their frozen meanings. Internal timestamps use canonical UTC milliseconds without changing the original operation bytes.

Operation approval expiry is a separate admission cutoff. F retains its checks before dispatch, create and exec. It does not use that expiry to shorten the command wall deadline or manufacture timeout cancellation intent. Neither later approval expiry nor an authorization-epoch change rewrites factual effects or restores consumed authority.

Recovery inspects the saved deadline and full request binding; it never creates a replacement deadline. The run timer uses the remaining original duration rather than granting a fresh timeout after claim. A detected clock rollback or invalid accounting record refuses further launch. Local wall-clock accounting detects only the clock observations it actually receives: it establishes no boot continuity, independent scheduling or enforcement while JavaScript cannot execute.

Production refuses create without independent lifetime ownership and late-create fencing, and refuses exec without an atomic configuration mechanism. Cleanup also requires independent identity-bound fencing and complete artifact evidence. Public API absence is retained as a separate `public_cleanup_observation`; it cannot be promoted to `confirmed_absent` by production. A durable `prepared` stage can still establish `not_created` where no create attempt occurred. Jobs whose create was attempted retain uncertainty until trusted evidence closes the actual lifecycle obligations.

F preserves original consumed grants, launch fences, typed output/exit facts and the settlement outbox. Reconciliation cannot relaunch a job, unconsume its grant, infer command success from logs, or infer termination from SDK abort or Cordis disposal. Complete typed RPC evidence retains its factual meaning; unknown configuration or cleanup can still require `OUTCOME_UNKNOWN`. Recorded cancellation proves intent. `CANCELLED` additionally requires proven no launch and executor-confirmed cleanup under C's unchanged rules.

## Concrete research addressed

The saved *AUKORA Composition and Authority Research Report* has PDF SHA256 `ec31096dc739bc3758c72063beccce6d62d3360572a5f7db806e70c1f605e72c`; its textual authoring source has SHA256 `9e862aa2046c58d734eacaca08492eefe730e3de907c36be4c580b911f755cc0`. This increment addresses these bounded findings from that saved Astra handoff:

| Saved finding | Source response and remaining limit |
| --- | --- |
| `ExecSandboxRequest` lacks an expected configuration revision; pre/post readbacks do not make launch atomic (textual source line 120). | An explicit production exec refusal prevents accepted readbacks from authorizing an unsupported launch. Existing effective configuration observations remain evidence. No atomic target condition was implemented. |
| Effective policy includes provider rules, global precedence, credential bindings and runtime additions; network generation changes do not prove universal revocation (lines 138–139). | The increment preserves existing full effective-configuration checks and does not substitute the authored policy digest or a network transition for an execution fence. Complete atomic binding remains required. |
| Ownership, fencing and failure semantics must be explicit; revocation must not wait for a hung executor (lines 160–161). | The job retains its own request, original deadline, consumed authority and settlement evidence. Local timers and graceful disposal are explicitly insufficient; independently schedulable control remains missing. |
| Independent deadlines and late-create cleanup remain separate missing work (line 216). | Durable accounting now starts before claim/create and cannot renew on restart. Production separately refuses independent lifetime and complete cleanup claims until an actual mechanism exists. |

The report distinguishes the pinned Harness's locally hardened Cordis 4.0.2 from standalone Cordis. Parent/child ownership and an awaited disposer remain useful for graceful cleanup, but concurrent effects, cleanup errors and JavaScript death do not establish external workload termination. This increment does not alter Cordis or claim its lifecycle is qualified.

Grok's reported results in the saved report were not independently reproduced, and the toy implementation was not supplied. No toy code or reported PASS count is treated as implementation evidence here. The inspected handoff supplied no Muse or GLM attribution, so this increment makes no such attribution.

## Unimplemented qualification obligations

The fuller proposed private boundary remains in [DEADLINE_OWNERSHIP.md](DEADLINE_OWNERSHIP.md). The following mechanisms must be selected, implemented and independently observed before production admission can become available:

1. **Independent expiry and terminal launch fencing.** A durable owner must acknowledge the exact request, consumed grant, ledger/deployment identity, launch identities and immutable deadline before create. Its scheduling, clock/boot policy and restart behavior must continue when F, SDK, Cordis or gateway code cannot execute. Expiry or cancellation must exclude delayed creation and later exec for the same job before reclamation. A local timeout, heartbeat, gateway Ready deadline or missing API row is insufficient.
2. **Atomic configuration admission.** A reviewed target mechanism must bind or freeze the exact sandbox UUID/generation and complete admitted configuration at actual launch and through the relevant execution lifetime. It must cover policy, global overlays, provider/environment revisions, credentials/attachment state, middleware and extensions. Matching observations cannot exclude an intervening change or an A → B → A sequence.
3. **Complete immutable artifact ownership and reclamation.** Trusted control-plane/driver records must bind workload, supervisor/auxiliary containers, owned networks and all private volumes to the original deployment and sandbox identity. Scoped actions need identity-conditioned ownership checks and complete post-cleanup observations plus late-create exclusion. Shared or unrelated resources cannot enter deletion authority. Public sandbox absence or delete success alone cannot close this obligation.
4. **Retrievable evidence and conservative recovery.** Preserve partial attempts and control responses across restart, independently retrieve evidence bound to the original job/runtime, and retain unknown outcomes when proof is incomplete. Confirmed reclamation does not prove absence of earlier external effects. Evidence cannot enable replay, refund consumed authority or overwrite conflicting typed facts.

These are pending backend/host requirements, not new wire fields, callable methods or installed services. OpenShell remains pinned to `6648bd0c290efbc41ba131ee9831ee45cd431f94`, with its source-built TypeScript SDK package version `0.0.0`. The pinned API provides no expected configuration/generation condition for exec. This increment adds no guessed SDK option or silent protocol extension.

The authored keyless fixtures exercise local binding, immutable deadlines, clock rollback and refusal despite accepted observations or public API absence. Their explicit mocked executor may simulate missing mechanisms solely to preserve protocol checks; it never reports runtime qualification. Such fixtures cannot qualify a real deadline, artifact cleanup or atomic policy join. No guardian, gateway, guest, credentials, host/security setup or deployment is introduced by this source increment.

## Minimum provider integration contract

The unmounted provider should receive the existing trusted executor and operation resolver from H. It must not construct consumed grants or interpret Cordis configuration as approval. The [frozen contracts](../../contracts/src/index.ts) and [F declarations](../src/index.d.mts) remain authoritative:

```ts
interface OwnedExecutor {
  readonly capability: 'unavailable' | 'qualified'
  execute(request: OwnedExecutorRequest): Promise<ExecutionReceipt>
  reconcileOwned(): Promise<readonly ExecutionReceipt[]>
}
// OwnedExecutorRequest fields: operation, consumed_grant, request_id,
// image_digest, policy_digest, wall_time_ms, max_output_bytes; optional signal.
```

Use `createDshOpenShellExecutor({ShellExecutor,resolveSpec,executor,resolveOperation})` with the pinned DSH base explicitly imported by the host. Its one Cordis effect awaits the same executor disposal promise. Exactly one provider registers `ctx.shell`; `start()` remains unavailable. The factory checks capability before calling `resolveOperation`, so unavailable composition consumes no grant. Its exact frozen unavailable stub is sufficient for an unmounted/disabled join; it cannot call a real SDK.

The operation action is `shell.bash.foreground`. The closed target has `backend:'openshell-linux'`, `workspace`, immutable `image_digest`, exact `policy_digest` and `logical_workspace_root`. Closed parameters are `command,workdir,sandbox_mode,stdin,env,dsh_env,timeout_ms,max_output_bytes`. The workdir equals the approved logical root and maps privately to `/sandbox/work`. Empty stdin/env/dsh_env are explicit canonical values; mode is read-only or workspace-write. Wall/output request values equal the approved parameters and are capped at 30000 ms/65536 bytes per stream. Host create resources remain CPU500m/RAM512Mi, scratch128Mi and PIDs64; callers cannot add mounts or driver configuration.

F's constructor additionally receives actual trusted C methods `claimDispatch`, `requestCancel`, `settle` and `reconcileSettlement`. Claim binds the full operation/grant plus request ID/digest; settlement also binds the exact receipt/digest. F supplies the durable local launch fence before the mandatory one-use C claim. Resolver success, a grant envelope or a boolean callback cannot replace that call. The provider sees the unchanged receipt status, typed exit/RPC completion and cleanup uncertainty. Unknown results retain the receipt and reject the DSH run; a drained genuine nonzero exit resolves its result. The provider never retries an uncertain job or falls back to host Bash.

## Prerequisites for one real bounded Linux action

No real action is available through this increment. Even one inert request through the production executor requires these concrete inputs and mechanisms first:

1. Reviewed implementation of the independent owner, terminal create/exec fencing, complete scoped artifact reconciliation and atomic admitted-generation/freeze obligations above. Those implementations must replace the fixed refusals through reviewed source; accepted records, disabling concurrent administration or switching an `available` flag cannot supply them. Keep the provider unmounted until its actual configured path has the required evidence.
2. An approved immutable custom workload output with separately recorded Docker config ID and OCI manifest digest, exact source/context/layer/license evidence, UID/GID1000 and OCI workdir `/sandbox`. Current output pins are null. The exact existing official amd64 gateway/sandbox/supervisor/base references remain in [pins.json](pins.json) and [pilot-official-metadata.json](pilot-official-metadata.json). No mutable tag or assumed image-build result is acceptable.
3. H's approved deployment manifest identifying the real Linux amd64 kernel, Landlock ABI3+, seccomp user notification, Docker/cgroup2 versions, dedicated executor UID, protected control/ledger identities, resource ancestry, approved socket and loopback listeners, and private authenticated control placement. Any installation/daemon start, UID/ACL/cgroup/security change or mTLS/JWT creation requires separate explicit authorization. This source increment performs none of them.
4. Actual driver/kernel observations for CPU500m, memory512Mi, effective swap denial, PIDs64 and the exact 64/32/32Mi tmpfs mounts, plus bounded aggregate control/supervisor resources and log storage. Readback JSON cannot establish kernel limits. Workload has no network, host workspace/credential mounts, providers or model keys; supervisor/control privileges and credentials need separately inspected placement. The exact full effective configuration/admission tuple must agree with the approved profile and atomic mechanism.
5. The actual C store's ordinary authenticated owner review/reserve flow for one fresh exact operation, real consumed/prepared evidence and trusted one-use dispatch/settlement. Synthetic keys, raw PREPARED rows and prior fixtures cannot supply this real authority. Bind accepted host evidence to the exact SDK, image, policy, workspace, gateway, ledger, host profile and bounds. SDK source remains the pin above with package version0.0.0; no unchanged SDK build was repeated here.
6. Separately authorized execution of the one inert read-only foreground operation proposed in [pilot-profile.mjs](pilot-profile.mjs), with empty stdin/env/dsh_env and the fixed limits. Retain genuine exit1 output, drain RPC trailers, verify the post-RPC configuration, establish complete identity-bound owned cleanup/late-create exclusion, and deliver the exact F receipt through C. Scope deletion only to recorded owned artifacts; never stop unrelated processes. One successful seam observation cannot qualify crash/deadline, active egress denial or general execution.

[SETUP.md](SETUP.md) and [PILOT.md](PILOT.md) preserve the earlier dated setup proposal. Their older statements that the create-profile source or C complete/null allowance are missing are superseded by [NEXT_INCREMENT.md](NEXT_INCREMENT.md) and this increment. The frozen unavailable factory, no host fallback, no default workspace transfer and no credential entry remain in force. Source/mock checks and explicit setup permission do not replace runtime qualification or the still-missing backend mechanisms.
