# F next-development source checkpoint

This increment is isolated on `prime/next-f-create-profile`, based on F
`ee3e9577ccfc93d694e9ba358d8ef774dad43845`. It does not edit or mount today's
release. OpenShell remains `6648bd0c290efbc41ba131ee9831ee45cd431f94` and the
source-built SDK remains **0.0.0**. C dependency is
`292474f58f18c10bd4a9703909d02f12be82a0ac`; contracts remain the reviewed
`f4fbe48e9cbb2c751d7eb2aaa2b931a9522978d0` closure. Source review only;
tests, builds, Docker/gateway/guest calls and host setup are held.

## Actual source increment

`src/create-profile.mjs` owns the fixed template, rather than importing a pilot
proposal at runtime. `SdkTransport.create` now sends `resources.limits`
`{cpu:'500m',memory:'512Mi'}` and `driverConfig.docker.mounts` with the exact
three tmpfs definitions: `/sandbox/work`64MiB0700 UID/GID1000,
`/sandbox/.dsh`32MiB0700 UID/GID1000, `/tmp`32MiB01777. Options are closed to
the checked-in profile; host bind/volume mounts and caller driver JSON are absent.
The approved logical root maps to exec workdir `/sandbox/work`; OCI image
workdir stays `/sandbox` for the pinned driver's mount validation.

F durably stores private `create_template`, `create_profile_digest` and
`guest_workdir` before the one-use C claim. Readbacks check the exact resource
and driver template plus generated protobuf defaults at readiness, before exec
and after RPC drain. Profile mismatch refuses execution, preserves uncertainty
after attempted execution, and prevents automatic cleanup of pending jobs from
a legacy/different profile. No uncertain create/exec is retried.

`includeWorkdir=false` is shared by the pilot and production policy. The
workspace-write mode allows only those scratch mounts and `/dev/null`, changing
its exact policy digest. New operations need fresh exact C review/approval;
existing operations/grants and frozen v1 digest algorithms are never rewritten.
Foreground bounds are wall30000ms/output65536B per stream; accepted CPU,
memory, scratch and PID bounds must match the fixed profile. PIDs64,
`allow_driver_config=true`, `enable_bind_mounts=false`, `image_pull_policy=never`
and the aggregate cgroup slice remain host operator settings to admit/observe.

The pinned image recipe prepares owned mount targets without downloads,
credential/workspace copies or VOLUME declarations. `image/source-inputs.json`
records source/context hashes and null config/manifest outputs.
`image-manifest.mjs` inspects exact supplied OCI bytes/local-load projection,
always returning `OUTPUT_EVIDENCE_UNQUALIFIED`. It does not prove builder use,
layer contents or runtime enforcement and does not update image pins.

## H/bridge interface dependency

No authority, OperationProposal, ConsumedGrant, OwnedExecutorRequest,
ExecutionReceipt or C private-method fields changed. Existing
`createDshOpenShellExecutor({ShellExecutor,resolveSpec,executor,resolveOperation})`
and `claimDispatch/requestCancel/settle/reconcileSettlement` remain the join.
H must resolve exact logical root/operation parameters and keep defaults/caps
within wall30000ms/output65536B. H imports one shell factory in unavailable
mode until real runtime qualification; no model or guest route can supply
the trusted profile, accepted host proof, credentials or approval.

New F exports `createTemplate(image_digest)`, `createProfileDigest(image_digest)`,
`CREATE_PROFILE_ID`, `CREATE_BOUNDS`, `DOCKER_REQUIREMENTS`, `GUEST_WORKDIR`
and `IMAGE_WORKDIR` let H inspect this source profile. The profile digest uses
`aukora-prime.create-profile.v1\0` plus canonical JSON and is private evidence;
it does not replace frozen operation/request/receipt digests. Raw SDK readback
types remain broad JSON, with exact runtime validation. The pure image helper
uses the existing strict JSON parser from the contracts closure for textual OCI
ingress. Native launchers/background execution/host fallback stay unavailable.

Import only the reviewed delta for `packages/execution/**`. Parent owns
integration; this lane does not edit its index. The saved C/F six-case result
belongs to the earlier source checkpoint with a mocked SDK, not this increment.

## Minimum next approvals and remaining implementation

1. **Focused keyless local source checks, pending:** actual SDK serialization
   and TypeScript structural compatibility for the new template; generic
   profile/workdir/bounds/readback refusal cases; ordinary actual C approval to
   F mocked lifecycle/settlement. No backend or prior stopped sequence. Run only
   after the parent relays explicit approval for the exact focused scope.
2. **Image build scope, separately held:** named immutable base input layers,
   one local network-disabled single-platform build/export/load/inspect on the
   approved private daemon, exact config/manifest digests and source/layer/license
   evidence. Installation, daemon start and other images/keys are outside that
   build approval; see [image obligations](image/README.md).
3. **Private pilot setup/one inert call, separately held:** the exact named
   official packages and four immutable image inputs, private daemon and
   reviewed executor UID/control paths/socket/cgroup/loopback/mTLS/JWT placement,
   then the exact fresh approved no-provider/no-host-mount foreground operation
   in [pilot-profile.mjs](pilot-profile.mjs). Observe kernel/mount admission,
   genuine exit1/output/RPC drain, original C dispatch/settlement, and complete
   owned artifact cleanup. Resolve actual paths/UID/ports in H's reviewable
   manifest before that setup approval; do not guess active settings here.

The [independent lifetime/cleanup owner](DEADLINE_OWNERSHIP.md) and reviewed
atomic configuration-generation/freeze mechanism still need implementation.
Readback, Cordis disposal, abort, process death and Linux presence supply none
of those guarantees. Separate bounded deadline/owner-death/gateway-restart/
late-create/artifact observations remain needed for their claims. One inert
call does not qualify those claims or turn on general execution.
