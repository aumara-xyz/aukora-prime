Lane F supplies an owned foreground Bash lifecycle for Prime. It adapts Genesis source `1cde243eaf16fcf8b1e25b16c476c2149932450d` and uses OpenShell upstream v0.1.2 at `6648bd0c290efbc41ba131ee9831ee45cd431f94`. The TypeScript SDK package metadata is `0.0.0`; no npm `0.1.2` package is assumed. `provenance.json` records exact source hashes and retained licenses.

H imports `createDshOpenShellExecutor({ShellExecutor, resolveSpec, executor, resolveOperation})`. `ShellExecutor` is the pinned DSH service base; `resolveSpec` is H's pinned defaults/caps callback. Mount only this shell provider. The factory resolves policy, rejects background jobs, and checks capability before calling the trusted broker resolver. `installOwnedBash(ctx, options)` also supplies `aukoraConfinement`; argv-only native SDK launchers always refuse.

`OpenShellOwnedExecutor` accepts host-owned settings, `SdkTransport`, a private local `OwnedLedger`, `assertConsumed(operation, grant)` and synchronous trusted `qualification(settings)`. Qualification must return exactly true only after the real runtime/image/policy join is qualified. G1 supplies unavailable capability and reserves no grant. A naked ConsumedGrant envelope does not confer authority: `assertConsumed` must check the broker's durable consumed reservation. The executor snapshots and verifies the exact frozen v1 operation, image, guest policy, bounds and UUID fence before dispatch.

The operation uses action `shell.bash.foreground`. Closed target fields are `backend,workspace,image_digest,policy_digest,logical_workspace_root`. Closed canonical parameters are `command,workdir,sandbox_mode,stdin,env,dsh_env,timeout_ms,max_output_bytes`. Omitted stdin/env/dsh_env map to empty string/maps at the trusted boundary. `policyDigest(mode)` identifies the exact camel-case protobuf guest policy, distinct from the gateway's admission hash.

One local SQLite database holds an OS-released exclusive live-process lease while a separate FULL-sync database durably saves create/exec/delete fences, ownership and bounded output/exit checkpoints. Restart reconciles unfinished calls before admission and never relaunches a command. A missing object after an ambiguous create remains quarantined because late creation cannot be excluded. Lost trailers preserve observed typed exit/output with `rpc_completion=transport_failed`; stdout text never determines exit. Nonzero drained command exits resolve DSH results. Infrastructure uncertainty rejects with `executionReceipt` attached. Caller cancellation/owner disposal require independent cleanup; local transport death supplies no guest termination evidence.

Cleanup scans the complete explicit workspace inventory, checks name/UUID/owner label, rechecks before deletion, and waits for observed absence. OpenShell has no atomic expected-ID delete. Trusted gateway/driver administration remains a prerequisite; a concurrent hostile name replacement is outside this contract. Ledger locks apply only to one local host and a trusted local filesystem, not cross-host ownership. The ledger and SDK manifest are host-owned state, not tamper-proof trust anchors.

Guest policy retains hard Landlock, UID/GID 1000, closed environment, no providers, no network rules, no host files/credential mounts or uploads. Logical host workspace maps to disposable `/sandbox`. Actual driver isolation, metadata/control-plane denial, kernel enforcement and cleanup must be observed in G3; security-group rules alone cannot establish them. An approved immutable custom workload image is missing. Real gateway, guest execution, H/C runtime join and installed-app qualification are UNPERFORMED. Advanced browser work is outside this package.

Run the one focused disposable check from the integrated Prime root:

    node packages/execution/checks/protocol.mjs

It uses a mocked gateway plus real local SQLite and newly spawned disposable child processes. It does not qualify guest confinement. Node 24.11.1 ran the check successfully; node:sqlite emits its experimental-feature warning.

Build the exact third-party SDK in an empty task-owned directory, without user npm configuration or lifecycle install scripts:

    python3 packages/execution/build-sdk.py --archive <openshell-6648bd0.tar.gz> --into <empty-directory> --build

Archive URL: https://codeload.github.com/NVIDIA/OpenShell/tar.gz/6648bd0c290efbc41ba131ee9831ee45cd431f94
SHA-256: `298ee3c0566c51e593e9eadc724a0e1c072fbb542b4f362b82e82a254f8eaea6`.
The recipe preserves selected source/licenses and the upstream package lock, generates/builds the SDK and emits a dist digest manifest. SDK generation reads the pinned Google API module specified by upstream buf.gen.yaml. `loadPinnedSdk(sdkRoot, connectOptions)` checks that host-owned manifest and builds a lazy verified-HTTPS client; it performs no RPC during load. A owns dependency/runtime hashing and packaging. Build artifacts are not a runtime dependency on the donor or on this lane workspace.

Runtime preparation now provides `runtime/image/Dockerfile`, immutable official amd64 inputs in `runtime/pins.json`, `runtime/gateway.toml.in` and the bounded setup/transfer checklist in `runtime/SETUP.md`. The executor accepts a local immutable Docker config ID (`sha256:...`) as well as an OCI repository manifest reference; mutable tags still refuse. Actual image outputs remain null until the separately approved build.
