# Private Cordis tool provider — unmounted lab seam

One tool, `prime_cordis_probe`, proposes exactly:

```sh
/usr/bin/printf 'prime-cordis-probe-v1\n'
```

The closed operation is `shell.bash.foreground`, read-only, empty stdin/env/dsh_env,
1,000 ms and 1,024 retained output bytes per stream, public data and USD 0.
Its workdir is the approved logical root; F maps that root to `/sandbox/work`.
The immutable workload image and F's exact read-only policy digest are in the
operation. There are no model-supplied command, image, policy, proof, session,
parent, child, mount or credential fields. This is not mounted in the host or
Auma composition. NEXT owns any future mounting; F owns execution/lifetime work.

## Source and contract seam

Isolated base: `c66634acdef7220fc0274ab56587d563d99b28b3` (clean when received).
Only `packages/cordis-tool-provider` changes. Pinned DSH is
`0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`, including its Cordis 4.0.2;
OpenShell remains `6648bd0c290efbc41ba131ee9831ee45cd431f94`.

[Source](src/index.mjs) uses actual `ctx.provide`, `ctx.effect` and
`ctx.tools.register`. The separate service is `aukoraCordisProbe`; it does not
register or change `ctx.sandbox` or `ctx.shell`. The factory takes trusted host
inputs in a closure, not Cordis plugin configuration or agent intercepts.

1. H supplies protected identity/task/target fields to `createProbeOperation`.
   The builder fixes the command, policy and limits. H supplies an immutable
   `provider_build_digest`. `expected_state_version` binds that digest and the
   fixed meaning `prime.cordis.read-only-printf.v1`; C's trusted `observeTarget`
   must corroborate the actual selected release and target. `probeSourceDigest`
   hashes this module for review; it does **not** attest loaded code, the complete
   dependency closure or installation. Host release custody must supply that.
2. The existing C owner path calls `propose`, `approvalChallenge` and
   `approvalComplete`. The plugin provides no signer, login or automatic approval.
   Its private `readApproval(operation, {signal})` retrieves the independently
   obtained proof. Missing/invalid proof cannot grant permission.
3. `createCordisToolProvider({operation, authority, executor, readApproval})`
   requires the actual F executor class, sharing the exact C broker object.
   The broker supplies C's unchanged `reserve`, `claimDispatch`, `requestCancel`,
   `settle`, and `reconcileSettlement` methods. A dedicated executor is required
   because this provider owns its disposal request. Missing configuration is
   unavailable. This narrow adapter reads F's existing settings/admission source
   methods; it introduces no alternate executor interface or enable callback.
4. Invocation checks lifecycle and exact executor target/policy/bounds before
   retrieving approval, after retrieval, after C reservation and immediately
   before F. Only C creates the consumed grant. Only F claims dispatch, using
   the exact operation/grant/request digest. C rechecks session, task, policy,
   expiry, target and one-use state at that checkpoint. F owns SDK calls,
   receipts, cancellation, settlement and reconciliation.
5. Concurrent/repeated reservation attempts refuse. An uncertain reservation
   permanently fences this provider instance; a later instance still faces C's
   durable one-use rules. Unload after reservation can leave C `PREPARED`, which
   stays a reconciliation obligation. No local reset refunds or retries it.
6. Cordis disposal synchronously revokes captured service/tool references and
   aborts the local signal, then requests F cleanup once. It proves no remote
   termination. Unknown/unavailable receipts remain in C/F and reject the DSH
   tool result; genuine settled nonzero command exits retain their factual
   receipt. No host-shell fallback exists.

Child narrowing is deferred: no provider method delegates, recursively mounts,
or interprets a context as authority. Any future child scope needs an actual C
authorization contract. Plugin registration itself grants no capability.

## Focused checks

```sh
node --test packages/cordis-tool-provider/checks/provider.test.mjs
PRIME_PINNED_DSH_DIR=/path/to/existing/pinned/dsh-build \
  node --test packages/cordis-tool-provider/checks/cordis.test.mjs
```

The first command runs actual C owner-proof verification/kernel/store and F
lifecycle code. Authentication uses in-memory synthetic keys; F qualification,
target observations and SDK replies are explicitly mocked. It starts no guest
and never executes the displayed command. The lifecycle context in that file is
a stub. The second command uses the actual existing pinned Cordis, SystemPrompt
and ToolRuntime build; it checks provenance before import and explicitly skips
when no build is supplied. Its successful authority/executor path is still a
mocked protocol experiment. No install/build/network access is performed.

See [evidence](EVIDENCE.md) for commands actually run and their limits. The
repository-wide `./prime verify`, product build, browser observation, host mount,
owner enrollment and real Linux execution are **UNPERFORMED** in this scoped lane.
Global README/paper claims are untouched; NEXT owns any later integration claim.

## Prerequisites for one real Linux action

F's `e3ea48828524604c5ebd0008b031bceda76d0d70` lifetime increment deliberately
keeps production unavailable even with accepted observation records. Its
`runtime/LIFETIME_SAFEGUARD.md` is authoritative after NEXT integrates it. This
provider neither creates nor renews F's original durable wall deadline.

The next prerequisite is **implemented and reviewed independent deadline/terminal
create-and-exec fencing, complete owned-artifact reclamation, and atomic admitted
configuration binding/freeze in F's real backend path**. These are absent, not
waiting for a boolean approval flag. Matching pre/post digests cannot exclude
intervening drift. Full policy includes global/provider/environment/middleware
and attachment contributions; a base policy hash is insufficient.

After those mechanisms exist, the one-action path also requires an approved
immutable workload build (separate config and manifest identities), approved
private Linux gateway/control/ledger deployment, actual kernel/driver resource
and identity observations, accepted evidence bound to that exact runtime and
provider build, ordinary real C owner approval for a fresh exact operation, and
NEXT's reviewed private mount. Separate setup authorization must cover any
daemon, control credentials or host-security changes. This task performed none.
Retain genuine typed output/exit/RPC facts and complete identity-bound cleanup
through C; a single successful probe would not qualify crash/expiry/general use.
