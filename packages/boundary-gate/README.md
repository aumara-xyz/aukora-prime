# Boundary gate: harness-to-agent boundary (from the Genesis SKUNKWORKS lab)

The agent ("Auma") gets its hands only inside an NVIDIA OpenShell sandbox owned by a separate Linux user,
and the harness that runs the model cannot change the system except by proposing to a gate run by a
third Linux user. This package distills that lab into Prime's layout. It is unmounted: nothing in
`./prime boot` or the 66-job source profile starts it.

Source: `aumara-xyz/aukora-genesis`, `labs/deepseek-harness-boundary` at lab tip `6fa70cd`
(`labs/gate-hardening-r3`). Upstream DeepSeek Harness is MIT and is not vendored here.

| Part | Where | Status in Prime |
| --- | --- | --- |
| UID separation, single sudo rule, OpenShell 0.1.2 on rootless Podman | `host/`, `host/SETUP.md` | SOURCE-ONLY; lab run CLAIMED |
| Harness-side sandbox runner, egress probe, fail-closed self-check | `src/layout.mjs`, `src/sandbox.mjs`, `src/selfcheck.mjs` | SOURCE-ONLY, covered by `checks/` |

Checks (no network, no sudo, no OpenShell needed):

```sh
node --test packages/boundary-gate/checks/*.mjs
```

The sandbox-wrapper check replaces `/usr/bin/openshell` with a local stub and runs the wrapper's real
cleanup script inside a private PID namespace (`unshare --user --map-current-user --pid --fork
--mount-proc`). Where unprivileged user namespaces are unavailable that case is reported as skipped,
not passed. A green check is source evidence only: it does not establish real OpenShell isolation,
network absence, Podman storage quotas or the deployed sudo rule.
