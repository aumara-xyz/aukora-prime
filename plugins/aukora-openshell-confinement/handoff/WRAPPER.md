# Root-owned wrapper handoff

Grok owns `packages/boundary-gate/host/sbx-exec`, installation, sandbox startup
policy and shared composition. This lane changes only its new plugin directory.
The selected wrapper at `1ebe7539b0dd6e3bd8767fe173021595f69861dc` lacks the
interface below. The adapter remains disabled until that interface is joined.

Keep ordinary `sbx-exec <timeout-seconds> <command-string>` and the existing
`sandboxArgv()` unchanged. Add `sbx-exec --confinement-info`: read-only, no proposed
command or guest user code, bounded to 16 KiB JSON, nonzero on unavailable data.
The following closed version-1 envelope is required:

```json
{
  "version": 1,
  "openshell_version": "0.1.2",
  "sandbox": "auma-ws",
  "state": "Ready",
  "instance_id": "observed-running-instance",
  "policy_revision": 1,
  "applied_revision": 1,
  "workspace_root": "/sandbox",
  "network_mode": "none",
  "policy": {
    "version": 1,
    "filesystem_policy": {
      "include_workdir": false,
      "read_only": ["/bin", "/usr", "/lib", "/etc", "/proc", "/dev/urandom"],
      "read_write": ["/sandbox", "/tmp", "/dev/null"]
    },
    "landlock": {"compatibility": "hard_requirement"},
    "network_policies": {}
  }
}
```

This example is a schema, not runtime evidence. Obtain instance/state, applied
startup policy and revision from genuine OpenShell runtime/gateway state. Include
all runtime-added writable grants. Desired/saved policy, an operator boolean,
container isolation and `--no-auto-providers` do not establish this readback.
Refuse if actual applied startup state cannot be obtained. `policy_revision` and
`applied_revision` are positive integers and must agree. `instance_id` is a
nonempty bounded opaque identifier; do not log it into public evidence.

The wrapper must perform the same applied-policy validation while holding its
serialization lock immediately before each ordinary execution; never authorize
a replacement or changed sandbox from a cached info response. Unsupported state
exits nonzero with `aukora-openshell-confinement: applied-policy-unavailable`.
Unavailable execution transport uses `aukora-openshell-confinement:
sandbox-unavailable`. These fixed diagnostics contain no command or private data.

`workspace-write-policy.yml` is a source setup proposal for the startup policy.
OpenShell's default `best_effort` may run without filesystem rules on enforcement
failure; `hard_requirement` refuses startup. Filesystem and Landlock fields are
startup-only, so a saved update does not qualify the running instance.
[Pinned schema](https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.2/docs/how-it-works/policies/schema.mdx),
[policy lifecycle](https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.2/docs/how-it-works/policies/manage-policies.mdx).

The accompanying cleanup diff is a narrow source repair against that exact
wrapper: host serialization, numeric trusted supervisor ancestors instead of
agent-controlled `SKSBX` argv, checked guest cwd and TERM/INT/HUP cleanup.
It marks the exact insertion point for Grok's applied-policy check; it does not
implement that readback or provide a standalone activation-ready wrapper.
Before-call cleanup is necessary because losing the local client can leave an
older guest command alive after the host lock is released. Preserve the server
execution timeout already supplied by OpenShell; no second executor framework is
needed. Two process scans or a signal trap alone do not prove exhaustive absence
after SIGKILL. Observe the installed ordinary-command, timeout/cancel and detached
child behavior before reporting L1 live. This lane has not run those checks.
