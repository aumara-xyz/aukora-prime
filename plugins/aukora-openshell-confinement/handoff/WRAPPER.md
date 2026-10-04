# Root-owned wrapper handoff

Grok owns `packages/boundary-gate/host/sbx-exec`, installation, sandbox startup
policy and shared composition. This lane changes only its plugin directory.
The ordinary wrapper at historical reference
`1ebe7539b0dd6e3bd8767fe173021595f69861dc` lacked the interfaces below. Current
wrapper source at `50a49522fd34e7fbbaf42391767a4a029ab94a3e`, unchanged at
`edd910a7bcc0e4d93602697ed6583b8ae83fb5a6`, implements the
stream and policy contract. Grok reported an installed lookup with clean carrier
close, followed by a process launch refused because `pidfd_open` returned
`ENOSYS`. That result does not establish PTC or terminal acceptance.

The legacy ordinary command and `sandboxArgv()` are outside the R2 stream route.
`sbx-exec --confinement-info` is read-only, with no proposed
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

The wrapper must perform the same applied-policy validation under an
admission-only lock immediately before each stream launch. Bind that admission
to the same observed instance and applied revision; never authorize a replacement
or changed sandbox from a cached info response. Release the lock once the selected
OpenShell session and fixed carrier admission are established, before waiting for
process output, tool calls or completion. Close inherited lock descriptors so a
child cannot extend the lock lifetime. Unsupported state
exits nonzero with `aukora-openshell-confinement: applied-policy-unavailable`.
Unavailable execution transport uses `aukora-openshell-confinement:
sandbox-unavailable`. These fixed diagnostics contain no command or private data.

## Current R2 stream contract

The plugin invokes only the fixed root-owned entrypoint, as `auma`:

```text
sbx-exec --stream <timeout-seconds>
```

Accept one integer from 1 to 300 for this mode. Select the existing configured
OpenShell gateway/proxy and a fixed read-only installed guest Python/carrier path
inside the wrapper. Run `guest/exec.py` inside that admitted OpenShell session.
The selected image paths are `/usr/bin/python3`, `/usr/lib/aukora/exec.py`,
`/usr/lib/aukora/node/bin/node` and `/usr/lib/aukora/ptc/process.js`. Both the
native PTC row and the confinement row must select the same Node and bootstrap
paths; configuring only the confinement row leaves incompatible native defaults.
Caller argv, environment, proxy options and
model input must not select the host command or transport. Missing backend,
applied policy, guest carrier or required primitive refuses without host fallback.

Keep host stdin, stdout and stderr as raw byte pipes. Leave stdin open for the
launch frame, guest stdin and FD7 writes, half-close frames and terminal requests.
Stdout carries only the carrier's JSONL protocol bytes; stderr carries bounded
wrapper/SSH diagnostics. Do not add banners, allocate an outer PTY, close stdin
at launch, buffer output into files, or wait for input EOF before launching.
The guest carrier itself creates the process pipes, raw duplex FD7 socketpair
and genuine PTY. Its launch and request schema is implemented in `guest/exec.py`
and `lib/stream.mjs`; no caller-controlled host command string is accepted here.

The current wrapper separately bounds lock admission to 30 seconds, each of five
initial policy queries to 4 seconds, SSH admission to 30 seconds, and the second
policy check to 30 seconds. The adapter's default carrier startup deadline is
120 seconds, with a maximum of 120 seconds; its independent policy read has a
25-second deadline. Caller cancellation still applies throughout admission, and
the configured 1–300 second wrapper execution bound begins after admission.

Executions must remain independent: an outer `run_code` worker can await a nested
Bash launch, and terminals can coexist. No lifetime serialization lock or
before/after global process cleanup may cover this stream route. Cleanup and
trusted deadlines must target only the admitted execution's owned guest range.
Carrier quiescence plus clean carrier close is the plugin's completion condition;
host SSH exit, killing a local carrier or a gateway timeout alone is not guest
absence evidence. The guest subreaper/retained-child cleanup cannot independently prove
absence after same-UID carrier destruction. Grok must qualify trusted supervision
and loss handling on the actual installed path; unknown cleanup remains fenced.

The currently accepted writable paths remain `/sandbox`, `/tmp`, `/dev/null`.
Measure PTY device access under that actual applied policy. Any necessary device
grant needs exact operator approval and a separately agreed narrow descriptor;
this handoff neither adds `/dev` access nor treats source support as permission.

`workspace-write-policy.yml` is a source setup proposal for the startup policy.
OpenShell's default `best_effort` may run without filesystem rules on enforcement
failure; `hard_requirement` refuses startup. Filesystem and Landlock fields are
startup-only, so a saved update does not qualify the running instance.
[Pinned schema](https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.2/docs/how-it-works/policies/schema.mdx),
[policy lifecycle](https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.2/docs/how-it-works/policies/manage-policies.mdx).

## Historical ordinary-command cleanup

The accompanying `sbx-exec-cleanup.patch` is historical source work against the
ordinary wrapper at the reference above: host serialization, numeric trusted
supervisor ancestors instead of
agent-controlled `SKSBX` argv, checked guest cwd and TERM/INT/HUP cleanup.
It marks the exact insertion point for Grok's applied-policy check; it does not
implement that readback or provide a standalone activation-ready wrapper. Its
lifetime lock and global before/after cleanup must not be applied to R2 streams;
they can deadlock nested Bash and kill unrelated terminals. It is retained as a
historical ordinary-command handoff only. The current stream contract above
supersedes those semantics for every R2 execution route. Actual stream,
timeout/cancel and detached-child acceptance remains UNPERFORMED in this lane.
