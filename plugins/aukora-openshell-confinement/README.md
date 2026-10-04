# Linux OpenShell confinement adapter

SOURCE-ONLY, disabled pending Grok's root-owned stream wrapper and actual guest
acceptance. The R2 implementation supplies `sandbox`, `aukoraConfinement`, the
existing DSH `subprocess` interface, and a native Bash subclass. Process, Node PTC
duplex FD7 and genuine PTY routes use the explicit guest root `/sandbox`. Runtime
use remains UNPERFORMED; implementation and mock wire checks are not completion
of Peter's installed execution goal.

The fixed host carrier runs `sudo -n -u auma sbx-exec --stream <seconds>` from
host cwd `/` with a clean environment. Grok owns this wrapper entrypoint; it must
select the existing OpenShell SSH proxy and a fixed read-only guest carrier.
Model argv and data are sent inside that stream, never executed on the host.
Stock OpenShell v0.1.2 `sandbox exec` buffers piped stdin before launching and
cannot substitute for the live SSH stream. Timeout remains bounded to 1–300
seconds. Guest workdir and policy remain `/sandbox`. Caller loader, credential,
proxy and ordinary host environment entries are rejected; required native Bash
and terminal prompt/session constants are retained. Read-only mode, other roots,
unselected launch shapes and background Bash refuse.

The guest carrier creates a real socketpair inherited as Node FD7 and keeps its
bytes separate from stdout/stderr. It allocates a real guest PTY, performs resize,
observes its foreground group, and signals only owned identities. Each carrier
uses a Linux subreaper and pidfds for its own descendants, allowing independent
terminals and nested Bash without a shared lifetime lock or global kill-all.
Quiescence is reported only after owned-process cleanup and output drain. Carrier
loss remains unknown and fences further launches in that provider; gateway timeout
alone is not absence evidence. Same-UID carrier destruction still requires
independent OpenShell/root-wrapper supervision for installed qualification.

Grok must configure actual guest Node and built PTC `process.js` paths through
`nodeExecutable` and `bootstrapPath`, preserve those paths in the existing Node
runtime configuration, and retain mandatory confinement at every consumer.
Keep the native `subprocess` provider and `tool-fs-search` outside the named
`aukora-model-exec` subprocess realm. Tag this guest provider, the selected
`ptc-runtime`, the single `agent-loop`, and enabled `terminal-bash` backend with
`isolate: { subprocess: aukora-model-exec }`. Exactly one guest provider writes
that realm. PTC and terminal backends capture their plugin context; browser
terminal resolves the agent's context, which inherits the scoped agent loop.
An unmounted isolated realm refuses instead of falling back to the native one.
Leave `ptcRuntime` and `shell` visible to existing host consumers. This preserves
trusted file-search helpers without routing model code to a host executor by argv.
Actual selected rows and installed behavior still require Grok's acceptance.

The explicit `hostWorkspaceRoot` option preserves Grok's L1-a mapping: only that
exact configured session root maps to `/sandbox`, and policy mode is preserved.
No subdirectory or unrelated root is inferred. The two workspaces remain
independent; this is neither a host mount nor a shared-file assertion.
The older Linux unsupported-consumer patch is historical refusal-only work and
must not be applied to the completed R2 composition. No new DSH API is introduced.

`confine()` makes one bounded, cancellable preparation read through
`sudo -n -u auma sbx-exec --confinement-info`. It returns `full` file enforcement
only when the running instance's applied policy has `include_workdir:false`,
exactly `/sandbox`, `/tmp`, `/dev/null` writable, and Landlock `hard_requirement`.
Missing, unapplied, broader and `best_effort` policies refuse. No configuration
flag substitutes for real policy readback. The wrapper must repeat that check
immediately before every stream admission. The accepted writable roots are not
widened for PTY setup. Guest Python/pidfd/subreaper, PTY device access and syscall
inspection must be measured under the actual applied policy. Any required new
device permission needs Peter's separate approval.

DSH retains its existing execution deadlines and PTC protocol/output limits.
Preparation is cancellable; terminal allocation cancellation is detached when
the handle is published. Termination awaits guest cleanup and carrier close,
including pending operation settlement. Output and framing queues are bounded.
Guest input backpressure starts cleanup after two seconds without sink progress;
this also bounds cancellation queued behind a child that stops reading.
The older two-argument Bash wrapper cleanup patch remains historical work, not
the R2 stream contract.

Grok owns the shared composition rows, boundary-gate release inclusion and wrapper
policy/cleanup repair. `composition-row.yml` is a disabled handoff, not an
activation instruction. Linux host users, OpenShell, Podman and the sudo rule need
separate operator authorization; this plugin creates none.

Bash is disabled in the selected core preset; Grok must deliberately enable the
Linux row with `enableRunInBackground:false` and use `/sandbox` or the exact
explicitly declared host session root.
In-process filesystem tools remain outside this provider. Registration and source
checks do not qualify the installed system. See [the wrapper interface and policy
handoff](handoff/WRAPPER.md) for the exact owner boundary and remaining evidence.
