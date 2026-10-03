# Linux OpenShell confinement adapter

SOURCE-ONLY, disabled pending the root-owned wrapper join. This plugin supplies
`sandbox`, `aukoraConfinement` and a subclass of the existing native Bash executor.
It has a supported foreground `workspace-write` path for the explicit guest root
`/sandbox`. Runtime use remains UNPERFORMED; the wrapper on the selected base does
not yet expose the required applied-policy readback and therefore refuses.

The existing boundary-gate transport is prepared through its real `sandboxArgv()`.
Only exact Bash argv, `workspace-write`, and the explicit guest root `/sandbox`
are accepted. Arguments are quoted independently; a failed guest
`cd` refuses. Timeout is host configuration, bounded to 1–300 seconds. The host
runner receives a clean environment. Read-only mode, other workspaces and other
launcher shapes, background execution, alternate workdirs, stdin and caller
environment overrides refuse. The trusted host `dshEnv` overlay is suppressed:
guest commands do not receive host DSH context or `DSH_HOME`. The native executor
spawns the transport at host cwd `/` while keeping policy and command cwd at
guest `/sandbox`; it does not mount a host project.

`confine()` makes one bounded, cancellable preparation read through
`sudo -n -u auma sbx-exec --confinement-info`. It returns `full` file enforcement
only when the running instance's applied policy has `include_workdir:false`,
exactly `/sandbox`, `/tmp`, `/dev/null` writable, and Landlock `hard_requirement`.
Missing, unapplied, broader and `best_effort` policies refuse. No configuration
flag substitutes for real policy readback. The wrapper must repeat that check
under its execution lock before every ordinary two-argument command launch.

OpenShell's server already receives the command wall timeout. Genesis owns local
execution deadlines; the `confine()` AbortSignal covers preparation. Cancellation
of the local client alone does not prove guest absence. The owned-file handoff
replaces forgeable argv cleanup exemptions with numeric supervisor ancestry and
adds serialization, checked guest cwd and signal cleanup. Those source changes
still require Grok's actual wrapper join and installed-path evidence.

Grok owns the shared composition rows, boundary-gate release inclusion and wrapper
policy/cleanup repair. `composition-row.yml` is a disabled handoff, not an
activation instruction. Linux host users, OpenShell, Podman and the sudo rule need
separate operator authorization; this plugin creates none.

Bash is disabled in the selected core preset; Grok must deliberately enable the
Linux row with `enableRunInBackground:false` and use a session cwd `/sandbox`.
In-process filesystem tools remain outside this provider. Registration and source
checks do not qualify the installed system. See [the wrapper interface and policy
handoff](handoff/WRAPPER.md) for the exact owner boundary and remaining evidence.
