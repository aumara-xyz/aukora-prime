# Linux OpenShell confinement adapter

RAN on the Linux pilot for one-shot bash: the live release mounts this plugin (`linux-openshell.patch.yml`) and
Auma's foreground `workspace-write` bash runs in the guest root `/sandbox` through the root-owned `sbx-exec`
wrapper (operator-recorded; the 2026-10-04 red-team saw `pwd` = `/sandbox` and no host root). This plugin
supplies `sandbox`, `aukoraConfinement` and a subclass of the existing native Bash executor. NOT YET: background
bash, `run_code` and terminals refuse, and the wrapper does not yet expose an applied-policy readback.

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

`run_code` and terminal are separate consumers, not Bash aliases. Patched Node
PTC, persistent terminal and browser terminal already require
`aukoraConfinement`; this provider refuses their unsupported launch argv before
transport preparation. Node PTC needs bidirectional FD7 control frames. Terminal
needs live PTY input/output, resize and guest foreground observations. The current
wrapper closes stdin, buffers output and uses `--no-tty`. Its whole-sandbox lock
and cleanup also cannot support persistent terminals or a PTC worker awaiting a
nested `tools.bash()` call. The shared-consumer guard handoff refuses these routes
on Linux regardless of custom shell argv; it does not widen this provider's
supported contract. See [the path-by-path source map](handoff/ROUTES.md).

`confine()` makes one bounded, cancellable preparation read through
`sudo -n -u auma sbx-exec --confinement-info`. It returns `full` file enforcement
only when the running instance's applied policy has `include_workdir:false`,
exactly `/sandbox`, `/tmp`, `/dev/null`, `/dev/pts`, `/dev/ptmx` writable (the last two let a PTY open inside the sandbox), and Landlock `hard_requirement`.
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
