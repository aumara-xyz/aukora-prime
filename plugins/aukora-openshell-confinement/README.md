# Linux OpenShell confinement adapter

SOURCE-ONLY, disabled. This plugin provides the two services required by Genesis's
mandatory confinement patch: `sandbox` and `aukoraConfinement`. It never launches
a process from `confine()` or returns host fallback argv.

The existing boundary-gate transport is prepared through its real `sandboxArgv()`.
Only exact Bash argv, `workspace-write`, and the explicit guest root `/sandbox`
are accepted for preparation. Arguments are quoted independently; a failed guest
`cd` refuses. Timeout is host configuration, bounded to 1–300 seconds. The host
runner receives a clean environment. Read-only mode, other workspaces and other
launcher shapes refuse.

**Execution remains refused.** The lab wrapper cannot enforce read-only file
effects or equate guest and host workspaces. It has no reliable guest cleanup
after cancellation; its cleanup exemption trusts an agent-controlled argv marker.
Its partial transport is never returned to the harness. No setting can declare
these gaps qualified or upgrade enforcement to full.

Grok owns the shared composition rows, boundary-gate release inclusion and wrapper
policy/lifecycle repair. `composition-row.yml` is a disabled handoff, not an
activation instruction. Linux host users, OpenShell, Podman and the sudo rule need
separate operator authorization; this plugin creates none.

Bash is disabled in the selected core preset. In-process filesystem reads are
outside this provider. Registering these services proves neither containment nor
the installed app's behavior.
