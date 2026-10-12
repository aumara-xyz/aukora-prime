# Node spawn — source-only groundwork

`bash ops/node-spawn/spawn.sh --plan member-node /path/to/admission-record`
prints the ordered conditional commands without invoking LXD or any external
command. The record must be a readable, nonempty regular file, not a symlink;
its presence is **not verified admission**. Contents are never read or executed.

The gaps listed at the top of `spawn.sh` are real refusal points. Without
`--plan`, the first refusal is `INVITE_ADMISSION_VERIFIER_MISSING`, before any
container is created. Repeated plans/refusals leave state unchanged. **This is
not yet a working installer or a qualified resumable installation.** Image/profile,
admission binding, fresh gate/owner enrollment, protected install and sandbox
production need supported recipes. Existing gate scripts are named and reused;
no gate installer or automatic owner approval is invented. Unresolved operands
are marked `<...>`; the printed plan is not a shell script to paste and run.

[North Star](../../plan/NORTH-STAR.md) records a second complete node running in
`aukora-staging` on 2026-10-12, with separate users, local gate keys, OpenShell and
an approved release. That was an operator-run path using a script retained in the
container, **not this script**. The failed first launch established that the
launcher checkout and release must share a commit. Current `ensure-sandbox.sh`
only checks admission; older SETUP text claiming it creates the sandbox is stale.

This script has **not been run against LXD, a fresh Ubuntu container, staging or
the live node**. Tests use stubs and synthetic records; they do not prove valid
invitations, installation, owner enrollment, listener confinement or containment.
Run `node --test ops/node-spawn/test.mjs` with Node **24.11.1**; it includes guard
mutations. No dependencies are added.

For now every node is a container in one account the incubator controls, so the
incubator's operator can read it, including its keys and state. A member's own
server that the incubator cannot reach comes later, with export.
