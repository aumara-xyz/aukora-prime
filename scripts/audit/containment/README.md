# Bounded containment verification

This is source for operator-reviewed verification. It has no default production
targets or privileged launch commands. Importing either Python module performs no
effects. The previous fixed protected-file mutation/user-provisioning harness has
been removed; its historical results are retained in the evidence account.

Source checks, with no live endpoints or host changes:

```sh
node --test tests/aukora-containment.test.mjs tests/aukora-auma-firewall.test.mjs tests/aukora-openshell-confinement.test.mjs
```

The operator must supply an exact reviewed plan, its SHA-256, independently
collected before/after observer files, and trusted launch argv. The default runner
only validates the plan and returns `UNPERFORMED` (exit 2). Launching additionally
requires `--execute-reviewed-plan`. That flag is an execution request, not a source
test or approval supplied by this repository. No live command was run by the F
source lane.

## Evidence and verdict

`run.py` exports `parse_jsonl`, `summarize`, `evaluate_runs`, and `validate_plan`.
The closed plan contains `schema_version:1`, `run_id`, `runs`, `observer`, and
`control_coverage`. Each run names its phase (`real` or `control`), exact absolute
`argv`, bounded `timeout_seconds`, and manifest. Exactly one whole argv element is
`{manifest_base64}`; the runner substitutes encoded JSON without generating a
shell program. The manifest binds the same `run_id`/phase and a nonempty list of
`expected_routes`, each with exact `route_id`, `route`, `target`, and `expect`.
Probe JSONL rows bind those same fields plus `result`, `detail`, and optional
`complete`/bounded `metadata`.

**Any real `ALLOWED` is FAIL**, including loopback TCP, unexpected or duplicate
rows and retained adverse evidence in malformed output. A later observer or
transport error cannot erase that result. `FAIL` also covers a failed workspace
operation or changed outside snapshot. Missing rows, parse errors, unsupported
operations, raced identities, resource errors, byte/time/entry caps and incomplete
controls yield `INCONCLUSIVE`, exit 2. PASS requires complete exact real coverage,
workspace success, an unchanged independent observer, and every corresponding
typed positive decoy control. Exit 0 only means that particular supplied evidence
passed; it does not qualify the observer, source custody or deployment.

Each real run requires these six complete observation categories:

- `inventory-unix`: all `/proc/net/unix` entries including abstract/unnamed
  endpoints, plus sockets found beneath explicitly reviewed roots. Traversal
  anchors directories with no-follow descriptors and fails on inaccessible or
  replaced subtrees. Reviewed-root custody still binds emitted path names to
  those observed inodes; metadata enumeration cannot prevent later renames.
- `inventory-tcp`: IPv4/IPv6 loopback and wildcard listeners in the final network
  namespace. The union with outside inventory must have exact attempted routes;
  this includes gateway 17690 and every other listener, rather than a short list.
- `inventory-processes`: every visible process of the configured UID, exact
  PID/start-time/UID, namespace, and complete UID/GID maps. Protected identities
  require separate signal-permission, proc-FD and proc-memory access rows.
- `inventory-shm`: bounded `/dev/shm` metadata and exact attempted entries.
- `final-environment`: exact configured keys; only public PATH/LANG/LC_ALL/TERM
  values may be compared or emitted. Credential values and hashes are omitted.
- `final-mountinfo`: every field, mount/parent ID, topology and row order; unknown,
  missing or extra entries refuse equality. A new mount generation needs a newly
  reviewed inventory, not automatic baseline adoption.

The independent `observer_inventory` binds `run_id`/`complete`, all Unix/TCP
endpoints, exact processes, shared-memory entries, user D-Bus/systemd-user paths,
socket types and target presence. Rootless Podman must be explicitly included at
the configured user's `/run/user/<uid>/podman/podman.sock`; neither a missing
rootful socket nor the absence of a mount proves rootless control-plane denial.
Every discovered or outside endpoint requires a matching attempt. A namespace
view alone cannot certify the host inventory. The probe's own identity can be
classified as owned only when independently bound by `owned_probe`; ancestors or
matching command lines are not blanket exemptions. An operator post-launch
observation barrier is still required to supply that dynamic binding.
The outside snapshot also binds exact network/PID/mount namespaces and complete
UID/GID maps. Standard descriptors require independently observed
`stdio_roles` entries with device/inode/mode; an unclassified standard handle is
inconclusive, while a socket or protected-path handle remains adverse evidence.

Observer config names `before_path`, `after_path` and the trusted observer `uid`.
Files have exact `{run_id,complete,collected_at_ns,snapshots}` objects, nonempty
matching snapshot keys and timestamps bracketing the launches. They must be
regular, owned by that UID, and reached through non-writable, symlink-free trusted
ancestors. Shared temporary directories are refused. Snapshot collection/custody
is an independently reviewed operator prerequisite; the runner does not synthesize
it or read production credential/ledger bytes.

## Safe operations and controls

Production file checks open and close without reading content, writing bytes,
creating files or truncating. Special files and aliases refuse. Directory checks
inspect write access without creating a protected file. Production processes get
only `kill(pid,0)`, bounded FD metadata and memory-open/close permission checks;
there is no state-changing signal, memory read or protected environment read.
Socket attempts send no protocol bytes or API requests; connecting can still
affect a server's connection/log state and therefore needs live authorization.
Regular-file checks anchor every parent directory and the final inode with
Linux `O_PATH`/`O_NOFOLLOW`, then reopen that pinned inode without reading or
writing it. An explicitly mapped allowed workspace uses an anonymous `O_TMPFILE`
inode for its write/read/close positive check; no production pathname is created,
overwritten or removed. Missing Linux support remains inconclusive.

Controls use only a fresh private temporary tree, synthetic memory, owned sockets,
an exclusive shared-memory marker and a pidfd-bound disposable child. They never
create users, change services or sweep PIDs. All ten kinds must be named:
`decoy-read`, `decoy-write`, `decoy-create`, `decoy-signal`, `decoy-fd`, `decoy-mem`,
`decoy-shm`, `decoy-unix`, `decoy-abstract`, and `decoy-tcp`. Non-socket target is
`owned`; Unix targets are `stream`/`datagram`/`seqpacket`, and TCP targets are
`ipv4`/`ipv6`. Repeat typed socket kinds when required. `control_coverage` binds
each exact real run/route ID to an appropriate control run/route ID. A stream or
IPv4 control cannot qualify a different endpoint type/family. Unavailable pidfd,
proc-memory or socket types remain inconclusive.

Limits are explicit: 256 manifest routes, 2,048 inventory entries, 256 KiB probe
input/output, 64 KiB per row, 150 ms per socket and a 12-second probe alarm. The
runner independently caps both streams together at 1 MiB, bounds each child and
the entire reviewed plan, and kills only its immediate owned child. Its death
does not prove guest termination or cleanup. No retries or host fallback occur.
TCP resets, missing paths and refused connections remain inconclusive without
independent liveness/namespace/rule evidence; errno alone cannot prove containment.

## Pending deployment acceptance

The source wrapper/adapter now requires a closed version-2 readback. A fixed
read-only helper compares all three workload mount records and the supervisor's
one read-only channel mount against a reviewed protected profile. It also compares
tmpfs, devices, PID/IPC modes and root-filesystem mode; missing/extra/changed
mount fields refuse. The binary bind may move only when its measured file content
matches the approved SHA-256. Full records travel only through the internal host
readback; public source fixtures use synthetic identities.
Direct shell-confinement calls accept either the guest root or the exact explicitly
configured host workspace identity, while producing the same guest-only runner
argv. Missing mappings and alternate/subdirectory/traversal/alias strings refuse;
no host filesystem access or host command path is inferred by that mapping.

The fixed profile `/etc/aukora-boundary-gate/openshell-inventory.json` must have
root-owned, non-writable, symlink-free custody. It has exactly these nine fields:
`version:1`, `expected_mounts`, `expected_supervisor_mounts`,
`expected_workload_config`, `expected_supervisor_config`,
`workload_binary_digest`, `uid_ranges`, `gid_ranges`, `forbidden_host_ids`.
Both configuration objects have exactly `Tmpfs`, `Devices`, `IpcMode`, `PidMode`,
`ReadonlyRootfs`. The UID/GID ranges are exactly `[{host_id:165536,size:65536}]`
and forbidden IDs exactly `[1001]`. No admission profile is automatically adopted from
observations. New container identities require another operator-reviewed profile.
The expected binary content SHA and deployed profile/helper custody remain
operator prerequisites; the supplied historical inspect lacks fresh process facts.
The helper also hashes the actual kernel `/proc/<container-pid>/exe` inode and
requires it to match the observed binary bind. An existing trusted authority to
read that subuid-owned process executable is required; permission failure refuses,
with no new privilege route or guest command used to obtain evidence.

The narrowed root repair exports the pinned driver's actual supported
`OPENSHELL_PODMAN_USERNS=auto:size=65536` knob. Per-call admission verifies complete
fresh UID/GID maps, rejects every mapping of owner 1001, and requires workload
CapPrm/CapEff/CapBnd zero, NNP1 and seccomp2. Group observations must stay within
the approved subordinate range. Process start time/container identity, effective
policy/revisions and profile are checked again before returning the readback.
Global policy overrides refuse; the sandbox policy's exact configuration revision
must match accepted admission. The admitted provider revision is typed and checked
for stability, but these CLI outputs do not expose a separate current provider
revision. Environment custody and provider-generation qualification remain open.
This is bounded observation rather than atomic launch authorization; the legacy
two-field `--confinement-id` token is unchanged. Durable executor/control-plane
generation fencing and shutdown proof remain separate qualification requirements.
The stock rootless launcher still needs SETUID/SETGID to change identity; its
launch permissions are deliberately retained. Removing them needs a separately
reviewed nonroot bootstrap/ownership patch and rebuilt artifact. The immutable
custom workload-image pin remains unqualified. Source fixtures establish none of
the actual recreation/exec/workspace compatibility or runtime enforcement.

Grok's server acceptance must retain three distinct cases: normal owner/supervisor
use plus workspace works; the actual guest including userns-root cannot reach
auma files/rootless Podman/host gateway; and an owned disposable reverted-protection
control detects the route. Include complete UID/GID maps, capability/NNP readback,
namespace binding, final environment/mount inventory and observer evidence. A
gateway exception for socket UIDs 1001 and 166535 is source checked; the shared
guest/supervisor UID cannot identify the supervisor or close inherited host
sockets. A's FD repair and runtime custody acceptance remain separate. No complete
runtime PASS, key enrollment, security setting change or deployment is claimed.

## Explicit inventory bootstrap and recreation

The default `ensure-sandbox.sh` still refuses a missing protected inventory before
persistence or recreation. Only the operator's explicit `--bootstrap-profile`
argument selects preparation: it requires protected committed generation inputs,
serializes with the ordinary host admission lock, recreates the named sandbox
(after a successful workspace snapshot), restores its workspace, checks the
startup policy and network mode, and **always exits 7** before normal admission,
workspace-link publication or workload execution. It does not generate, install
or accept a profile. This also forces recreation of a Ready container: changing
the gateway's userns default alone cannot update that container's maps.

Commit only `inventory-generation-schema.json`, `workload-pin.json` and the helper.
The schema contains public immutable mount/configuration constraints, subordinate
ranges and the forbidden owner identity; it contains no mount Name/Source IDs.
The binary pin is independently approved source input, never a hash adopted from
the current runtime. Install both input files beside the helper at
`/usr/local/lib/aukora-boundary/openshell/`, with root-owned non-writable files and
ancestors. The generator corroborates ranges with the owner's `/etc/subuid` and
`/etc/subgid`; disagreement with reviewed constraints refuses.

Operator order (source recipe; not performed by this lane):

1. Hold all admission/workload traffic and independently establish that owned
   foreground and stream jobs are quiescent. The bootstrap lock does not join an
   already admitted stream; CLI death does not prove guest termination. Keep the
   traffic hold until the final live acceptance. Preserve the installed inventory.
2. Install the reviewed main source, helper, public schema and approved binary
   pin with protected custody. Restart the gateway with its reviewed
   `OPENSHELL_PODMAN_USERNS=auto:size=65536` configuration. Run the explicit
   `ensure-sandbox.sh --bootstrap-profile` as the existing sandbox owner. Expected
   result is exit 7 at the fresh-binding barrier; any earlier error blocks progress.
   Initial absence of the admission profile is allowed only for this preparation.
3. Run `/usr/bin/python3 -I -S` with the installed `sandbox-inventory.py`, arguments
   `auma-ws generate --out` and a new normalized absolute path in an operator-owned
   private review directory. The generator reads the running sandbox without
   guest commands, repeats bounded identity/policy/process observations, and
   writes a proposed nine-key profile exclusively with mode 0600. Existing output
   refuses. Missing kernel executable read authority, owner-inclusive maps,
   configuration drift or a binary-pin mismatch refuse without a privilege fallback.
4. Review that private candidate against the committed constraints and independently
   bound current sandbox/container/process identities and actual volume custody.
   A fresh volume Name/Source is candidate data, not provenance proof. Recheck the
   current read-only observations; any recreation/drift requires new generation
   and review. The source generator never installs or approves its own output.
5. Explicitly install the reviewed generated artifact, under the operator's
   authorized main-source rule, as root:root 0644 at
   `/etc/aukora-boundary-gate/openshell-inventory.json`. Run ordinary startup and
   normal exact `auma-ws check`. Stale UUIDs remain refused; generation is never
   called by an ordinary admission, the wrapper or the service's default path.
6. Obtain the three-case actual guest containment receipt with zero ALLOWED,
   including A's ordinary/stream descriptor closure. Only then release traffic.

Neither successful generation nor an exact profile check establishes image
qualification, atomic launch fencing, volume provenance, resource bounds or cleanup.
If the paired root/inventory source or its live prerequisites miss the release
cutoff, defer both together; do not ship a relaxed check or extend the cutoff.
