# Independent deadline and cleanup ownership — Proposed

The later [separate-process source increment](GUARDIAN_PROCESS.md) now implements
a durable monitor/lease, original-deadline timers, private IPC and continuing
late-resource reconciliation. This document preserves the wider qualification
design: actual terminal admission fencing, atomic configuration, complete driver
artifact evidence and protected Linux deployment remain unimplemented/unqualified.
The source process is unmounted and cannot open production execution gates.

This is a source design checkpoint, not a guardian implementation or runtime qualification. It changes no frozen operation, grant, request, receipt, status or C settlement contract. No guardian process, clock policy, private control endpoint or host placement has been selected or installed. H must keep the qualified executor unmounted until a durable independent guardian acknowledgement precedes every create and a reviewed atomic configuration-generation/freeze mechanism covers execution. An accepted qualification proof cannot substitute for either mechanism.

## Pinned baseline and existing behavior

The source baseline is F `ee3e9577ccfc93d694e9ba358d8ef774dad43845` (production repair `b18b0e0546f39de244edff9ef8ea91ba781b3fc4`), C `292474f58f18c10bd4a9703909d02f12be82a0ac`, OpenShell `6648bd0c290efbc41ba131ee9831ee45cd431f94`, source-built SDK `0.0.0`, and DSH `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720` with its vendored Cordis 4.0.2. The latest C/F handoff confirms disposable joined checks only; actual runtime remains unavailable. The create-profile source increment is a separate reviewed change on this development branch.

The current [owned executor](../src/owned-executor.mjs) reserves a permanent local launch fence before the one-use C `claimDispatch`, persists `create_attempted` before create and `exec_attempted` before exec, and retains exact request/consumed-grant bindings and settlement outbox. The create-profile increment freezes `create_template` (full desired JSON), `create_profile_digest` (domain `aukora-prime.create-profile.v1`) and `guest_workdir:'/sandbox/work'` before reserve/claim/create; admission checks the exact resources/mounts before and after exec, and cleanup refuses pending legacy or different profiles. These source/readback guards are not an external guardian acknowledgement, atomic configuration fence or all-artifact cleanup proof. [OwnedLedger](../src/ledger.mjs) uses a process-held SQLite lease and a separate durable jobs database. Lease loss permits a successor to reconcile; it neither kills a guest nor permits replay. Reopening an invalid, missing or replaced ledger must remain unavailable rather than initialize a replacement identity.

The executor's wall timer, SDK abort and cleanup polling require live JavaScript. Its cleanup verifies public sandbox ownership and paginated API absence. That is not independent proof of workload, supervisor, auxiliary-container or private-volume absence. The pinned delete API explicitly permits asynchronous cleanup and names the target rather than accepting an expected UUID. Its response binds a targeted sandbox UUID when present; that response alone does not prove driver reclamation. Cordis's awaited owned effect helps graceful cleanup, but a disposed fiber, SDK cancellation, CLI exit, missing socket or stopped gateway proves neither guest termination nor absence of prior effects.

The pinned gateway has a durable provisioning repair deadline. That deadline ends at Ready; it is not the approved foreground execution lifetime. Exec timeout can emit synthetic exit 124 without terminalizing the launch. Neither mechanism supplies the independent per-call obligations below.

## Proposed private registration boundary

The following are mandatory information groups for a future trusted F/H/guardian adapter. Names in this table describe a proposed private record, not implemented method signatures or new transport fields. C/F's existing request and receipt digest domains stay unchanged. Any new guardian-record encoding/digest domain requires its own review.

| Group | Required binding or evidence |
| --- | --- |
| Durable owner | `guardian_id`, durable registration identity and generation, `ledger_id`, `gateway_identity`, immutable deployment identity and `host_profile_digest`. Bind the exact private control placement and source/image/profile identity; a matching URL alone is insufficient after deployment replacement. |
| Original authorization | Preserve the full frozen `operation` and `consumed_grant`, exact `operation_digest`, `request_id`, `request_digest`, operation/grant/reservation identities and actual C dispatch binding. Copies grant no new authority. No signing keys reach this adapter. |
| Launch identity | Original `create_request_id`, `delete_request_id`, workspace, unique sandbox name, owner token and exact immutable sandbox UUID once assigned. Register before create even while that UUID is unknown. A later UUID must be corroborated against the original create/ownership record. |
| Admitted workload | Exact image digest, policy digest, existing private ledger `create_template` (full frozen desired JSON), `create_profile_digest` (domain `aukora-prime.create-profile.v1`) and `guest_workdir:'/sandbox/work'`, resource/mount profile, and full upstream effective configuration/admission tuple. Retain policy/config/provider identities distinctly; uint64 equality tokens remain canonical decimal strings. These ledger fields do not supply the external guardian acknowledgement, atomic configuration fence or all-artifact cleanup proof. |
| Lifetime | Trusted acceptance instant, approved maximum wall duration, fixed expiry, clock/boot identity and restart rule, guardian generation and acknowledgement. The lifetime starts before create and includes provisioning; the caller cannot extend it with heartbeat, reconnect, config update or a new approval for the same job. |
| Authoritative fencing | Durable create/exec admission identity, active/fenced generation, outstanding create disposition, and proof a terminal fence prevents delayed creation or new compute/exec for the original job. This must operate where creation and launch are admitted, not solely in an F memory flag. |
| Owned artifacts | Exact workload and supervisor/auxiliary-container IDs, owned networks if any, and all sandbox-private/channel/image-created volume identities. Bind each artifact's sandbox UUID, deployment and independently inspected ownership; explicit empty sets require evidence. Shared/externally owned resources are outside deletion authority. |

No model, guest, ordinary operation JSON or arbitrary callback may supply the guardian's accepted clock, identity, profile, registration acknowledgement or control credentials. H owns the private host boundary. The adapter must verify a durable bound acknowledgement before F crosses `create_attempted`; if acknowledgement is refused, incomplete or uncertain, preserve the local non-launch fence and do not create or retry registration as a launch attempt. An ambiguous C claim stays ambiguous and must not be promoted to accepted by a guardian acknowledgement.

The guardian must be independently schedulable when F, Cordis, SDK or gateway JavaScript cannot execute. It needs reviewed, least-scoped access to the exact deployment's authoritative admission and compute records. Choosing a supervisor, lease service or gateway extension is pending. Requiring a guardian does not authorize Docker socket access, credentials, host services, permission changes or a new deployment.

## Deadline, late creation and recovery obligations

1. **Persist before effect.** Commit the original job binding, immutable deadline and registration acknowledgement before create. Persist each transition before invoking the corresponding control action. A crash between F reservation, C claim and guardian registration must have a unique recoverable disposition and must never relaunch the job.
2. **Do not restart the clock.** Recovery must preserve the original deadline. On clock rollback, missing time records, boot change or uncertain expiry, fence admission and reconcile conservatively. The selected mechanism must define how it bounds guest lifetime during F death, guardian restart, gateway restart, host reboot and temporary control-plane unavailability. Wall-clock timestamps and a planned TTL alone are not observed enforcement.
3. **Fence before reclaiming.** Deadline or cancellation triggers durable prevention of further create/exec admission for the original identity before cleanup. A lost create reply followed by empty inventory does not prove `not_created`: creation may still be in flight. Corroborate terminal create disposition and late-create fencing under the authoritative lifecycle mechanism; keep reconciling until both are proven. Do not replay an uncertain create or exec to discover its result.
4. **Reclaim only owned artifacts.** Recheck immutable identity and ownership immediately before each control action through a reviewed identity-conditioned path. Same-name replacement, duplicate ownership, missing provenance or an unexpected deployment forbids destructive cleanup. No broad prune, name-prefix deletion or unrelated process stop is allowed.
5. **Confirm reclamation independently.** Record complete control-plane/driver inventories, including all pages and exact auxiliary/volume identities, and the observations after scoped reclamation. API sandbox absence, delete success, a stopped main container, or labels alone cannot close the artifact obligation. A create fence must also exclude new late artifacts after that observation.
6. **Preserve partial progress.** Retain durable attempts, responses and pending artifacts across every restart. Retries of scoped reconciliation require their original binding and reviewed idempotency; they cannot create or exec again. Cleanup deadline expiry or unavailable evidence retains unknown cleanup and blocks qualification/admission. It is not an excuse to discard the job.
7. **Publish through F/C.** The guardian provides bound control-plane evidence to the trusted executor; it does not call an unreviewed guest settlement route. F preserves typed output, RPC/config facts and its durable outbox. C receives the unchanged `settle`/`reconcileSettlement` boundary. Original grants, launch fences, unknown receipts and reconciliation evidence remain retained; cleanup does not erase them.

## Proposed evidence boundary and unchanged factual outcomes

A private evidence record must identify its durable source and generation; bind the registration, deployment/ledger, operation/grant/request digests, sandbox UUID and create/delete identities; and preserve exact observation time, observed control revision, action/response identity, complete inventory and artifact ownership/absence facts. It must separately state deadline/fence disposition, late-create exclusion, owned-artifact reclamation, configuration provenance, typed command exit and RPC completion. Evidence must be independently retrievable after process restart from the trusted control plane. Stdout, telemetry/log text, an unbound boolean, local process disappearance or a caller assertion is not sufficient evidence.

The adapter's evidence remains richer private material. It must not insert extra fields into the frozen receipt, fabricate an exit, relabel a complete RPC as failed, or overwrite conflicting earlier typed facts. Reconciliation uses the same receipt/request/operation/grant/sandbox identity and follows C's reviewed rules:

- A fully drained RPC plus a genuine typed command exit preserves COMPLETED/FAILED, subject to the existing configuration and cleanup obligations; late cancellation cannot change that known command outcome.
- Lost trailers, synthetic-or-genuine ambiguous 124, started execution without typed terminal evidence, configuration uncertainty or unknown cleanup retain OUTCOME_UNKNOWN. Confirmed absence proves reclamation, not command outcome or absence of external effects.
- CANCELLED requires recorded cancellation and proven no launch: `rpc_completion:'not_started'`, `started_at:null`, `exit_code:null`, plus executor-confirmed `not_created`/`confirmed_absent`. Killing a launched guest cannot meet that rule.
- Owner acknowledgement cannot unconsume, retry or clear factual uncertainty. Any future separately reviewed admission disposition is outside this document; the same job can never relaunch.

## Atomic configuration precondition remains unresolved

Pinned `ExecSandboxRequest` carries workspace/name, command, workdir, environment, timeout, stdin, TTY/login behavior and `request_id`. It has no expected configuration revision, expected admission instance, expected sandbox UUID or guardian generation field. F's readiness/pre-exec/post-RPC effective readbacks detect persistent drift and preserve a durable pending final-verification fence; they cannot exclude a change between observations or an A → B → A configuration sequence.

Before qualified mounting, H/F must review an authoritative mechanism that freezes the exact sandbox generation/admitted configuration through the launch boundary and execution lifetime, or admits exec atomically against that bound generation and supervises any later transition. It must cover policy, registered settings, global overlays, provider/environment revisions, attachment epoch, middleware and extension state. A promise not to change config, polling or DI isolation is insufficient. Pinning a create-template digest/workdir protects source/readback consistency but does not add the missing upstream atomic precondition. No guessed RPC fields or silent SDK patch are approved here.

## Next bounded qualification requirements

Source implementation and review must select the private registration/clock/fencing/reclamation mechanism and retain its evidence, then join H's exact immutable image/profile and accepted host/deployment identity. Public contracts and authority semantics remain untouched. Until those steps and observed enforcement are complete, runtime capability stays unavailable.

After explicit bounded setup authorization, one approved inert foreground call can establish the source seam, retained genuine exit-1 output, RPC drain, original C dispatch/settlement and exact owned cleanup. It cannot establish the crash/deadline claims. Separate scoped authorization is required for disposable deadline, F/guardian owner-death, gateway restart, delayed create and scoped auxiliary/volume reclamation observations. Those observations must use generic keyless fixtures without real provider credentials, host workspace mounts, forbidden prior sequences or unrelated processes.

This increment performed only source reads and added this document. No tests, builds, Docker/gateway/guest calls, cloud actions, keys, setup, permissions or runtime qualification were performed.

## Dedicated control identity and workspace-data boundary — Proposed

This additional design is reviewed against candidate source
`6ad539fdd4f5b2b55f995a96289df0df4619dd3c`. It does not select account numbers,
create an account, change host permissions or settings, install a service, migrate
storage, mount an executor, or qualify containment. The preceding historical
source checkpoints remain dated evidence. The frozen operation/request/receipt
envelopes and C/F digest and settlement semantics remain unchanged.

This proposal covers the pilot Podman/gateway custody problem and a future trusted
adapter. References to the retained owned SDK executor, C/F joins and guardian
describe their separate source obligations. They do not assert that the currently
mounted pilot wrapper has those ledger, dispatch or guardian joins. Joining that
wrapper to the proposed broker requires its own reviewed implementation and
actual-path acceptance; moving an account cannot supply the missing join.

The reported staging observations for 2026-10-06 are guest **34 DENIED / 0 ALLOWED /
2 INFO** and host **43 DENIED / 7 ALLOWED / 6 INFO**. F did not rerun them. The host
allowances include the ISCSIADM abstract socket on that run. These counts do not
close containment. The dedicated-runtime proposal addresses named Podman,
gateway and namespace/control-delegation surfaces; other allowed routes retain
their separate disposition and acceptance obligations.

### Trust and custody

The threat includes a compromised harness or workload, workspace-controlled
bytes, and untrusted host processes under the original agent identity. Preserve
that original identity as a denial target; moving the control service does not
make the old host-as-agent probe trusted. Kernel, root administration, accepted
OS/runtime dependencies and protected deployment authority remain explicit trust
anchors. A malicious root administrator or compromised trusted control service
is outside this proposed separation; a different UID does not contain either.

| Principal or boundary | Authority and required custody |
| --- | --- |
| Owner/C authority | Authorizes the exact operation through the existing reviewed proof, consumption and dispatch path. Its signing material is unavailable to harness, broker, observer, builder and guest. Peer authentication alone grants no effect authority. |
| Dedicated runtime control identity | A separately reviewed UID/GID, distinct from the agent, `aukora-host`, `aukora-gate`, root and every workload/subordinate identity. It owns Podman API/storage, gateway control credentials, the fixed broker and trusted observer. These services deliberately share a trusted control domain; splitting them further requires a separate reviewed interface. |
| Harness and guest | Hold no direct runtime API, control credential, service-manager capability or namespace/control FD. Workspace bytes are data for the host. The exact approved Bash bytes may execute only through the existing owned guest lifecycle. No host fallback. |
| Builder and promoter | The builder is a separate unprivileged execution domain with no runtime/authority sockets, signing material or deployment-write capability. Its output is untrusted until independently checked, exactly approved and promoted by the protected deployment authority. |
| Deployment and host anchors | Bind immutable generation, complete executable closure, accepted profile, gateway/runtime and ledger identities. Require protected ancestors, authoritative mount/inode identity, approved owner/groups/ACLs and no writable alias. A hash or account name alone establishes none of these. |

The reviewed profile must name actual primary and supplementary groups,
subordinate UID/GID ranges and non-overlap rules, socket/runtime/storage paths,
credential custody, manager permissions, mount identities, immutable code/config
closure and service graph. Control code and state stay outside workspace and
`skgate` write grants. Group membership, ACLs, shared caches or inherited FDs must
not restore access. State that legitimately changes remains protected durable
state bound to its deployment; it is not described as immutable code.

Current [Podman units](../../boundary-gate/host/systemd/aukora-auma-podman.service)
run as `auma`; [the API script](../../boundary-gate/host/openshell/podman-service.sh)
uses that identity's `/run/user` socket. The
[gateway script](../../boundary-gate/host/openshell/gateway.sh) also uses its HOME
for TLS state and selects port 17690 without itself specifying a bind address.
Client metadata naming loopback is not listener evidence. The
[network exception](../../../host/auma-local-deny/auma-local-deny.nft) explicitly
notes that supervisor and guest share mapped host UID 166535. A UID-based rule
cannot distinguish those processes by itself. Actual listener, TLS principal,
network namespace and descriptor custody must distinguish the trusted control
path from the workload.

### Closed broker and control-service boundary

The broker exposes only reviewed fixed verbs for the registered runtime and
owned job. This table states required behavior, not new API method names or
transport fields.

| Capability | Mandatory behavior |
| --- | --- |
| Dispatch | Corroborate trusted caller, exact original operation and consumed grant, durable C `DISPATCHED` binding, request digest/fence and accepted deployment/profile before one guest launch. An ambiguous claim or launch remains fenced; no blind retry. |
| Cancellation | Record the existing cancellation intent, preserve consumption and original deadline, fence further admission, then coordinate owned reconciliation. Abort, CLI death and caller disconnect prove no cleanup or command outcome. |
| Observation | Derive sandbox/process/container identities from the original trusted registration. Return bounded typed metadata bound to original request/job/runtime and observation generation. No caller-selected PID, generic `/proc` reader, namespace FD or stdout-based outcome proof. |
| Reconciliation | Preserve exact job/deployment/ledger identity and durable evidence/outbox. Use only reviewed identity-conditioned control actions on confirmed owned resources. Public API absence cannot become complete cleanup or a late-create fence. |

No generic Podman/OpenShell forwarding, host executable path, arbitrary host
argv, shell program, mount source, loader option, caller environment or credential
is admitted. Guest command/environment data retain the existing closed operation
schema and bounds. They travel only as bounded guest payload through the fixed
transport; they never select or alter a host executable, host interpretation or
launcher options. Trusted host
callbacks, resolvers and providers must themselves belong to the approved code
closure. Authentication of a socket peer supplements the exact authority checks.

The Podman directory/socket and gateway credential/control path must be private
to the dedicated domain, with no untrusted ACL, group access, inherited descriptor
or generic proxy. Preserve credential-free default guest mounts. Admission needs
independent evidence that neither workload nor harness can read credentials,
access another process's descriptors or memory, signal/inject into the control
domain, or obtain its capability indirectly.

Service-control custody includes system and user managers, session buses,
`systemd/private`, transient units, drop-ins, environment files, helper scripts,
linger and delegated managers, along with privilege rules. Unit/config/helper
bytes and their complete executable closure are protected. Every route that can
start an unfiltered sibling or act as the control identity is denied or subject
to the same reviewed admission boundary. Restricting only the Genesis process
does not close manager delegation. Filesystem socket permissions do not cover
abstract sockets such as the separately open ISCSIADM route.

### User-namespace separation and lifecycle ownership

Required rootless namespace capabilities remain with the trusted control domain.
The fixed metadata observer may use its reviewed `podman unshare` path; this is
not a capability exposed to the harness. Preserve its exact mapped-root UID/GID
maps, caller namespace lineage, source/runtime pins, retained pidfd/start-time
identity, mount/inode observations and original deadline. Arbitrary targets,
changed lineage, PID reuse, missing evidence and host-root fallback refuse.

Before any untrusted instruction, the selected launcher must enforce the reviewed
policy on namespace create/join, mapping helpers, setuid/file-capability paths,
inherited namespace/control FDs and service-manager delegation. A restriction on
the name `unshare` is insufficient. Review `clone`/`clone3`, `unshare`, `setns`,
subordinate mapping helpers and alternate launch paths together with ordinary
fork/thread/Node compatibility. Any selected syscall filter must explain how it
handles pointed arguments and alternative ABIs. Missing enforcement leaves this
class unavailable; no global sysctl change is selected by this document.

Replace the current sudo-only bridge with the independently running authenticated
broker before applying inherited `NoNewPrivileges` and namespace restrictions.
The [Genesis unit](../../boundary-gate/host/systemd/aukora-genesis.service)
explicitly omits that restriction because its current sudo bridge needs privilege
elevation. Retaining that bridge while claiming inherited restriction would be
inconsistent. Trusted runtime namespace access must still work without returning
that elevation route to untrusted code.

Graceful Cordis teardown uses one explicitly ordered, awaited owned coordinator:
stop new admission/observers, join child work, request scoped reconciliation and
retain unresolved evidence/outbox. Separate effects do not establish that order.
The independent control owner retains durable deadlines/fences when JavaScript
cannot execute; no Cordis disposal promise or planned TTL proves crash cleanup.
Failures preserve uncertainty rather than skipping a remaining ownership step or
settling from process disappearance. Existing factual C/F outcome rules above
continue to apply.

### Host never executes workspace bytes

The runtime host harness/control domain may interpret workspace bytes only as
bounded data under an explicit, command-specific parser. It may execute only
protected, immutable, digest-pinned deployed code and its complete executable
dependency closure. Approval names that
generation and closure; custody prevents writable aliases and substitution. A
workspace path, revision, matching digest, owner review or `noexec` mount does not
grant host execution authority.

This rule covers executable selection, interpreter script arguments, `-c`/eval
strings, stdin programs, generated modules, executable configuration, Node/Python
imports and dependencies, workers, native addons/libraries, shell-sourced/startup
files, preloads, plugin/provider selectors and subprocess helpers. Accepted
OS/runtime dependencies are explicit external anchors; unresolved dynamic
dependencies do not silently fall outside the closure. Use fixed executable and
import roots, sanitized startup environment and fixed host working directory;
missing configuration/custody refuses. Workspace roots identify data and approved
guest workload scope, not host discovery roots.

At this source base the [launcher](../../../scripts/launch-dsh.py) explicitly
supplies release `pluginSetRoot` and `grantRoot`. The
[composition policy](../../../plugins/aukora-composition-gate/src/policy.js)
still has CWD-derived defaults, but those defaults are not evidence that this
launcher selects workspace code. Its covered load branch checks the bytes it
returns; preserve that protection. It explicitly excludes dependencies, workers,
child processes and later filesystem reads and passes unmatched modules onward,
so it cannot establish the complete host-execution boundary alone. The launcher
also imports release Python code, which belongs in the protected closure.

The current [memory identity](../../../plugins/aukora-kira/lib/project-identity.mjs)
uses trusted configured workspace attachments, and
[project memory](../../../plugins/aukora-kira/lib/project-memory.mjs) does not
launch Git. A historical Git finding does not apply to those current modules.
The registered [self-change tool](../../../plugins/aukora-action-gate/lib/self-change-tool.mjs)
does launch the configured owner checkout's script as a host child after a source
marker check. It does not execute the proposed worktree directly, and its Git
calls disable hooks/fsmonitor, but a marker is not immutable deployment custody.
Move that execution, source-side materialization/build verification and any
registered workspace-configured commit workflow into the reviewed builder domain,
or keep the host route unavailable. Analyze each Git command/config separately;
no claim is made that every metadata read executes hooks or a pager.

Candidate scripts and build tools may execute inside the separate builder under
their reviewed resource/data scope. Builder caches, outputs and dependencies
have no writable route into runtime code. Independent byte/closure verification,
fresh exact approval and protected immutable promotion precede execution by a
host control service. Review/rebuild does not itself promote a checkout.

The existing [descriptor search](../../../plugins/aukora-action-gate/lib/descriptor-search.mjs)
keeps accepted workspace bytes on ripgrep stdin with `--no-config` and host CWD
`/`. Preserve that qualified data path. Its matcher module, packaged binary and
subprocess provider still need deployed closure/custody; a provider accepting an
absolute executable or PATH name is not that proof. No grep implementation or
previously refused fixture is changed by this design.

### Reviewed rollout and rollback

These are prerequisites for a separately authorized migration, not commands or
authorization to perform one.

1. Freeze new admission only to the affected owned route. Preserve evidence
   retrieval and the exact bounded trusted reconciliation path; define its
   service/job scope without stopping unrelated processes.
2. Review the dedicated identity, group/subid maps, broker interfaces, service
   graph, complete code/config closure, credentials, network and descriptor
   policy as one new profile. The [inventory producer](../../boundary-gate/host/openshell/sandbox-inventory.py)
   currently fixes `auma`/1001, subordinate range 165536:65536, forbidden owner,
   workspace ownership and observer mappings. Producer/schema, units, network,
   workspace/mirror custody and accepted pins must migrate together. No permissive
   discovery or freshly observed live baseline replaces approved expectations.
3. Provision a separate deployment, storage and ledger identity through reviewed
   setup. Do not reinterpret old Podman storage through `chown`, changed mappings
   or copied credentials. Preserve root-protected workspace ancestors, exact leaf
   grants, read-only Git/mirror mounts and authoritative mount/inode evidence.
4. Qualify the actual new installed path, then obtain fresh accepted deployment,
   image/policy/profile/code/config pins and open only that route. Qualification
   does not renew an old approval or original deadline.
5. Retain every original grant, request, job, launch fence, receipt, outbox,
   reconciliation record and unknown outcome under its original deployment/ledger
   identity. The [executor](../src/owned-executor.mjs) already refuses changed
   gateway/runtime/create-profile binding during cleanup. Old reconciliation
   requires independently established old custody; missing evidence remains
   `OUTCOME_UNKNOWN`. Never relabel or relaunch an old job through the new runtime.

Rollback is a freshly approved release at the current monotonic floor, preserving
authority epochs and all effect history. It never restores consumed grants,
clears unknown jobs, lowers/resets the approval floor or automatically restores
old credentials, the sudo bridge or a shared runtime identity. If prior code or
placement cannot satisfy this boundary, rollback means admission remains
unavailable with reconciliation retained. Reverting bytes is not permission to
reactivate an insecure control path.

### Acceptance and detecting controls — UNPERFORMED

Qualification must use the actual pinned DSH, installed service/config/closure,
accepted image/profile and real registered repository tree through normal
admission. Required observations bind original request/job/deployment and retain
exact command, typed result, control revision and limits. Source checks and mock
providers cannot establish these installed properties. Proposed controls below
use only separately authorized benign disposable state; they do not recreate the
previously refused race/canary fixture or touch real credentials or unrelated
processes.

| Required real observation | Meaningful detecting control |
| --- | --- |
| Approved foreground Bash works through the sole selected fixed guest carrier with that carrier's exact bounded I/O/exit semantics; owned cleanup is observed separately. | Remove a fixed-target or exact operation/request binding check in isolated source; its altered-binding refusal must fail before any real effect. |
| If the retained SDK adapter is selected, streaming preserves typed nonzero output and drains RPC completion, separately from cleanup. The pilot wrapper/SSH carrier is not claimed to expose that SDK receipt. | Remove typed-exit retention or RPC-drain checking in the selected adapter's disposable protocol control; its loss/uncertainty assertion must detect it. |
| Wrong peer, consumed grant, request digest, profile or deployment refuses; ambiguity never launches twice. | Remove each selected check separately; the corresponding mismatch/replay assertion must detect it using generic disposable bindings. |
| Direct Podman/gateway/credential access and control-process memory/FD/signal injection are denied from every untrusted principal and namespace. | Use a harmless independently accessible disposable counterpart to show the tested denial is enforced rather than caused by an absent dependency. Never expose the real control socket or credentials as a control. |
| User/system-manager, privilege-helper and namespace create/join delegation paths are denied; required trusted observer namespace path still succeeds. | A separately authorized disposable unprotected counterpart demonstrates that the exact alternate launch path is available; missing service/helper/kernel support is UNPERFORMED, not DENIED. |
| Observer proves exact source, maps, namespace lineage, PID/start identity, mount/inode and original deadline. | Remove each chosen identity/deadline check separately; the associated stale/different generic metadata assertion must detect it, beyond malformed-JSON rejection. |
| Approved workspace writes/data reads work; deployed closure, control state, Git and mirror custody remain protected. | Remove selected ancestry/mount/alias validation in an isolated fixture; its specific custody assertion must detect the loss. |
| Workspace scripts/imports/stdin/eval/config/PATH/preloads/providers/helpers refuse on host while approved deployed helpers and guest workloads work. | Remove custody, closure, fixed selection, environment isolation or promotion checking one at a time; each corresponding benign negative must become distinguishable in the acceptance harness. |
| Builder executes only in its separate scope and cannot access runtime, authority or protected deployment writes. | An isolated promotion-check removal must be detected; builder output alone must never qualify a host executable. |
| Restart/death retains original deadlines, exact job scope, late-create fence, complete owned-artifact evidence and no duplicate launch. | Remove the original deployment/request fence in disposable source; the replay/altered-binding assertion must detect it. API absence and process death remain insufficient cleanup evidence. |

Read back actual listeners/TLS principals, groups/ACLs/subids, namespaces and
descriptor inheritance; do not infer them from script comments or desired unit
settings. Preserve remaining abstract/session-bus/manager and other allowed routes
in the containment matrix. Host schema subset, fixture custody, accepted pins,
DSH drift and repository-tree collisions are a commit qualification gate. Its
PASS is separate from every installed observation above, which remains
UNPERFORMED in this design-only increment.

## Source references

- [F ledger](../src/ledger.mjs), [lifecycle](../src/owned-executor.mjs), [raw SDK transport](../src/sdk-transport.ts), [effective configuration](../src/effective-policy.mjs), [qualification acceptance](../src/qualification.mjs).
- The saved C/F alignment handoff at F `ee3e9577ccfc93d694e9ba358d8ef774dad43845` and C `292474f58f18c10bd4a9703909d02f12be82a0ac` supersedes the older C complete/null blocker in PILOT.md and REPAIR_HANDOFF.md. It records source alignment and a held setup boundary; it grants no runtime permission.
- Exact OpenShell source: [create admission](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/proto/openshell.proto#L1242), [async deletion](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/proto/openshell.proto#L1419), [exec request](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/proto/openshell.proto#L1858), [timeout ambiguity](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/crates/openshell-server/src/grpc/sandbox.rs#L3419), [provisioning repair deadline](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/crates/openshell-server/src/compute/provisioning_deadline.rs), [driver auxiliary cleanup](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/crates/openshell-driver-docker/src/lib.rs#L1938). These references were inspected from the saved local pinned source; no network research was run.
