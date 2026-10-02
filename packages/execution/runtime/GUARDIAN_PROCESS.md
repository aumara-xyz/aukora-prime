# Separate-process guardian source

This increment implements an independently running monitor and cleanup worker,
its own durable SQLite state and OS-released process lease, private Unix IPC,
immutable per-job deadline timers, and repeated reconciliation after API absence.
The worker has no create, exec, approval or settlement route. It is not mounted
by F/H or the application. Existing production launch gates remain unavailable.

`@aukora/prime-execution/guardian` exports `GuardianStore`, `startGuardian`,
`guardianCall`, `guardianRegistrationDigest` and `PinnedGuardianBackend`.
The separately launched entry is `src/guardian/process.mjs`; it reads only an
explicit protected configuration and reopens an already provisioned store.
It does not silently initialize missing recovery state. Actual SDK/bootstrap
execution, control credentials, Linux services and host placement are unperformed.

## Implemented lifetime and recovery

The closed private registration preserves the entire frozen request, its digest,
consumed grant, original local lifetime/digest, create/delete identities, unique
name/owner token, image/profile/workdir and immutable gateway/ledger/deployment/
host-profile scope. Registration is monitoring custody, not a C dispatch claim
or a qualified launch acknowledgment. Exact duplicates return the same retained
record; changed bindings or deadlines and reused operation/grant identities refuse.
Capacity is 64 permanent records; it refuses new registrations when full instead
of discarding unknown jobs.

SQLite FULL-sync checkpoints save registration before acknowledgment and a
cleanup attempt before control calls. A separate SQLite lease prevents concurrent
guardian owners and releases on process death. The guardian's timer spends the
original `accepted_at + wall_time_ms`, even after the registering process exits.
Recovery schedules only the remaining original duration; an expired saved job
immediately requests cleanup. Saved clock high-water observations and per-process
timers detect observed backward movement and latch cleanup conservatively. They
do not prove boot continuity, bound outage duration or protect against privileged
clock/state rollback.

Deadline/cancellation/clock uncertainty durably latch `cleanup_requested`; no
heartbeat, duplicate registration or reconnect can renew it. The worker keeps
scanning registered identities after public absence and after a cleanup reply,
so a previously invisible late resource remains a reconciliation obligation.
Before reclamation it requires exact name, workspace, owner token, original
create-request origin and immutable UUID. A learned UUID never changes. Foreign
or duplicate same-name resources remain untouched. Uncertain cleanup retries
first reobserve that exact immutable resource and reuse only the original
idempotent conditional action ID. They never retry create or exec.

Every record retains `effect_outcome:'unknown'`, `runtime_qualified:false`,
`terminal_fence:'unavailable'` and `artifact_cleanup:'unverified'`. Public absence,
one successful reclaim, guardian acknowledgment and graceful shutdown cannot
change these fields or clear F/C consumption/launch fences. Cancellation is
monitor intent only; F/C remain responsible for their existing factual receipt
and settlement rules. No guest or inline application callback can provide an
independent guardian or convert this record into authority.

## Concrete pinned gateway limits

OpenShell stays `6648bd0c290efbc41ba131ee9831ee45cd431f94`, SDK source-built
version **0.0.0**. The concrete adapter scans the actual paginated SDK inventory.
It deliberately refuses reclamation: public metadata cannot corroborate the
original create request, and name-addressed delete cannot compare the guardian's
previously observed UUID at admission. No fictional protobuf fields are added.

The pinned gateway already implements internal mutation and target fencing.
Create `request_id` supplies durable deduplication; its owner survives client
cancellation. The gateway's 300-second provisioning repair deadline is attempt
bound and retries identity-bound stop, but ends at Ready and can extend with
configuration changes. Exec admission binds the internally resolved UUID and
checks `ensure_target` before relay. Delete captures its resolved UUID and
protects it while waiting. These mechanisms do not expose the caller's approved
generation or an independently enforced foreground wall deadline.

The still-needed target primitives are precise:

- Durable request/deployment/attempt-bound terminal fencing that rejects future
  create/exec, fences outstanding driver creation, survives restart and reports
  terminal late-create exclusion before cleanup can settle.
- Atomic launch comparison of the expected immutable sandbox UUID, runtime
  generation and complete effective configuration identity, or an independently
  qualified freeze covering that launch/lifetime. Equal readbacks cannot close
  the intervening-change race.
- Caller-bound immutable-ID reclamation and complete driver inventory/evidence
  for workload, supervisor/auxiliary containers, networks and all private volumes,
  joined to terminal creation exclusion. Public Sandbox absence is insufficient.

These require reviewed upstream/control-plane implementation or an equivalently
qualified external target boundary. They are not implemented by the process
loop, a registration callback, an acceptance boolean or a missing API row.

Pinned source evidence: `proto/openshell.proto` lines1242/1419/1858;
`grpc/mutation_replay.rs` lines219/380; `compute/provisioning_deadline.rs`
lines4/424/496; `compute/mod.rs` line2134; `grpc/sandbox.rs`
lines917/2389/3307/3419; Docker driver lines1515/1938/1995/2168/2223/2284.
The source hashes are retained in the private handoff; no new broad research ran.

## Focused process evidence and deployment prerequisites

`node packages/execution/checks/guardian-process.mjs` ran seven keyless cases on
Mac Node24.11.1 with separate owner, guardian and serialized fixture-backend
children. They cover owner exit, delayed resource discovery, immutable deadline
across guardian death/restart, exclusive ownership, registration replay/extension,
UID/owner/origin substitution, API outage recovery and exact uncertain cleanup
retry. Only named disposable child processes and private temporary socket/state
were used. The initial sandbox socket creation failed EPERM before any case;
automatic approval then allowed the scoped local fixture run. The simulated
backend has a real serialized conditional operation inside its own child, not
the pinned gateway's API. No actual SDK/gateway/guest or credentials were used.

These are process-mechanism results. Cross-UID Linux authentication, protected
store/config custody, anti-rollback/boot clock policy, service supervision,
independent gateway/host outage behavior, driver artifacts and real containment
remain unqualified. The Unix socket is0600 in a0700 worker-owned directory;
same-UID access is not authenticated separation from an application or guest.
H must select and explicitly obtain approval for those host/control placements;
this increment installs no service, creates no keys and changes no host security.

Four focused pinned-adapter/strict-ingress cases also passed: complete pagination
without invented create provenance, incomplete/cyclic inventory refusal, no named
delete workaround, and duplicate-key/fatal-UTF8/BOM rejection. The new declaration
closure typechecked using the existing compiler/Node types; this was no SDK build.

Before one real bounded action, implement the missing target primitives, provide
the immutable workload outputs and actual kernel/resource/control observations,
join the real authenticated C review/reserve/dispatch, and qualify the separately
configured guardian/evidence path. F's factory and v1/C interfaces are unchanged;
the process registration is an additional private monitor boundary. The previous
[lifetime safeguard](LIFETIME_SAFEGUARD.md) and [design obligations](DEADLINE_OWNERSHIP.md)
remain applicable. A process fixture cannot open any production gate.
