# Smallest Linux readiness and qualification proposal

This is a per-action approval plan, not authorization or a setup script. Operator
task9 owns current Mac CLI/Nebius authentication and existing CPU host/SSH reads.
No H200, new VM, scaling, public endpoint or paid API is required. Preserve the
existing CPU preview's users, services, Docker/containerd state, ports and files.
This lane has performed no host action. Older pilot facts do not replace today's
read-only inventory.

## Read-only prerequisites and ordinary preparation

Record the exact existing host and SSH identity privately; never include them in
release evidence. Confirm Ubuntu24.04/linux-amd64, kernel/Landlock ABI3+, seccomp
user notification, cgroup2/systemd, runtime-default AppArmor/seccomp, free disk,
current preview CPU/RAM/PIDs, Docker/containerd presence, listeners and occupied
UIDs. Record existing firewall/forwarding state without changing it. Refuse setup
if the pilot's bounded footprint could disturb the preview. Missing kernel or
security support is a blocker, not permission for an upgrade or Unconfined mode.

Ordinary preparation may stage/inspect exact public artifacts and generate only
nonsecret configuration in a task-owned directory. It does not install packages,
start daemons, change permissions/users/network settings or generate credentials.
Use the recorded official package bytes in [pilot-official-metadata.json](pilot-official-metadata.json):

| Artifact | Exact version | SHA256 |
| --- | --- | --- |
| docker-ce | `5:29.8.2-1~ubuntu.24.04~noble` | `b53a44a6ff13277710978adbdbfea27fcdd7ac9f198017e733d2b8dc2343f8dc` |
| docker-ce-cli | `5:29.8.2-1~ubuntu.24.04~noble` | `008b3b49b474136063fe0fbe8999b0e77c3e8556d7f7de21f98f05715e2f76ba` |
| containerd.io | `2.3.6-1~ubuntu.24.04~noble` | `2eb8c6e244fe6886f2fa2eee9ec418c4b9bb44eb44fca748504f57c23341aed2` |
| docker-buildx-plugin | `0.37.1-1~ubuntu.24.04~noble` | `3c398af6eea280ddb57f32334d83867efd2bf07c4bc1be75fbd0a61c490ea925` |

The least disruptive candidate extracts those verified packages without running
maintainer scripts, then stages the needed binaries for the dedicated pilot.
No system-wide Docker installation or default-service start is required by that
candidate. Verify extracted ELF dependencies and exact `--help`/config validation
before approval. Existing libc6, libsystemd0, libseccomp2, iptables/nftables and
runtime-default profiles must satisfy the packages; any missing dependency needs
its own exact version/hash and installation approval. Do not silently apt-install
it or use extraction to bypass a required service/security prerequisite.

Use the existing verified Node24.11.1 and source-built SDK0.0.0 only if their exact
bytes/dependency closure can be placed in the protected tools tree without relying
on the preview user's HOME. Copying/installing that protected closure is an explicit
action below. No npm lifecycle install, SDK rebuild or Rust toolchain is needed
for the proposed official gateway. Record hashes/licenses and refuse missing bytes.

## Proposed exact host actions — approve individually before applying

The names/numbers below are concrete proposals. Task9 must confirm they are unused;
if one collides, update this proposal and obtain approval for the replacement.
Do not change an existing account or listener to make it fit.

| Action | Exact proposed scope | Approval/review before effect |
| --- | --- | --- |
| H1 protected files | Root-owned0755 `/opt/aukora-openshell-pilot/tools` for verified binaries/Node/SDK; root-owned0700 `/var/lib/aukora-openshell-pilot` and `/run/aukora-openshell-pilot`. No existing tool/symlink replacement. | Copy/install bytes and ownership/modes; dependency installations remain separately enumerated. |
| H2 identities | New non-login `aukora-exec` UID/GID40001 and `aukora-guardian` UID/GID40002. No supplementary Docker/sudo groups. Workload stays1000:1000; pinned supervisor65534:65534. | Account creation and exact service role/credential authority. Numeric separation alone does not authenticate IPC. |
| H3 resource owner | New `aukora-openshell-pilot.slice`: CPUQuota100%, MemoryMax2G, MemorySwapMax0, TasksMax256; pilot services and private daemon/container descendants only. This is a smaller aggregate CPU proposal than the earlier150% plan. | Capacity/readback and actual cgroup ancestry. No preview service joins or global log/swap changes. |
| H4 private runtime | Dedicated `aukora-openshell-pilot-containerd.service` and `aukora-openshell-pilot-docker.service`; private root/state below the paths above. Containerd socket `/run/aukora-openshell-pilot/containerd.sock`; Docker socket `/run/aukora-openshell-pilot/docker.sock`, root:root0600. Use the private containerd address/namespace, data-root/exec-root/pidfile; never default Docker/containerd roots/sockets. | Service files and daemon starts. Verify exact binary flags/config first. No `docker.service`, docker-group grant or privileged workload. |
| H5 networking | Private daemon has no bridge, iptables/ip6tables rule management, masquerading, forwarding enablement or userland proxy; log-driver none. Proposed gateway HTTPS127.0.0.1:19843 and health127.0.0.1:19844. Workload network none; trusted supervisor/gateway host network. | Exact validated daemon/gateway config and before/after listener/firewall/sysctl evidence. Unsupported flag/config or any unintended global change blocks this start. No public publishing, firewall exception or port reuse. |
| H6 image input/build | Pull only the four immutable amd64 gateway/sandbox/supervisor/Debian references below into this dedicated daemon; one network-disabled workload build/export/load from `runtime/image`. | Image transfer, daemon/build use and local storage allowance. Preserve source/layer/license bytes and distinct manifest/config outputs. No registry publication. |
| H7 control credentials | One dedicated control HOME/XDG below root-private control state; exact gateway mTLS/JWT/guest TLS files, and separately protected executor/guardian client material. Private keys0600 for their intended principal, parent dirs0700. No provider/model key, user HOME copy or private-key stdout/dry-run. | Each new credential/principal/placement and exact auth config. Upstream shared local client certificates do not prove distinct principals; resolve that actual auth boundary before qualification. |
| H8 control launch | Pinned gateway on the private daemon, explicit root-trusted control role to reach its root-only Docker socket; clear image CMD so it cannot override loopback TOML. Mount only exact control/config/socket paths. No control/socket mount in workload/supervisor. | Exact inspected launch argv, config/auth and privilege/mount list. Validate pinned binary options; no guessed CLI flag or disabled TLS/auth. Source template requires reviewed `allow_driver_config=true` for the closed tmpfs profile, bind mounts remain false. |
| H9 guardian placement | Guardian40002 private0700 store/config,0600 socket; preserve FULL-sync state/identity and OS lease. Proposed own `aukora-openshell-pilot-guardian.service`. Executor40001 state/credentials separate from preview UID1000. | Protected service/boot/clock policy and authenticated cross-UID control source must first be implemented/reviewed. Current0600 same-UID IPC cannot simply be opened with an ACL/group and called qualified. No current application mount. |

H4/H5 require a captured, validated configuration and exact command manifest from
the extracted binaries before approval. Desired flags are not an assertion about
installed behavior. If a dedicated daemon cannot meet the no-global-change scope,
stop the proposal; do not alter the existing preview/network to accommodate it.
H7/H8 likewise need the exact pinned TLS/JWT fields and source-supported argv;
the existing [gateway template](gateway.toml.in) and [pilot notes](PILOT.md) are
input material, not a complete accepted launch manifest.

The official gateway platform manifest is
`ghcr.io/nvidia/openshell/gateway@sha256:e0e18aa7a497290eed1f6ffb36f51540f037cec967c6d4354a264fecfd988620`.
Exact sandbox, supervisor and Debian platform references are [pins.json](pins.json).
The custom workload config-ID and OCI manifest remain null; build/export/inspect
must supply both. Preserve UID1000:1000, OCI workdir `/sandbox`, exec mapping
`/sandbox/work`; CPU500m, RAM512Mi, PIDs64 and tmpfs64/32/32Mi. Observe actual
Docker HostConfig/kernel limits, aggregate slice/swap and mount options. Build
metadata or persisted desired fields do not establish enforcement.

## Readiness versus one real executor qualification action

H1–H9 are readiness proposals. They cannot solve the target-side primitives in
[GUARDIAN_PROCESS.md](GUARDIAN_PROCESS.md): durable terminal create/exec fencing,
atomic approved UID/generation/full-config admission, caller-bound immutable
reclamation and complete driver artifact evidence. Those require reviewed source
changes or an equivalently qualified external target boundary. The official pinned
gateway exposes none of these caller primitives. Disabling concurrent policy
administration and running the seven process fixtures do not add them.

Only after those source/control joins and placement evidence exist should C obtain
the owner's fresh exact approval/reservation for the one inert read-only command
in [pilot-profile.mjs](pilot-profile.mjs), wall30000ms/output65536B per stream,
empty stdin/env/dsh_env, no providers/host mounts. Use actual C one-use dispatch,
the separately accepted guardian and actual F SDK lifecycle. Observe UID/GID,
`/sandbox/work`, genuine exit1/output, drained RPC, exact configuration, terminal
late-create exclusion, complete owned cleanup and C receipt/replay fence. This
one seam cannot qualify independent crash/boot/deadline or active egress denial;
those require separately scoped observations. Current F remains unavailable.

## Scoped rollback and stop conditions

Preserve original request/grant/receipt/guardian state and unknown outcomes before
stopping anything. Stop only the newly named pilot units and recorded owned PIDs
after identity corroboration. Reclaim only ledger-bound immutable sandbox/artifact
identities through the reviewed target mechanism; no broad prune, prefix deletion,
system Docker stop or unrelated process signal. If cleanup/late creation remains
uncertain, retain its monitors/state and blocker; rollback cannot prove no prior
effect or refund/reuse the approval.

Remove only verified pilot-created containers/images/private networks/volumes,
then the dedicated daemon/containerd if ownership and absence are established.
Preserve evidence/ledgers and credentials needed for uncertain reconciliation.
Remove pilot unit/slice/tool/control files or unused newly created accounts only
after their recorded obligations are closed and the corresponding removal is
approved. Never remove shared Docker roots, alter preview files/accounts, or
restore unrelated firewall/sysctl settings. Compare the captured preview health,
listeners, firewall/sysctls and resource use after each action; deviation stops
the next step and is reported with its exact attempted action.
