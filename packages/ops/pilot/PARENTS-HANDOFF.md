# H-only protected parent and UID handoff

The reviewed source artifact is `parents.py`. It uses the Ubuntu Python standard library, creates only fresh approved Prime parents/accounts, and never installs packages, initializes PostgreSQL, writes worker configuration, installs units or starts/stops services. G prepared it locally; H alone executes this shared-parent step after agreeing the disjoint boundary with the exclusive PG operator (task30, thread `designated PostgreSQL operator`).

The operator-reported distro PostgreSQL identity must remain UID113/GID114. Existing users/groups or existing/symlink Prime roots cause refusal before account creation. The script never modifies the postgres account or adds global postgres group membership. System account allocation selects unused IDs, records the actual public UID/GID/NSS-group map at `/var/lib/aukora-prime/assigned-identities.json` root:root0644, and prints that map for H to relay. No passwords or service-plane secrets appear in the output.

| Created directory | Owner:group | Mode |
|---|---|---|
| `/var/lib/aukora-prime` | root:root | 0711 |
| `/run/aukora-prime` | root:root | 0711 |
| `/var/lib/aukora-prime/app` | prime-app:prime-app | 0700 |
| `/var/lib/aukora-prime/authority` | prime-authority:prime-authority | 0700 |
| `/var/lib/aukora-prime/memory` | prime-memory:prime-memory | 0700 |
| `/var/lib/aukora-prime-witness` | root:root | 0755 |
| `/var/lib/aukora-prime-witness/pilot` | prime-authority:prime-authority | 0700 |
| `/run/aukora-prime/authority` | prime-authority:prime-authority-ipc | 0710 |
| `/run/aukora-prime/memory` | prime-memory:prime-memory-ipc | 0710 |

Three same-name primary groups/users are created as system accounts with locked passwords, `/usr/sbin/nologin`, and no home creation. Two IPC groups and one distinct PG socket group `prime-pg-socket` are created. App supplementary groups: `prime-memory-ipc`; authority: `prime-authority-ipc`; memory: `prime-authority-ipc,prime-memory-ipc,prime-pg-socket`. App gains no authority IPC or memory primary-group membership. The retained authority witness lies outside every D restore namespace; its same authority UID does not establish an independent witness.

H must stage the reviewed bytes in an already authorized root-owned task directory with root-owned canonical ancestors and no group/other write permissions. Copy into a new root-owned file, confirm its final SHA-256 using a trusted outer tool against the independently retained handoff digest, then execute only that verified staged path. Do not privileged-execute a candidate/Ubuntu-writable upload and rely on its own hash check. The internal pin catches accidental drift after trusted staging; code can never establish its own independent identity. The staged artifact must remain root-owned/non-writable throughout execution.

Source SHA-256 of `parents.py`:

```
8c20c620e324cdc163fdd681bd2c71573300f32d99ee6d0634129df7e92caa07
```

Read-only local plan:

```
python3 -B packages/ops/pilot/parents.py plan
```

After H completes the trusted outer staging/verification, the exact approved phase is:

```
/usr/bin/python3 -B /absolute/root-protected/staged/parents.py provision-layout --expected-artifact-sha256 8c20c620e324cdc163fdd681bd2c71573300f32d99ee6d0634129df7e92caa07
```

The displayed staged path is an explicit operator input, not an existing-file claim. H verifies the returned identities, account locks/no-login shell, actual supplementary memberships, canonical ownership/modes and traversal before passing actual UID/GID values to worker configuration. A partial account/directory error requires reconciliation from retained output and scoped observations; the script refuses automatic retry and never deletes or repairs pre-existing state. `/run` entries are volatile; reboot reconstruction needs a separately reviewed scoped artifact after qualification.

The PG operator exclusively creates `/var/lib/aukora-prime/postgres` postgres:postgres0700 and `/run/aukora-prime/postgres` postgres:prime-pg-socket0750. PG Unix socket mode0770/group prime-pg-socket on port55434, private peer mapping `prime-memory -> prime_memory`, and dedicated synthetic database `aukora_prime_synthetic` remain the operator's steps. No PG child is created by this artifact, no ACL/password is generated, and app has no PG traversal grant. Eight pinned PG packages were reported installed already; do not run a duplicate install.

H resolved the earlier PG/D config-read group conflict by approving this sixth distinct socket group before the fresh-parent phase ran. PostgreSQL may use `prime-pg-socket` at process/unit scope only; it never gains the memory worker's primary `prime-memory` group. Private D config remains root:prime-memory0440 under root:prime-memory0750. App gains neither group. Task40 guard source `ca382593545c9877e0fce4f19e406c90f7a84027` requires root-owned0440/worker-primary-group with protected matching0750 parent. The verifier retains negative PG-read probes on every D private config and checks actual process/group contexts; new source agreement is not actual OS qualification.

The intended PG unit has User/Group postgres and `SupplementaryGroups=prime-pg-socket`; any approved manual operator process uses only `-g prime-pg-socket`, never prime-memory. Socket dir postgres:prime-pg-socket0750/socket0770 at55434; no global postgres account group change. The unchanged PG data owner/group remains postgres:postgres0700. H and the exclusive operator must serialize parent creation before PG child creation.

Worker activation remains held for reviewed authority-store bootstrap, C/D/B/bridge joins, exact H deployment-manifest boot and actual Linux PG/UID checks. The parent/UID artifact is independent of those qualification holds. Source PostgreSQL peer configs and disabled unit templates are separate pinned preparation; no service starts, secret generation or private import is performed by G.
