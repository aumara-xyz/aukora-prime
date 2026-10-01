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

Three same-name primary groups/users are created as system accounts with locked passwords, `/usr/sbin/nologin`, and no home creation. Two IPC groups are created. App supplementary groups: `prime-memory-ipc`; authority: `prime-authority-ipc`; memory: `prime-authority-ipc,prime-memory-ipc`. App gains no authority IPC or memory primary-group membership. The retained authority witness lies outside every D restore namespace; its same authority UID does not establish an independent witness.

H must stage the reviewed bytes in an already authorized root-owned task directory with root-owned canonical ancestors and no group/other write permissions. Copy into a new root-owned file, confirm its final SHA-256 using a trusted outer tool against the independently retained handoff digest, then execute only that verified staged path. Do not privileged-execute a candidate/Ubuntu-writable upload and rely on its own hash check. The internal pin catches accidental drift after trusted staging; code can never establish its own independent identity. The staged artifact must remain root-owned/non-writable throughout execution.

Source SHA-256 of `parents.py`:

```
f73240dd89cb589188f82fff79b6b0cbaecdebd32ee40d0cba68916ca8b7ad78
```

Read-only local plan:

```
python3 -B packages/ops/pilot/parents.py plan
```

After H completes the trusted outer staging/verification, the exact approved phase is:

```
/usr/bin/python3 -B /absolute/root-protected/staged/parents.py provision-layout --expected-artifact-sha256 f73240dd89cb589188f82fff79b6b0cbaecdebd32ee40d0cba68916ca8b7ad78
```

The displayed staged path is an explicit operator input, not an existing-file claim. H verifies the returned identities, account locks/no-login shell, actual supplementary memberships, canonical ownership/modes and traversal before passing actual UID/GID values to worker configuration. A partial account/directory error requires reconciliation from retained output and scoped observations; the script refuses automatic retry and never deletes or repairs pre-existing state. `/run` entries are volatile; reboot reconstruction needs a separately reviewed scoped artifact after qualification.

The PG operator exclusively creates `/var/lib/aukora-prime/postgres` postgres:postgres0700 and `/run/aukora-prime/postgres` postgres:prime-memory0750. PG Unix socket mode0770/group prime-memory, private peer mapping `prime-memory -> prime_memory`, and dedicated synthetic database `aukora_prime_synthetic` remain the operator's steps. No PG child is created by this artifact, no ACL/password is generated, and app has no PG traversal grant. Eight pinned PG packages were reported installed already; do not run a duplicate install.

Config and unit emission is held. Task40 guard source `ca382593545c9877e0fce4f19e406c90f7a84027` now requires root-owned0440/worker-primary-group with root:worker0750 parent. PostgreSQL unit-only supplementary `prime-memory` membership would also permit reading a D config owned root:prime-memory0440 under that parent, including D's private C-channel material. Ordinary DAC does not distinguish NSS membership from process supplementary membership. H/task40 must resolve that boundary for every PG launch context before emitting secret-bearing D config or starting workers. No extra group/ACL or activation workaround is introduced here. New C authority-store bootstrap API, C/D/B repairs, exact app deployment-manifest interface and actual Linux PG/UID checks remain pending. The parent/UID step is independent of these holds.
