# Private C/D PostgreSQL fixture

This is a disposable synthetic acceptance fixture, outside the package exports.
It does not qualify production routes, prove human presence, enroll a real owner,
or activate the installed product. Its signer lives outside Linux workloads,
inside the user's Mac trust boundary. H owns protected staging, existing assigned
identities, descriptors and worker lifecycle. The exclusive operator owns every
PostgreSQL start/stop/restart and the two marked schemas' create/drop plans.

The source pins are contracts `f4fbe48`, C `8c4aa99`, D `dee8e47` (runtime remains
`1959785`), B `b3a9baf`, and bridge base `17c4291`. The unchanged memory review
helper SHA256 is `89cf53048efa6d12baff858f388b078ea64917ffb874d62d75f26d64648a96c0`.

## Entry points and closure

- `deployed-profile.mjs`: closed public profile, fixed tasks/hosts/extraction,
  protected/private JSON file guards and H-local descriptor construction.
- `deployed-bootstrap.mjs`: setup-only C provisioning, D table migration,
  existing C/D worker start, and D's bounded committed-save verification.
- `deployed-actor.mjs`: existing B transport/bridge client running as App997.
- `deployed-controller.mjs`: Mac-only synthetic ES256 signer and fixed SSH actor launch.
- `deployed-pipes.mjs`: strict bounded anonymous stdin/stdout protocol.

Stage the full Prime-local authority, memory, contracts and runtime-bridge
packages; UI `adapters/{transport,capture-review}.mjs`, package/license/provenance
material; the existing locked pg 8.16.3 plus 13 dependencies; and the approved
Node closure. Standard `require('pg')` from memory's package must resolve inside
the staged Prime root, for example `source/node_modules/pg`. No NODE_PATH,
external repository or external driver fallback is accepted.

C contains exactly four preserved relative links under
`packages/authority/upstream/vendor/authority/deps/node_modules/@noble/`:

| Link | Exact text |
| --- | --- |
| hashes | `../../@noble/hashes@2.2.0` |
| curves | `../../@noble/curves@2.2.0` |
| post-quantum | `../../@noble/post-quantum@0.6.1` |
| ciphers | `../../@noble/ciphers@2.2.0` |

Preserve those typed links and their contained versioned targets. C's computed
imports additionally require aumlok `prime-verifier.mjs`, Kira `strict-read.mjs`,
and vendored authority `lib/index.js`; staging only static import strings is insufficient.

## Controller grammar

The CLI accepts exactly `--config ABSOLUTE_JSON --phase PHASE`. Phases are `plan`,
`save`, `after-authority-restart`, `after-memory-restart`,
`after-postgres-restart`, and `disable`. JSON is parsed with frozen
`contracts.parseStrictJson`, maximum 64 KiB/depth 32. Controller config, profile
and signer state are regular canonical paths, current-Mac-owner 0600 in a
current-owner 0700 directory. No config JavaScript is imported.

The closed controller config has these fields:

```json
{
  "version": 1,
  "kind": "prime-private-cd-pg-controller/v1",
  "synthetic_fixture": true,
  "backend": "mac-strict-ssh-v1",
  "postgres": {
    "host": "/run/aukora-prime/postgres",
    "port": 55434,
    "database": "aukora_prime_synthetic",
    "user": "prime_memory",
    "max": 4,
    "connectionTimeoutMillis": 5000
  },
  "fixture_path": "/PRIVATE/fixture.json",
  "profile_path": "/PRIVATE/profile.json",
  "signer_path": "/PRIVATE/signer.json",
  "source_root": "/opt/aukora-prime-acceptance/SOURCE_SHA256/source",
  "node_path": "/opt/aukora-prime-acceptance/SOURCE_SHA256/tools/node",
  "actor_config_path": null,
  "ssh_identity_path": "/absolute/operator-controlled/ssh-identity",
  "ssh_known_hosts_path": "/absolute/operator-controlled/ssh-known-hosts",
  "deployment": null
}
```

Paths above are placeholders, never discovered by the fixture. H supplies the
existing SSH paths; source code checks their metadata without reading key bytes.
`plan` invokes D's `planWorkerPostgresFixture`, writes its exact public state and
two-schema creation plan, generates two disposable P256 credentials, and writes
only their public material to the profile. Only the Mac signer file retains
private keys/counters. Plan connects to no database or IPC endpoint.

Before a workflow phase, H fills `actor_config_path` with exactly
`/etc/aukora-prime/acceptance-RUN/app/actor.json` and supplies this closed
deployment record from its actual staging checks:

```json
{
  "kind": "prime-private-cd-pg-h-stage/v1",
  "source_sha256": "64lowerhex",
  "actor_sha256": "64lowerhex",
  "node_sha256": "64lowerhex",
  "actor_config_sha256": "64lowerhex",
  "protected_stage_verified": true,
  "actor_uid": 997,
  "actor_gid": 987,
  "signer_location": "mac-private-controller"
}
```

This is H's fixture deployment input, not a production acceptance kernel. The
controller does not independently prove remote stage ownership or source equality.
It reports that limitation. `source_root` must contain the record's exact source
SHA; Node is pinned to that stage's exact `tools/node`, with `tools/LICENSE` retained.

The only launch is `/usr/bin/ssh`, destination `ubuntu@192.0.2.1`, using
`-F /dev/null`, BatchMode, StrictHostKeyChecking, explicit existing identity and
known-hosts paths, no forwarding/agent/local command/connection sharing. Its
remote command is fixed sudo as `prime-app:prime-app`, the pinned staged Node,
the fixed actor entry, exact protected actor config and one allowlisted phase.
There is no Ubuntu signer backend, arbitrary argv, discovery, shell input or
new authentication/group/socket/port.

## Protected service descriptors

H calls `makeFixtureDescriptors({profile,credentials:{memory,primary,secondary}})`
locally with three distinct H-provisioned 32-byte lowercase-hex secrets. This
pure export returns closed `{authority,memory,actor}` JSON. It generates or
writes no credentials. Only C/D descriptors contain the private memory-effect
secret; only D/app descriptors contain the two owner-control secrets. The Mac
controller has none of them. Public profile equality is retained in all three.

Config files must be root-owned 0440, primary group C986/D985/App987, in direct
root-owned 0750 parents of that same group. All ancestors must be real root-owned
directories with no group/other write. Actual/effective worker identity and
existing group membership are H's acceptance checks; fixture entry points also
require the exact real UID/primary GID before reading configs.

| Item | Fixed path / identity |
| --- | --- |
| C socket | `/run/aukora-prime/acceptance-RUN/authority/authority.sock`, parent C995:984 0710/socket 0660 |
| D socket | `/run/aukora-prime/acceptance-RUN/memory/memory.sock`, parent D994:983 0710/socket 0660 |
| C state | `/var/lib/aukora-prime/authority/acceptance-RUN`, C995 private |
| C witness | `/var/lib/aukora-prime-witness/pilot/acceptance-RUN`, C995 private, outside D restore |
| Actor witness | `/var/lib/aukora-prime/app/acceptance-RUN/witness.json`, App997 0600/private 0700 parent |

No group change is performed: App997:987 uses existing supplemental983;
C995:986 and D994:985 use existing approved private IPC/PG access. Mac remains
the existing current owner. Ubuntu1000 is the fixed SSH account, never the signer.

Bootstrap CLI: `--config ABSOLUTE_ROOT_JSON --role authority|memory --phase
provision|initialize|serve|verify`. `verify` additionally requires exactly
`--expected ABSOLUTE_ROOT_JSON`, read with the D config guards.

- `authority/provision` calls local `provisionNewAuthorityStore` once. Existing
  state or retained witness refuses. This helper is never an IPC/public method.
- `memory/initialize` calls D's exact assigned-UID pool/migration helper only
  after the operator created its marked schemas. It creates bounded tables,
  not a database, schema or role.
- `serve` starts the existing worker factories. D's `initializeSchema:false`
  prevents implicit startup migration. Host/task/source and owner selection
  come from the frozen profile and authenticated credential association.
- `memory/verify` calls D's genuine committed intent/effect/receipt/byte/citation
  audit with `project:false`. It never substitutes SQL evidence for C proof.

There are no setup, raw save, reserve, dispatch, settlement, drain, maintenance,
import/restore or key endpoints exposed to the app. Public capability remains
unqualified/unavailable throughout this fixture.

## Fixed signing transcript and checks

Pipe frames are closed `{version:1,sequence,type:'request'|'response',payload}`,
strict UTF-8 JSON plus LF, at most 64 KiB/depth32, at most32 frames per direction,
one exchange at a time and absolute30-second request/response/write deadlines.
Replay, gaps, duplicates, bad UTF-8, partial oversize, EOF and timeout close the
peer; nothing is resent. The local SSH child has bounded exit/escalation and a
180-second overall phase bound.

Closed payloads:

- `{type:'review',owner,operation,memory_capture}` ->
  `{type:'reviewed',operation_digest}`.
- `{type:'sign',owner,purpose:'login'|'approval',request,public_key,proof_template}`
  -> `{type:'assertion',material}`. Login template must be null.
- `{type:'result',report}` -> `{type:'accepted'}`.

Save permits exactly primary login, primary review, primary approval, secondary
login, result. Read phases permit only primary login, secondary login, result.
The controller checks fixed two-owner identity/task/policy, exact host/extraction
and independent draft using D's `expectedWorkerCaptureDigests`; initial heads
must be `{}` and state their exact D digest. It recomputes C WebAuthn challenge
bytes/options and binds every proof-template field to the retained full operation.
An actor-selected byte buffer or generic signing request is refused. Shape alone
does not establish C issuance: actual C's durable login/review/session/proof
verification remains authoritative on use.

Counter and phase admission are read under an exclusive lock. Attempted phase
and incremented counter are fsynced before launch/assertion output. A failed or
uncertain attempt is never admitted again or automatically retried. Lost SSH,
dispatch or SQL responses preserve the existing C/D reconciliation behavior.

The actor checks altered statement, attribution, extraction and cross-owner
requests before consumption, then saves through real C reserve/claim and D's
durable intent/effect/receipt path once. It obtains C COMPLETED status, a genuine
retained-head citation and D's closed actual-save expectation. Saved/pending is
distinct from indexed/searchable; this minimal fixture does not drain the index.
H may separately scope D's existing bounded projection check.

H then performs the three named restarts, preserving the same C state/witness
and PG database. Each new actor phase performs fresh synthetic authentication
and checks identical canonical-byte digest, retained citation, actual C status,
secondary-owner read/cite/status refusals, and public unavailability. The actor
cannot prove that H restarted a process or PG; H records PID/start/restart evidence.
The existing operator alone starts/restarts/stops PG and executes exact create/drop
plans. No controller code runs those lifecycle commands.

After evidence, `disable` persists a disable-intent marker, unlinks the private
signer file and fsyncs its directory, then records completion. Any marker prevents
further signing even if unlink/fsync was uncertain. No secure-erasure claim is
made. It retains content-free counters/phases and the synthetic saved expectation;
H/operator stop the isolated workers and clean only the allocated fixture state
and two marked schemas. C/D consumed or unknown evidence is never reset/replayed.

## Source evidence versus deployed evidence

The three new source test files exercise the actual C/D/B objects, P256 proof
verification, durable SQLite test storage, closed pipe parsing, negative binding,
counter persistence/phase fencing and cold store reopens. They do not prove
PostgreSQL, separate UID ACLs, SSH deployment integrity, real passkeys or a live
product. H/operator's actual private C/D/PG result is a separate acceptance record.
