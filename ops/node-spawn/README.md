# Node spawn

No step of this installer has run on a real Linux host. The Linux path has run
only against disposable trees, with users/services and the build, manifest,
bootstrap and installed readback replaced by fixtures. Helper checks use real
local Git, throwaway signed invites and SQLite. The pilot's existing staging
observations do not qualify this installer.

```sh
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
bash ops/node-spawn/spawn.sh --dry-run --config /absolute/operator/spawn.json
bash ops/node-spawn/spawn.sh --linux --config /absolute/operator/spawn.json
```

Real mode requires root on Linux and bootstrap Node 24.11.1, Python 3 and Git
already on the operator's PATH. This is still not a bare OS installer.
Dry run supports bash 3.2 and bash 5, reads
configuration and prints exact commands without transport or installation.
`--root` maps destinations for the harness; user/group/systemd commands carry
that root explicitly. A redirected tree is not an activated host.

The root-controlled JSON config contains version `1`, safe `node`, and these
fields: `source_checkout`, full 40-hex `release_commit`, `node_archive`, reviewed
`node_archive_sha256`, `public_signer_epochs`, `built_harness`, `offer`,
`auma_offer`, `root` (network creator public identity), `admission` (trusted HTTPS
authority) and `door_config`. File operands are absolute. Keep config and bearer
offers private. The checkout must be clean and at the named commit, including
these helpers. Supply its pinned `vendor/dsh-source.tar.gz` and a previously
built harness; `build-dsh.py --verify-built` checks the binding before the
existing materializer runs. No download or cloud allocation is implemented.
No inline key, credential or address is printed.

The member and Auma use different keys. Each needs its own one-time invite,
currently **two admissions**, subject to the inviter's three-invite quota.
One invite cannot authorize an extra key. A single-invite identity binding needs
the owner's protocol decision. Offers are `{invite, chain}` with the inviter's
signed root-first ancestry. Current offers expire after 48 hours.

The adapter requires an **existing authoritative service**: `POST /preflight`
receives `{root, invite, chain}` and returns HTTP 200
`{available:true, invite_id}`; `POST /redeem` additionally receives signed
`redemption`, returning HTTP 200 `{admitted:true, record}` only after durable
spending and closed-relay admission. Known refusals return non-200 `{code}`.
Redirects refuse. Returned ancestry, offer, redemption and generated key must
match exactly. HTTPS authenticates this authority; signed ancestry alone does
not prove spending or relay admission. The [admission service](../buzz-relay/README.md#invite-admission-http-service)
implements that server in source; installed operation remains unqualified. It shares one trusted store and the existing
`ops/buzz-relay/admit.mjs` outbox. The relay owner's key stays at the relay.
There is one closed community relay; this command installs none. The door's
existing loopback route needs a separately supplied transport to that relay.

The eight functions in `linux.sh` follow this sequence:

1. `verify_invites`: check signatures, ancestry and current expiry; ask the
   authority about spend/member/quota state; check commit/runtime inputs;
   refuse preexisting unbound keys before user creation.
2. `create_users`: reconcile homes/Auma UID 1001, create the member, host, gate
   and sandbox accounts; install private offer/config copies.
3. `install_release`: clone the exact local commit, verify the Node archive and
   version, verify the built harness, materialize the release, generate the
   manifest from **staged** package/owner-key/checkout copies; publish the
   launcher before `gate-bootstrap check-package`.
4. `generate_keys`: exclusive 0600 keys as `aukora-member` and `aukora-host`.
   Auma's door runs as the host user; its key belongs in that private home.
   No human owner key is generated.
5. `redeem_invites`: admit exactly each generated key and store signed records
   privately. Redemption can refuse after installation because preflight does
   not reserve an invite.
6. `configure_door`: derive the wake allowlist from the verified member record;
   leave owner authority unset. Template fields: `channel`, `sessionId`, optional
   empty `admit`.
7. `start_and_accept`: install reviewed units; check package/runtime; show and
   raise the release card; install only a genuine owner approval; check the
   monotonic floor; write `release.env` from `.dsh-build/genesis-artifacts.json`;
   start services and run package/runtime/floor/service/door readback.
8. `owner_next`: name the member's own enrollment and exact release review.
   Nothing signs, clicks, enrolls or approves for the member.

Before keys or spending, real mode requires existing protected owner state,
matching gate signer provisioning/public epochs, reviewed OpenShell binaries,
sandbox/workspace inventory and units, local-deny unit, reviewed restricted
sudoers rule, exact Auma subuid/subgid
range, and state/support/targets directories. The gate user's private signer
custody and public SPKI hash must match the protected epoch registry before
new member keys or spending. These are **unimplemented fresh-host
prerequisites**. File presence is not evidence of valid provisioning: the gate's
owner-state validation, signed approval and service selfchecks still decide.
Missing enrollment prints the member action and refuses `OWNER_ENROLLMENT_REQUIRED`;
other gaps refuse `SPAWN_HOST_PREREQUISITES_REQUIRED`, `SPAWN_GATE_SIGNER_REQUIRED`
or `SPAWN_AUMA_RANGE_REQUIRED`. No enrollment producer, sandbox, provider
credential, root service operation or real approval was exercised here.

Root-held phase bindings preserve installation across an enrollment pause and
identities across an approval pause. Exact completed reruns only read back:
no reinstall, new spend, duplicate card or floor reset. Changed inputs, keys,
admissions or configuration refuse. A crash during staging, between key creation
and its phase marker, or after remote spending before record storage needs
operator reconciliation; arbitrary crash recovery is not proved. A refused
approval leaves the harness unstarted. Exact-floor proof is retained and checked.

Installed readback loads the release's actual door readers, checks nonmember
relay refusal and authenticated Auma query. It does **not** prove a live session,
wake, reply, owner ceremony or containment. Existing `installed-accept.mjs` uses
uninvited throwaway channel owners and cannot silently qualify a closed network.

## Original LXD plan and exhaustive gaps

Baseline `263e8eff8a3b30311f6543003ea0a8959b0cf8f2`: `--plan NODE ADMISSION_RECORD`
verifies an **already redeemed** `{chain}` against independently configured
`AUKORA_NETWORK_ROOT_PUBKEY`, then prints 17 conditional shell-escaped LXD steps
and unresolved operands. No LXD/install call executes. The LXD path remains,
with only four Linux-dispatch lines added. References below name the inspected
baseline. No literal TODO markers existed; these GAPs are all pending work:

| Refusal / pending work | Baseline file:line |
|---|---|
| LXD_PROFILE_MISSING: pinned isolated image/profile | spawn.sh:62 |
| RESUME_CONTRACT_MISSING: shared allocation/crash binding | spawn.sh:63 |
| RUNTIME_INSTALL_MISSING: pinned Linux prerequisites | spawn.sh:69 |
| PRINCIPAL_INSTALL_MISSING: users/ranges/sudoers | spawn.sh:74 |
| SOURCE_INSTALL_MISSING: protected named checkout | spawn.sh:78 |
| OWNER_ENROLLMENT_DERIVATION_MISSING: subject/epoch/registry/activation | spawn.sh:89 |
| FRESH_KEYS_MISSING: first gate key/public epoch bootstrap | spawn.sh:90 |
| GATE_INSTALL_MISSING: complete protected package installation | spawn.sh:94 |
| OPENSHELL_BINARY_PROVENANCE_MISSING: binary/custody provenance | spawn.sh:106 |
| GUEST_IMAGE_INPUTS_MISSING: absent guest/exec.py and reviewed image inputs | spawn.sh:111 |
| SANDBOX_PRODUCER_MISSING: qualified workspace inventory producer | spawn.sh:113 |
| NODE_STATE_MISSING: provider/state/targets/Linux overlay | spawn.sh:117 |
| APPROVAL_RESUME_MISSING: preserve exact existing floor/proof | spawn.sh:121 |
| OWNER_APPROVAL_REQUIRED: owner review/decide_review | spawn.sh:125 |
| RELEASE_ENV_MISSING: exact approved record selection | spawn.sh:129 |
| AUXILIARY_SETUP_MISSING: memory/Aura/shared relay configuration | spawn.sh:139 |

Other baseline refusals: `USAGE` spawn.sh:28,30; `NODE_OPTIONS_FORBIDDEN` :56;
planned `OFF_LOOPBACK_LISTENER` :53, `NODE_VERSION_MISMATCH` :70 and
`SOURCE_RELEASE_MISMATCH` :80,131. Admission helper: `NODE_NAME_INVALID`
admission.mjs:17; `NETWORK_ROOT_REQUIRED` :18; `ADMISSION_RECORD_INVALID` :23,44;
`ADMISSION_RECORD_REQUIRED` :33,38,40,42; `NODE_VERSION_MISMATCH` :49;
`ADMISSION_USAGE_INVALID` :50. Member installer: `MEMBER_CONFIG_INVALID`
install-member.py:26,93; `MEMBER_CONFIG_UNPROTECTED` :35;
`MEMBER_CONFIG_ROOT_REQUIRED` :41; `MEMBER_CONFIG_CONFLICT` :73;
`MEMBER_CONFIG_IO` :84. Offline verification proves a signed path, not present
expiry, quota, shared spending or allocation to a unique node.

Run `node --test tests/node-spawn-*.test.mjs ops/node-spawn/test.mjs` and
`node tests/node-spawn-invite.test.mjs --mutations`. Mutants use private fixture
copies. These results do not prove global single use, installed custody,
enrollment, containment or a working fresh node. The incubator operator can
read node keys/state; the member's private owner key stays on their own device.
