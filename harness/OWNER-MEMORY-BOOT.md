# Protected owner-memory boot supply

SOURCE-ONLY child of `251fdb5776daa90aab37251e56b73758a633d67c`. H now supplies
the existing `primeNextHostServices` in pinned DSH's boot preparation callback
when an explicit protected configuration is selected. Without that option the
preview remains unconfigured. No C/D/Bridge constructor, publisher, database,
worker, identity, witness, enrollment or protected input is created by app boot.

After separately reviewing and building this source and protecting the actual
release and existing operator inputs, the command is:

```sh
./prime boot --deployment-manifest /absolute/protected/preview-deployment.json \
  --owner-memory-config /absolute/protected/owner-memory.json
```

The second file is strict UTF-8 JSON, at most 8192 bytes, with exactly:

```text
version: 1
kind: "prime-owner-memory-host/v1"
app_deployment: {source_commit: full40hex, release_digest: "sha256:" + full64hex}
worker_deployment: {source_commit: full40hex, release_digest: "sha256:" + full64hex}
channel: {
  socketPath: absolute canonical Unix socket path,
  credential: {id: existing audience-specific credential ID, secret: existing lowerhex secret},
  socketAccess: {server_uid: existing worker UID, client_uid: actual app UID, group_gid: existing IPC GID},
  limits?: existing IPC client limits
}
browserBinding: {
  ownerBinding: {owner_id, passkeyProfile: {profile, origin, rp_id}},
  context: {owner_id, task_id, conversation_id}
}
```

This is grammar, not a usable configuration or permission to generate secrets.
The app pin must match the independently verified deployment manifest and full
release digest. The worker pin binds the existing authenticated worker response
and may identify a separate worker artifact. Parent and child each require a
canonical regular, single-link, root-owned `0440` configuration outside the
release, with its GID equal to the actual nonroot app's primary GID. Its direct
parent must be root-owned `0750` with that GID; all ancestors must be root-owned,
canonical directories with no group/other write. File and ancestor identities
are checked across the bounded read; the child also checks the parent's content
hash. Only path and hash cross spawn; contents are not printed or saved in app
state. The operator must independently verify that this dedicated group contains
only its intended app principal and that actual IPC directory/socket custody
and supplementary group membership match the existing client profile.

The browser owner must equal the context owner. A configured HTTPS profile uses
its exact origin and domain RP ID. The separately chosen `localhost-pilot-v1`
profile is only `http://localhost:18731` / `localhost`; IP aliases and other ports
refuse. This selects existing source guards, not browser support, enrollment or
owner authentication. Credentials retain their actual server-assigned IPC role.

The existing connection gate, exact origin guard, sixteen public bridge methods,
session/proof review, literal memory draft and unknown/replay handling remain
unchanged. The app supplies no private authority method or restore route.
Capability reporting keeps its existing seven-field preview JSON. Presence of
configuration or a service does not enable controls. H's read uses the actual
MAC-authenticated IPC client, requires the server's `owner_control` role, and
requires the still-current worker to report `available: true`,
`public_routes: "available"`, `public_dispatch: "qualified-owner-memory/v1"`
with the exact configured worker source/release pins. Only then can
`owner-passkey` and `durable-memory` leave the unavailable list. Other capability
IDs and the overall preview `PENDING` status remain. Every actual operation
still checks the worker's public gate independently; no capability read approves
or consumes an operation. Withdrawal fences new work and stale availability;
already submitted effects are neither cancelled nor retried by app disposal.

**Remaining Bridge block at this baseline:** the selected retained Bridge's
public acceptance function deliberately returns null for the retained profile;
its capability reply has no qualified public-dispatch marker. H therefore still
refuses even after valid boot input. Bridge must provide its genuinely qualified
retained public composition/capability backed by actual owner enrollment,
retained publisher/witness custody, PG and protected source/release evidence.
The existing internal `handleTrusted` listener cannot satisfy this gate. H does
not add an acceptance Boolean or manufacture the missing reply field. The
separate authenticated internal restore forwarding packet is still pending.

Operator prerequisites remain the actual protected C state/witness and enrolled
public verifier, immutable Task/source bindings, actual D PG/retained stores and
four-method authenticated publisher transport, and existing separated worker
IPC. No discovery or new OS/security/configuration action is included. The
historical synthetic-P256 PG experiment does not qualify this source or supply
these inputs. No activation, real owner save or runtime result is claimed here.
