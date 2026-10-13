# Buzz relay on the node (North Star step 2)

Puts a Buzz relay (block/buzz, Apache-2.0, built from the private fork `aumara-xyz/aukora-buzz`) beside the
harness on a Linux node: its own user `aukora-buzz`, its own Postgres and Redis, one rootless Podman pod, one port
on `127.0.0.1`. It changes nothing belonging to the harness, the gate or their users. No Buzz source is copied into
this repository; the fork is pinned by commit in `PIN`.

Status is in [plan/NORTH-STAR.md](../../plan/NORTH-STAR.md), not here.

```
# from the Mac, with the fork checked out at the commit in PIN and SSH to the node as an admin:
scp ops/buzz-relay/* NODE:/tmp/aukora-buzz-install/      then on the node:  bash install.sh [--owner-pubkey HEX]
git -C ~/aukora-buzz archive --format=tar "$(cat ops/buzz-relay/PIN)" | ssh NODE 'sudo -u aukora-buzz sh -c "mkdir -p ~/src/SHA && tar -x -C ~/src/SHA"'
ssh NODE 'sudo -u aukora-buzz /usr/local/lib/aukora-buzz/build.sh SHA'     # about 20 to 40 minutes, niced
ssh NODE 'sudo systemctl enable --now aukora-buzz && bash /usr/local/lib/aukora-buzz/check.sh'
ssh -N -L 127.0.0.1:3000:127.0.0.1:3000 NODE                                 # then Buzz's app on the Mac sees it as its local relay
```

To close an existing relay, run from a **full Prime checkout** on the node with Node 24.11.1 available
(the ops-only copy above cannot load the door/member JavaScript imports):

```
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
bash ops/buzz-relay/close.sh --owner-pubkey "$OWNER_PUBKEY" --key-file /absolute/path/to/door.key
```

This preserves other relay settings and database rows, saves 0600 environment/logical-dump backups beneath the
service account's directory, restarts through the unit, and requires both HTTP membership refusals. Re-run the
same command after interruption; a pending completed backup is reused even if Postgres was stopped. Failures
restore the environment and restart; they do not revert membership rows bootstrapped by startup or restore the
dump. Keep the door disabled on failure. The output gives the owner's own-machine commands; only the agent's
public-key handoff file travels to that machine, never the owner's private key to the node.

Install from a full checkout to bundle the verifier and its existing imports for installed `check.sh`.
A successful verified close writes `INTENDED_MEMBERSHIP=closed` in `/var/lib/aukora-buzz/node.env` and a
root-owned `closed` marker beside `relay.env`; a rollback writes `close-failed`. New installs declare
`closed` by default. Reinstall preserves an existing declaration and leaves older installations without one
undeclared: their checks fail until the operator closes the relay with the command above, or explicitly runs
`bash ops/buzz-relay/close.sh --acknowledge-open` from a full checkout. That command writes
`INTENDED_MEMBERSHIP=open-acknowledged` without changing the relay or clearing closure alarms. It acknowledges
open access; it does not close the relay. `close.sh --reopen` explicitly reopens the relay, records
`open-acknowledged` and removes only `closed`.

Full, health and watch checks always report membership **CLOSED**, **OPEN** or **UNKNOWN**. Both `/query` and
`/events` are probed without authentication and with a valid throwaway non-member key, concurrently with
five-second timeouts. CLOSED requires all four refusals (authentication refusal is sufficient only for the
unauthenticated requests; non-members must receive the relay's explicit membership refusal). OPEN requires
an accepted query or an acknowledged event with the exact probe id. Malformed responses, unrelated refusals
and transport failures leave the state UNKNOWN unless another probe proves OPEN. An open relay may store the
synthetic kind-1 probe note on each check.

The check fails for UNKNOWN, an undeclared or invalid intended state, or a mismatch: `closed` requires CLOSED;
`open-acknowledged` requires OPEN. The existing five-minute watch timer reports that nonzero exit as a failed
`aukora-buzz-watch.service`; membership alarms do not restart or reopen the relay. Health failures retain the
watch's existing restart behavior. Checks also fail while `close-failed` exists, or if the `closed` marker
exists and closure cannot be proved. A successful close clears `close-failed`; `close.sh --acknowledge`
clears only that alarm. These files record operator intent; the service-owned parent directory does not
protect them from deletion by the service account. An ops-only installation without the verifier reports
UNKNOWN. These HTTP probes do not prove WebSocket admission, owner custody or harness wake containment.

A changed port needs the pod made again (data is kept): `sudo systemctl stop aukora-buzz`, then as aukora-buzz
`podman pod rm -f aukora-buzz`, then install and start.

Reinstall preserves the original `postgres.env`, `redis.env`, `relay-secrets.env` and database directories.
It derives private files in `secrets/` for the database containers: Postgres uses `POSTGRES_PASSWORD_FILE`,
and Redis reads a mounted config. Both mounts are read-only. Run the installer before restarting with these
scripts; it does not restart a running service. The installer checks the port on every run, including when the
user already exists. An occupied port is accepted only with the expected loopback pod mapping, the service uid,
and a listener exit pipe linked to the pod's infra conmon. Unrelated listeners, unavailable process metadata,
or another networking backend whose ownership cannot be established are refused; stop the listener first.
The health check also accepts the old Redis container until an explicit service restart replaces it; old
containers keep their original environment exposure until that restart.

Remove: `sudo systemctl disable --now aukora-buzz`, then `sudo loginctl disable-linger aukora-buzz` and
`sudo userdel -r aukora-buzz` (this deletes the relay's data), and delete the unit file and `/usr/local/lib/aukora-buzz`.

Say plainly: loopback only means anyone with a login on the node can reach the relay's port; without
`--owner-pubkey` the relay is open to all of them. Media uploads need an S3 store, which is not installed. Buzz is
Block's; this runs a fork and has not been sent to them. “Never printed” does not mean “never exposed to the
service account”: `aukora-buzz` can read its credential files. Database passwords are no longer supplied in
Podman's configured environment or command arguments; Postgres's image entrypoint can still export its file
password into the process environment internally. The relay remains on `--env-file`, so its credentials are
readable through `podman inspect` and permitted process-environment access by that account. At `PIN`
(`9def3e963d16fb6901f7b8461c39654b3682c5a1`), `crates/buzz-relay/src/config.rs` reads `DATABASE_URL`, `REDIS_URL`,
`BUZZ_RELAY_PRIVATE_KEY` and `BUZZ_GIT_HOOK_HMAC_SECRET` directly with `std::env::var` (lines 619, 668, 899,
1058); the pinned fork has no file-based alternative for these settings. This reduces incidental exposure;
it does not isolate credentials from the service account.

`admit.mjs --help` describes issue, redeem, admit and resume with isolated key files. The admissions store holds, unencrypted, every member's public key and who invited whom (the whole invite graph); a spend committed before expiry is still delivered after expiry.
It also holds event ids, signed ancestry and times; no secret keys are stored. Spending and pending delivery commit together. Resume with the same owner, relay and store: append the
missing admission bytes, then retry the member add, even if the spent invite has since expired. Completed invites
refuse replay. A lost relay acknowledgement can repeat the add request; recovery requires idempotent relay membership
adds, not exactly-once HTTP. Keep this private local store intact; never reset it or restore an older copy.

On a CLOSED relay owned by the signing key, this keeps out keys nobody vouched for; it does not prove a unique human.
Invites are bearer codes: another valid key can redeem first. The append-only file contains compact admissions;
the database retains signed chains for recovery. Local tests use a bridge stand-in; they do not establish live relay
closure, idempotence, owner custody, store rollback resistance or enforcement in the installed application.

## Invite admission HTTP service

`admission-server.mjs` wraps that engine for [node-spawn](../node-spawn/README.md). `POST /preflight` receives
`{root, invite, chain}` and verifies availability without spending. `POST /redeem` adds the signed `redemption`;
it returns `{admitted:true, record}` only after durable spending and the relay owner's signed kind-9030 member add.
The record carries the owner's signed kind-39704 confirmation of the network root, last redemption id, and
SHA-256 of the canonical chain; node-spawn requires that signature before recording admission. The confirmation
is preserved in the admission database. The same signed redemption returns the same committed record on retry; a different redemption of a spent invite
is refused. Refusals return non-200 `{code}` without request bytes. Both routes require `application/json`, reject
unknown fields and bounded/slow bodies, and return `cache-control: no-store`. Fixed-window limits apply to the
socket's remote address and globally. Logs contain the invite id and outcome; the service stores no private key
in its admission graph. The service user can read its own key file.
Defaults are 256 KiB per body, five seconds per request, and 30 requests per address / 300 globally per minute.

Nothing in this section has been installed or run against a real closed relay. The repository's admission tests
use throwaway keys and a fake relay bridge. They do not prove real relay closure or membership idempotence, owner
custody, unique people, host containment, public TLS, or resistance to an operator restoring an older store.

On Linux, use a full Prime checkout and Node **24.11.1**. The owner must first choose the relay owner key and close
the relay with that public key using the procedure above. The admission service needs that same owner key in a
file private to its own user; this is a separate custody decision from closing the relay, whose operator flow
keeps the owner's private key on the owner's machine. Do not transfer a production key without that decision.

```
export PATH=$HOME/.local/node-v24.11.1/bin:$PATH
bash ops/buzz-relay/install.sh --with-admission
# Owner-authorized provisioning: install the existing owner key, without printing its bytes.
sudo install -o aukora-admission -g aukora-admission -m 0600 /absolute/private/owner.key /var/lib/aukora-admission/owner.key
sudo systemctl enable --now aukora-admission.service
bash /usr/local/lib/aukora-buzz/check.sh --admission
```

The opt-in installer creates `aukora-admission`, its 0700 state directory, copies the module import closure and
Node executable into root-owned `/usr/local/lib/aukora-buzz`, and installs the
[`units/aukora-admission.service`](units/aukora-admission.service) template. It never creates or copies an owner
key, enables the unit, or starts/restarts a service. Without `--with-admission`, admission installation is skipped.
The unit sets HOME to `/var/lib/aukora-admission`, a 0077 umask, a writable state path, no capabilities, and loopback
network restrictions; the key is loaded with the engine's isolated-file loader. Preserve the store across restarts;
the pending outbox is recovered using the same owner and relay. A lost acknowledgement may resend a member add.

The default listener is `127.0.0.1:3100`. TLS termination belongs to the operator's reverse proxy, which should
forward only `/preflight` and `/redeem` to that loopback address without logging bodies. The service neither serves
TLS. Forwarding headers are ignored by default: callers behind one proxy share its address limit. An operator
may opt in with `--behind-tls-proxy --trusted-address-header x-forwarded-for` only when a trusted proxy strips
all client copies and sets one valid IP address, and callers cannot bypass that proxy. Lists, repeated headers,
and invalid addresses are refused. An address-limited request does not consume the global allowance.
For a direct non-loopback bind, the CLI requires both `--host ADDRESS` and `--behind-tls-proxy`; the flag records
operator intent and does not prove TLS. Such a deployment also needs an explicitly reviewed unit override for its
loopback IP restrictions. Node-spawn must use the operator's HTTPS endpoint (or its existing explicit loopback
transport option for local tests). The owner decides key custody, closure, proxy configuration and activation.
