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
A successful verified close writes a root-owned `closed` marker beside `relay.env`; a rollback writes
`close-failed`. Full, health and watch checks fail while `close-failed` exists, or if `closed` exists and
membership refusals cannot be verified. A successful close clears `close-failed`; `close.sh --acknowledge`
clears only that alarm. `close.sh --reopen` explicitly reopens the relay and removes only `closed`.
With neither marker, OPEN remains informational and health/watch skip membership probes, which can store a
synthetic note on an open relay. These markers record operator intent; the service-owned parent directory
does not protect them from deletion by the service account. An ops-only installation without the verifier
cannot report PASS closed.

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
