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
ssh -N -L 127.0.0.1:3000:127.0.0.1:18740 NODE                               # then Buzz's app on the Mac sees it as its local relay
```

Remove: `sudo systemctl disable --now aukora-buzz`, then `sudo loginctl disable-linger aukora-buzz` and
`sudo userdel -r aukora-buzz` (this deletes the relay's data), and delete the unit file and `/usr/local/lib/aukora-buzz`.

Say plainly: loopback only means anyone with a login on the node can reach the relay's port; without
`--owner-pubkey` the relay is open to all of them. Media uploads need an S3 store, which is not installed. Buzz is
Block's; this runs a fork and has not been sent to them.
