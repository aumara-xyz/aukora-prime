# C1 HTTPS ingress

This is source and an operator procedure, not a deployed C1. It keeps the
harness and owner page on container loopback, exposes two named HTTPS hosts
through Caddy, and exchanges a short-lived one-time claim for the harness's
authority-bound cookie. The reusable harness launch token stays in its private
loopback descriptor.

Use Node `v24.11.1` for the repository build. Caddy and LXD run on the existing
Ubuntu host; the claim broker runs as root inside the unprivileged C1 container.

## Operator inputs

Choose values in the operator shell; do not put them in this repository:

```sh
export APP_HOST='app.example.invalid'
export OWNER_HOST='owner.example.invalid'
export PUBLIC_IP='203.0.113.10'
export HOST_HARNESS_PORT='28735'
export HOST_OWNER_PORT='28736'
```

Replace the example values. The two hostnames must be different lowercase DNS
names. Create public `A` records for both names pointing to `PUBLIC_IP`; create
`AAAA` records only when the host's IPv6 route and firewall are ready. Allow
inbound TCP 80 and 443. Do not allow the two high ports or the container's
addresses from the internet.

## C1 preparation

Run these inside C1 from the clean reviewed clone after the pinned harness has
been rebuilt with this repository's patch set:

```sh
sudo install -d -o root -g root -m 0700 /etc/aukora /var/lib/aukora-claim
printf 'https://%s\n' "$APP_HOST" | sudo tee /etc/aukora/public-origin >/dev/null
printf 'https://%s\n' "$OWNER_HOST" | sudo tee /etc/aukora/owner-origin >/dev/null
sudo chown root:root /etc/aukora/public-origin /etc/aukora/owner-origin
sudo chmod 0644 /etc/aukora/public-origin /etc/aukora/owner-origin
sudo install -o root -g root -m 0755 ops/node-spawn/ingress/claim.py /usr/local/lib/aukora-claim.py
```

Add this exact argument to the existing foreground `launch-dsh.py` invocation,
without changing its release, approval, state, patch, user, or loopback flags:

```text
--public-origin-file /etc/aukora/public-origin
```

The public values are world-readable so the unprivileged harness service can
read them, but remain root-owned and non-writable. The launcher refuses a
non-root-controlled file and any value other than one
canonical `https://hostname`. It passes only the hostname as `--trusted-host`.
Restarting the harness changes its private launch token; the claim broker reads
the current descriptor for each exchange.

The gate owner page must listen only at `127.0.0.1:17792`. Install this unit
inside C1 after checking the source and paths against the installed release:

```ini
[Unit]
Description=AUKORA one-time browser claim broker
After=aukora-genesis.service aukora-boundary-gate.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 -I -S /usr/local/lib/aukora-claim.py serve --public-origin-file /etc/aukora/public-origin --owner-origin-file /etc/aukora/owner-origin --state-file /var/lib/aukora-claim/claims.json --launch-url-file /home/aukora-host/genesis/state/launch-url.json --harness-port 18735 --owner-page-port 17792 --listen-port 18736
Restart=on-failure
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/aukora-claim
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
StandardOutput=null

[Install]
WantedBy=multi-user.target
```

Save it as `/etc/systemd/system/aukora-claim.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now aukora-claim.service
sudo ss -ltnp | grep -E '127\.0\.0\.1:(17792|18735|18736)\b'
```

Only these three container-loopback listeners are expected. The broker handles
the claim path for the application host and forwards the separate owner host to
the owner page. It does not turn that legacy page into WebAuthn approval.

## Host proxy and Caddy

On the LXD host, map exactly two host-loopback ports to C1:

```sh
sudo lxc config device add C1 aukora-app proxy "listen=tcp:127.0.0.1:${HOST_HARNESS_PORT}" connect=tcp:127.0.0.1:18735
sudo lxc config device add C1 aukora-owner proxy "listen=tcp:127.0.0.1:${HOST_OWNER_PORT}" connect=tcp:127.0.0.1:18736
sudo ss -ltnp | grep -E "127\\.0\\.0\\.1:(${HOST_HARNESS_PORT}|${HOST_OWNER_PORT})\\b"
```

Render and validate the Caddy configuration on the host:

```sh
python3 ops/node-spawn/ingress/render.py \
  --app-host "$APP_HOST" --owner-host "$OWNER_HOST" \
  --harness-port "$HOST_HARNESS_PORT" --owner-port "$HOST_OWNER_PORT" \
  --output /tmp/Caddyfile.c1
sudo caddy validate --config /tmp/Caddyfile.c1 --adapter caddyfile
sudo install -o root -g root -m 0644 /tmp/Caddyfile.c1 /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

The named HTTPS sites use Caddy's automatic certificates. The template has no
access-log directive, bounds request bodies, preserves Host, Origin, Cookie and
Fetch Metadata, supports WebSocket upgrades and unbuffered SSE, replaces all
client-supplied forwarding headers, refuses any public `token` query, and aborts
unmatched hosts. The owner host adds `frame-ancestors 'none'` and
`X-Frame-Options: DENY`.

## Mint and use one claim

Run inside C1 as root immediately before Peter opens the node:

```sh
sudo /usr/bin/python3 -I -S /usr/local/lib/aukora-claim.py mint \
  --public-origin-file /etc/aukora/public-origin \
  --state-file /var/lib/aukora-claim/claims.json --ttl-seconds 300
```

Give the printed link directly to Peter. Do not pipe it to a log or put it in a
ticket. Its code is in the URL fragment, so browsers do not send it in the URL;
the page removes the fragment and posts a bounded same-origin body. The store
contains only its SHA-256 digest. A valid attempt is durably marked spent before
the private harness exchange, so a failed exchange does not revive it. Mint a
new link if that happens.

## Outside checks

From a machine outside the host, run:

```sh
curl -fsS -o /dev/null -D - "https://${APP_HOST}/__aukora/claim"
curl -fsS -o /dev/null -D - "https://${OWNER_HOST}/" | grep -Ei 'strict-transport-security|x-frame-options|content-security-policy'
curl -sS -o /dev/null -w '%{http_code}\n' -H "Origin: https://wrong.invalid" "https://${APP_HOST}/api/remote.mux"
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Sec-Fetch-Site: cross-site' "https://${APP_HOST}/api/remote.mux"
curl --http1.1 -sS -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H "Origin: https://wrong.invalid" "https://${APP_HOST}/api/remote.mux"
curl -kfsS --resolve "wrong.invalid:443:${PUBLIC_IP}" "https://wrong.invalid/" >/dev/null && echo 'FAIL: unexpected host answered' || echo 'PASS: unexpected host closed'
```

The first two commands must show valid public certificates and HSTS; the owner
response must also refuse framing. The three hostile browser-marker probes must
return `403`, never `101`. The unknown host must not answer. From outside, both
high ports and the container addresses must be unreachable. After Peter uses the
claim, browser storage must show a `dsh-auth-*` cookie with `Secure`, `HttpOnly`
and `SameSite=Strict`; repeating the same link must be refused.

## Limits

This does not prove a fresh C1 exists, that Peter opened it, that the binding or
WebAuthn ceremonies work, that the owner understood an approval, or that the
harness RPC surface is safe for the internet. A claim grants only a harness
browser session; it grants no gate authority. It does not protect against host
root, Caddy or DNS compromise, container escape, stolen browser cookies, denial
of service, model cost, or an unreviewed owner-page implementation. The cloud
operator and shared kernel remain inside the threat model. Real C1 certificate,
firewall, raw-port, browser, WebSocket, SSE, restart and cookie observations are
still required.
