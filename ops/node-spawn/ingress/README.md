# Browser-node HTTPS ingress

This is source and an operator procedure, not a deployed C1. It keeps the
harness and owner page on container loopback, exposes two named HTTPS hosts
through Caddy, and exchanges a short-lived one-time claim for the harness's
authority-bound cookie. The reusable harness launch token stays in its private
loopback descriptor. Returning sign-in uses the enrolled gate passkey and the
same spent-once claim store; a cookie permits app access and grants no approval.

On a host with multiple nodes, every app and owner hostname and every one of the
three loopback ports must be globally unique. A hostname's generated site blocks
contain only that node's ports; no rule may let one node's hostname reach a
sibling node's harness, owner page or claim broker. App cookies use the
`__Host-` prefix, `Path=/`, `Secure`, and no `Domain`, so they are host-only and
are not sent to sibling servers. Same-site requests from a sibling to the app
can still attach the app cookie. One closed catch-all follows all named sites.

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
export HOST_CLAIM_PORT='28737'
```

Replace the example values. The two hostnames must be different lowercase DNS
names. Create public `A` records for both names pointing to `PUBLIC_IP`; create
`AAAA` records only when the host's IPv6 route and firewall are ready. Allow
inbound TCP 80 and 443. Do not allow the three high ports or the container's
addresses from the internet.

## C1 preparation

Prepare the offline inputs and standalone LXD image described in the
[browser installer runbook](../browser/README.md). On the local LXD host, create
the fresh node with all three distinct host-loopback ports and both hostnames:

```sh
bash ops/node-spawn/browser/create.sh --name C1 --image "$IMAGE_FINGERPRINT" \
  --inputs "$INPUTS" --checkout-sha256 "$CHECKOUT_SHA256" --revision "$REVISION" \
  --node-sha256 "$NODE_SHA256" --dependencies-sha256 "$DEPENDENCIES_SHA256" \
  --app-host "$APP_HOST" --owner-host "$OWNER_HOST" \
  --app-port "$HOST_HARNESS_PORT" --owner-port "$HOST_OWNER_PORT" \
  --claim-port "$HOST_CLAIM_PORT"
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase before
```

The installer writes root-owned, non-writable
`/etc/aukora/public-origin` and `/etc/aukora/owner-public-origin`, enables the
root-owned `aukora-browser-claim.service`, and adds
`--public-origin-file /etc/aukora/public-origin` to `aukora-browser.service`.
The harness receives only the validated hostname as `--trusted-host`. The
reviewed browser release sets `cookieMaxAgeDays: 1`; the broker refuses a cookie
whose signed lifetime or emitted `Max-Age` exceeds one day. It reads the current
private launch descriptor on every exchange.

The broker listens on container `127.0.0.1:18736`; the gate uses `17792` and the
harness uses `18735`. The broker handles app claim, sign-in and sign-out paths.
It admits at most 32 simultaneous connections and applies absolute five-second
header and ten-second body read deadlines, with one request per connection.
It does not forward harness WebSocket upgrades or SSE: normal app traffic must
reach the harness directly. Returning sign-in requires the gate's protected
`--passkey-setup` and `--browser-join` configuration; the installer's initial
legacy bearer page supplies no passkey login and is not owner enrollment.

## Host proxy and Caddy

Creation already maps three host-loopback ports with LXD non-NAT proxies. Do
not add duplicate devices. Inspect the actual standalone host's listeners and
expanded configuration (LXD 5.21 does not support `config show --format`):

```sh
lxc --force-local config show C1 --expanded
sudo ss -ltnp | grep -E "127\\.0\\.0\\.1:(${HOST_HARNESS_PORT}|${HOST_OWNER_PORT}|${HOST_CLAIM_PORT})\\b"
```

`browser-app` connects to container `127.0.0.1:18735`, `browser-owner` to
`127.0.0.1:17792`, and `browser-claim` to `127.0.0.1:18736`. All use
`bind=host nat=false` and listen only on host `127.0.0.1`; the container has no
NIC. Render and validate the Caddy configuration on the host:

```sh
python3 ops/node-spawn/ingress/render.py \
  --app-host "$APP_HOST" --owner-host "$OWNER_HOST" \
  --harness-port "$HOST_HARNESS_PORT" --owner-port "$HOST_OWNER_PORT" \
  --claim-port "$HOST_CLAIM_PORT" \
  --output /tmp/Caddyfile.c1
sudo caddy validate --config /tmp/Caddyfile.c1 --adapter caddyfile
sudo install -o root -g root -m 0644 /tmp/Caddyfile.c1 /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

For one node, those existing flags retain the same rendered behavior. For more
than one node, keep the complete non-secret inventory in a root-owned regular
file with no group/other write bits. The JSON is a non-empty array; every object
has exactly `name`, `app_host`, `owner_host`, `harness_port`, `owner_port`, and
`claim_port`. Names use the same syntax as `create.sh` and are unique. Hostnames
and ports are unique across the whole array. For example, stage the reviewed
values and install them without exposing any private claim or launch token:

```json
[
  {"name":"C1","app_host":"app-one.example.invalid","owner_host":"owner-one.example.invalid","harness_port":28735,"owner_port":28736,"claim_port":28737},
  {"name":"C2","app_host":"app-two.example.invalid","owner_host":"owner-two.example.invalid","harness_port":29735,"owner_port":29736,"claim_port":29737}
]
```

```sh
sudo install -o root -g root -m 0644 "$REVIEWED_NODES_JSON" /etc/caddy/aukora-nodes.json
sudo python3 ops/node-spawn/ingress/render.py --nodes /etc/caddy/aukora-nodes.json \
  --output /etc/caddy/Caddyfile.aukora-candidate
sudo python3 ops/node-spawn/ingress/render.py --check /etc/caddy/Caddyfile.aukora-candidate \
  --nodes /etc/caddy/aukora-nodes.json
sudo caddy validate --config /etc/caddy/Caddyfile.aukora-candidate --adapter caddyfile
sudo install -o root -g root -m 0644 /etc/caddy/Caddyfile.aukora-candidate /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo python3 ops/node-spawn/ingress/render.py --check /etc/caddy/Caddyfile \
  --nodes /etc/caddy/aukora-nodes.json
```

### Add a second node

1. Choose C2's two new DNS hostnames and three unused loopback ports. Add both
   DNS records, but do not expose the high ports.
2. Run `browser/create.sh` with `--name C2`, C2's `--app-host` and
   `--owner-host`, and its own `--app-port`, `--owner-port`, and `--claim-port`;
   then run `browser/acceptance.sh --name C2 --phase before`.
3. Add C2's six fields to the reviewed JSON array, install that file root-owned,
   and run the render, `render.py --check`, `caddy validate`, install, reload,
   and live-file `render.py --check` commands above in that order.
4. Complete C2's separate owner approval, start, after-approval acceptance and
   outside checks. C1's claims, cookies and owner approval do not apply to C2.

### Remove one node

1. Remove only that node's object from the reviewed JSON; at least one node must
   remain. Install the revised root-owned file, render a fresh candidate, run
   `render.py --check` and `caddy validate`, install it, reload Caddy, and check
   the live file exactly as above. Confirm the removed hostnames no longer answer
   before reusing any port.
2. Deactivate or destroy only that node using the browser runbook. Remove its DNS
   records and retained data according to owner policy. Do not delete another
   node's container, profile, ports, origins or state.

HSTS defaults to `max-age=31536000` on each HTTPS hostname. Render with
`--hsts-include-subdomains` only when all descendants of both configured hosts
are dedicated to HTTPS; leave it off for shared zones. It covers descendants
of the host sending the header, not its parent or siblings. This renderer
does not serve or pin the registrable parent domain.

The named HTTPS sites use Caddy's automatic certificates. The template has no
access-log directive, bounds request bodies, preserves Host, Origin, Cookie and
Fetch Metadata, supports WebSocket upgrades and unbuffered SSE, replaces all
client-supplied forwarding headers, refuses app `token` queries on HTTPS and
both hosts' `token` queries on HTTP, and aborts
unmatched hosts. The owner host adds `X-Frame-Options: DENY`; the gate's policy
supplies `frame-ancestors 'none'`. The proxy preserves the gate's Content-Security-Policy
so its hash-pinned passkey script can run; it supplies no replacement policy.
Other HTTP requests redirect only their path to the fixed HTTPS host, dropping
every query string because unknown query names may also contain secrets.
A token in an initial HTTP request has already crossed the network in cleartext;
the 404 prevents forwarding it onward. Use only HTTPS links.

## Mint and use one claim

After Peter approves the initial card through the separate owner page, start
and check the node, then mint one link as root inside C1:

The mint command's stdout is the secret. Disable shell transcripts and do not
capture, log or share its output beyond giving the link directly to the owner.

```sh
lxc --force-local exec C1 -- bash /opt/aukora-genesis/src/ops/node-spawn/browser/start.sh
bash ops/node-spawn/browser/acceptance.sh --name C1 --phase after
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B \
  /opt/aukora-genesis/src/ops/node-spawn/browser/node.py claim
```

`claim` prints only the link. The after-approval acceptance checks the claim
service is active, protected origin-file custody, anonymous public-authority
`401`, one claim's exchange for a bounded public-authority cookie, cookie access
to the harness, and refusal on its second use. These requests stay on container
loopback with the configured public Host and Origin; they do not qualify TLS,
Caddy, actual browser storage, WebSocket or SSE. Acceptance spends its own test
claim and never prints it or its cookie.

To expire the prior private owner bearer, request a gate restart through:

```sh
lxc --force-local exec C1 -- /usr/bin/python3 -I -S -B \
  /opt/aukora-genesis/src/ops/node-spawn/browser/node.py rotate-owner-link
```

The harness requires the gate; inspect installed status after rotation or passkey
activation and run `start.sh` if it became inactive, then repeat acceptance.
Activate returning sign-in from the actual protected setup and browser binding
configuration using the [browser runbook](../browser/README.md)'s
`node.py enable-owner-signin` command. It selects passkey/browser-join mode;
Peter still creates his credential and signs his final binding himself.

Give the printed claim link directly to Peter. Do not pipe it to a log or put it in a
ticket. Its code is in the URL fragment, so browsers do not send it in the URL;
the page removes the fragment and posts a bounded same-origin body. The store
contains only its SHA-256 digest. A valid attempt is durably marked spent before
the private harness exchange. If the harness returns its exact launch-token
refusal, the broker reads the descriptor once more and retries only if its
token changed. It never un-spends the claim. Mint a new link if that bounded
retry fails, or if the descriptor or exchange is unavailable.

## Returning sign-in and sign-out

After protected passkey enrollment, open `https://${APP_HOST}/__aukora/signin`.
The app page directs the browser to the configured owner hostname's
`/owner/signin`. The gate issues the node/origin/nonce-bound challenge and uses
its existing passkey verifier. It returns one short-lived code in the app URL
fragment. The app removes that fragment and submits it in a bounded same-origin
body; the broker redeems it at the gate's loopback `/owner/signin/redeem` route,
pins the app audience and expiry, stores that same code's digest in `ClaimStore`,
then spends it before exchanging the private launch token for the app cookie.
Gate and broker restart do not restore a spent code. No enrolled passkey means
this path refuses; root-minted operator claims remain the bootstrap path.

Sign out with a same-origin empty `POST /__aukora/signout` from the app. This
clears the exact `__Host-dsh-auth-` cookie derived from the configured public app authority,
with matching Path, Secure, HttpOnly and SameSite attributes. It does not revoke
a stolen copy or close an already open WebSocket. A browser tab should close
its active app connections when signing out.

## Session revocation limit

The pinned harness has no per-session registry or revoke API. It caches the
signing secret at activation and stores it in `DSH_HOME/.credentials.yaml`,
`records['client-connection/browser-session']`, a version-1 grant. Restart alone
retains that secret and does not revoke cookies. `revoke-sessions.mjs` inspects
the installed `aukora-browser.service` and legacy `aukora-genesis.service`,
requires exactly one active, loaded harness with the expected launcher and
state root, and refuses ambiguous or unverifiable state. It stops that unit,
requires it to be inactive, rotates only that grant's
secret with an atomic private write, then starts the service and requires it
to be active. Stopping also drops active connections. If rotation or restart
fails, repair the named refusal before reopening the app; the command never
prints the signing secret or other credentials.

On the browser node, run as root with the reviewed built harness directory:

```sh
/opt/aukora-node/bin/node /opt/aukora-genesis/src/ops/node-spawn/ingress/revoke-sessions.mjs \
  --harness-root "$REVIEWED_HARNESS_ROOT"
```

The helper requires a complete reviewed build root and reuses its
existing `yaml` dependency from `packages/credentials/credentials-local`.
It checks the resolved YAML package's complete directory and file tree for
root ownership, write protection and absence of links before loading code.
No YAML library is added here. The command refuses a symlink, hardlink,
non-private credentials file, writable ancestry, unsupported record or failed
stop/restart. It requires the installed unit's `ExecStart` to use the source
launcher and exact `/home/aukora-host/genesis/state` state root; that launcher
sets `DSH_HOME` to its `home` child. It rotates exactly
`/home/aukora-host/genesis/state/home/.credentials.yaml`, with no caller-selected
credential file. Root must confirm the installed release uses the default
credentials provider path before qualification; a custom provider/path needs a
reviewed adaptation. It preserves unrelated credentials and file ownership. The fresh
activation loads the new key, so every earlier cookie fails its HMAC check.
Observe old-cookie refusal and a new sign-in on the installed node after this
command; service-active status alone does not establish browser behavior.

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
return `403`, never `101`. The unknown host must not answer. From outside, all
three high ports and the container addresses must be unreachable. After Peter uses the
claim, browser storage must show a `__Host-dsh-auth-*` cookie with `Secure`, `HttpOnly`
and `SameSite=Strict`; repeating the same link must be refused.

## What this does not protect against

Sign-out is local to that browser: it clears its cookie, leaves a copied cookie
usable until its absolute expiry (at most one day), and does not close upgraded
sockets. The pinned harness has no per-session revocation. The fixed revocation
command above stops the serving unit and rotates its signing secret before
restart, invalidating every previous cookie and dropping active connections.
An ordinary restart alone retains the key and does not revoke cookies.

Use a dedicated registrable parent domain, with no untrusted sibling hosts or
model-authored active content. `SameSite=Strict` treats app and owner siblings
under one registrable domain as the same site. The pinned harness rejects a
foreign Origin but permits its absence after checking Host, so a same-site GET
can carry the app cookie. No state-changing GET was traced in this review;
that does not establish safety of the whole GET surface. `__Host-` keeps the
cookie off sibling servers and prevents parent-domain cookie shadowing; it
does not stop sibling-initiated requests to the app. HSTS on the app does not
pin the owner or another sibling. Expose a test user only on a dedicated parent,
using HTTPS links and with these sign-out and cookie-copy limits understood.

This does not prove a fresh C1 exists, that Peter opened it, that the binding or
WebAuthn ceremonies work, that the owner understood an approval, or that the
harness RPC surface is safe for the internet. A claim grants only a harness
browser session; it grants no gate authority. It does not protect against host
root, Caddy or DNS compromise, container escape, stolen browser cookies, denial
of service, model cost, or an unreviewed owner-page implementation. The cloud
operator and shared kernel remain inside the threat model. Real C1 certificate,
firewall, raw-port, browser, WebSocket, SSE, restart and cookie observations are
still required.

Source checks use a software signer and the pinned harness's BrowserAuth with
synthetic credentials. They prove the tested refusal and key-rotation behavior,
including that the old activation accepts its old cookie until restart. They
do not prove real passkey enrollment, hardware custody, a unique person,
binding ceremony truth, cookie theft resistance, proxy deployment or the
installed service's revocation behavior. Peter must choose passkey custody and
recovery policy and approve the configured release before runtime qualification.
