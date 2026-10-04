# auma host-local deny (pilot firewall)

The OpenShell sandbox account `auma` (uid 1001) and its rootless-container subuids (165536-231071)
may not connect to services on the host itself: the Genesis runtime (18735), the relay (18733),
the other loopback services and anything listening on a local address.

Only two destinations stay open:

- `127.0.0.1:17690`, auma's own OpenShell gateway. The in-container supervisor connects to it.
- `127.0.0.53` and `127.0.0.54` port 53, the systemd-resolved stub.
- `127.0.0.1` TCP 32768-60999, the kernel's ephemeral range. `openshell ssh-proxy` connects to a
  transient listener it opens there, and every `sbx-exec` call needs it. The fixed services that
  listen inside this range (54783, 54784) are rejected first. Residual: a future service listening on
  an ephemeral loopback port would be reachable; keep services on fixed ports below 32768.

The first version (without the ephemeral range) broke `sbx-exec` and the self-check's egress probe,
which stopped the runtime fail-closed on 2026-10-04 (19:03-19:07 WITA).

The rule matches new connections by socket owner (`meta skuid`) whose destination is a local
address (`fib daddr type local`). Replies on connections that other users open to auma are not
affected. Unix sockets are covered by file permissions, not by this rule.

- `auma-local-deny.nft`: the rule (an idempotent table replacement).
- `aukora-auma-local-deny.service`: loads it at boot, before the network and the runtime.
- `install.sh`: root installs and enables both. It refuses if auma's uid or subuid range differ.

Checked by `./security-review-containment`: the host-as-auma loopback TCP rows must be DENIED.
