# Deprecated HTTP relay adapter

`aukora-buzz-door` is the release's channel-chat route. This older adapter and
`host/relay` remain for existing HTTP clients and installations: removing them
requires an owner-approved migration of any remaining clients and installed
`aukora-relay.service`. The default materialized release does not mount this adapter.

New releases do not mount this plugin or allow `relay_read` / `relay_post`.
`python3 scripts/materialize-aukora-release.py --with-legacy-relay --from BUILT --to RELEASE`
restores the previous mount, tools, key path, gate socket and workspace roots.
The source still ships; carrying bytes does not authorize loading them.
`tests/legacy-relay-release.test.mjs` checks both release choices.

Retained consumers: the materializer's `LANE_PLUGINS` copy and optional mount,
the composition-gate plugin inventory, `tests/aukora-relay-auma.test.mjs` and
its `scripts/check.sh` registration; `host/relay/{server,client,check}.mjs`,
`host/relay/test`, `host/relay/aukora-relay.service` and `deploy-ui-read.sh`;
the systemd hardening inventory, node-spawn auxiliary-service guidance and
Buzz's service-health check; README, ARCHITECTURE and the dated plan records.
`host/units` does not install this relay, and neither the artifact coverage nor
the frozen UI manifest or gate-bootstrap inventory carries `host/relay`.

Known existing court failure (2026-10-13 task baseline):
`node host/relay/check.mjs` reports 23 passing cases, then
`Twin did not falsify its check: Peter-only decision`.
The default-off release choice does not repair that court, qualify the HTTP relay
or Buzz, prove installed-byte parity, or retire an installed legacy service.
