# Trusted operator verifier

Both operator entrypoints use only Node builtins until the bootstrap has verified the fixed `/opt/aukora-boundary-gate` installation, its entrypoint and protected ancestors, and the closed `trusted-verifier-pins.json` data. The manifest pins canon, floor, operator-data and the retained renderer by SHA256. Every buffer is checked before any local module executes. Canon, floor and operator-data then execute directly from those checked buffers; no pathname is imported again. The retained renderer is provenance data, with its exact function inlined into canon so the verified module has no relative imports.

Candidate releases are disjoint canonical paths used for JSON reads and hashes. Neither entrypoint imports their modules, invokes their helpers or launches a candidate subprocess. The gate RPC wire, canonical owner text, signed receipt verification and monotonic floor behavior are retained. `--operation` retains its existing interface; this repair does not broaden owner approval or change the review UI.

The operator must install both entrypoints, all four named pin files and the manifest together, as regular single-link files under root-owned directories without group/other write access. Changing a pinned module requires a reviewed operator update and corresponding manifest update. The manifest comes from the trusted installation, never a candidate, CLI argument, environment setting or discovery path. An arbitrary checkout copy of either CLI refuses before local imports; there is no production fixture override. This intentionally requires updating older source tests that expected a developer-checkout CLI to run successfully.

The trusted entrypoint, root operator and Node runtime are the bootstrap trust anchors. An attacker controlling those anchors can replace checks and pins. JavaScript refusal of `NODE_OPTIONS`, `NODE_PATH` or Node flags cannot undo a preload that already ran. The proposed service unit removes preload variables before Node starts; interactive operator invocation must likewise use the reviewed Node binary with a clean environment and no preload flags. Verify actual installed bytes, ownership, launch environment and service behavior separately.

Run the focused source gate:

```sh
node packages/boundary-gate/src/vendor/check-trusted-verifier.mjs --mutations
```

It checks 10 source groups and 11 guard-removal variants. Actual CLI/module buffers run in a Node VM with synthetic root metadata and Unix replies. Candidate files genuinely write separate markers if executed; show, raise and install must leave both absent. Wrong-hash canon/floor/helper buffers must not write their markers. A post-read buffer replacement checks that execution does not reread its pathname. Marker and Ed25519 operations use real disposable filesystem/crypto operations. This is source acceptance, not a root installation, live owner enrollment, Linux enforcement or complete release qualification. Tiny synthetic fixtures are retained.

Existing candidate JSON/path validation limits, preload-safe interactive operation, full repository integration tests and installed-host acceptance remain separate checks. Shared capability/claims rows belong to the integrator. Provenance and license: `trusted-verifier-provenance.json`; first-party code is AGPL-3.0-or-later.
