# Threat model

## What this system is

AUKORA contains a Genesis-derived agent runtime on a Linux pilot and a separate Prime NEXT source layer. The runtime proposes changes; a separate boundary gate permits the named changes through owner review. Tool checks, signed receipts and launch admission have distinct scopes; none establishes whole-product containment ([ARCHITECTURE.md](../ARCHITECTURE.md), [CLAIMS.md](CLAIMS.md)).

## Adversaries considered

- A hostile chat-channel member or compromised relay account supplying forged events, hostile text or repeated mentions ([door source](../plugins/aukora-buzz-door/lib/index.mjs), [aukora-buzz-door.test.mjs](../tests/aukora-buzz-door.test.mjs)).
- Malicious or mistaken model output, including text recalled from memory or fetched from the web, proposing an unauthorized action ([action gate](../plugins/aukora-action-gate/lib/index.mjs), [check.mjs](../plugins/aukora-action-gate/check.mjs), [recall injection](../plugins/aukora-kira/lib/injection.mjs), [kira-injection.test.mjs](../tests/kira-injection.test.mjs)).
- A nonroot process on the node trying to modify protected authority or reach the owner channel ([install trust limits](../packages/boundary-gate/host/install/README.md), [server.mjs](../packages/boundary-gate/src/server.mjs), [gate.mjs check](../packages/boundary-gate/checks/gate.mjs)).

## What is defended

Statuses below are recorded observations in [NORTH-STAR.md](../plan/NORTH-STAR.md) and [ops/pilot/README.md](../ops/pilot/README.md), not fresh runtime verification; the latest record has the live pilot on `c603bbf`, switched on 2026-10-13 with the owner's approval after an earlier switch that day was rolled back.

| Asset or action | Mechanism and scope | Source + test/check | Recorded execution |
| --- | --- | --- | --- |
| Harness tool calls | Action gate before every registry tool call; excludes direct plugin/host effects and actions inside a started process. | [index.mjs](../plugins/aukora-action-gate/lib/index.mjs); [check.mjs](../plugins/aukora-action-gate/check.mjs) | Real node: action gate and file fence RAN on the pilot; complete mediation unqualified. |
| Theme, owner note, plugin-set approval | Boundary gate: separate proposal/owner channels, exact-byte one-use approval, signed hash-chained ledger; plugin-set target is operator-only. | [targets.mjs](../packages/boundary-gate/src/targets.mjs); [boundary.mjs](../packages/boundary-gate/checks/boundary.mjs), [owner-review.mjs](../packages/boundary-gate/checks/owner-review.mjs), [gate.mjs](../packages/boundary-gate/checks/gate.mjs) | Real node: theme approval/receipt RAN October 4; owner note source tests only. |
| Release and admitted plugins | Owner-approved plugin set bound to release/record; monotonic release floor, fresh approval for rollback. | [plugin-set.mjs](../plugins/aukora-composition-gate/src/plugin-set.mjs), [release-floor.mjs](../packages/boundary-gate/src/release-floor.mjs); [aukora-plugin-set-trusted-verifier.test.mjs](../tests/aukora-plugin-set-trusted-verifier.test.mjs) | Real node: signed launch RAN; rewritten switch staging only, not run live. |
| Channel input | Signed-event/channel checks; admitted mentions wake the configured session; JSON-quoted DATA with plugin provenance, including owner chat. Framing is advisory to the model. | [index.mjs](../plugins/aukora-buzz-door/lib/index.mjs); [aukora-buzz-door.test.mjs](../tests/aukora-buzz-door.test.mjs), [installed-accept.mjs](../plugins/aukora-buzz-door/checks/installed-accept.mjs) | Staging only: installed acceptance and session wake RAN with stand-in owner; turn stopped at missing model credentials. |
| Recalled text | Quoted DATA with attribution, without instruction authority or a live-state attestation. | [injection.mjs](../plugins/aukora-kira/lib/injection.mjs); [kira-injection.test.mjs](../tests/kira-injection.test.mjs) | Source tests only for framing; real-node scratch recall probes do not show model use. |
| Door key and configuration | Isolated loading: no symlinks, writable ancestry or hard-linked files; key mode 0600; invalid configuration leaves the door unavailable. The harness account can read its own key/configuration. | [index.mjs](../plugins/aukora-buzz-door/lib/index.mjs); [aukora-buzz-door.test.mjs](../tests/aukora-buzz-door.test.mjs), [installed-accept.mjs](../plugins/aukora-buzz-door/checks/installed-accept.mjs) | Staging only; live door key/configuration absent. |

## Explicitly not defended or claimed

- Root on the node can replace the trust anchors, and the gate user is trusted ([install README](../packages/boundary-gate/host/install/README.md), [gate README](../packages/boundary-gate/README.md)).
- There is no containment on macOS ([HANDOFF](../plan/HANDOFF-2026-10-12.md)).
- A biometric approval proves a key signed exact bytes after a match on one device, not a unique person; legacy gate receipts prove only the gate key signed bound bytes, not a biometric match or owner-key custody ([HANDOFF](../plan/HANDOFF-2026-10-12.md), [NORTH-STAR](../plan/NORTH-STAR.md)).
- A co-presence receipt grants nothing, and one-use enforcement belongs to the counting gate, not an offline proof ([copresence README](../packages/copresence/README.md), [check.mjs](../packages/copresence/check.mjs), [NORTH-STAR](../plan/NORTH-STAR.md)).
- The boundary does not protect what the model sends to its configured provider; disabled uploaders are configuration evidence, not wire measurements ([HARD-QUESTIONS.md](HARD-QUESTIONS.md#21-what-leaves-this-machine)).
- Relay closure and its software are unqualified here: it is recorded open and uses Block's Buzz in a private fork ([NORTH-STAR](../plan/NORTH-STAR.md)).
- The Buzz desktop app's Touch ID path and the pilot gate approval remain two separate paths with two keys ([NORTH-STAR](../plan/NORTH-STAR.md)).
- Recalled memory is not guaranteed true; remembered records are unreviewed and possibly wrong ([Kira README](../plugins/aukora-kira/README.md)).

## Known open issues

- Full Linux containment and inherited guest descriptors remain open; the file fence has four retained failing check/open-race cases ([SECURITY-BOUNDARY.md](../SECURITY-BOUNDARY.md#open-obligations), [NORTH-STAR](../plan/NORTH-STAR.md), [file-fence-race.test.mjs](../plugins/aukora-action-gate/file-fence-race.test.mjs)).
- Owner enrollment/recovery, which key signs on the pilot, closed-relay admission and live Buzz door configuration remain unresolved; wake quotas do not bound model/tool cost, and posting is content-blind ([README known gaps](../README.md#known-gaps), [NORTH-STAR](../plan/NORTH-STAR.md), [door source](../plugins/aukora-buzz-door/lib/index.mjs)).
- Protected NEXT memory/inference/execution joins remain unqualified; NEXT boot requires root-owned manifest ancestry, and the rewritten live switch has run on the pilot once to completion (its first live attempt stopped and restored) ([CLAIMS.md](CLAIMS.md), [NORTH-STAR](../plan/NORTH-STAR.md), [pilot README](../ops/pilot/README.md)).

## Check it yourself

Use Node 24.11.1 and the prerequisites in [README.md](../README.md#from-a-clone-to-a-running-system).

- `./scripts/fresh-clone-check.sh .` builds a committed fresh clone and boots a temporary approved release, checking authenticated screens, unauthenticated refusal and action-gate refusal; the CI job **fresh clone boots** runs it ([script](../scripts/fresh-clone-check.sh), [checks.yml](../.github/workflows/checks.yml), [fresh-clone-check.test.mjs](../tests/fresh-clone-check.test.mjs), [fresh-clone-runtime.test.mjs](../tests/fresh-clone-runtime.test.mjs)). Same-user throwaway authority proves no real owner, containment, persistent installation, model reply, Buzz or memory ([README](../README.md#from-a-clone-to-a-running-system)).
- `./security-review` runs scoped source/fixture checks and the historical signed prefix; read PASS/FAIL/UNPERFORMED counts, not only exit status, and retain exclusions; it runs no live probes, deployment or provider ([runner](../scripts/audit/security-review.mjs), [security-review-runner.test.mjs](../tests/security-review-runner.test.mjs)).
- `./prime verify` runs the configured NEXT source profile; preserve failures and exclusions, which include real owner enrollment, protected service custody, OpenShell and paid inference ([profile README](../packages/ops/fast-verify/README.md)). Source success does not qualify the installed system ([CLAIMS.md](CLAIMS.md)).
