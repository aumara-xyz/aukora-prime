# Threat model

## What this system is

AUKORA contains a Genesis-derived agent runtime on a Linux pilot and a separate Prime NEXT source layer. The runtime proposes changes; a separate boundary gate permits the named changes through owner review. Tool checks, signed receipts and launch admission have distinct scopes; none establishes whole-product containment ([ARCHITECTURE.md](../ARCHITECTURE.md), [CLAIMS.md](CLAIMS.md)).

## Adversaries considered

- A hostile chat-channel member or compromised relay account supplying forged events, hostile text or repeated mentions ([door source](../plugins/aukora-buzz-door/lib/index.mjs), [aukora-buzz-door.test.mjs](../tests/aukora-buzz-door.test.mjs)).
- Malicious or mistaken model output, including text recalled from memory or fetched from the web, proposing an unauthorized action ([action gate](../plugins/aukora-action-gate/lib/index.mjs), [check.mjs](../plugins/aukora-action-gate/check.mjs), [recall injection](../plugins/aukora-kira/lib/injection.mjs), [kira-injection.test.mjs](../tests/kira-injection.test.mjs)).
- A nonroot process on the node trying to modify protected authority or reach the owner channel ([install trust limits](../packages/boundary-gate/host/install/README.md), [server.mjs](../packages/boundary-gate/src/server.mjs), [gate.mjs check](../packages/boundary-gate/checks/gate.mjs)).

## What is defended

Statuses below come from operator reports in [NORTH-STAR.md](../plan/NORTH-STAR.md) and [ops/pilot/README.md](../ops/pilot/README.md), not fresh runtime verification; the operator reports the live pilot on `c603bbf` after the rewritten switch on 2026-10-13, but no signed export of that switch is retained in this tree.

| Asset or action | Mechanism and scope | Source + test/check | Recorded execution |
| --- | --- | --- | --- |
| Harness tool calls | Action gate before every registry tool call; excludes direct plugin/host effects and actions inside a started process. | [index.mjs](../plugins/aukora-action-gate/lib/index.mjs); [check.mjs](../plugins/aukora-action-gate/check.mjs) | Real node: action gate and file fence RAN on the pilot; complete mediation unqualified. |
| Theme, owner note, plugin-set approval | Boundary gate: separate proposal/owner channels, exact-byte one-use approval, signed hash-chained ledger; plugin-set target is operator-only. | [targets.mjs](../packages/boundary-gate/src/targets.mjs); [boundary.mjs](../packages/boundary-gate/checks/boundary.mjs), [owner-review.mjs](../packages/boundary-gate/checks/owner-review.mjs), [gate.mjs](../packages/boundary-gate/checks/gate.mjs) | Real node: theme approval/receipt RAN October 4; owner note source tests only. |
| Release and admitted plugins | Owner-approved plugin set bound to release/record; an installed production launch rechecks the protected monotonic floor, and the hook refuses a waiver from a root-protected installed release. | [plugin-set.mjs](../plugins/aukora-composition-gate/src/plugin-set.mjs), [release-floor.mjs](../packages/boundary-gate/src/release-floor.mjs); [aukora-plugin-set-trusted-verifier.test.mjs](../tests/aukora-plugin-set-trusted-verifier.test.mjs) | The operator reports that the rewritten switch ran live; no signed export of that switch is retained in this tree. |
| Channel input | Signed-event/channel checks; admitted mentions wake the configured session; JSON-quoted DATA with plugin provenance, including owner chat. Framing is advisory to the model. | [index.mjs](../plugins/aukora-buzz-door/lib/index.mjs); [aukora-buzz-door.test.mjs](../tests/aukora-buzz-door.test.mjs), [installed-accept.mjs](../plugins/aukora-buzz-door/checks/installed-accept.mjs) | Staging only: installed acceptance and session wake RAN with stand-in owner; turn stopped at missing model credentials. |
| Recalled text | Quoted DATA with attribution, without instruction authority or a live-state attestation. | [injection.mjs](../plugins/aukora-kira/lib/injection.mjs); [kira-injection.test.mjs](../tests/kira-injection.test.mjs) | Source tests only for framing; real-node scratch recall probes do not show model use. |
| Door key and configuration | Isolated loading: no symlinks, writable ancestry or hard-linked files; key mode 0600; invalid configuration leaves the door unavailable. The harness account can read its own key/configuration. | [index.mjs](../plugins/aukora-buzz-door/lib/index.mjs); [aukora-buzz-door.test.mjs](../tests/aukora-buzz-door.test.mjs), [installed-accept.mjs](../plugins/aukora-buzz-door/checks/installed-accept.mjs) | The operator reports a live key/configuration and one post before Buzz was parked; no signed export of that live door state is retained in this tree. |

## Explicitly not defended or claimed

- Root on the node can replace the trust anchors, and the gate user is trusted ([install README](../packages/boundary-gate/host/install/README.md), [gate README](../packages/boundary-gate/README.md)).
- There is no containment on macOS ([HANDOFF](../plan/HANDOFF-2026-10-12.md)).
- A biometric approval proves a key signed exact bytes after a match on one device, not a unique person; legacy gate receipts prove only the gate key signed bound bytes, not a biometric match or owner-key custody ([HANDOFF](../plan/HANDOFF-2026-10-12.md), [NORTH-STAR](../plan/NORTH-STAR.md)).
- A co-presence receipt grants nothing, and one-use enforcement belongs to the counting gate, not an offline proof ([copresence README](../packages/copresence/README.md), [check.mjs](../packages/copresence/check.mjs), [NORTH-STAR](../plan/NORTH-STAR.md)).
- The boundary does not protect what the model sends to its configured provider; disabled uploaders are configuration evidence, not wire measurements ([HARD-QUESTIONS.md](HARD-QUESTIONS.md#21-what-leaves-this-machine)).
- Relay closure and its software are unqualified here: it is recorded open and uses Block's Buzz in a private fork ([NORTH-STAR](../plan/NORTH-STAR.md)).
- The Buzz desktop app's Touch ID path and the pilot gate approval remain two separate paths with two keys ([NORTH-STAR](../plan/NORTH-STAR.md)).
- Recalled memory is not guaranteed true; remembered records are unreviewed and possibly wrong ([Kira README](../plugins/aukora-kira/README.md)).

The eye is denied by the action gate before capture, and source courts exercise the desktop's shared private-surface latch across image, accessibility and input awaits, native owner presenters and IPC-origin changes ([action-gate court](../tests/aukora-eye-action-gate.test.mjs), [read-fence court](../tests/desktop-eye-privacy.test.mjs), [native-presenter court](../tests/desktop-owner-privacy.test.mjs), [IPC-origin court](../tests/desktop-ipc-origin.test.mjs)). These courts are registered in `scripts/check.sh`; none runs in `./security-review`. They use synthetic windows, frames and callbacks, so they do not prove that an installed Electron build routes every actual private surface through the latch, that compositor pixels have disappeared when a real window closes, or that a real eye request is refused during such a transition.

## Known open issues

- Full Linux containment and inherited guest descriptors remain open; the file fence has four retained failing check/open-race cases ([SECURITY-BOUNDARY.md](../SECURITY-BOUNDARY.md#open-obligations), [NORTH-STAR](../plan/NORTH-STAR.md), [file-fence-race.test.mjs](../plugins/aukora-action-gate/file-fence-race.test.mjs)).
- Owner enrollment/recovery, which key signs on the pilot, closed-relay admission and live Buzz door configuration remain unresolved; wake quotas do not bound model/tool cost, and posting is content-blind ([README known gaps](../README.md#known-gaps), [NORTH-STAR](../plan/NORTH-STAR.md), [door source](../plugins/aukora-buzz-door/lib/index.mjs)).
- Protected NEXT memory/inference/execution joins remain unqualified; NEXT boot requires root-owned manifest ancestry. The operator reports that the rewritten live switch completed on the pilot after one stopped-and-restored attempt, but no signed export of that switch is retained in this tree ([CLAIMS.md](CLAIMS.md), [NORTH-STAR](../plan/NORTH-STAR.md), [pilot README](../ops/pilot/README.md)).

## Check it yourself

Use Node 24.11.1 and the prerequisites in [README.md](../README.md#from-a-clone-to-a-running-system).

- `./scripts/fresh-clone-check.sh .` builds a committed fresh clone and boots a temporary approved release, checking authenticated screens, unauthenticated refusal and action-gate refusal; the CI job **fresh clone boots** runs it ([script](../scripts/fresh-clone-check.sh), [checks.yml](../.github/workflows/checks.yml), [fresh-clone-check.test.mjs](../tests/fresh-clone-check.test.mjs), [fresh-clone-runtime.test.mjs](../tests/fresh-clone-runtime.test.mjs)). Same-user throwaway authority proves no real owner, containment, persistent installation, model reply, Buzz or memory ([README](../README.md#from-a-clone-to-a-running-system)).
- `./security-review` runs scoped source/fixture checks and the historical signed prefix; read PASS/FAIL/UNPERFORMED counts, not only exit status, and retain exclusions; it runs no live probes, deployment or provider ([runner](../scripts/audit/security-review.mjs), [security-review-runner.test.mjs](../tests/security-review-runner.test.mjs)).
- `./prime verify` runs the configured NEXT source profile; preserve failures and exclusions, which include real owner enrollment, protected service custody, OpenShell and paid inference ([profile README](../packages/ops/fast-verify/README.md)). Source success does not qualify the installed system ([CLAIMS.md](CLAIMS.md)).
