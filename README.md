![AUKORA's intended human-first architecture](docs/assets/aukora-human-first.png)

*Human first. AI next.*

The software that proposes an act should not be the authority that permits it.

AUKORA is an open, AGPL personal-AI foundation where the human holds identity, memory and authority. Models and apps are replaceable; the intended durable center is the person and the boundaries they control.

The image describes the intended architecture. The measured implementation status and its limits are below.

## Check it yourself

Use Node 24.11.1. Clone this repository and run:

```sh
git clone https://github.com/aumara-xyz/aukora-prime.git
cd aukora-prime
./prime verify
```

**Known failing entry point at this preparation checkpoint — RAN:** bare `./prime verify` currently routes to the memory snapshot verifier and exits 1 in under a second:

```json
{"verdict":"REFUSED","reason":"memory:cli-arguments-invalid"}
```

The new keyless verification command is being integrated. Its target is about three minutes, with per-check PASS/FAIL and an explicit UNPERFORMED list. **No final PASS or successful duration has been observed for that command here.** The existing snapshot-verification interface remains `./prime verify SNAPSHOT OWNER [RETAINED_HEADS_JSON]`; it is a different, data-dependent check.

These three keyless source checks were run at the documentation baseline `9d6c2205`:

```sh
node packages/contracts/check.mjs
node packages/ui/prime-authority/checks/controller.mjs packages/contracts/src/browser.mjs
node harness/check-static-csp.mjs
```

## Status

This documentation checkpoint is based on `9d6c2205`. Later repair handoffs require integration and checks before the status is updated. RAN means executed under the stated conditions; SOURCE-ONLY means inspected code; UNPERFORMED means no qualifying execution has been established.

| Status | Claim | Command or evidence | Limit |
| --- | --- | --- | --- |
| Working — RAN | Frozen Node/browser contract representations and byte vectors. | `node packages/contracts/check.mjs` — 421 assertions. | Format checks, not complete effect mediation or deployment qualification. |
| Working — RAN | Owner UI controller handles its synthetic review/authentication scenarios. | `node packages/ui/prime-authority/checks/controller.mjs packages/contracts/src/browser.mjs` — 11 cases. | No real enrollment, real authentication or executed effect. |
| Working — RAN | Static HTML script CSP binds selected inline script bytes. | `node harness/check-static-csp.mjs` — 39 assertions, six routes. | Browser parity remains UNPERFORMED; this does not confine the agent. |
| Working in a bounded experiment — recorded RAN | One synthetic-P256-approved save using PG 16, C uid 995 and D uid 994; bytes, citation and receipt survived independent authority, memory and database restarts. | `cat docs/evidence/bounded-memory-experiment.json` inspects the dated summary. | One synthetic save, older source, no real owner; stored, not indexed or searchable. Reading the summary does not repeat the experiment. |
| Disabled — SOURCE-ONLY | Public owner-memory authority and effect routes await trusted host acceptance. | [Runtime bridge](packages/runtime-bridge/README.md), [host interface](harness/OWNER-MEMORY-HANDOFF.md). | A disposable preview access cookie is not owner authority. |
| Disabled — SOURCE-ONLY | Actual OpenShell execution. | [Execution source and qualification](packages/execution/README.md). | Real gateway, TLS/JWT configuration, required Landlock, network denial and remote kill/absence are UNPERFORMED. Mock protocol checks do not qualify them. |
| Disabled — SOURCE-ONLY | Live model inference. | [Inference source](packages/inference/README.md). | No budget-capped real reply has been established. Provider credentials belong in the separate broker/settings path. |
| Proposed | Registered agents and human networking, agentic browser, handset, 27-cell receipt wiring, seven-word ceremony behind the UI and NDI integration. | [Design and Built / Proposed table](docs/AUKORA-GOLDEN-BOUNDARY.md). | These are designs, not functioning product capabilities. |

Real PostgreSQL and separate Linux users are not wholly unperformed: the bounded synthetic experiment above ran. Qualification of the current complete product and current source under those conditions remains UNPERFORMED.

## Known gaps

At this documentation baseline:

- The keyless `./prime verify` entry point has the known refusal above. The longer authority suite was reported to outlive the five-minute session during its 265-save loop; a bounded fixture and normal signed re-login are being integrated. Production session TTL must stay unchanged.
- Server logout needs durable revocation and approval/session binding joined through the bridge and UI. Authority-only repair source is in a later handoff; it has not qualified the complete path here.
- Terminal authority history retains too much copied content. Later compaction source needs integration and a regression on the committed bytes.
- Forget, purge and restore need their approved routes, independently retained controls and forgotten-payload checks joined end to end. Logical purge does not promise erasure of physical media, WAL or external copies.
- The owner review must show every saved policy-relevant field or use fixed server defaults. NFC, format controls, line separators and invisible fillers need a declared review filter without rewriting historical bytes.
- The lifecycle regressions for cancellation before handler start, disposed owner state and recovery after known outcomes must remain shipped and reproducible.
- Same-UID witness rollback remains a declared limit. Candidate-writable evidence is not an independent trust anchor.
- The signer is synthetic. The owner's real passkey enrollment is the top P1 item and requires the owner's action. A real passkey with user verification establishes a real authenticator with user verification; it does not establish hardware custody, human identity or comprehension.
- OpenShell remains unqualified and disabled. Live inference, a second-machine reproducible release digest, device revocation/key rotation and bounded login-challenge lockout remain unqualified or incomplete.
- Threads needs an actually available read-only workspace host or an explicit unavailable state. UI appearance alone does not establish the host path.
- Two owned package manifests still need their missing license declarations added with the existing `AGPL-3.0-or-later` variant and corresponding provenance checked.
- A private security reporting contact has not yet been confirmed.

The live agent is not yet fully contained. Root and identity design still need hardening. Every repair should land with a focused regression and update this list when the integrated command actually passes.

## Read and contribute

- [The Golden Boundary — canonical paper](docs/AUKORA-GOLDEN-BOUNDARY.md)
- [Review prompt](SHARE.md)
- [Architecture and build instructions](docs/ARCHITECTURE.md)
- [License inventory](licenses/README.md), [AGPL v3 license text](LICENSE), [donor provenance](provenance/donors.json) and [component ledger](provenance/core-ledger.json)
- [Vulnerability reporting — private contact pending](SECURITY.md)
- [Contributor rules](AGENTS.md)

First-party source currently declares **AGPL-3.0-or-later**. Third-party code retains its own licenses: DSH is MIT, OpenShell is Apache-2.0, and vendored dependencies keep their notices. See the inventory for the specific closure and its gaps.
