# How AUKORA fits together

**Repository map:** `plugins/` + `apps/aukora-desktop/` — pilot runtime and owner client.
`packages/boundary-gate/` — separate authority; [20-file review map](SECURITY-BOUNDARY.md).
`packages/{authority,memory,execution,inference,runtime-bridge,ui,ops}/` + `harness/` — NEXT source.
`evidence/current.json` + `docs/` — current claims, public receipts and archived history.
`scripts/` — check/operator index; `plan/` — directions; `labs/` — NOT LIVE; [research/](research/README.md) — separate research reports.

*Start here if you are reading the repository rather than running it.* The component table describes the selected source account in [evidence/current.json](evidence/current.json). Current factual claim rows are generated in [CLAIMS](docs/CLAIMS.md). The component status rows below are generated from the same canonical data as the README and Security Boundary. **REPORTED** means a supplied operator observation with its timestamp; **SOURCE** means present code, and **NOT YET** means a missing qualification. A linked test is a review entry point, not a new result from this refresh.
[docs/CLAIMS.md](docs/CLAIMS.md) is the claim-by-claim account; the [README](README.md) carries current status; history is archived.

The repository holds two layers. Keep them apart while reading:

1. **The organism (operator-reported on one Linux pilot).** A Genesis agent runtime ("Auma") whose plugins are admitted only as an
   owner-approved set, whose one-shot bash route uses an NVIDIA OpenShell sandbox, and whose governed theme/plugin-set changes go
   through proposals to a boundary gate. Approval uses the owner channel, accessible to the gate user and root;
   the desktop app is one route to it.
2. **Prime NEXT packages (SOURCE).** `packages/authority`, `memory`, `execution`, `inference`, `runtime-bridge`,
   `contracts`, `ui`, `ops`: a stricter authority path under construction. `./prime verify` runs their 66-job source
   profile. They are not what runs on the pilot. See [docs/PRIME-NEXT-ARCHITECTURE.md](docs/PRIME-NEXT-ARCHITECTURE.md).

## Revision and observation identity

<!-- BEGIN GENERATED current-revisions -->
| Identity | Revision / observation | Meaning |
| --- | --- | --- |
| Source account | `70d180f38bdd701c3c25e0e4f196fd82dbe3e091` | Base reviewed for this documentation snapshot; the review command emits the received HEAD and dirty state. |
| Public main observed | `03adf90c40225e823b1bf0282aff1be2728e9f69`, 2026-10-04T16:00:00Z (integration tree before this evidence commit; SOURCE, ahead of the deployment) | Read/fetch observation, not a deployment proof; main may advance. |
| Pilot deployment | `3673b98a3e090d122ed0853386ff60913287c3a8`, 2026-10-05T12:41:00Z · **REPORTED** | Release 3673b98 was read back running on the pilot at 2026-10-10T06:02Z, an operator-side readback from the owner's machine (evidence/pilot/2026-10-10-readback.md), not an independent attestation. The installed gate package remains Peter-reported as the old package 4c24fd0. No normal admitted shell or accepted bound workspace. Later source commits and observer success do not establish admission, containment closure or whole-product acceptance. |
| Tested revision | Per-check HEAD and file digests from `./security-review` | No current test result is inferred from a commit message or this table. Historical results stay in [evidence history](docs/EVIDENCE-HISTORY.md). |
<!-- END GENERATED current-revisions -->

## The organism on one page

```
 owner's Mac                                   Linux pilot (one host, separate Linux users)
 ───────────                                   ────────────────────────────────────────────────────────────────
 AUKORA desktop app  ── SSH tunnel ──►  Genesis runtime "Auma"  (user aukora-host, loopback :18735)
 (apps/aukora-desktop)                    │  plugins admitted by the composition gate (owner-approved plugin set)
   owner card:                            │  harness tool-registry calls reach the action gate
   gate facts first,                      │  bash ──► sbx-exec (root wrapper, one sudo rule) ──► OpenShell sandbox
   model text fenced,                     │                                                    (user auma, /sandbox)
   one-click Approve                      │  proposes changes (cannot approve)
        ▲                                 ▼
        └──── owner.sock ◄──── BOUNDARY GATE (user aukora-gate) ◄──── propose.sock
                               signed hash-chained ledger · owner-only targets · signed receipts
                               signs plugin-set approvals ─► /etc/aukora-approvals (root) ─► launcher
                                                                    release floor ─┘   (systemd ExecStartPre)
```

Calls through this harness tool registry reach the action gate. Other processes, direct plugin or host effects, and actions inside a started process are outside that registry check; see its [scope](plugins/aukora-action-gate/lib/index.mjs). This diagram does not establish complete mediation.

## Components

<!-- BEGIN GENERATED current-components -->
| Component | Role and code | Existing check / observation | Status / evidence timestamp | Limit |
| --- | --- | --- | --- | --- |
| Genesis runtime | Pinned DSH/Cordis host and compiled harness; recorded launcher binds 8389 artifacts to six exact patches; [launcher](scripts/launch-dsh.py); [materializer](scripts/materialize-aukora-release.py) | [existing release check](tests/aukora-plugin-set-trusted-verifier.test.mjs) | **RECORDED** · Runtime readback from the owner's machine, 2026-10-10 05:56 and 06:02 UTC: eight AUKORA service units active on a Nebius VM; Genesis runtime release 3673b98, boundary gate, OpenShell 0.1.2 gateway and sandbox, and HTTP relay under separate accounts; memory shared the runtime account; only SSH listening off loopback; desktop owner app attached through a loopback forward; evidence at 2026-10-10T06:02:11Z | Operator-side readback, not an independent attestation. Running processes and services do not establish containment: the 2026-10-04 result remains FAIL and the inherited-descriptor finding is open. Normal shell admission, a bound workspace, installed bytes and the gate package version (Peter-reported 4c24fd0) were not read back. Owner enrollment remains unperformed. Later source commits and observer success do not establish admission, containment closure or whole-product acceptance. |
| Buzz Nostr relay | Separate loopback relay beside the node's HTTP message service; [install source](ops/buzz-relay/README.md) | [dated pilot and Mac records](plan/NORTH-STAR.md) | **RECORDED** · Later North Star entries report the separate loopback Buzz Nostr relay and Mac desktop channel messages; evidence at 2026-10-12 | Auma's reply route remains unqualified. The relay was recorded open to node logins and tunnel users. Invites are NOT BUILT. The pinned Buzz fork is private; this task did not inspect it or contact the pilot. |
| Buzz door in staging | Host plugin for channel reads, wakes and replies; mounted without configuration; [door source](plugins/aukora-buzz-door/lib/index.mjs) | [dated staging record](plan/NORTH-STAR.md) | **RECORDED** · North Star records staging approval by its stand-in owner key, a passed release-floor check and an interface returning HTTP 401 without a token; evidence at 2026-10-12 about 11:15 UTC | Staging only; the live harness was unchanged. The door reported unavailable without a key or configuration. A wake and Auma answering through Buzz were NOT RUN. This is a retained operator record, not a new runtime observation. |
| Composition gate | Records/adopts the owner-approved plugin set bound to the release and record; [set admission](plugins/aukora-composition-gate/src/plugin-set.mjs) | [existing signer check](tests/aukora-plugin-set-gate-signer.test.mjs) | **REPORTED** · Historical 3ac3509 PACKAGE_VERIFIED/floor readback is retained; Peter now reports live 3673b98 with old gate package 4c24fd0; evidence at 2026-10-05T12:41:00Z | No current bootstrap, floor or package readback ran here. Historical signer epoch/ledger sequence is not a current installed claim; rollback still needs fresh owner approval. |
| Boundary gate | Separate proposal/owner channels, exact-byte review and signed event ledger; [gate](packages/boundary-gate/src/gate.mjs); [ledger](packages/boundary-gate/src/ledger.mjs) | [existing gate fixture](packages/boundary-gate/checks/gate.mjs) | **REPORTED** · Peter reports the installed gate remains the old package 4c24fd0; separate channel/exact-byte review mechanism exists in source; evidence at 2026-10-05T12:41:00Z | Live runtime 3673b98 does not imply gate-package parity. This docs task did not verify installed bytes, human attendance, native owner-key enrollment or hardware custody. |
| Signed launch and v2 floor | Pre-Node custody check; signer epoch/ledger sequence floor; fresh approval for rollback; [bootstrap](packages/boundary-gate/host/install/gate-bootstrap.py); [signed floor](packages/boundary-gate/src/release-floor.mjs) | [source/runbook](packages/boundary-gate/host/install/README.md); [existing check](tests/aukora-plugin-set-trusted-verifier.test.mjs) | **REPORTED** · Historical 3ac3509 PACKAGE_VERIFIED/floor readback is retained; Peter now reports live 3673b98 with old gate package 4c24fd0; evidence at 2026-10-05T12:41:00Z | No current bootstrap, floor or package readback ran here. Historical signer epoch/ledger sequence is not a current installed claim; rollback still needs fresh owner approval. |
| Boundary self-check | Before-start check and 15-minute timer; failure refuses/stops the configured runtime; [self-check](packages/boundary-gate/bin/selfcheck.mjs); [timer](packages/boundary-gate/host/systemd/aukora-selfcheck.timer) | [existing stubbed check](packages/boundary-gate/checks/selfcheck-bin.mjs) | **REPORTED** · Production self-check/timer account plus disposable transient start-gate proof: forced failure blocked the unit main process; evidence at 2026-10-04T11:39:37Z | The transient proof establishes before-start failure handling, not a live sabotage or continuous gate-service loss dependency. The reported BindsTo/RemainAfterExit unit change is pending; source/RPC stubs do not establish current egress policy. |
| Action gate | Routes harness tool-registry calls through configured guard/policy before effects; [action entry](plugins/aukora-action-gate/lib/index.mjs); [policy](plugins/aukora-action-gate/lib/policy.mjs) | [existing source check](plugins/aukora-action-gate/check.mjs) | **REPORTED** · Peter reports live release 3673b98. The 2026-10-10 readback saw the runtime process and its composition-gate plugin import; it did not exercise the action gate or Kira. The October 12 plan correction reports the memory service up and one saved note without indexing or search; evidence at 2026-10-12 (plan correction; no rerun) | Mounted pilot route is recorded; host file fences and a source guard do not establish complete mediation or containment. |
| OpenShell confinement | Normal shell admission and bound workspace remain unaccepted; retained confinement source and historical host-local deny; [adapter](plugins/aukora-openshell-confinement/lib/index.mjs); [wrapper](packages/boundary-gate/host/sbx-exec); [host-local policy](host/auma-local-deny/README.md) | [separate live command scope](scripts/audit/containment/README.md) | **REPORTED** · Peter status report: live 3673b98, no normal admitted shell, no accepted bound workspace. Earlier bound guest 33 DENIED / 0 ALLOWED was ADMISSION-BYPASSED; host-as-auma 40 DENIED / 7 ALLOWED. Kimi later reports observer pass, with admission blockers remaining.; evidence at 2026-10-05T12:41:00Z | ADMISSION-BYPASSED guest results do not qualify the normal route. Observer pass does not clear admission or the host allowed routes. Historical inherited-descriptor finding remains retained; no live check ran in this docs task. |
| Desktop owner card | Gate-decided labels and plain action line, trusted facts first, model text fenced last, one-click approval; [card](apps/aukora-desktop/aumlok-approval.html); [adapter](apps/aukora-desktop/aumlok-signer-airlock.mjs) | [clarity check](tests/aukora-owner-card-clarity.test.mjs); [no-friction check](tests/aukora-owner-card-no-friction.test.mjs) | **REPORTED** · Supplied card/gate installation report; native app patched and relaunched with bridge polling; evidence at 2026-10-04T08:50:33Z | Recorded card installation plus source presence does not measure comprehension or attendance, prove native owner-root enrollment, or attest the current rendered window in this docs task. |
| Aumlok / native owner root | Identity/approval source; native owner-root custody and enrollment remain unqualified; [identity](plugins/aukora-aumlok/README.md); [owner-key source](packages/owner-key/README.md) | [historical source fixture](tests/aukora-airlock.test.mjs) | **NOT YET** · No selected public acceptance receipt | Owner enrollment is the owner’s action. A passkey with user verification proves a real authenticator, not hardware custody, who the human is or informed consent. |
| Kira | Memory plugin source for remembered notes, signed proposals and recall; [memory source](plugins/aukora-kira/README.md) | [recall source check](tests/aukora-kira-ask-recall.test.mjs) | **REPORTED** · Peter reports live release 3673b98. The 2026-10-10 readback saw the runtime process and its composition-gate plugin import; it did not exercise the action gate or Kira. The October 12 plan correction reports the memory service up and one saved note without indexing or search; evidence at 2026-10-12 (plan correction; no rerun) | The October 12 plan reports one saved note without indexing, search or demonstrated recall. This is not an owner-approved NEXT save. Replacement collector and per-note Aura association remain pending. |
| Aura observation/court lane | Composition-log adapters and independent-process court interfaces; [Aura source](scripts/aura/README.md); [retained court](vendor/append-only/replicas/README.md) | [existing witness check](tests/aukora-witness-commits.test.mjs) | **SOURCE** · Retained composition-log/court source and separate historical witness checks | SOURCE lane with separate historical runs; this is not the installed INTERIM gate collector or an independent current witness. |
| Aura gate collector / Nostr records | Installed INTERIM signed-ledger collection and cold verification through 153; [INTERIM install](host/aura-interim/README.md); [cold verification source](scripts/aura/verify-collected.mjs) | [installed verifier source](host/aura-interim/verify.mjs); [separate source check](scripts/aura/checks/collector.mjs) | **REPORTED** · Supplied e337397 collector cold-verification result; evidence at 2026-10-04T10:44:52Z | INTERIM pilot-generated owner/controller keys are not enrolled native owner custody. Root-recorded anchors are not an independent witness. The replacement collector and actual per-note Kira/Aura association remain separate pending acceptance. |
| PQ hybrid experiments | Pinned hybrid signature/KEM lab; grants no authority; [NOT LIVE lab](labs/pq-hybrid/README.md) | [existing lab check](labs/pq-hybrid/checks/hybrid.mjs) | **SOURCE** · Standalone lab on pinned Noble dependencies | NOT LIVE; grants no authority and does not qualify a deployed identity/receipt migration. |
<!-- END GENERATED current-components -->

## Aura coverage audit — 2026-10-12

**SOURCE-ONLY audit at `2a605d3706328ae46718cfe0c836178646c67342`, with the three wiring additions below identified separately.** No node, installed files, process or private record was inspected in this audit. Its then-current plan account reported live release `3673b98`, an INTERIM collector and a separate staging door. The later [component status](docs/STATUS.md) records live `c603bbf` and a briefly configured, now-idle Buzz door; neither account establishes that this checkout is running. The earlier plan's “every tool call, approval, memory write and self-change” describes several histories, not one complete signed master record.

Aura currently names **several distinct record paths**, plus a collector and a display. The [boundary ledger](packages/boundary-gate/src/ledger.mjs) signs each SQLite row with the gate's Ed25519 `receipt-ed25519.pem`; its signed body includes sequence, time, event, proposal, target, before/after hashes, original detail text and previous hash. The [action gate](plugins/aukora-action-gate/lib/receipts.mjs), [Kira](plugins/aukora-kira/lib/memory-store.mjs) and [code writer](scripts/aukora/aura-code.mjs) also use local hash chains. Sharing Kira's hashing rule does not join those chains or give them signatures.

The [INTERIM collector timer](host/aura-interim/aukora-aura-collector.timer) runs every five minutes after its initial delay. Its root snapshot helper copies the gate DB; [collect-gate](scripts/aura/collect-gate.mjs) verifies the pinned gate key and every row, encrypts each observation and appends a signed Nostr record to `gate-observations.nostr.jsonl`. This is local storage, not a relay publication: the installed service has `PrivateNetwork=yes`. It observes **only the gate ledger**, including caller reports. Its coverage head cannot establish that omitted kinds of action happened or were recorded elsewhere. The [replacement protected collector](packages/boundary-gate/host/aura/entry.mjs) is separate source; its presence is not evidence it replaced INTERIM on the node.

The materializer creates `plugins/aukora-aura-association/lib/index.js` from [association-plugin.js](scripts/aura/composition/association-plugin.js), and selects that plugin in the composed set. It runs `adapter.py associate` over the composition log `<state>/aura/records.jsonl` and retained/presented observations. **It writes nothing.** It does not connect ordinary memories to the gate collector and does not provide `aura.records`. The [Aura face projection](packages/ui/faces/settings/src/aura/projection.ts) folds durable session metadata with an FNV checksum; it explicitly fixes `identityBound`, `cryptographicReceipts` and `externallyAnchored` to `false`. Neither surface is a master ledger.

In the table, **G** is the signed gate ledger (and, when collected, its encrypted Nostr observation); **A** is `aura-actions/aura.jsonl`; **K** is the Kira chain/journal; **C** is `aura-code/aura.jsonl`; **N** is a signed Nostr event or binding, not automatically an Aura observation. “Reported mounted” cites the plan/component account, not a new runtime observation. “SOURCE” means the path exists but has no demonstrated live-node join here. Verification names refer to the commands immediately below; verification always requires the relevant exported bytes and separately trusted public keys/heads.

| Action | Record and writer today | Chain; signer | Identity bound | Stranger check | Node status / limit |
| --- | --- | --- | --- | --- | --- |
| Tool call judged by action gate | [Guard](plugins/aukora-action-gate/lib/index.mjs) appends `tool.decision`: tool, call/session, argument digest, allow/deny and rule; fsync before allow. Failed refusal logging can leave no record. | A; unsigned | Session/call IDs, no Aumlok subject | H | Action gate reported mounted; this is a decision, not proof of execution/result. No G join. |
| File read through a tool | Same `tool.decision`; session log can hold tool result. | A; unsigned | Session only | H | Reported mounted; direct host/plugin reads and inner process reads are outside this hook. |
| File write through a tool | Same `tool.decision`; governed gate target changes separately have `apply`. | A unsigned; G for gate target only | Session; G key for governed target | H / G | Reported mounted; no file-system-wide write journal or signed completion for ordinary writes. |
| Shell command in sandbox | Action decision precedes [OpenShell dispatch](plugins/aukora-openshell-confinement/lib/index.mjs); command arguments are digested. | A; unsigned | Session only | H | Dispatch reported mounted, containment unqualified; no signed record of each operation inside the shell. |
| Memory remember | [Tracked writer](plugins/aukora-kira/lib/tracked-memory.mjs) commits note digest/source plus `remember` to `remembered/aura.jsonl`, and journal entries; approved settlements use separate `kira-memory/aura.jsonl` and a receipt. | K; remembered tier unsigned; settlement receipt signed by configured memory issuer | Configured subject; default `aumlok:subject:owner` is an unlinked alias, not enrollment | M + H; approved export P | Kira reported mounted; plan reports one saved note, no demonstrated indexing/recall. Ordinary remembers do not enter G. |
| Memory recall | [Tracked recall](plugins/aukora-kira/lib/tracked-memory.mjs) verifies/filters existing notes and returns them; no new G/K recall receipt. Tool invocation can have A/session records. | No dedicated recall chain; A if tool | Configured read subject, not a signed recall identity | Existing notes M; no exact recall-result proof | Kira mounted report; recall not demonstrated. Automatic injection is not necessarily a tool call. |
| Memory forget | [Forget route](plugins/aukora-kira/lib/memory-deps.mjs) first appends content-free `forget` tombstone to `remembered/journal.jsonl`, then removes canonical object/salt; signed-tier erasure refuses. | K journal; unsigned | Note ID/actor; no owner signature on the forget event | J | SOURCE route, no live forget evidence; session logs/backups remain, no G join. |
| Owner approval | [Gate](packages/boundary-gate/src/gate.mjs) writes `review-issued`, `decide`, `apply`/`revert-applied` and signed receipt; failures/reconciliation have their own rows. | G; gate Ed25519 | Legacy owner socket/HMAC route, not enrolled Aumlok subject; source v3 adds explicit enrolled-owner proof | G; historical L2 export | Reported live owner popup approvals; v3 owner enrollment not reported installed. |
| Rejection/refusal | Gate writes `reject`, `decide` rejected/cancelled, `decide-refused`, `expire` on specified branches; A records its own denied decisions. Unknown/malformed requests need not append. | G signed by gate; A unsigned | Gate route/approver or session, no universal owner subject | G / H | Reported gate refusals; not an exhaustive record of all refused requests. |
| Plugin-set or release change | Gate proposal/decision/apply records approved plugin-set bytes bound to release and record; bootstrap installs approval and floor. Composition admission serialization has a separate `aura/records.jsonl`. | G; gate key. Separate composition log/issuer receipts | Legacy gate identity; configured composition issuer, not automatic Aumlok enrollment | G; composition Q | Release approvals reported; records do not alone prove the running bytes or every later start. |
| Self-change | [self-change](scripts/aukora/self-change.mjs), [advance](scripts/aukora/advance.mjs) and [become](scripts/aukora/become.mjs) append `code.change`, `main.advance`, corresponding `.result`, `approval.unused`/reconciliation and `code.become`; gate theme changes use G. | C unsigned, linked approval artifact separately signed by configured Aumlok controller; theme G | Approval subject/control checked separately; C carries approval digest/ID and approver DID, not an enrolled node subject by itself | H plus approval D; theme G | Historical Mac script runs and live theme receipt reported; no general live Linux C-to-G join. |
| HTTP relay post by Auma | [Relay client](plugins/aukora-relay-auma/lib/index.mjs) records `relay-intent` before send and `relay-posted` after response, body digest/size, request and message IDs. | G; gate key | Literal `auma` principal, no Aumlok subject | G | Plan reports 30 live posts with intents. Caller report does not attest the relay independently. |
| Buzz post by door | [Door](plugins/aukora-buzz-door/lib/index.mjs) uses same intent/completion op around signed channel post; receipt-post tool additionally carries gate receipt evidence. | G gate key + N door's BIP-340 key | Door Nostr key and configured session; no automatic Aumlok binding | G / N; receipt post B | Staging post reported, live harness unchanged; real model reply not demonstrated. |
| Buzz message waking a turn | Baseline door had no G wake row. **New SOURCE:** `buzz-wake` note before delivery names event ID, sender key and SHA-256 of session ID; failure prevents handoff. A failed followup can leave a note and a retry can append another. | G via `aura_note`; gate key; incoming N signed by sender | Sender key and session digest, not owner attribution or enrolled Aumlok identity | G / N | New source only; records a verified message handoff intent, not model completion. |
| Model turn | [Remembered hook](plugins/aukora-kira/lib/memory-remembered-hook.mjs) captures eligible real user prompts and assistant final messages after durable-session flush; child completion has a separately marked host source. | K unsigned, plus unsigned durable session log | Configured Kira subject; owner/agent attribution is not a signature | M + H | Capture reported mounted. Pauses, privacy filters, failed flush/capture and unsupported paths prevent “every turn” coverage; no per-inference gate receipt. |
| Contact verified | [Contact writer](plugins/aukora-nostr/bin/add-contact.mjs) stores owner-signed SAS confirmation in `nostr/contacts.json`; [resolver](plugins/aukora-nostr/lib/contact.mjs) validates binding/confirmation before VERIFIED. | Signed confirmation document; no append-only Aura/N event chain | Peer subject/npub/controller plus owner's configured controller signature | No dedicated cold CLI; `verifySasConfirmationDetailed` / `resolveContact` require trusted context | SOURCE; no node contact verification evidence. Mutable contact file is not history. |
| Identity binding made | [Binding tool](plugins/aukora-nostr/bin/reissue-binding.mjs) asks Aumlok signer, verifies response and writes `nostr/binding.json`. | Signed binding document, no G append | Exact `aukora:1:…` subject ↔ Nostr pubkey, signed by configured Ed25519 controller/machine key | I | SOURCE native binding; INTERIM collector has a synthetic binding instead. Binding grants no authority or uniqueness. |
| Co-presence receipt accepted | Baseline [receiver](packages/copresence/receiver.mjs) atomically consumes verified core digest in caller's durable store. **New SOURCE:** configured gate socket records `copresence-accepted` with core digest after consumption. | Baseline digest marker, no chain; new G gate signature; original receipt two P-256 signatures | Device keys; optional member-signed device statement, not automatic Aumlok enrollment | R; new G | SOURCE. If G write fails the digest stays spent and caller receives `copresence:aura-unrecorded`; no acceptance success is returned. |
| Invite issued | [Invites](packages/invites/index.mjs) creates Nostr kind 39701; CLI returns signed event for private transfer. Issuance alone is not stored in G/admission DB. | N; inviter BIP-340 key | Network root and inviter Nostr keys, no Aumlok subject | N; path V after admission | SOURCE; not an installed membership network claim. |
| Invite redeemed | Kind 39702 signs invite event ID; CLI returns event. Consumption occurs at authoritative admission, not mere signing. | N; joining member BIP-340 key | Invite/event/member keys, no Aumlok subject | N; V | SOURCE; signature does not prove single use. |
| Admission made | [Admission operator](ops/buzz-relay/admit.mjs) transactionally stores consumption and the signed-pair record in its SQLite delivery row; `admissions.jsonl` receives only unsigned compact root/invite/redemption/inviter/member identifiers before relay add. **New SOURCE:** configured gate socket records `admission` with SHA-256 of `JSON.stringify(record)` before relay add. | Signed N invite/redemption ancestry + local DB/log; new G gate key | Root/inviter/member Nostr keys, no Aumlok subject | V; new G | SOURCE; failed G write leaves resumable committed admission, not relay admission success. Retries may repeat the same digest note. |
| Runtime start | Gate writes `gate-start` (and genesis/reconcile/expiry rows); harness reports `harness-start` through propose socket. | G; gate key | Gate fingerprint; harness PID is explicitly caller-reported/unverified | G | Gate/runtime starts reported. Gate restart is distinct from harness start or proof of installed release. |
| Runtime stop | No ordinary `harness-stop` / `gate-stop` append site; `code.become` may describe a specific script outcome, systemd/session logs are separate. | None for general stop | None | No Aura stop check | Gap; crash/power loss cannot promise a final local append. |
| Self-check | Bin invokes gate `selfcheck`; result is stored with `source: propose-socket/harness`, `verification: caller-reported-unverified`. | G; gate key signs the report | Gate key, not independent checker/owner signature | G | Timer reported live; plan counted 828 rows. Signature authenticates receipt of a report, not the truth of containment. |

**Verification commands and limits.** All paths below name copies explicitly provided to the reviewer, not live/private node paths. Run under Node **24.11.1**. These are reader entry points, not test results from this audit.

- **G — gate rows:** `node packages/boundary-gate/bin/gate.mjs verify --db /ABS/LEDGER.db --pub /ABS/GATE.pub` verifies an exported SQLite ledger against a public key whose full SPKI SHA-256 the reviewer must independently pin. The optional read-only `readGateSnapshot` API in [gate-snapshot.mjs](scripts/aura/gate-snapshot.mjs) additionally requires that explicit digest and bounds the snapshot. These checks establish signatures and the supplied chain, not latestness. `node docs/evidence/l2-demo-2026-10-04/verify.mjs --anchor ANCHORS.jsonl` checks the **fixed historical export** and its covered external anchors; it does not read today's node. Private collector cold verification is `node packages/boundary-gate/host/aura/entry.mjs verify` for the protected configuration, or the installed INTERIM `host/aura-interim/verify.mjs`; strangers lack its decryption context unless the owner supplies it. A Nostr envelope alone does not expose its encrypted gate payload.
- **H — unsigned Aura history:** `node scripts/aura/verify-append-only.mjs RETAINED.json AURA.jsonl` checks extension of a previously retained head/prefix, using `vendor/append-only/verify.py`. `node scripts/aura/verify-append-only.mjs retain AURA.jsonl` emits such a head. It does not verify a writer, signatures, truth, latestness or total coverage; action rotation needs the linked preceding segments too.
- **M / J / P — memory:** `node scripts/kira/verify-memory.mjs --state EXPORTED_STATE_HOME` checks remembered IDs/source-event digests/chain references. For the distinct journal, `node --input-type=module -e 'import fs from "node:fs"; import {verifyChain} from "./plugins/aukora-kira/lib/memory-journal.mjs"; const r=verifyChain(fs.readFileSync(process.argv[1],"utf8").split("\n").filter(Boolean)); console.log(JSON.stringify(r)); process.exitCode=r.ok?0:1' JOURNAL.jsonl`. For approved public evidence, `python3 scripts/kira/verify-public-evidence.py --export BUNDLE --issuer-anchor ISSUER.pub --approver-anchor APPROVER.pub` has its own receipt/key/record checks; it is not an export of the unsigned remembered tier.
- **Q / D — composition and code approval:** `python3 scripts/aura/adapter.py associate --state STATE --retained RETAINED.json --presented PRESENTED.json` checks association/court/composition separately. `python3 scripts/aumlok/verify-approval-cold.py APPROVAL.json --approver-did DID --subject SUBJECT --control-digest CONTROL_SHA256 --operation OPERATION.txt --now UNIX_SECONDS` checks the exact code-card bytes against independently selected signer/control inputs and evaluation time; use it alongside H, not H alone. The [become membrane](scripts/aukora/become.mjs) compares code, actions, signed memory and remembered heads against its locally retained observation. It refuses conflict/unavailable evidence except a missing first prior; it neither collects G nor supplies an independent witness.
- **N / I / V — public signed documents:** `node --input-type=module -e 'import fs from "node:fs"; import {verifyEvent} from "./plugins/aukora-nostr/lib/event.mjs"; verifyEvent(JSON.parse(fs.readFileSync(process.argv[1],"utf8"))); console.log("VERIFIED")' EVENT.json`; binding verification is `node --input-type=module -e 'import fs from "node:fs"; import {verifyBindingWithKey} from "./plugins/aukora-nostr/lib/identity.mjs"; const r=verifyBindingWithKey(JSON.parse(fs.readFileSync(process.argv[1],"utf8")),{controllerKeyHex:process.argv[2],expectSubject:process.argv[3]}); console.log(JSON.stringify(r)); process.exitCode=r.verdict==="verified"?0:1' BINDING.json CONTROLLER_HEX SUBJECT`; admission path verification is `node --input-type=module -e 'import fs from "node:fs"; import {verifyRecord} from "./packages/invites/index.mjs"; console.log(JSON.stringify(verifyRecord({root:process.argv[2],record:JSON.parse(fs.readFileSync(process.argv[1],"utf8"))})))' RECORD.json ROOT_HEX`. The event command verifies under the event's embedded public key; compare that key with the independently expected sender. These checks prove key signatures/path consistency, not human identity, global spend/quota or actual relay admission.
- **R / B — co-presence and posted gate receipt:** `node packages/copresence/verify.mjs RECEIPT.json` verifies the light receipt; `node packages/copresence/verify-intent.mjs RECEIPT.json --text "EXACT_TEXT" --approver DEVICE_HEX` checks an exact-text receipt. Neither proves receiver consumption or physical proximity. `node plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs EVENT.json --gate-key GATE.pub --ledger LEDGER.json --anchor ANCHORS.jsonl --door-key DOOR_HEX --channel CHANNEL_UUID` verifies a receipt-bearing post against supplied pins/anchors, not an arbitrary Buzz message's delivery.

**Gaps, in priority order for the owner's master-record design:**

1. **Enroll the owner's actual identity and choose the node's signing route.** The collector's binding is precisely `identity.verifyBindingWithKey(binding, {controllerKeyHex, expectSubject: ownerSubject})`; the configured author key must match that binding and records name the configured owner Nostr key. [INTERIM keygen](host/aura-interim/keygen.mjs) instead creates owner/author/controller keys on the pilot and derives a synthetic subject from `aukora-INTERIM-owner:<pubkey>`. It is not Peter's enrolled Aumlok subject. [Gate capture host](plugins/aukora-kira/lib/gate-capture-host.mjs) can map only the exact placeholder `aumlok:subject:owner` to the protected collector configuration's `owner_subject`; this checks consistency with configuration, not identity enrollment, and does not rewrite old notes. The source gate's owner-proof path needs active owner subject/root/epoch plus registry/activation evidence; no real node enrollment is reported. Peter must choose/enroll the owner root, authorize the binding and approve the compatible gate/release/receipt-consumer migration. Historical gate signatures do not become owner signatures retroactively.
2. **Join and measure coverage across existing histories.** The collector misses A, K, C, contact/binding changes, invite issue/redemption and ordinary runtime stops; recall has no dedicated result receipt. A gate decision is not an execution result. The three new `aura_note` kinds close only the Buzz handoff, configured admission and configured co-presence reporting gaps in source. The closed digest-only schema records authenticated gate acceptance of a caller's report, marks it `caller-reported-unverified`, and grants no authority. The note op shares the existing persistent propose-socket append budget; it does not acquire a new unlimited write route. No second ledger is introduced. Digests still permit equality/guessing tests and are not anonymization.
3. **Install the source joins through the owner route and observe them.** New notes require the changed, root-installed gate package and regenerated reviewed package manifest, then compatible caller releases/configuration. This patch does not change bootstrap-pinned launcher/owner-key source files or `bin/gate.mjs`; those static source pins do not move. The package inventory for `src/gate.mjs` does change. The replacement collector, configured read lifecycle/grants, same-result Kira capture, and new callers need separate installed acceptance. Staging recorder evidence is not a real-model wake, and this audit authorizes no node change.
4. **Connect the display, verifier and WASM paths without overstating them.** The Aura face is a session projection; the association tool is a read-only composition comparison. [Kira gate capture](packages/boundary-gate/host/aura/ARCHIVAL-INTERFACE.md) can bind a specific original gate completion to a note under protected pins, but ordinary capture and historical notes do not acquire that binding. The [WASM proposal path](plugins/aukora-kira/lib/wasm-proposal.mjs) prepares proposals; no installed cell-to-master-record or Pentora-to-master-record join is demonstrated. Each needs a named source event, reference and observed installed path, not a renamed counter.
5. **Retain independent observations and define failure semantics.** Root-held keys, same-host checkpoints and locally retained membrane heads cannot establish independent custody or a latest complete life. External ledger anchors cover only the anchored gate prefix. Report failures and gaps explicitly: failed note recording can precede a refused wake, follow irrevocable co-presence consumption, or leave admission delivery pending. Neither signatures, append-only comparison nor co-presence evidence proves unique humans, informed approval, causal completeness, or runtime containment.

## Three flows, end to end

1. **Auma changes something she may only propose (her theme).** Auma calls `aukora_gate_propose` → the gate validates
   the exact bytes against the target schema and base hash and records `propose` → the owner's app receives the
   pending question over `owner.sock` → the card shows the gate-computed from→to, then the model's note fenced →
   one click → `review` + `decide_review` → the gate writes the bytes from its own version store, signs a receipt,
   appends `decide` and `apply`. Auma's own socket has no approve operation (`packages/boundary-gate/src/gate.mjs`).
2. **A new release goes live.** Materialize → root `gate-bootstrap approval raise` (owner channel only; agents cannot raise
   it) → the card states whether the plugin set is unchanged since the previous approval → one click → `gate-bootstrap approval install`
   writes the gate-signed approval into a root-owned approval root and moves the release floor → `release.env` →
   restart: `gate-bootstrap check-package`, self-check, `gate-bootstrap floor check`, launcher, composition gate
   admission. Bootstrap source/runbook: [host/install](packages/boundary-gate/host/install/README.md).
3. **Auma runs a command.** The action gate judges the call → the OpenShell adapter accepts only one-shot
   `workspace-write` bash in `/sandbox` → `sbx-exec` runs it in the sandbox as `auma` → output returns. Paths under
   the gate's and approvals' directories are refused before bash runs.

## Browser node: how the pieces connect

This is the browser-node route described by the later [component status](docs/STATUS.md) and
[North Star](plan/NORTH-STAR.md). The owner approval line is a prerequisite to the app path, not a later browser
action: the harness is stopped until that line has completed.

```
 owner browser
      | HTTPS app host
      v
 Caddy app host -> one-time claim broker -> host-only one-day cookie -> harness pre-binding guard
                                                                    -> Aumlok Bind -> Kira owner overlay -> Aura snapshot
                              ^
 owner browser -> Caddy owner host -> gate owner page -> signed release approval -> floor + launcher

 after-approval acceptance --evidence -> public evidence record -> offline verifier
```

1. **Browser to Caddy — RAN on a real node; two-node routing is builder-reported.**
   `ops/node-spawn/ingress/render.py` requires two distinct hostnames and three distinct loopback ports per node,
   and rejects reuse across a multi-node file. `ops/node-spawn/ingress/Caddyfile.template` sends the app hostname
   to that node's harness or claim broker, sends the owner hostname to that node's owner page, rejects public
   launch-token queries, and aborts unmatched hosts. A rehearsal browser reached one node over HTTPS. By the
   builder's report, C1 and R1 later answered on their own two hostnames behind one Caddy; no committed machine
   record independently retains that two-node observation.
2. **Caddy to the one-time claim broker — RAN on a real node by the builder's report.**
   The app host routes only `/__aukora/claim`, sign-in and sign-out paths to
   `ops/node-spawn/ingress/claim.py`. Its protected claim store retains claim hashes, expires them, bounds attempts
   and spends a claim under a file lock before exchanging it. The broker reads the root-protected loopback launch
   descriptor and sends the launch token to the harness itself; the public request never receives that token.
3. **Claim broker to harness session cookie — RAN on a real node by the builder's report.**
   The pinned harness patch `patches/public-browser-secure-cookie.patch.json` mints a public-host
   `__Host-dsh-auth-*` cookie. The broker accepts only the configured authority, `Secure`, `HttpOnly`,
   `SameSite=Strict`, `Path=/`, no `Domain`, and a signed lifetime of at most one day. R1 reportedly passed the
   one-use exchange and host-only cookie checks. The cookie authenticates an app session; it grants no owner
   approval. Sign-out clears that browser's cookie but does not revoke a copied cookie or an upgraded socket before
   expiry; `plan/REVIEW-BROWSER-NODE.md` retains that open limit.
4. **Cookie to pre-binding restriction — RAN on a real node by the builder's report, with open limits.**
   `plugins/aukora-action-gate/lib/browser-bootstrap.mjs` allows only the first-screen HTTP paths, binding POSTs and
   five named bootstrap RPCs until it can read a binding control record. Its harness hook,
   `patches/browser-bootstrap-guard.patch.json`, checks HTTP and upgrades before routing and checks Remote dispatch
   before providers run. On rehearsal R1 at the fixed revision, the first screen and brand image served while the
   contact card, malformed plugin path, app page and session creation were refused; after-approval acceptance passed
   in unbound mode. This rests on the builder's report and has no committed run record. A readable control record
   lifts the guard, `prepare` returns the drawn words to the signed-in client, and GET/HEAD under most of `/plugins/`
   remains an admitted static prefix.
5. **Restriction to Aumlok binding routes — partial RAN; final Bind is NOT YET.**
   `plugins/aukora-face/aumlok/src/index.ts` registers the prepare, bind, cancel and status routes, and
   `plugins/aukora-face/aumlok/src/client/binding-bridge.ts` uses same-origin HTTPS POSTs.
   `plugins/aukora-aumlok/lib/browser-binding.mjs` permits one expiring draw, requires acknowledgement and exact
   phrase retyping, rate-limits attempts and makes the first durable v3 binding. A stand-in-approved rehearsal
   reached phrase generation and retyping in a real browser. The final Bind action and the owner's own binding have
   not run.
6. **Binding to Kira identity overlay — SOURCE only on a browser node.**
   On a successful bind, `plugins/aukora-aumlok/lib/browser-binding.mjs` derives the bound subject, rewrites the
   release's `aukora-kira` memory-owner overlay to that subject, durably writes it under the support root and reads
   it back. Because final Bind has not run, no browser-node observation joins that overlay to Kira capture, indexing
   or semantic recall.
7. **Owner page to gate approval — RAN on a real node.**
   This happens before steps 1–6 can reach a running harness. `ops/node-spawn/browser/node.py` installs the release,
   starts the separate gate and claim services, raises the operator-only plugin-set proposal and leaves the harness
   stopped. The owner hostname exposes the bounded page implemented by
   `packages/boundary-gate/src/owner-page.mjs`; the gate binds review and the decision to the exact proposal bytes
   and signs the apply row. The North Star records the owner's own click on three fresh builds; each then started
   and passed after-approval acceptance. This is release approval, not the later Aumlok identity Bind and not a
   passkey qualification.
8. **Gate approval to release floor and launcher — RAN on a real node.**
   The browser unit in `ops/node-spawn/browser/node.py` checks the installed gate package, runtime, browser profile
   and monotonic release floor before invoking `scripts/launch-dsh.py`. The launcher rechecks the approved artifact
   record, pinned harness build, authority inputs and owner-approved plugin set before it spawns the harness. The
   retained rehearsal record uses a stand-in approval; the three owner-approved starts are builder reports.
9. **Running release to Aura snapshot — RAN on staging and the pilot; SOURCE only as a browser-node hop.**
   `plugins/aukora-face/settings/src/aura/snapshot-reader.ts` forms one display snapshot from three separate heads:
   the gate ledger, Kira's remembered chain and the checked running-release artifact record. The signed-in route ran
   on the live pilot and all three heads were shown in staging. No report or retained evidence shows that snapshot
   on a browser node. It does not merge those histories or prove their completeness.
10. **Acceptance to evidence record — RAN on a stand-in-approved rehearsal node.**
    `ops/node-spawn/browser/acceptance.sh --evidence` asks `ops/node-spawn/browser/node.py` for public check outcomes,
    the gate-signed plugin-set receipt and apply row, release floor and installer-input digests, then creates a new
    file exclusively. `scripts/audit/browser-node-evidence.mjs` verifies the receipt signature, approval bindings,
    signed apply row and floor core binding offline. The committed record
    `evidence/browser-node/2026-10-13-rehearsal-r1-38004c5.json` predates the pre-binding restriction, uses a stand-in
    approval and is itself unsigned; its claimed check outcomes and observation time are not independently proved.

### What each piece trusts

| Piece | What it takes on trust from the hop before it |
| --- | --- |
| Caddy | The operator's DNS/TLS setup and the root-owned renderer input correctly associate each hostname with that node's three loopback ports. |
| Claim broker | Its protected origin, claim store and launch descriptor name the intended running harness; it trusts the loopback harness to mint the cookie whose shape and lifetime it checks. |
| Harness session | The cookie HMAC and request Host/Origin checks identify an authenticated browser session; they do not identify the owner or grant approval. |
| Pre-binding guard | A failed control-record refresh means unbound; any readable record in the configured binding directory means bound. |
| Aumlok binding | The authenticated session holder received and returned the node's draw; that does not prove a person read or typed the words. |
| Kira overlay | The binding's stored subject and the configured support/state roots are the identity and location Kira should use. |
| Boundary gate | The separate owner-page bearer route and exact review response came from the approving owner; a gate signature alone cannot prove that human fact. |
| Floor and launcher | The protected gate package, installed approval/floor, artifact record and release-local pins are the authorized inputs. |
| Aura snapshot | Each provider's supplied head represents its own history; combining three heads does not make one complete ledger. |
| Evidence verifier | Signed gate/floor fields are cryptographically bound, but the unsigned node record's check results, time and installer observations are producer claims. |

### Not joined yet

- Cross-node claim and cookie isolation has no retained real-node refusal record; the two-node success is the
  builder's report, and sibling-site request isolation remains open.
- The current pre-binding fixes have only builder-reported installed execution. The readable-record, returned-word
  and open `/plugins/` limits above remain accepted gaps, and ordinary sign-out is not per-session revocation.
- Final Aumlok Bind by the owner, the resulting Kira owner overlay and a second owner-bound node are NOT YET.
- Passkey approval with a real authenticator on an installed browser node, and its join to the node gate, are NOT
  YET. Source enrollment and owner-sign-in routes do not establish authenticator custody or approval attendance.
- Kira capture, current indexing and semantic recall have not run through a browser node. A separate builder report
  about real embeddings on another store is not that join.
- The three-head Aura snapshot has not been observed on a browser node, and the committed browser evidence predates
  the pre-binding restriction and does not carry an owner approval.
- Co-presence evidence is not connected to browser-node binding or authority; a co-presence receipt grants nothing.
- Admission and the Buzz relay are intentionally absent from the relay-free browser release. No invitation,
  closed-relay admission, channel join or reply is part of this path.
- Voice is disabled by default and no browser node has run the Linux speech runtime, microphone or spoken reply.
- No model reply has run on a browser node. The rehearsal evidence therefore does not establish a usable assistant,
  owner identity, containment or an end-to-end sovereign node.

## Not mounted, fixtures, history

Present in the tree but not part of the live organism (see [lab index](labs/README.md)): `plugins/aukora-gate-demo` (a one-file fixture for the
composition gate's governed-grant lane), `plugins/aukora-box`, `plugins/aukora-organism`,
`plugins/aukora-subscription-hands`, `plugins/aukora-nostr` (a library, used by the collector),
`labs/deepseek-harness-boundary` (the lab the boundary gate was distilled from), `labs/laya-screen`.
Historical reports live in `docs/` with their dates; [ARCHIVE.md](ARCHIVE.md) lists retired material.

## What this does not claim

Not containment of a hostile agent on the Mac, not independent verification (all verifiers are this project's code),
not that only approved code runs (bare dependencies, the gate bootstrap and workers are outside the plugin set), and
not human attendance or comprehension at an approval. [docs/CLAIMS.md](docs/CLAIMS.md#not-claimed) names each.

For review, follow [README](README.md) → [SECURITY-BOUNDARY.md](SECURITY-BOUNDARY.md) → this architecture → [verification scope](README.md#check-it-yourself) → [paper](docs/AUKORA-GOLDEN-BOUNDARY.md) → [separate research](research/README.md). The [retained containment baseline and host follow-up](README.md#containment-baseline) remain distinct from the offline verifier; full containment is unqualified.
