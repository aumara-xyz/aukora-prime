# AUKORA Ideas Ledger

Peter's ideas, big and "crazy", kept in one place so none get lost and none get mistaken for shipped work. Kept current by Grok. Started 2026-10-03 ~10:00 WITA (UTC+8).

**Status:** RUNNING (being worked now) / NEXT (queued behind the current milestones) / PARKED (kept, not scheduled) / DONE / DROPPED.
**Evidence labels:** RAN = executed, output exists. SOURCE-ONLY = written or read, nothing ran. UNPERFORMED = not done.

Toy-lab results below come from one Linux box with a QEMU riscv64 guest. They are **not Prime and not real hardware**, and nothing in Prime was changed. We port the rules and tests, not the code or the timings.

The current priority is the five milestones in [CONVERGENCE.md](CONVERGENCE.md). An idea here does not authorize spend, cloud, credentials or a new lane.

## How Peter adds an idea

Tell Grok in chat, or open a GitHub issue with the label `idea`. Grok gives it the next ID, adds a row here with status PARKED, and links the issue. Only Peter moves an idea to RUNNING or DROPPED.

## Ledger

| ID | Idea | Status | Evidence | Next step | Owner |
|---|---|---|---|---|---|
| I-01 | **Bare-metal authority kernel:** a Rust `no_std` kernel hosting WebAssembly agents that can only *propose*; every effect is exact bytes, human-signed, spent once, with a receipt a stranger can verify. | RUNNING (lab) | RAN (toy): Phase 1 16/16 pass, 11/11 teeth twins bit. Phase 3: 41 rows, 40 pass / 1 fail (kernel signing key extractable from the boot image, fixed in Phase 4 with a separate signer; re-attack UNPERFORMED); hostile corpus 43/43; Kani 28/29 (the 1 is the intended control). Phase 4: 10,000 lifetime steps, 14,327 jobs, 5,096 effects, 197 restores, 265 key rotations, at most one effect per operation throughout. Worst open defect: re-rotating to an already-used key after a rollback revives a spent approval. | Port five items to Prime, each with a teeth twin: (1) witness-retained authority high-water (used keys, highest epoch, consumed set); (2) strict canonical parser with every bound inside it; (3) queryable recovery outcome plus signed checkpoint with incremental import; (4) per-operation refusal on quota exhaustion; (5) storage head never ahead of durable bytes. After milestone 3. | Grok (lab), Dot/Claude Code (port) |
| I-02 | **Collapse to Touch:** AI talking directly to the metal, with no OS layers in between. | PARKED | SOURCE-ONLY (concept). I-01 is the nearest experiment. | Write a one-page threat model: what the boundary is when there is no OS. | Grok |
| I-03 | **Trust onto metal, in trust order:** boundary first, then receipts with a serial anchor, then weights in silicon, then the human key on hardware. "Minimal named signed trust." | PARKED | RAN (toy, partial): Phase 3 receipts measured what actually ran ("approve A, load B" refused). SOURCE-ONLY: a hard-wired-weights note (7 sourced claims, 5 speculative). No TPM, attestation or measured boot. | Keep as the ordering rule for hardware work. No hardware spend without Peter. | Grok |
| I-04 | **Ternary / quad-cube permissions:** three-valued Deny / Unknown / Allow, fail-closed, Unknown never collapses to Allow. | NEXT | RAN (toy): ternary study found no gain from ternary hardware or a ternary VM; the three-valued *type* is worth keeping. Kani verified the authorization algebra in the toy. | Port the exhaustive property tests to Prime's authority checks (port plan item 9), with a twin that collapses Unknown to a boolean and must fail. | Claude Code (proposed) |
| I-05 | **Ternary tesseract orientation memory.** | PARKED | SOURCE-ONLY (concept). Not tested. Muse's ternary Round 2 is paused awaiting Peter. | Peter decides: resume or close Muse Phase 2. | Peter |
| I-06 | **Sovereign Agent Mesh:** Nostr federated swarm with a tiny, closed set of event kinds. Transport is not permission. | PARKED | SOURCE-ONLY. Master Plan v4 defers federation and AgentPassport. The private agent relay (rev `921b3c0`, RAN, reviewed OK for loopback over SSH) is a small step toward agent-to-agent messaging, not the mesh. | Draft the closed event-kind list after milestone 5. | Grok (draft), Dot |
| I-07 | **Auma the field, agents as organs:** one Auma per person; agents are organs inside it, never separate authorities. | PARKED | SOURCE-ONLY (product framing). | Use as product language; Muse later. | Peter, Muse |
| I-08 | **Recursion / LoRA self-improvement run:** a fresh, pre-registered run under a $40 / 4 h cap. | PARKED (blocked) | Recursion reference lab: 18 synthetic CPU checks (REFERENCE/EXAMPLE only). Baseline registration is a partial draft; no model evaluation ran; verified governance training corpus is zero. No GPU yet. | Finish the registration and readiness conditions; Peter approves the GPU and the cap at the time. Not on the critical path. | Dot, Peter |
| I-09 | **Experience Memory permission split:** separate permissions to store / disclose / use as dataset / export / train on / activate. | NEXT | SOURCE-ONLY (spec draft). Master Plan v4 already keeps saved vs indexed separate and requires consent classes. | Fold into the memory-save path design after milestone 3. | Claude Code (proposed) |
| I-10 | **OpenViking semantic recall.** | PARKED | SOURCE-ONLY. Master Plan v4 defers it; full-text search is enough at first. | Revisit after milestone 4 with owner-filter, delete and rebuild tests. | Dot |
| I-11 | **Friend nodes, one VM each.** | NEXT | UNPERFORMED. | Milestone 5. Peter approves each VM's spend. | Dot, Peter |
| I-12 | **Windows build** of the app. | PARKED | UNPERFORMED. | After milestone 5. | Dot |
| I-13 | **Seven-word recovery ceremony.** | NEXT (decision needed) | SOURCE-ONLY: Master Plan v4 keeps it as a requirement but the recorded generator gives only about 34 bits; it needs an independently generated root of at least 128 bits with a reviewed seven-word encoding or an extra factor. | Peter picks the encoding / extra-factor design. | Peter, Claude Code |
| I-14 | **AUMA language licence:** CC BY-SA 4.0 vs AGPL. | NEXT (decision needed) | SOURCE-ONLY: public notices at `89d0cf5` record the AUMA Language as CC BY-SA 4.0, after an earlier "AGPL, no CC grant" decision. Open. | Peter confirms: code AGPL-3.0-or-later plus language CC BY-SA 4.0, or something else. | Peter |
| I-15 | **Network of Aumas improving each other** via reviewed patches; running self-change only ever produces proposals. | PARKED | SOURCE-ONLY. Master Plan v4: self-change produces proposals only; an independent approved release path installs. | After I-06 and milestone 5. | Grok, Dot |
| I-16 | **Hardware passkey / hash display:** a separate trusted screen that shows the exact hash being approved. | PARKED | SOURCE-ONLY. Master Plan v4: a PWA is not a trusted transaction display; high-impact effects need a separately trusted display or foreground human completion. | Milestone 3 uses a normal passkey first; revisit for high-impact effects. | Peter, Claude Code |
