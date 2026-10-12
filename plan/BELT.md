# The belt: what is left to bring into Prime (2026-10-12)

The Honey Pot map has 110 families. 36 came in whole with the Genesis runtime (commit `c358ac7`) and one more (the seed
path law) is already identical here. The other 45 were each read at their source by an independent reviewer (Codex,
four read-only jobs; own tests run where that needed no network, keys or database). Nothing was copied on the
strength of this table: no family got the verdict COPY. The full reports and source locations are private, with
the Honey Pot keeper.

- PORT (28): worth having; needs rewriting to this repository's stack or rules first. S or M is the size.
- SUPERSEDED (9): this repository already has the same thing or a stronger one. Nothing to do.
- PARK (4): research or notes; belongs under research/ if anywhere, not in running code.
- DROP-CANDIDATE (4): the reviewer would leave it behind. Only Peter drops a family.

A row is finished when it is marked DONE here with the commit, or Peter has ruled on it. Where a reason says the
licence is unstated or proprietary, the code is the owner's own and the licence is his to state.

| # | family | verdict | size | the reviewer's reason | state |
|--:|---|---|---|---|---|
| 2 | state-root/backup | PORT | S | Runnable, but destructive overlap and incomplete manifests prohibit copying as-is. | open |
| 5 | cordis-plugins | PORT | S | Reproduced narrow synchronous-disposal gap; Prime already has most lifecycle controls. | open |
| 6 | durable-workflow | PORT | M | Useful restart/idempotency semantics; Convex conflicts with Prime’s PostgreSQL stack. | open |
| 7 | lane-send leftover | PORT | S | Missing client, but repeated-verb bypass and unbounded sending need repair. | DONE (ported; see the commit that changed this row) |
| 8 | agent-engine-binding | PORT | S | 22 reconciliation tests pass; retain comparator, exclude automatic-approval client. | DONE (ported; see the commit that changed this row) |
| 10 | inference-providers | SUPERSEDED |  | Prime has the same lane with newer reservation and worker handling. | no action |
| 11 | local-model-inference | PORT | S | Recoverable bounded proposer utilities; pinned experiment reports NO_SIGNAL. | open |
| 13 | recursion/lineage | PARK | S | Research protocol and negative results belong in research, not runtime. | parked |
| 14 | model-tuning/lora | PORT | M | Fixture instrument passes; policy adapter and licensing need resolution. | open |
| 15 | nebius-compute | PORT | M | Useful registry concept; current checker is warn-only and can fail open. | open |
| 16 | egress-control | PORT | S | Useful DNS pinning; offline tests pass, proprietary licence blocks adaptation. | open |
| 19 | capability-confinement | PORT | S | Small DSH inheritance hardening missing at the general subprocess seam. | open |
| 21 | strict-json/canonicalization | PORT | S | Useful display scanner, but confirmed bypass and unresolved licence. | open |
| 24 | governed-capsule | PORT | M | Keep frozen candidate/check binding; avoid importing patched Council runtime. | open |
| 31 | pqc-hybrid-signing | PORT | M | Primitive already in Prime; offline rotation verification remains useful. | open |
| 35 | time-proof-anchors | PORT | S | Offline beacon verification passes; retain advisory scope. | DONE (ported; see the commit that changed this row) |
| 37 | authority-graph/policy-rings | PORT | M | Classifier useful; donor table fails coverage and ratification cannot transfer. | open |
| 38 | effect-settlement | PORT | S | Checker passes pinned fixture; Prime already has stronger runtime recovery. | DONE (ported; see the commit that changed this row) |
| 40 | code-attestation | SUPERSEDED |  | Prime already binds exact releases to approval and protected rollback ordering. | no action |
| 43 | identity-anchor/continuity | PORT | S | Small session-overlap helper useful; private veil/persona stack excluded. | open |
| 44 | dream-consolidation | PORT | M | Distinct receipt-to-lesson slice; replay inflation, producer and licence unresolved. | open |
| 46 | postgres-memory-store | PORT | M | Useful lifecycle checks trapped in fixed host/run assertions. | open |
| 47 | memory-erasure/retention | PORT | M | 87 tests pass; add custody protection and Prime owner-forget binding. | open |
| 48 | retrieval-engines | SUPERSEDED |  | 22 tests pass; Prime already has the evolved engine. | no action |
| 49 | resource-governor | SUPERSEDED |  | Both implementation modules already byte-identical in Prime. | no action |
| 50 | hosted-node-web-tier | DROP-CANDIDATE |  | Working static-page curtain, not a hosted tier; licence unstated. | for Peter |
| 51 | skills | PORT | M | Governed text authoring useful; OpenCode services need replacement. | open |
| 52 | self-improvement-loops | PARK | S | Numerical research with restrictive rights and unconfined generated code. | parked |
| 54 | wolf-paper-trading | PORT | M | Extract synthetic portfolio limits; reuse stronger Prime receipts. | open |
| 55 | room | DROP-CANDIDATE |  | Current entry points explicitly retired; wrapper sends private messages. | for Peter |
| 58 | cross-node-federation | SUPERSEDED |  | Prime has the evolved relay; dirty author migration needs separate review. | no action |
| 59 | drift-sentinels/immune | PARK | S | Lexical model-drift research tied to a forge, not a portable integrity gate. | parked |
| 60 | ops-and-tooling | PORT | S | Useful pure planner; adapter conflicts with Prime process ownership. | open |
| 61 | conversation-safety-rails | SUPERSEDED |  | The Genesis honesty and turn-trust rails are here since `c358ac7` (Honey Pot's byte check). The lab's fuzz court and injection court are in no repository: a PORT of those as tests is open. | open (courts only) |
| 63 | self-knowledge/proprioception | PORT | S | Cited tests pass; replace Phi-specific readers and assertions. | open |
| 66 | agent-swarm | PORT | S | Rebuild task/status slice atop existing licensed non-authority evidence. | open |
| 67 | browse-web-hands | DROP-CANDIDATE |  | Unauthenticated browser control with sandbox disabled and admin bridge. | for Peter |
| 68 | fusion-council | PORT | M | Keep exact-SHA review semantics; replace Crush and add bounded spend. | open |
| 69 | spatial-shell/cube-glyphs | PORT | S | Pure tests pass; no source licence grant, and demo signing is unnecessary. | open |
| 71 | knvs-canvas | SUPERSEDED |  | Prime already holds the lineage; stale integration needs repair, not recopying. | no action |
| 72 | renderer-csp-hardening | PORT | M | Useful boundary design, but proprietary code cannot be copied. | open |
| 74 | boundary-gate | SUPERSEDED |  | Prime has the stronger factored gate and carried lab substrate. | no action |
| 93 | installer | SUPERSEDED |  | Prime already has stronger completion-marker and packaging checks. | no action |
| 94 | invites/vouch-graph | DROP-CANDIDATE |  | Public graph leakage and missing verifier/enrollment safeguards. | for Peter |
| 100 | parallax | PARK | S | Untracked proposed research with no independent instrument or implementation. | parked |
