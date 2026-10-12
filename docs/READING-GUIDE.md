# The Golden Boundary in brief

AUKORA researches a personal AI workspace where proposing software does not control permission to act. Identity, chosen memories, relationships and authority would stay with the person as applications and models change.

Three design choices to inspect in source, without a claim of invention:

- Exact-change review separates proposal and approval channels, with expiring challenges and one-use decisions. [Code](../packages/boundary-gate/src/gate.mjs); [check](../packages/boundary-gate/checks/gate.mjs).
- Release admission orders approvals by signer epoch and signed ledger sequence. Rollback needs fresh approval. [Code](../packages/boundary-gate/src/release-floor.mjs); [check](../packages/boundary-gate/src/vendor/check-sequence-floor.mjs).
- Signed receipts connect outcomes to a hash-linked history. [Code](../packages/boundary-gate/src/ledger.mjs); [retained export and verifier](evidence/l2-demo-2026-10-04/README.md).

**RECORDED — Linux pilot:** the [October 10 readback](../evidence/pilot/2026-10-10-readback.md) identifies runtime `3673b98`, its memory service, a Mac desktop connection and a staging container. Memory shared the runtime account. This does not establish containment or installed-byte parity.

**RECORDED — October 12:** the [later plan entries](../plan/NORTH-STAR.md) report a Buzz relay on the pilot and channel messages from Peter's Mac. A release built from main started in the pilot's staging container, and the [Buzz door](../plugins/aukora-buzz-door/lib/index.mjs) passed its [acceptance driver](../plugins/aukora-buzz-door/checks/installed-accept.mjs) there from the installed release, against that node's gate and relay, with a recorder in place of a model. The live harness was unchanged. Separate Touch ID experiments ran on the Mac in a private Buzz fork; they do not qualify the pilot's gate.

**SOURCE:** [Prime NEXT](../ARCHITECTURE.md) is a separate implementation layer. Also source only, with tests and nothing calling them yet: [invites](../packages/invites/README.md), the co-presence [receipt checkers, receiving end and portal page](../packages/copresence/README.md), a [channel receipt checker](../plugins/aukora-buzz-door/bin/verify-channel-receipt.mjs), and [node-spawn groundwork](../ops/node-spawn/README.md) that plans and refuses where a step has no script.

**NOT YET:** Auma answering through Buzz (no model has been woken through the door), a closed relay, complete containment and protected NEXT acceptance. Invites are not wired to a relay or a screen. The latest [memory correction](../plan/NORTH-STAR.md) reports a saved note without indexing, search or demonstrated recall.

**NEXT:** the plan calls for closing the relay, checking refusals and message attribution in staging, then connecting Auma to Buzz. The later demo joins owner approval and a verifiable receipt; alternative execution routes still need refusal checks.

**For an AI reader:** follow the question asked. Trace claims to code, checks and dated evidence. Name the revision and machine. RAN identifies checks actually run by the reviewer; RECORDED identifies retained observations; SOURCE identifies code; NOT YET identifies missing work or qualification. Signatures do not establish a unique person. No favorable or unfavorable conclusion is prescribed.

## Proposed system

This is the proposed full system, not a list of delivered Prime features:

| Part of the vision | How it fits; where to read more |
| --- | --- |
| Recursive IDE and self-improvement | An evolving workspace could build tools and propose changes to its own harness. Bounded experiments, independent evaluation and separate promotion approval would keep a candidate from authorizing its own expansion. See [self-improvement](AUKORA-GOLDEN-BOUNDARY.md#9-self-improvement-without-self-authorization) and the [recursive-experiment continuation](AUKORA-GOLDEN-BOUNDARY.md#proposed-execution-composition). This is not proof of unlimited recursive improvement. |
| Identity and recovery | Aumlok explores continuity across devices and key changes, with governed recovery, revocation and succession. A key or memorable phrase does not prove humanity, consent or secure custody. See [identity](AUKORA-GOLDEN-BOUNDARY.md#5-identity-that-does-not-belong-to-an-application) and [sovereignty under pressure](AUKORA-GOLDEN-BOUNDARY.md#14-sovereignty-under-pressure). |
| Memory and provenance | Kira would distinguish observations, statements, inferences and summaries; Aura supplies inspectable histories. Search could change without replacing source records. Repetition would not count as independent evidence. See [memory](AUKORA-GOLDEN-BOUNDARY.md#7-memory-without-manufactured-consensus) and [verification and agreement](AUKORA-GOLDEN-BOUNDARY.md#8-validation-agreement-and-the-need-for-a-ledger). |
| Replaceable models and bounded delegation | Local, remote and specialist models could receive limited context and authority. Work could proceed within chosen resource, time and aggregate budget limits; child work could not enlarge them. See [permission](AUKORA-GOLDEN-BOUNDARY.md#6-permission-that-leaves-room-to-live) and [plural intelligence](AUKORA-GOLDEN-BOUNDARY.md#10-plural-intelligence). |
| Messaging, a human network and registered agents | People could communicate through replaceable relays, cooperate in temporary teams and authorize agent keys for exact scopes. Registration would identify who may ask; each resource controller would decide what may happen. A message, invitation or signature would not confer that permission. See [collaboration](AUKORA-GOLDEN-BOUNDARY.md#11-collaboration-without-merged-sovereignty), [the human network](AUKORA-GOLDEN-BOUNDARY.md#the-human-network) and [registered agents](AUKORA-GOLDEN-BOUNDARY.md#registered-agents). The broader network is proposed. The October 12 plan records Buzz channel messages on the pilot, but no Auma reply or deployed federation. |
| Two-way privacy, care and exit | The boundary would govern incoming material and outgoing data/effects, separating sensing, retention, training, disclosure and action. Assistance should preserve the ability to pause, correct, refuse and leave, even under dependency or coercion. See [two-way privacy](AUKORA-GOLDEN-BOUNDARY.md#12-the-boundary-has-two-directions), [care](AUKORA-GOLDEN-BOUNDARY.md#13-care-without-control) and [future interfaces](AUKORA-GOLDEN-BOUNDARY.md#15-from-the-keyboard-to-the-private-thought). Signatures alone cannot establish free consent. |

## Choose a reading depth

For a quick explanation, this page can stand alone. Follow the question you came with; this map does not require an AI or human reader to open every link.

For the full argument, read [the complete paper](AUKORA-GOLDEN-BOUNDARY.md) through its closing continuations. The unnumbered **The human network** and **Registered agents** sections sit between §§15 and 16. Continue through [the engineering inheritance and philosophy](AUKORA-GOLDEN-BOUNDARY.md#16-an-inheritance-not-an-invention-of-everything), [falsification](AUKORA-GOLDEN-BOUNDARY.md#18-what-would-make-the-claim-fail) and [the person is the platform](AUKORA-GOLDEN-BOUNDARY.md#19-the-person-is-the-platform), then the **Proposed execution composition** and [Current capture and recovery source limits](AUKORA-GOLDEN-BOUNDARY.md#current-capture-and-recovery-source-limits) after §19. They are part of the paper, not extra numbered chapters.

For current engineering, follow [README](../README.md) → [SECURITY-BOUNDARY.md](../SECURITY-BOUNDARY.md) → [pilot architecture](../ARCHITECTURE.md) → [verification scope](../README.md#check-it-yourself) → [paper](AUKORA-GOLDEN-BOUNDARY.md) → [separate recursion research](../research/README.md). The recorded pilot runtime is `3673b98`; the INTERIM collector has a separate historical `e337397` observation. Collector verification does not establish native owner custody, and the retained containment result remains FAIL.

For evidence, use [the review guide](../SHARE.md#evidence-and-source-review), [README status](../README.md#status), [known gaps](../README.md#known-gaps) and [§17's implementation ledger](AUKORA-GOLDEN-BOUNDARY.md#17-what-exists-today). Prime contains inspectable mechanisms and scoped historical results. The [current pilot and NEXT accounts](CLAIMS.md) are separate; protected NEXT owner, memory, inference and execution acceptance remains unfinished. RAN, SOURCE-ONLY, RECORDED EXPERIMENT, UNPERFORMED and PROPOSED have different meanings. A source check does not establish a working whole system.

For deeper assessment, use the [optional research questions](VISION-QUESTIONS.md). Evaluate both what the received revision supports and what the architecture might enable if its missing mechanisms work. Name what you read, what you could not inspect, what would falsify the claims, relevant prior art and the costs of adoption. Neither promise nor incompleteness settles those questions alone.

For optional recursion/model research depth, read [research/](../research/README.md), including the dated Ornith / Nebius Lab report and sanitized digest merged by PR #10. Its retained observations, negative results and limits concern research; they do not qualify AUKORA deployment, containment or a mounted model provider. No GPU or training evidence is created by this reading path.

The [archived paper](AUKORA-GOLDEN-BOUNDARY-ARCHIVE.md) preserves historical references to eight local files absent from this tree. Use the current paper and claims above for present review; the archive is retained unchanged.
