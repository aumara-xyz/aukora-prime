# Skunkworks: an owner-sovereign agent that learns its own runtime

Status: **PROPOSED. Nothing in this plan has been run.** Written 2026-10-06. Every number is labelled
SOURCE (read from a public page or file), ARITHMETIC (computed here, not measured) or ESTIMATE (a guess, to be replaced by a measurement).
This is a lab track. It does not change the running release, `main`, or any authority code.

## The idea in one paragraph

Take an open-weights model that is already strong at agentic coding (Ornith-1.5), and teach it, first, the native
architecture of a frozen, pinned copy of an open-source agent runtime (prime-agent upstream). Then run that model inside
AUKORA's containment as an untrusted worker. As it pulls in AUKORA's own tested and proven pieces, it trains on what has
already passed review. The model gets better at the system it lives in. AUKORA keeps deciding what it is allowed to do.

Capability can come from anywhere. Authority comes only from the owner's key. Self-improvement inside the lab is free;
anything that expands what the agent may do is a card the owner approves.

## Why this order

1. The upstream runtime is a **frozen download**: a fixed commit does not move, so a fine-tune is reproducible.
   AUKORA's own repository is a moving target and is not the first training corpus.
2. The model learns the runtime it will run on before it learns our additions.
3. Our additions enter only after they are tested and proven, so the model trains on verified work and not on drafts.

## Pinned inputs

| Input | Pin | Label |
|---|---|---|
| prime-agent upstream (the runtime to learn) | `PrimeIntellect-ai/prime-agent` at `7a52276cb17310f331f1075f28fa5cf9c4ae0a0a` | SOURCE (commit read 2026-10-06) |
| Its license | MIT; keep the copyright and permission notice | SOURCE (LICENSE file read in a separate review) |
| Ornith-1.5-397B and -35B-A3B | `ornith-ai` on Hugging Face; license tag `mit`, not gated | SOURCE (API metadata, license file itself not yet read) |
| Official FP8 build of the 397B | `ornith-ai/Ornith-1.5-397B-FP8` | SOURCE |

"prime-agent upstream" is a different project from AUKORA Prime. No affiliation is implied.

## Hardware and cost (all unmeasured)

| Setup | Weights size | GPUs (141 GB each) | Label |
|---|---|---|---|
| 35B-A3B, FP8 | ~36 GB | 1 | ARITHMETIC |
| 397B, FP8 | ~400 GB | 4 minimum, 8 comfortable | ARITHMETIC |
| 397B, BF16 | ~800 GB | 8, little room for long contexts | ARITHMETIC |
| 397B, 4-bit | ~200 GB | 2 to 3, with quality loss | ARITHMETIC |

- A single H200 instance has been recorded at about $5.40 per hour. An 8-GPU node, if priced linearly, is about $43 per hour. ESTIMATE.
- Whether an 8-GPU H200 node is available to us is unknown. Capacity may be the real limit. NOT VERIFIED.
- Nebius credits are being requested. Do not start the 8-GPU stage before they land.

## Stages and gates

Each stage ends with a stop decision. A stage that fails ends the track at that stage.

**Stage 0: paperwork, no GPU.**
Read the Ornith license files and the prime-agent notice requirements. Decide what must travel with any released weights.
Gate: license read in full, notices listed.

**Stage 1: can the 35B drive the tools? (about 1 to 2 GPU-hours, ESTIMATE)**
Serve Ornith-1.5-35B-A3B on one H200. Run prime-agent upstream as a disposable guest, inside OpenShell, with no keys, no owner
state and egress denied. Give it a small fixed set of tasks.
Gate: it completes the tasks with correct tool calls at a rate set in advance. Its published benchmark scores are claims until this passes.

**Stage 2: native-architecture tuning on the 35B.**
Corpus: the pinned prime-agent source, its docs, its tests, its tool schemas and a short directive describing the role. No private
data. Evaluation: questions about the runtime and small changes to it that must pass its own tests, drawn from a held-out set the
model never sees in training.
Gate: the tuned model beats the untuned model on the held-out set by a margin fixed before training. If not, the recipe is wrong and
Stage 3 does not start.

**Stage 3: guest harness with a capped mentor.**
The tuned model works inside the guest. A host-held, rate-limited broker may ask an external model (for example DeepSeek) for advice.
The API key lives on the host broker and never in the guest. Every proposal, refusal and approval is recorded.
Gate: a replayable log of what it tried and what the wall refused.

**Stage 4: the 397B.**
Repeat Stage 2's recipe at scale on a multi-GPU node, only if Stage 2 passed and credits cover it. Tooling for fine-tuning a model this
size is not verified.
Gate: a measured improvement over the 35B on the same held-out set.

**Stage 5: self-evolution with a fixed judge.**
The model proposes tasks, scaffolds and changes to its own harness. A fixed evaluation it cannot edit scores them.
Training data is limited to replay-verified, accepted work. A candidate that regresses is kept and inspectable, not deleted.
Anything that expands authority is a card for the owner.

## Guardrails that do not move

1. The agent proposes. The owner's key decides. A separate gate applies exactly what was approved.
2. The judge, the gate and the boot identity are outside the agent's reach. If it can edit its own judge, "improvement" means nothing.
3. No owner keys, credentials or host sockets inside the guest.
4. A hard stop time and a hard spend cap before any GPU starts. No idle-based shutdown that the serving process can defeat.
5. Training data is pinned, hashed and reproducible. Test data is sealed and never trained on.
6. Every claim is labelled RAN, SOURCE, NOT VERIFIED or UNPERFORMED. Negative results are published.

## What this is not claiming

- No result exists yet. Ornith's published benchmark numbers are the vendor's own, on its own harness.
- Fine-tuning on a frozen runtime does not make the model trustworthy. It makes it better at that runtime. The gate does the trusting.
- Self-improvement does not remove the owner from the loop. It reduces how often the owner needs to be asked about routine work.

## Kill conditions

- Stage 1 tool-call rate below the pre-set bar.
- Stage 2 shows no held-out gain over the untuned model.
- The license review finds a restriction that blocks fine-tuning or redistribution.
- Any run reaches a host path or credential from inside the guest.

## Open questions

1. Which fine-tuning framework handles this MoE architecture at the 397B scale.
2. Whether an 8-GPU H200 node is obtainable, and its real price.
3. What evaluation set measures "understands the runtime" without leaking into the training data.
4. How to keep the mentor broker's key out of every log.

## Owners (proposed)

Peter approves spend, GPU start times and promotions. Claude orchestrates and checks against the box. Dot builds and runs.
Auma reviews from inside, look-only. A reviewer who cannot execute their subject says UNPERFORMED, never passed.
