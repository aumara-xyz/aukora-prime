# AUKORA Convergence: the front page

Last updated 2026-10-03 ~10:00 WITA (UTC+8) by Grok. This page wins over every older plan. Details live in [MASTER-PLAN-v4.md](MASTER-PLAN-v4.md); Peter's ideas live in [IDEAS-LEDGER.md](IDEAS-LEDGER.md).

Labels: **RAN** = executed and the output exists. **SOURCE-ONLY** = the code says so, nothing ran. **UNPERFORMED** = not done.

## North star

1. Peter opens his Electron app and talks to Auma, and gets a **real model reply**.
2. One **passkey-approved memory save**, plus the **same save refused** when there is no approval.
3. **Two friends** running Auma on their own nodes.
4. Later: a network of personally owned Aumas. Nodes talk over Nostr. **Transport is not permission.**

## Current state (2026-10-03 ~10:00 WITA)

| Fact | Label |
|---|---|
| The agent relay is live on the private pilot at rev `921b3c0`. The Dot/Grok handshake over it worked. | RAN |
| A real Auma reply in the app. | UNPERFORMED |
| A real owner-approved memory save. | UNPERFORMED |
| Public `main` is `89d0cf5`. The suite is red: 59 pass, 6 fail, 1 not run. The cause is commit `b867c72` (a deliberate source change, not the environment). An explicit "retire this unsent proposal" command is approved **with conditions**. | RAN (reproduced) |
| Integration head `a8be12f`, now `40e1033`, exists only on Peter's Mac, not on GitHub. | RAN (lanes audit) |
| Lanes audit: 364 checkouts, 224 abandoned, 176 lane commits not merged, Mac disk 97% full. | RAN |

## Operating rules

1. **One trunk.** Lanes merge into it every few hours. Build plus the suite run after every merge.
2. **Red gets fixed first.** No new lanes until the trunk builds and the suite runs.
3. **Teeth twins.** Every check ships with a twin that disables only that check and must fail, in the same run.
4. **Label everything** RAN / SOURCE-ONLY / UNPERFORMED.
5. **Never fake.** If something fails, name the exact failing command and its output.
6. **Peter alone** approves spend, cloud changes and credentials.
7. **A Grok review is never Peter's approval.**

## Roles

- **Peter:** holds the key. Decides.
- **Dot (GPT/Codex):** lead builder and integrator. Owns the trunk.
- **Claude Code:** builds (proposed: owns the memory-save path) and red-teams merges. Claude cloud and Claude local are **separate identities**.
- **Grok:** red-teams against the actual bytes; keeps this page and the ideas ledger current.
- **Muse:** marketing, later.
- **Astra, GLM:** outside reviewers.

## Next 5 milestones, in order

| # | Milestone | Owner | Pass test |
|---|---|---|---|
| 1 | Trunk pushed, lanes reconciled | Dot (Grok reviews) | One integration branch on GitHub contains `40e1033` or its successor. Every one of the 176 lane commits is merged or explicitly dropped. Build plus suite run on that commit, with the exact counts posted. |
| 2 | The Electron app talks to Auma | Dot, Claude Code reviews | Peter types in the app and gets a real DeepSeek reply. The provider call is visible in a receipt. Spend stays under the proposed **$10 chat cap** (Peter approves cap and key setup). The twin: with the route disabled, the app says "unavailable" and does not fake a reply. |
| 3 | Passkey enrolment plus one real save | Claude Code (proposed), Dot integrates | Peter enrols a passkey. One reduced-guarantee memory save goes through with his approval and leaves a receipt. The refusal twin: the identical save without approval is refused, with zero effects. |
| 4 | Restart, export, restore | Claude Code and Dot | After an app restart, the saved item is recalled with its citation. Export, then restore into an empty target, and the item is still there with its original ID. |
| 5 | Two friend nodes | Dot, Peter approves spend | Two friends each run Auma on their own VM, with their own key, and each completes milestone 2 and 3 on their node. |

## How to coordinate

- **GitHub Issues** for work and decisions. Labels: `milestone`, `blocker`, `review`, `decision-needed`, `idea`, and `lane:*`. Start at the "Convergence tracker" issue.
- **The relay** is only for short status pings. Anything that matters goes into an issue.
- Comment format: task, revision, claim/review/decision/fix, evidence ref, result, blocker, next owner. No "OK/thanks" loops.
- Decisions come only from Peter.
- Full reference plan: [MASTER-PLAN-v4.md](MASTER-PLAN-v4.md). Ideas: [IDEAS-LEDGER.md](IDEAS-LEDGER.md).
