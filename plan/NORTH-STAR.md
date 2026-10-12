> Copied 2026-10-04 from Peter's PRIME-NORTH-STAR.md; verbatim except one redaction marked [REDACTED: ...]; status tags (RAN / SOURCE / NOT YET) added 2026-10-04 with that day's truth on Nebius (live at the SHA in the latest Room line).

# AUKORA PRIME — NORTH STAR (replaces archived MASTER-PLAN-v4 as the front page)

ONE SENTENCE: a personal AI organism on a Linux server you control, reached from your own app, that can grow and
even change itself — and can never act past the boundary without its owner's approval, with a receipt anyone can check.

THE BODY (where each organ lives in Prime main; status = RAN on Nebius / SOURCE / NOT YET):
- [RAN] Harness + Cordis (the body): DeepSeek Harness, every organ is a Cordis plugin. Genesis runtime zipped in at 7ae564b;
  runs on Nebius as aukora-host under systemd, Peter's Electron attached over an SSH tunnel.
- Boundary (the floor): packages/boundary-gate — [RAN] separate Linux users (auma / aukora-host / aukora-gate),
  [RAN, partial] OpenShell sandbox for Auma's hands: her one-shot bash runs in the sandbox as `auma` (L1-a); her file
  tools still run on the host inside the file fence, and run_code / terminals / background bash are refused (L1 R2),
  [RAN] owner-only gate with signed hash-chained receipts (OWNER socket red-team: auma and aukora-host reach it 0 times),
  [RAN] signed-enforcement launch: the runtime starts only with the owner-approved plugin set bound to the release and
  record, never below the monotonic release floor (rollback = a fresh owner card); root tools never import a candidate,
  [SOURCE] 815-attack corpus. The Genesis lab, in Prime.
- [SOURCE] AUMLOK (who): the owner's identity (seven words + handle -> owner key). Approves exact bytes. On Linux the gate user
  holds signing authority [RAN: gate-signed receipts]; the owner approves in the popup in his Electron app [RAN: L2 popup
  shows on Peter's screen; Approve applies only via OWNER review/decide_review, dry-run applied with a signed receipt]
  (later: passkey/Touch ID on his Mac [NOT YET]).
- [RAN] KIRA (what she remembers): every turn hashed into a chain and indexed in OpenViking for recall. Tracked, never
  approved. Emoji-safe, junk and injection kept out of the index.
- [RAN: records written] AURA (what happened): the append-only record of every tool call, approval, memory write and self-change.
  Anyone can verify it with the membrane minimal verifier (vendor/aukora-membrane, minimal/verify.py, no deps)
  [NOT YET run against the Nebius record].
- [SOURCE] NOSTR (her voice to the world): the Aumlok identity's public key; encrypted messages and contacts with safety
  numbers; next: identity backup and home-anywhere sync.
- KERNEL + ACTION GATE + PHI-GUARD + PATH FENCES: every tool call judged before it runs; one-use authority.
  [RAN] action gate + file fence + literal shell secret-path tripwire (fence-r2..r4) on Nebius; [SOURCE] phi-guard.
- [SOURCE] WASM CELL: proposals run in a sealed WebAssembly cell before they become effects (plugins/aukora-box/.../wasm-proposal-cell).
- SELF-CHANGE: Auma proposes a change to herself -> owner approves -> Cordis hot-reload -> receipt. Theme-only first.
  [RAN] gate propose -> OWNER review -> approve applies exact bytes -> signed receipt (dry run, harness-channel TEST proposal);
  [RAN 2026-10-04 11:08 UTC+8] Auma's own gate tool proposed accent #FFD700 (b9187db9), the owner approved it in the
  popup, the gate applied it and signed the receipt, and the running interface picked it up without a restart (hot-reload).
- THE MIND (later): [Ornith / recursion research report and sanitized digest](../research/README.md) [RESEARCH: retained by PR #10; not a deployed provider]. Today DeepSeek [RAN]; next the Nebius recursion model (Ornith) as a model provider, trained on her
  own verified life [NOT YET]; routes to other models through a host-held, capped ask_model tool. The walls stay outside the model.

TARGET DEMO (the plane), each step tagged with 2026-10-04 truth:
- [RAN] Auma chats in the Genesis UI on Nebius
- [RAN, partial] her one-shot bash runs in OpenShell as `auma` (L1-a, live since 9ed4380); run_code, terminals and
  background bash (L1 R2) are refused until the guest carrier is qualified
- [NOT YET] she cannot read the host: her file tools still run on the host inside the file fence; claimed only when L1 is
  complete
- [RAN] she cannot approve her own change
- [RAN 11:08] owner approves Auma's own theme proposal in the popup
- [RAN 11:08] hot-reload; [RAN] signed receipt
- [RAN] she remembers across a restart
- [RAN] a stranger verifies the receipt and the signed ledger (docs/evidence/l2-demo-2026-10-04/verify.mjs), and since
  08a602d against the ledger head anchored outside the pilot (branch ledger-anchor)

AFTER THE DEMO (waves, one family per bee, queen merges, live on Nebius after each):
1. Wire every organ above that is SOURCE-only on Nebius into the running app (Nostr, WASM cell, membrane verifier
   in the Aura face, First Echo, governed recall, path fences/phi-guard).
2. Then the Honey Pot absorb order ([REDACTED: private operator path] HONEY-POT.md, 73 families; not in this repository), top-10 gems first.
3. Then Ornith as Auma's model.

RULES: HONEY-POT-PROTOCOL. "On main" = on GitHub Prime main. "Live" = running on Nebius at a named SHA.
Only Peter says "done". Safety lives inside AUKORA (no GitHub enforcement). Nothing old is left behind: every
family in the Honey Pot map ends either in Prime main, or on the map with the reason it was dropped.
Reference papers: docs/AUKORA-GOLDEN-BOUNDARY.md (Genesis).
What Prime takes from the field (Hermes, goose, OpenClaw, harness-security research): plan/FIELD-DISTILL.md (directions, not claims).

---

ADDED 2026-10-12 (Peter's direction that day; written by the Buzz builder session). Nothing above is changed.
Status words as above, plus: RAN-MAC = ran on Peter's Mac only, not on Nebius.

ONE REPO, ONE PLAN: this repository (aumara-xyz/aukora-prime, public) is where everything ends up, and this file is
the plan Peter steers by. Other repositories are sources to absorb from, not second homes. "Prime main" means this
repository's main; an older private repository with a similar name (last pushed 2026-10-03) is not it.
Live on Nebius today: release 3673b98, a commit of this repository, under the old service name `aukora-genesis`.
Main is ahead of it (63 files at 4d59ad8); the safe way to bring the pilot up to main is NOT YET named or checked.

THE NETWORK UNDER THE NODE: BUZZ.
The harness and Cordis stay: they are the node. Buzz (block/buzz, Apache-2.0: a Nostr relay with channels, threads,
search, media, workflows, agents as members, and desktop and phone apps that pair by scanning) goes underneath as the
network. Its relay runs on the node; Auma joins it as a member; people reach the node from Buzz's own apps today and
from Aukora's interface later. Approvals stay with the boundary gate; Buzz carries the signed results so others can
check them. Nothing in Prime is replaced.
- Why it fits: [SOURCE, in the live release] plugins/aukora-nostr already gives each node a Nostr identity bound to
  the Aumlok key, contacts with safety numbers, NIP-17/NIP-44 private messages, a relay client with NIP-42 sign-in,
  and a phone-approval verifier. It has no relay of its own (its defaults are public relays). Buzz is that relay,
  owned by the node.
- [RAN, read-only look at the pilot 2026-10-12] aukora-nostr ships in the live release but is NOT in its plugin set
  and has no state on the pilot: it is source there, not running. The pilot's `aukora-relay` service is not a Nostr
  relay: it is a small token-authenticated HTTP message API (/v1/messages) for headless clients, so it and Buzz do
  not overlap.
- [RAN-MAC 2026-10-12, test keys, plugin code unchanged at b887061, Buzz relay built from the fork] aukora-nostr
  against a Buzz relay on the same machine: it connects and signs in (NIP-42); a private message it wraps and
  publishes is accepted, the recipient fetches it, opens it and proves the sender; a stranger asking for the
  recipient's messages is refused by the relay. ONE DIFFERENCE: NIP-17 stamps wraps with a random time up to two
  days back, and Buzz's relay refuses any event more than 15 minutes from its clock, so the plugin's normal send
  is refused ("event timestamp too far from server time"); stamped with the current time it works. Either the
  relay lets kind 1059 be older, or the plugin stamps "now" for this relay. Not decided.
- [NOT YET, unchecked] joining a Buzz channel (NIP-29 groups: kind 9 with an `h` tag and membership), which
  aukora-nostr does not do today; mounting the plugin on the pilot means a new owner-approved plugin set.
- Several nodes can run side by side with one person playing every user: the cheapest test of the network.

WHAT THE BUZZ WORK ADDED (in the private fork aumara-xyz/aukora-buzz; see its AUKORA-PLAN.md and shim/README.md):
- [RAN-MAC, real Touch ID] an agent's shell command held until the owner's sealed key approves it; the signed
  approval published in the channel; a stranger verifies it with the engine's single-file verifier (aumlok-id b5b6ca8).
  This is the "later: passkey/Touch ID on his Mac [NOT YET]" line above, built for Buzz; it is not yet joined to the
  pilot's gate, which signs with its own key. Which key signs on the pilot is an open decision.
- [RAN-MAC, real Touch ID] Buzz's own workflow approval step released only by the owner key.
- [RAN-MAC, real Touch ID] standing bounds: one signature lets an agent work in one folder with no touch per command,
  enforced by the macOS sandbox (writes only in the folder, no network). A convenience line, not containment.
- [RAN-MAC, real Touch ID] goal loop: an agent keeps working until an owner-written check passes.
- [RAN-MAC, real Touch ID] Prime Agent (Prime Intellect's open-source agent; unrelated to Aukora Prime) running in
  Buzz on DeepSeek and held by the same gate, through a per-tool-call hook patched into it.
- [RAN-MAC, test keys] a refusal by the owner closes the rest of the turn; a receipt checker for bounds.
- On the Mac there is no containment: the agent runs as the owner. The claim "a refusal holds even when the agent
  tries another route" can only be made on Linux, on the floor described above.

WHAT CONTACT ADDED (aumara-xyz/aukora-contact):
- [RAN, Mac + iPhone] two screens exchange light and both sign the moment (the light handshake only).
- [NOT YET on devices] approving an exact text on the phone; sound and motion senses.
- [RAN-MAC, test receipts] a co-presence receipt riding beside a Buzz grant as evidence that grants nothing.
- [RAN, outside any repository] a graded-task loop: one model writes, one attacks, hidden tests decide (62 runs).
- [SOURCE] a recursive-language-model harness with known defects; never run inside Buzz.
This is the human-to-human invitation: a person is let in by meeting another person.

CORRECTIONS TO STATUS ABOVE, as of 2026-10-12 (from the Genesis lead's read; nobody re-ran these that day):
- KIRA / OpenViking: the service is up; the one recorded saved note is saved but not indexed and not searchable.
  Recall is not shown.
- AURA: the anchor publisher runs on the owner's Mac; which side signs and which holds the ledger is unchecked.
- Cordis: the harness runs on the Cordis host; Prime's Cordis tool provider is unmounted.
- OpenShell: 10-04 FAIL stands (34 denied, 1 allowed, through inherited sockets). 10-06 staging: guest 33 denied /
  0 allowed; host-as-auma 44 / 6 with six exceptions the owner accepted. No probe on 10-12.
- Not in any running product: First Echo, the one-use kernel decide(), governed recall, the membrane write guard,
  Pentora (display), Laya (lab result: escalate only, 13.5% false alarms), the WASM cell ("a relay, not a sandbox").
- The H200 lab node is stopped and is not needed until Ornith is the model.

ORDER FROM HERE (each step ends with a check someone runs; only Peter says "done"):
1. Pilot healthy from the owner's Mac (owner bridge reconnected 2026-10-12); name and check the safe path to bring
   the pilot up to main.
2. Buzz relay on the pilot under its own Linux user, loopback only.
3. Auma joins the relay as a member through aukora-nostr; a message from Buzz's phone app reaches her and her
   reply comes back.
4. One owner approval path: the gate on the node decides; the owner's touch on his own device is what releases it;
   the signed result lands in the channel and a stranger verifies it. THE DEMO: phone -> Auma -> held -> touch ->
   receipt -> verified.
5. Standing bounds enforced by the floor (separate user + OpenShell) instead of the macOS sandbox, then the test
   that matters: deny, the agent tries other routes, all refused, by an independent tester.
6. A builder agent (Prime Agent) works from this file inside those bounds, one step at a time, each with an
   owner-written check; pushes and deploys ask the owner. This is where the owner stops prompting and only approves.
7. One memory, decided by test: Buzz's agent notes, Kira for what the owner signed, OpenViking for recall.
8. Co-presence on a grant with real devices (can happen at any time).
9. Wave 1 above (wire every SOURCE-only organ), then the Honey Pot absorb order, into this repository.
10. A second node joins by invitation; a person on it verifies an approval from the first.
11. The front door: "Go Sovereign" (a hosted node, first week covered, then handed to its owner; later anyone
    hosts their own), invitations by co-presence, then the phone app and Bitchat, then spatial and AR interfaces.

HONEY POT, as its keeper reported on 2026-10-12 from the 10-04 map (not re-run; Prime has moved since):
- The index has 110 families; the Prime absorb list has 73 lines (15 "no" + 58 "partial", none "yes"). Across the
  110: 9 yes, 73 partial, 28 no. "Yes" means files present, not wired or running. The gap between 110 and 73 is
  not reconciled.
- Top gems in the map's order (ran in the installed app first): path-law/read-fence (aukora-seed paths, law, guard),
  phi-guard (action-gate policy and kernel), OpenViking, the approval popup with its signer and stranger verifiers,
  release/build scripts, caged worker and workspace patch, the authority kernel, the Aura chain, governed recall,
  loopback doors. This is not the absorb order, which starts with foundations.
- Most at risk of being forgotten: path-law/read-fence and phi-guard (Prime has nothing equivalent); the cross-node
  relay from the lab (in no repository); conversation-safety-rails and organism (source only); drift sentinels;
  and about 72 commits in a local checkout of the older private Prime repository that never reached GitHub.
- Messaging families: nostr-messaging (#57), cross-node-federation (#58), aumlok-identity (#33, prerequisite for
  both), conversation-safety-rails (#61). Buzz under the node is how #57 and #58 get a relay of their own.

OWNER DECISIONS OPEN: which key signs on the pilot; the go to change anything on the pilot; whether the Apache fork
loading the AGPL engine by path is acceptable (a question for counsel) and where the Buzz code finally lives;
which model runs the builder agent.

SAY PLAINLY TO ANYONE SHOWN THIS: an approval proves a key signed exact bytes after a biometric match on one device,
not a unique person. "Used once" is kept by the gate that counted, not provable offline. A co-presence receipt is
evidence and grants nothing. Buzz is Block's; this is built on a fork and has not been sent to them.
