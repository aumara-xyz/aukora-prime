Earlier entries preserve historical reports. Later dated corrections in [NORTH-STAR.md](NORTH-STAR.md) supersede their status.

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
  was refused ("event timestamp too far from server time"). FIXED in the fork's relay the same day (aukora-buzz
  c-relay change "accept a gift wrap dated up to two days back"): the plugin's own send, unchanged, is now accepted,
  fetched and opened; a wrap 3 days old or in the future, and any other event more than 15 minutes off, are refused.
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

SAY PLAINLY TO ANYONE SHOWN THIS: a legacy gate-signed approval proves the gate key signed the bound bytes; it does
not prove a biometric match, owner-key custody or a unique person. "Used once" is kept by the gate that counted,
not provable offline. A co-presence receipt is evidence and grants nothing. Buzz is Block's; this is built on a
fork and has not been sent to them.

STEP 2, 2026-10-12 (written by the builder session in this repository; nothing above is changed):
- OWNER GO: Peter wrote "nebius go" to the builder on 2026-10-12, first-hand. It covers step 2: a new user and a new
  service beside the harness. Bringing the pilot's harness up to main is a separate go, not given.
- [RAN on the pilot] ops/buzz-relay: user `aukora-buzz` (its own subordinate id range, no sudo), one rootless Podman
  pod with the relay, Postgres 17 and Redis 7, state under /var/lib/aukora-buzz, secrets made on the node and never
  printed. The relay image was built on the pilot from aukora-buzz 9def3e9 (has the gift-wrap time fix).
  `aukora-buzz.service` started; ops/buzz-relay/check.sh 10 of 10 PASS: the three containers run, /health answers on
  127.0.0.1:18740, aukora-buzz listens nowhere else, and aukora-genesis, the gate, the OpenShell gateway, OpenViking
  and aukora-relay were still active. Nothing of the harness, its plugin set, mounts or release floor was changed.
- [RAN, Mac -> SSH tunnel -> pilot, disposable keys, plugin code unchanged] plugins/aukora-nostr against that relay:
  signs in, a private message is accepted, the recipient fetches and opens it and the sender is proved; a stranger
  asking for the recipient's messages is refused; a wrap 47 hours old is accepted, one 3 days old or in the future is
  refused.
- [NOT RUN] the step's own done-check: Buzz's desktop app on the Mac joining this relay and a message round-tripping.
  That needs Peter at the app. Media upload (no S3 store installed). A reboot of the pilot. Closed mode: the relay
  is OPEN to any login on the node and anyone on the tunnel; it has no owner key yet.
- The pilot's firewall rule refuses Auma's sandbox the relay's port. Step 3 needs that one port allowed for her, which
  is a change to the boundary and is Peter's to approve.
- The install scripts had one independent read-only review (Codex) before the first start; its nine findings were
  fixed. First build attempt failed at its first step (no registry for short image names); recorded in the history.
- [RAN by Peter at the app, 2026-10-12 17:01 local] step 2's done-check: Buzz's desktop app on his Mac, through the
  tunnel, joined the pilot's relay, he created the channel "TEST MONDAY" and sent a message. Confirmed on the pilot:
  the relay's own database holds the channel creation and his two messages (09:01 to 09:02 UTC), all signed by one
  key, the app's existing identity. Not shown: a second person or device reading them; the phone app; an agent
  answering (he added Buzz's "Fizz" agent and addressed it; no reply was looked for).
- [RAN on the pilot, later the same day] Buzz binds a community to the host name a client asks for: from the pilot
  itself, ws://127.0.0.1:18740 was refused (404) while the same socket asked for as localhost:3000 was accepted.
  The relay now listens on 127.0.0.1:3000 on the pilot, so a process on the node and the Mac through the tunnel
  both dial ws://localhost:3000. check.sh 10 of 10 PASS after the move; Peter's channel messages are still in the
  database; a WebSocket from the pilot's own Node opens. A phone will need a real host name the same way.
- STEP 3, what was found (read-only): plugins/aukora-nostr is a library with no tools, not a mountable plugin, and
  it is not in the live release's plugin directory. Nothing on the pilot wakes Auma except the owner typing in the
  UI (aukora-relay-auma is pull-only). The harness does give a plugin a way to start a turn: the `agents` service
  (`agent.followup`), already used by aukora-goal-resume and aukora-box. So step 3 is a new host plugin that holds
  her Buzz key outside the model, hands a channel message to her as data and gives her one tool to answer. That is
  a new plugin set and a new release on the pilot: both are Peter's to approve, and the safe path to bring the
  pilot up to main (step 1) has to be named first. Her sandbox does not need the firewall opened: the plugin runs
  in the harness process, which the rule does not restrict.

ADDED LATER ON 2026-10-12 (the builder session in this repository; Peter's decisions that day in his words where
quoted; nothing above is changed):

THE NETWORK AND WHO IS IN IT (Peter's design; he ruled on it, it is not open):
- "You can download the open-source software, but you can't be part of the network without a direct invite from me
  or someone I've invited, or so on and so forth." He invites people he knows; they invite people they know.
- An invite is a one-time code. It can be given remotely: the people are known to the inviter, so no meeting is
  required. It expires after 48 hours. Each member starts with three invites; ways to earn more come later.
- A valid invite is what unlocks a node on the incubator account (Nebius), "Take Me Sovereign".
- The joining ceremony: the new member does the screen-to-screen co-presence with their OWN two devices first
  ("just you and your screen"), which teaches the gesture; then the Aumlok phrase. The same gesture is used later
  between people, and "more and more elaborate" human verification is added as the network grows.
- What keeps bots out at the start is the invite chain from the creator, not the ceremony.
- [NOT BUILT] No invite code, redemption, count or membership check exists in this repository (searched 10-12): the
  invitation tree is "PROPOSED, nothing built" in the Golden Boundary paper, the Identity screen says vouching "will
  come with invites", and the one earlier attempt is a patch outside any repository (belt row 94).
- [SOURCE, tested] what an invite can be built from, already here: the Identity screen's signed contact code (one
  use, 60 seconds, replay refused: packages/ui/faces/aumlok/src/contact-qr.ts, contact-verification.ts; no test
  reaches the scan route), the contact states up to VERIFIED and the key binding (plugins/aukora-nostr/lib/contact.mjs,
  identity.mjs; tests/aukora-contact-migration.test.mjs), the co-presence receipt checkers (packages/copresence), and
  a relay that admits only listed keys (Buzz's closed mode, not yet run here).
- [OPEN] "Lock out after five guesses": the phrase becomes a key on the member's own device, offline, so nothing
  counts guesses today, and the phrase with its handle is about 34 bits. A lockout needs a step the node checks.

FOR THE PROTOTYPE (Peter: "whatever you recommend is fine"):
- ONE closed relay for the first network: Peter's key is the owner, invited members' keys are admitted, their nodes
  talk through it. A relay per member, and Buzz's mesh mode, come later; an identity is a key the member holds, so
  moving later strands nobody.
- The relay that can wake a node's harness stays on loopback on that node. A community relay with a public host name
  is a second instance (the Buzz builder's point, taken).
- Say plainly to anyone shown it: whoever runs the relay can read channel messages and who talks to whom. Buzz's own
  "direct messages" are private channels on the relay, not end-to-end (checked in the fork's source by its
  builder). Messages sent with aukora-nostr's gift wraps are end-to-end, and Buzz's apps do not show them.
- No phone is needed for the first demo. A second device is needed only for the screen-to-screen ceremony.

STEP 3 STATE, evening of 2026-10-12:
- plugins/aukora-buzz-door has had two independent reviews (Codex; 7 then 10 findings, fixed). Only admitted keys
  can wake her, into a named session, with plugin provenance. [RAN on the Mac, Node 24.11.1] its tests with the
  live test against the pilot's relay, 35 of 35. [NOT RUN] inside a harness.
- [RAN in the pilot's STAGING container only] main at ce1d342 materialized into a release (25 AUKORA plugins, 656
  files recorded, the door carried) with the 10-04 script still in that container, and staging's gate produced the
  approval it would raise. Not approved, not started, running staging service not switched. A snapshot of the
  container was taken before the next attempt. The live harness is untouched.
- ./prime verify under Node 24.11.1 on the Mac at 8f186df: 62 PASS, 0 FAIL, 13 unperformed by design (so the suite's
  own word for the run is UNPERFORMED). The one earlier failure was a stale test expectation (65ede20).
- ORDER, from the other sessions' reviews: close the relay; run the refusals in staging before the wake that
  works; find where a turn labelled as the owner's is stored as "Peter said" before the door goes live; then live.
- THE DEMO needs no new key work: Auma proposes one harmless action from a Buzz message, the gate holds it, Peter
  approves in the popup he already has, the door posts the gate's signed receipt in the channel, a stranger
  verifies it with the existing script. The owner's Touch ID signature is the upgrade after.
- [RAN in the pilot's STAGING container only, 2026-10-12 about 11:15 UTC] a release built from main started.
  main at 22b9c0d was materialized there with the 10-04 script; staging's gate raised the plugin-set approval, the
  staging stand-in owner key approved it (ledger sequence 169), the approval was installed and the release floor
  moved to release-22b9c0d; the floor check passed; the staging harness started on it with the plugin set enforced
  and its interface answers (401 without a token). The door is mounted and reports itself unavailable, as written,
  because no key or config has been placed: the other plugins registered as before.
  FIRST ATTEMPT FAILED and is the lesson for the live switch: the unit runs the launcher from the source checkout
  beside the releases, and that checkout was still at 3673b98, so the old launcher refused the new release
  ("release-verification-failed: FAIL artifact integrity", three restarts, then failed). Checking the source
  checkout out at the release's own commit, as the 10-04 script does, fixed it. The launcher and the release must
  be the same commit.
  Also seen: an LXD snapshot of that container freezes it and copies every file (about 13 minutes, 15 GB); it was
  interrupted and the container resumed part-way, so the snapshot `pre-buzz-door-20261012` is NOT a trustworthy
  rollback point. The rollback point is a protected backup inside the staging container (gate state, approvals,
  units) and its saved pre-release environment file. Staging's floor is now 22b9c0d; going back needs a fresh approval
  from the staging owner key. The live harness was active and untouched throughout.
  [NOT RUN] a wake in staging: needs the relay reachable from the container, her key and door.json, and a session.
- The live gate's signed ledger (read 10-12): 1,814 entries since 10-03, among them 21 proposals, 21 decisions, 17
  applied, 1 rejected, 30 relay posts by Auma with their intents, 828 self-checks. The owner's approvals from the
  app are there, and its head is anchored to the `ledger-anchor` branch (latest anchor seen 10-12 18:26 +0800).
- [RAN in the pilot's STAGING container only, 2026-10-12 about 11:40 UTC] the door, from an installed release,
  against the node's own gate and relay. main at a9a597b went through the whole loop there (fetch, materialize,
  approval raised and approved with the staging owner key at ledger sequence 183, floor moved, launcher source
  moved to the same commit, harness restarted and active). Then plugins/aukora-buzz-door/checks/installed-accept.mjs,
  run as the harness user against release-a9a597b, 11 of 11: the relay is reachable from the node; the tools
  register with the row's configuration; a mention from a key that is not admitted starts no turn; buzz_post from
  another session is refused; the stranger's message is still readable as data; a mention from the admitted key is
  handed to the named session once, with plugin provenance and the words as one quoted string; a post from that
  session is accepted, the second is rate-limited, and the gate's ledger verifies and holds the intent and the
  completion (sequence 186, 187).
  The run before it, on release-22b9c0d, FAILED three rows: the door imported a harness package, which a plugin
  cannot resolve in a release, so no turn could start (fixed in a9a597b).
  What this does not show: a model. The session was a recorder; what Auma does with what she is handed is NOT RUN.
  The relay was still open; the keys and the channel were throwaway. Nothing on the live harness was changed.
- THE BELT AND THE DEMO PIECES, evening of 2026-10-12. Fifteen Codex workers (Astra, ultra), each in its own
  throwaway clone, each leaving one change that was brought onto main one at a time with its tests rerun, then
  the clone deleted. Landed, all [SOURCE; RAN on the Mac under Node 24.11.1 only]:
  the co-presence receiving end and device binding (34 tests), the portal page with its gates (135 pass, 3 skip
  for want of outside reference data), the relay member tool (11 pass, 2 gated on a live closed relay), a test
  pinning that a plugin-started turn is never the owner's words (no code needed changing), node-spawn groundwork
  (plan mode only; it refuses at the three steps that have no script: admission by invite, fresh owner-key
  enrollment, sandbox provisioning), and belt rows 5, 7, 8, 19, 35, 38 and the courts for 61.
  Corrections to two of those commit messages, which left the result blank or short: belt 35's check
  (`node labs/time-anchors/checks/drand.mjs`) passes, 10 checks and 16 mutants killed; belt 19's test passes 1
  and leaves 1 UNPERFORMED on the Mac (it needs the pinned harness archive in vendor/), so the new harness patch
  has not been applied in a real build yet: the next release build in staging is its first real test.
  Row 61's courts found six gaps in this repository's own conversation rails; they are kept as twelve
  known-failing cases, not hidden: organism state missing from trust classification and from honesty
  capabilities, claims-delimiter spoofing, malformed lens responses missing from unread evidence, current
  claims-table rows ignored, current "Not claimed" prose omitted.
  Still running when this was written: invites, the receipt-in-the-channel pieces, the documentation pass.
- LINUX IS THE DEFINITION OF DONE (from 2026-10-12, night). Two outside reviews (Mistral GLM, round two on ee40825;
  a second reader on 70d180f) showed the day's checks had been passing on a Mac while the code is for Linux, and
  that claims lived in commit messages. Since 9c2d175 a second CI workflow runs ./security-review, the gate's
  checks, scripts/check.sh and every top-level test on Linux on every push.
  [RAN on GitHub's Linux runner] first run, at b085413: tests 82 PASS / 9 FAIL / 4 UNPERFORMED; check.sh 86 of 97
  with 4 failed. At 17b5ce0, after the fixes: tests 88 PASS / 0 FAIL / 9 UNPERFORMED; check.sh 96 of 103 passed,
  0 failed, 3 unperformed, 4 skipped (3 are macOS-only by design); the gate's checks and ./security-review with
  no FAIL. What is UNPERFORMED there and why: tests that need the pinned harness built (kira-injection,
  kira-memory-live-path, kira-aura-association, kira-recall-output-seam, filetool-search-race), the pinned
  harness archive (subprocess-env-scrub), donor history (contact-migration), outside reference data (three
  portal cases), a scratch base the daemon boundary accepts (owner-protocol), Linux host fixtures (host.mjs),
  and the door suite's one live-relay case. A file with any skipped case is counted UNPERFORMED, not PASS.
  The first run's failures included the door's own tests failing on Linux, a mutation check in check.sh that had
  never run, and an acceptance driver that would have overwritten a live node's door settings: all found by the
  outside red-team, all fixed in 17b5ce0.
- ERRATA for commit messages (they cannot be changed): 70d180f says the red-team's gaps "are closed"; two of its
  six (the content-blind post channel and unbounded cost per turn) were reduced, not closed, as the door's
  header says. 9cf9a91 says "a new member binding a device": the code verifies a binding statement; it creates
  none. b46018e was reverted (810bf6c) and returned reconciled (02260b9).
- ALSO LANDED that night, all [SOURCE; Mac and the Linux runner; no node]: the gate's entry point takes an owner
  key when one is enrolled (none is); a third approval target, a short owner note; buzz_post_receipt in the door;
  admission by invite for a closed relay and a procedure to close an open one; node-spawn checks the invite
  first; the six gaps in the conversation rails fixed in source (bundles not rebuilt); per-unit systemd
  hardening proposals; the file fence's check-then-open race reproduced and kept as four failing cases.
- OWED: ./prime verify on a quiet machine (it timed out in places under load: 58 PASS where it had been 62);
  one gate check that fails intermittently under load; the face bundles; a wake with a real model.
- WHAT A CHANGE TO THE HARNESS PATCH SET COSTS, found on the pilot the night of 2026-10-12. Commit 87f71c4 added one
  harness patch. On the real machine that one line had three consequences no test here had shown:
  1. [RAN in staging] the release build refused: "harness-patch-set-mismatch", because the built harness there was
     made with the old patch set. The pilot keeps its own build and deploy scripts on the host (the ones that
     built every release since 10-03); following them, the harness was rebuilt for main in a fresh checkout
     beside the old one (about three minutes, niced; exit 0, the new patch verified in the built files), and the
     old build checkout was put back where it was. Staging was pointed at the new build and materialized main.
  2. [RAN in staging] the release was approved and its floor moved, and then the harness would not start:
     "REFUSED: launcher-hash:upstream-dsh.json". The gate's root-installed manifest pins six launcher inputs, one
     of them the file that lists the patches.
  3. [RAN in staging] upgrading the gate package to match was refused twice: the manifest generator reads only
     staged copies ("staging-installed-path"), and then "launcher-source-pin": the gate's bootstrap source
     hard-codes the hash of that same file, and of the owner-key package's files, and neither pin had been moved
     by the commits that changed them. Nothing in this repository compares those pins with the real files.
  The old gate package was restored automatically, the previous release (a9a597b) was approved again with the
  staging owner key (ledger sequence 202) and staging's harness is up on it. The live harness was untouched.
  So today's main cannot start on a node until the bootstrap's pins are reviewed and moved and the gate package
  is installed with them: that is the designed cost of changing what the launcher trusts, and a test that makes
  the drift visible in CI is being added.
- [SEEN on the pilot host, read only] the deploy history is there as scripts and logs, one set per release, and a
  driver that gives the agent a turn with a real model without the desktop app, by an admin reading the launch
  token. That is how staging's Auma can be woken through the door once a release from main starts there.

CORRECTIONS, night of 2026-10-12 (source status; no new installed observation):
- "[NOT BUILT] No invite code, redemption, count or membership check exists": `d16c4fe` added signed invites,
  redemption and quota checks; `463770b` joined invite spending to the relay owner's admission tool.
- Node-spawn "refuses at the three steps that have no script: admission by invite, fresh owner-key enrollment,
  sandbox provisioning": `ef10e6c` added signed admission-record verification before any container operation and
  narrowed the later refusals. A fresh installed node, authoritative shared admission accounting and complete
  enrollment/sandbox provisioning remain unqualified.
- The rails' six gaps "are kept as twelve known-failing cases": `0548eaf` repaired them in source and made those
  cases pass; `9270be2` reconciled the source pins. Neither commit rebuilt the face bundles.
- "Still running when this was written: invites, the receipt-in-the-channel pieces, the documentation pass":
  these landed in `d16c4fe` (invites), `2ab9e85` (receipt format/checker), `e6ea06e` (door receipt tool), and
  `d06c5da` (documentation). Source presence does not establish a model wake, deployed invite admission or a live
  receipt round trip.
- [RAN on the pilot, live node, 2026-10-12 night; read-mostly] scripts/kira/viking-probe.mjs as the harness user
  against the OpenViking service that runs there: configuration loaded, server health answers, the key is
  accepted, the embedder answers, a throwaway note was written and read back, a query BY MEANING found exactly
  that note above the threshold, and it was deleted again. 7 of 7. So OpenViking itself works on the pilot. What
  this does not show: Kira using it. The release that runs there selects lexical recall and was not built with
  the OpenViking setting (--kira-openviking-home, added in 7fc6ea0); a release built with it is the next test.

### 2026-10-12 late night: first full Linux verdict on tonight's tip was RED; three causes, fixed

Linux CI on 8727a39 failed three checks. Every run between 17b5ce0 (green) and 8727a39 had been cancelled by the next push, so these went unseen for hours. Lesson kept: let a run finish.

1. **A release's Kira never asked OpenViking.** Two landings (fce1152, 7fc6ea0) combined so that recall was forced to plain text search whenever the release selected `lexical`, which is the only value a release can select. The opt-in (`--kira-openviking-home`) therefore changed nothing. `tests/kira-openviking-http.test.mjs` had only ever passed inside the worker's sandbox, over a stand-in transport; over real HTTP it failed from the commit that added it, and I landed it without running it. Fixed: naming an OpenViking home is the opt-in; without one, text search. RAN on the Mac: that test and every `tests/kira-*.test.mjs`. The pilot probe (7/7) exercised OpenViking directly and was not affected; **recall through a release with OpenViking is still NOT RUN anywhere**.
2. **Red-team replay** (`packages/boundary-gate/checks/redteam.mjs`): the look-alike authority word scanner (559bb4a) adds one warning to 66 attack rows; the lab comparison counted it. The comparison now checks every lab warning exactly as before and pins which 66 rows carry the new one; no benign row carries it. This had been red in `./security-review` since 559bb4a and I reported that script's exit code without reading its rows. From now: read the FAIL count, not the exit code.
3. **Gate bootstrap check, Linux only, intermittent**: its fixture lived in the shared temporary directory; the bootstrap compares each ancestor directory before and after opening, and parallel checks creating files there made it refuse. The fixture now lives under a parent only that check writes to (`~/.cache/aukora-prime-checks/gate-bootstrap`). Passed on the pilot (Linux) before the change as well, which is why it is called intermittent and not fixed-and-proven.

Staging: the roll of 8727a39 was refused at `launcher-hash:upstream-dsh.json` and restored itself. Cause is the script's order (the package was checked before the launcher checkout was moved to the new commit), not the source.

### 2026-10-12 night: tonight's `main` runs in staging; a Buzz mention starts a turn in a real session there

RAN in the staging container on the pilot, release `dcb2141`, approved with the staging stand-in owner key (not Peter's), gate package upgraded from staged copies, release floor OK:

- **Installed door acceptance: 11 of 11**, with the signed ledger holding the intent and the completion. The scratch home must be inside the harness user's home: the door refuses a key or configuration under a directory others can write (it refused `/var/tmp`, correctly).
- **A mention from the configured owner key started a turn in a real harness session through the door** (`handed_by_door=true turn_started=true`). The message arrived with the plugin's provenance, not the owner's. The turn then stopped at `MISSING_CREDENTIAL`: **staging has no model key**, so there is no reply yet. I did not copy the pilot's model key into staging; that is Peter's to do or allow.
- **Found: after a harness restart the configured session is not live**, and the door logs `configured Buzz session unavailable` until a client opens that session again (`session/create` with its id). The mention that arrived meanwhile was held and delivered once the session was open; nothing was lost. Until this is fixed, a node that restarts does not answer Buzz until someone opens the session.
- NOT RUN: the relay closed with an owner (the one relay is the one Peter's app uses; closing it with a throwaway owner would lock his app out); admission by invite against the real relay; Kira recall through this release with OpenViking; anything on the live harness, which still runs `3673b98`.

Outside view from the Honey Pot session, same night, kept because it is right: the demo's gaps are not belt rows. The Buzz app's Touch ID approval and the pilot gate's approval are two paths with two keys, and "which key signs on the pilot" is still open; showing one approval flow before they are joined would make the system look safer than it is. It also advised parking belt rows 11, 14, 43, 44, 54, 63, 66, 69 and 21; the belt worker on the next PORT rows was stopped on that advice.

### 2026-10-12 night: memory through a release, on the pilot: RAN, 6 of 6

A release directory was built from `main` (`6a63831`) on the pilot host with `--kira-openviking-home`, under `/opt/aukora-probe` beside the live release. Nothing was approved, installed or switched; the live harness stayed on `3673b98` and stayed active. `scripts/kira/release-recall-probe.mjs`, run as the harness user with scratch memory state, using that release's own Kira files and composition and the node's real OpenViking:

- remember: 1 note; recall by meaning with a question sharing no word with it: `openviking-semantic`, not degraded, note returned; recall by text: found; forget: removed from the ledger and the index; then absent from both. Each step in a fresh process.

This is the first time the path release composition -> Kira -> OpenViking has run anywhere. What it does not show: Auma using recalled notes in a turn (no model was involved), the live release doing it (the live release predates the fix and selects text search), or recall quality beyond one synthetic sentence.

Two things an operator must get right, found the hard way and now in `plugins/aukora-kira/README.md`: run with the backend's environment (`DSH_HOME`, `AUKORA_SUPPORT_ROOT`, no `AUKORA_STATE`). The probe now prints Kira's own refusal name instead of one opaque code.

### 2026-10-12 night: after a restart the door reopens its own session: RAN in staging

Staging rolled to `0356b04` (gate package upgraded, stand-in owner key, floor OK). Then: a new session and a throwaway owner and channel, harness restarted, **no client opened the session**, a mention posted: `handed_by_door=true turn_started=true`. The turn again stopped at the missing model key. Before this commit the same sequence produced `configured Buzz session unavailable` until a client opened the session. NOT RUN: the live harness; a reply (no model key in staging).

### 2026-10-13 early: the Aura snapshot behind the Pentora page: RAN in staging

Staging on `1fdffae` (rolled, stand-in owner approval, floor OK). The route the Aura Coherence page reads: without sign-in 401; POST 405; signed in 200 with `no-store`, a snapshot naming three sources. The gate ledger has a verified head; Kira's and the code chain's heads are reported **absent** (`kira-head-not-exposed`, `code-head-not-exposed`), not invented. After the door acceptance added three signed ledger entries (240 to 243) the snapshot's head changed. Installed door acceptance passed on this release as well. NOT RUN: the page in a browser (nobody has looked at the picture move); so "Aura is the cohesion of all actions" is today a picture of the gate ledger only. Feeding it Kira's head and the code chain's head is the next step for that page.

### 2026-10-13 early: a review of the night's work, six defects, all fixed; staging on `3854a3b`

A read-only review of `17b5ce0..1fdffae` demonstrated six defects with small scripts (first attempt was blocked by the model provider's content filter; plain "correctness review" wording went through). Fixed: the eye (`cf85d26`; `aukora_see` is denied again, which corrects my earlier landing that allowed it), the door's unbounded wait and the invite's order-dependent comparison (`5d7efb7`), the memory probe and the project mapping file (`8984fe0`). The fixed probe RAN on the pilot against the real OpenViking, 6 of 6, in a probe-only namespace, scratch left empty. Its macOS fallback did not work over real HTTP, so the probe is Linux-only now and says so.

RAN in staging on `3854a3b`: roll with gate package upgrade and stand-in approval; restart with no client, mention starts a turn; installed door acceptance PASS; Aura route 401 / 405 / 200.

Also tonight: 111 checks that nothing ran are registered (`fd41bcf`); six found red or unfit are listed in `plan/CHECKS-INVENTORY.md` and not registered. A worker's rewrite of the harness build format was NOT landed (it would force every harness to be rebuilt); it is in `plan/PROPOSAL-harness-build-identity.md` for Peter. `./prime verify` ran to completion on the Mac: 64 PASS, 0 FAIL, 12 UNPERFORMED.

Way of working that paid for itself: run new tests on the pilot (Linux, Ubuntu's umask 002) before pushing. It caught the mounts test needing the harness archive, three node-spawn tests, two unfit registrations and the probe's HTTP path, none of which the Mac or a worker's sandbox showed.

### 2026-10-13 early: Aura's snapshot with all three sources present: RAN in staging

Staging on `727d9d7`. Two findings on the way:

- **Kira had never been running in staging.** Staging had no owner deployment overlay, so Kira refused to mount (`memory.identity:field-missing`) on every release rolled there tonight; the door, the gate and the Aura route were exercised in staging, Kira was not. Staging now has an overlay with a synthetic subject (not a person). Everything said tonight about Kira on a node comes from the pilot runs (the OpenViking probe and the release recall probe), not from staging.
- With Kira mounted: before any note, the snapshot reported `kira-chain` absent (`kira-ledger-missing`), which is true. After one synthetic note was remembered through the release's own Kira (and recalled by text), the snapshot showed `gate-ledger` (295 entries), `kira-chain` (1 entry) and `code-chain` (the release record's digest) all present, and the snapshot's head changed while the gate's head did not. So the Pentora on the Aura page is now a picture of approvals, memory and code together, and it moves when any one of them does.

NOT RUN: the page in a browser; a model turn; the live harness. The admission service (`727d9d7`) is not installed in staging.

Linux CI on `727d9d7` was red on one check: the new admission unit had no entry in the hardening proposals, and I had pushed without rerunning `scripts/check.sh` after landing it. Fixed in `5ad3467`; on the pilot the hardening test passes 5 of 5 with `systemd-analyze`.

### 2026-10-13 before dawn: second review, nine defects, all fixed; state at hand-over

A second read-only review (`1fdffae..577f9b3`) demonstrated nine defects; all are fixed (`a519217` live switch script, the eye fence, `e2937be` probe and type check, `80567c4` invites, `c8cf03c` two tests that followed). Linux CI green on `c8cf03c`.

RAN in staging on `c8cf03c`, the hand-over state: `ops/pilot/live-switch-main.sh` end to end with a fresh card approved by the stand-in key; installed door acceptance PASS; Aura snapshot with gate, Kira and code heads present; restart with no client, a mention starts a turn (stops at the missing model key).

RAN on the pilot host: release `c8cf03c` built beside the live one with Kira's OpenViking setting on; the memory probe 6 of 6 against the real OpenViking after its second fix. Live harness untouched: `3673b98`, active.

NOT RUN anywhere: the live switch on the pilot; the relay closed with an owner; the admission service installed; a model reply in staging; the Aura page or any face in a browser; any step of node spawn on a real machine.

### 2026-10-13 morning: the live pilot runs tonight's `main` (`c8cf03c`), by Peter's click

RAN on the live pilot with Peter's real touch (he approved the plugin-set card in his app): `3673b98` -> `c8cf03c`, gate package upgraded. After the switch: selfcheck PASSED, plugin set ENFORCED, harness, gate, relay, Buzz relay and OpenViking active; `scripts/kira/release-recall-probe.mjs` against the LIVE release 6 of 6 (scratch state, real OpenViking); one real model turn through the new release answered.

It took three runs. Two failures were mine and only showed on the live machine (the popup cannot appear while the harness is down; the launcher will not start until its port drains). The harness was down for roughly two minutes in total beyond the planned stop. Both are written up in `ops/pilot/README.md`; the drain is fixed in the script, the order (click before stop) is not yet.

Also found: Peter's desktop shortcut starts the app WITHOUT the pilot attach settings, so it silently falls back to the old Genesis release installed on the Mac (`~/au91-root/aukora-release-9572138ef`) and shows that. Only `~/.aukora-nebius/launch-aukora.sh` attaches to the pilot. That is why he saw "the old app".

NOT yet on live: the Buzz door answers `AUKORA_BUZZ_DOOR_UNAVAILABLE` because the live node has no relay key or door configuration for Auma (never created there); the relay is still open; the admission service is not installed.

### 2026-10-13 morning: the live switch was rolled back; the fixed build is verified on a real screen in staging

The live pilot ran `c8cf03c` for about twelve minutes and showed Peter no apps and broken thread icons. Cause: last night's rebuild of every face compiled in the Linux voice sidecar source, which had been left unbuilt on purpose; it needs a pin file at load that the pilot does not have, so the apps plugin threw, and that plugin serves every stock app and the thread icon. Goal resume threw at load too. The pilot was rolled back to `3673b98`. The rollback was cut off half-way when its connection closed and the harness was down for about eight minutes until I restarted it. Total unplanned downtime this morning: about ten minutes, all caused by me.

Fixed on `main` (`ddc3375`): an absent voice installation no longer stops the apps plugin; goal resume and the board plugin no longer throw at load; tools that make the owner's existing notes readable; recall by meaning under a partial index.

RAN in staging on `ddc3375`: no plugin threw at load; `ops/pilot/ui-probe.mjs` signed in: the icon, Auma Lingwa, Auma Live, Zeta Harp, Human Graph, Dakini Code, the Auma Live status and the Aura snapshot all served; installed door acceptance PASS. **Seen in a real browser for the first time** (staging, through a loopback tunnel): thread icons render; the apps panel lists the apps; Auma Lingwa opens and renders; the Aura Coherence page shows a settled Pentora with 3 of 3 sources present. Screenshots were sent to Peter. One thing seen there and not yet explained: two requests to `/api/aukora/aumlok-control` returned 404 in staging.

RAN on the live pilot (read-only): on `3673b98` everything the probe checks is served except the Aura snapshot, which that release does not have.

Measured on the live pilot (read-only): Kira holds 202 notes, 147 filed under the older label for `/home/aukora-host/workspaces/aukora-prime/.git`, 52 under the one for `/home/aukora-host/genesis/state/workspace`, 3 unresolved; none readable by the assistant until a project map exists. That is why she reported her memory as withheld.

The live pilot stays on `3673b98` until Peter has seen the screenshots and the switch script has been rewritten (click first, with everything still up; a mandatory screen probe and plugin-load check before success).

Also this morning: GitHub Actions switched off by Peter on seven private repositories; the "clones" he saw on the Buzz fork were its inherited workflows checking out the code.

### 2026-10-13: a fresh clone becomes a running system, proven on GitHub on every push

`scripts/fresh-clone-check.sh` RAN end to end twice: on the pilot (Linux, 286 s) and as the new CI job `fresh clone boots` on GitHub's own Ubuntu runner (272 s, commit `be6dcfb`, first run). From nothing but a clone of the public repository: the pinned harness archive is downloaded and its hash checked; it is built; a release is materialized; the plugin set is approved through the real approval commands with a throwaway owner key under a temporary root; the release starts on loopback with no model key; and, signed in with its own token: the screens answer, no plugin threw at load, every shipped face is in the client graph, the thread icon and the stock apps are served, an unauthenticated request gets 401, and the action gate refuses an unapproved action before its body runs.

What it does not show: a model reply (no key), a real owner or real containment (same-user temporary authority, and it says so), the Buzz relay (private fork), memory, or a real machine's install paths. But the claim "nobody can build this from the repository" is no longer true, and this morning's regression (a release with no apps) cannot reach `main` green again: the same probe now runs on every push.

Also done today: the rewritten pilot switch script completed a full staging rehearsal on its third try (two permission faults found and fixed by rehearsing); `tests/release-plugins-load.test.mjs` loads all 25 mounted plugins on Linux and macOS.

Open: `./prime boot` (the NEXT composition) still cannot be started by a stranger: its verifier requires root-owned manifest ancestry, and an example for it is blocked on a design decision (`plan/PROPOSAL-prime-up.md` is parked, not landed). The practical one-command start should be built on the fresh-clone machinery instead.

### 2026-10-13, later: the live pilot runs `c603bbf`, switched by the rewritten script with Peter's click

RAN on the live pilot with Peter's real touch. The rewritten `ops/pilot/live-switch-main.sh` raised one card with the old release fully up; Peter approved it in his app (plugin set `776100bc…`, record `c86aee14…`). First attempt after the approval: stopped at installing the approval (`gate unavailable (ENOENT)`: the gate unit was active a moment before its sockets existed) and restored cleanly. The script now waits for both sockets. Second attempt, no further click: `SWITCH_DONE`, having itself verified the signed-in screen probe (thread icon and every stock app served) and that no plugin threw at load. Self-check timer active afterwards.

On the live release, RAN: `ops/pilot/ui-probe.mjs` all served; `scripts/kira/attach-check.mjs` on a scratch copy: 147 and 66 notes eligible in the two mapped workspaces, none dropped for scope; `scripts/kira/viking-sync.mjs`: stuck at 23 indexed because three notes fail and the tool stopped there (fixed in source since; NOT yet rerun on the node).

Done and then set aside as off-priority, by Peter's ruling the same hour: Auma was given a relay key, door settings for his test channel and a session on the live node, and posted one line there; the door registered. He does not want Buzz worked on now. It is idle; nothing depends on it.

Peter's rulings this day, final: the product for now is BROWSER-BASED, a window onto a person's own node in the cloud; Electron and self-hosting come later. This week's target: a FRESH node (C1), not the pilot, opened in a normal browser and bound to him by the binding ceremony; then a second. Fresh nodes will be containers on the machine already paid for. Nothing counts as done until he has opened it himself.

### 2026-10-13 checker: browser-node evidence stops before a durable start

Checked `0427da2` offline under Node 24.11.1. The commit messages record, on the test machine: a fresh container from committed code; the pinned harness built offline; a release materialized; fresh gate keys; and before-approval acceptance PASS, with its last two fixes applied by hand to that node. A later message records one approval through the gate page by the owner's own click (ledger sequence 5), approval installed, floor verified and launcher provenance bound over 8,389 artifacts. Its start reached launcher checks and did not stay up.

No commit message at this revision records a second fresh-gate ledger-5 approval or the harness staying started, so neither is raised here. NOT RUN: sign-in from a browser, the binding ceremony, a real passkey, after-approval acceptance or a model reply. The full checker record is `plan/CHECK-2026-10-13.md`; it is source and report evidence, not observation of an installed browser product.

### 2026-10-13, afternoon: a fresh browser node, approved by the owner, opened in a normal browser

RAN on the test machine (a fresh unprivileged container, no network, nothing copied from any node), by `ops/node-spawn/browser`:
create from committed code; harness built offline; release materialized without relay or Buzz door; fresh gate keys;
before-approval acceptance PASS. The owner approved through the gate's page with his own click on three successive
builds; each started and passed the after-approval acceptance. A REHEARSAL instance of the last build, approved by a
stand-in, was signed in from a real browser over HTTPS with a one-time link (Secure, one-day session), loaded the full
app, and showed the binding screen through phrase generation and retyping.

Found only by running it for real, each fixed and tested: pnpm 11's offline settings; a 256 KB read bound against a
2 MB release record; git refusing a root-owned checkout; profile files written after the release was measured; a
proxy rule that never fired (the launch token reached the harness on the public address); the proxy sending an empty
Origin; a 30-day session where one day is required; a profile that disabled the browser client's upload transport;
the binding screen needing the node's origin as release bytes; SSH listening inside the stock image.

NOT RUN: the final Bind step in a browser; the owner's own binding; passkey approval; a model reply; voice; a second node.
Open from review (plan/REVIEW-BROWSER-NODE.md): a signed-in but unbound session keeps general RPC access (the pinned
harness has no hook to restrict it); four fixes are written and parked because they change the harness cookie patch.

### 2026-10-13 checker, evening: later source landed; the recorded browser run has not advanced through Bind

This update reads every commit message from 12:00 through `38004c5`; it does not add a machine observation. The
retained browser-node run remains: owner approval on three fresh builds, and a separate REHEARSAL instance approved
by a stand-in, signed in from a real browser over HTTPS, loading the app and reaching the binding screen through
phrase generation and retyping. Later commits add the `__Host-` public cookie, resumable passkey enrollment, model-key
installation, public acceptance evidence, multi-node ingress rendering and automatic first-run opening. Their own
messages do not record those later paths running on a node. The first-run commits record diagnosis on a rehearsal
node, including one visit in a real browser where the screen did not open, then explicitly say the corrected revisions
were not run in a browser on a node. NOT RUN remains: final Bind in a browser, the owner's own binding, a passkey with
a real authenticator, a model reply, voice and a second owner-bound node.

The post-noon Kira messages describe mismatches at about one note in nine, then record a real-node diagnosis: every
observed OpenViking 0.4.21 mismatch was the expected index part plus a 41-to-43-byte fields trailer. Source now writes
those parts as resources and lets other queue entries proceed while a failed or deferred entry waits. The change's
message says NOT RUN on the node and gives no post-change indexed, pending or failed counts, so no completed indexing
claim is made here and the approximate one-in-nine observation is not presented as an exact count.

Aura's earlier screen was seen in staging with 3 of 3 sources. The later redesigned shared-surface screen is SOURCE
only at this checkpoint: its message records the Aura, face-copy and UI suites and says nobody viewed it installed.
Ingress reached one rehearsal browser over HTTPS; the two-node renderer and later host-only cookie have source tests,
not a two-real-node run. Voice is likewise SOURCE only: 87 of 87 tests are recorded, while the Linux runtime,
microphone, model and spoken reply were not run on a node.

The browser review now has findings 1, 3, 4 and 5 fixed in source only. Finding 2 remains OPEN: an unbound authenticated
session retains general RPC access; the described change is parked without a recorded node rehearsal.

Diff-support limit: the external-machine/browser RAN statements in `c043a31`, `09157b7`, `048fe7e`, `c449dfe`,
`5d8052a`, `08b6fba`, `ebf46eb`, `dc44ab9`, `bc780e7`, `10ebe61`, `eead4f8` and `38004c5` are supported here by
their commit messages only; their diffs contain source, tests or status prose, not an independently retained machine
record that proves the observation. The source-test RAN lines name present tests and relevant changes; this audit found
no message that names a missing test.

### 2026-10-13, night: builder's report of real runs after the checker's cut-off

The checker above rightly kept three items at SOURCE because no commit message recorded them as run. These are
the builder's observations on the test machine, by its own report unless a record is named:

- Kira indexing after parts moved to resources: the sync on the pilot's real store ended `indexed=903 pending=1
  failed=2` (one missing object, one unreachable transport), from a previous stall at 687 with 93 mismatches.
  The live pilot release still reads the old index.
- First-run open: on a rehearsal node (`aukora-r1`, stand-in approval) at `38004c5`, a real browser signed in
  with a one-time claim over HTTPS and the binding screen opened by itself beneath the harness notice, with its
  explanation visible. It took three looks at a real node to get there; each earlier attempt passed its tests.
- Two nodes behind one web server: C1 (waiting for the owner) and R1 answered on their own hostnames; R1 passed
  the after-approval acceptance including the one-use claim exchange and a host-only (`__Host-`) cookie.
- Evidence: `evidence/browser-node/2026-10-13-rehearsal-r1-38004c5.json` is the first record collected from a
  node; `scripts/audit/browser-node-evidence.mjs` verifies its receipt signature, approval bindings, signed apply
  row and floor binding offline. It is a rehearsal record with a stand-in approval, and it is unsigned.
- Aura's redesigned screen was seen rendered in staging (`0427da2`), not on the pilot.

Still NOT RUN: the final Bind step in a browser; the owner's own binding of a fresh node; passkey with a real
authenticator; a model reply on a browser node; voice; a second owner-bound node.

### 2026-10-14 checker: the unbound restriction ran before its last two fixes; Bind remains the owner's step

This update uses only commit messages since the prior checker cut-off and the full browser-node review. It adds no
machine observation. By the builder's report, rehearsal node `aukora-r1`, approved by a stand-in, booted with the
pre-binding restriction, opened the binding screen by itself in a real browser over HTTPS, refused session creation,
session listing and file upload with 403 `browser-node:binding-required`, and passed the after-approval acceptance in
unbound mode. That node run preceded two fixes in `f47a61e`: the contact-card identity read is now refused, as are paths
with an empty segment, an encoded slash or a backslash. The guard, boot and mux suites ran after those fixes; no message
records the fixed revision running on a node.

A second model family reviewed the restriction read-only. Three items remain open: any readable binding control record
lifts the guard; `prepare` returns the drawn words to the signed-in client; and GET/HEAD under `/plugins/` is an open
prefix. The first committed rehearsal record,
`evidence/browser-node/2026-10-13-rehearsal-r1-38004c5.json`, uses a stand-in approval. Commit `5dd0e97` records 22
after-approval checks and offline verification of its receipt signature, approval bindings, signed apply row and floor
binding; the record predates the pre-binding restriction.

Kira's latest source fuses semantic and lexical rankings by reciprocal rank. Commit `aee1bc9` records the reproducer
moving from rank 3 to rank 2 and the Kira Viking CLI plus OpenViking recall and sync suites running. It explicitly leaves
real embeddings and the 700-note store unperformed. By the builder's report, C1 and R1 answered on separate hostnames
behind one web server, and R1 passed after-approval acceptance with the one-use claim exchange and a host-only
`__Host-` cookie; no committed machine record independently retains that two-node observation.

Next: the owner approves one clean node once and presses Bind himself in a real browser. These reports and the committed
rehearsal record do not prove the later restriction fixes on a node, owner binding, real authenticator custody, a model
reply, voice, containment or cross-node hostname isolation.

### 2026-10-14, early: builder's report after the checker's cut-off

By the builder's report, on the rehearsal node `aukora-r1` (stand-in approval) at `f47a61e`, in a real browser over
HTTPS after the two review fixes: the contact card answered 403, `/plugins//events` answered 403, the brand image
and the first screen were served, an app page and session creation answered 403, a boot method answered 200, and
the after-approval acceptance passed in its unbound mode. Against the builders' own memory store (about 700
notes, real embeddings) the question that had missed its short direct note returned it second after recall fusion.
Staging was rolled to `aee1bc9` and its screen probe passed. None of this has a committed record.
