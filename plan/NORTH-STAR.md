> Copied 2026-10-04 from Peter's PRIME-NORTH-STAR.md; verbatim except one redaction marked [REDACTED: ...]; status tags (RAN / SOURCE / NOT YET) added 2026-10-04 with that day's truth on Nebius (live at the SHA in the latest Room line).

# AUKORA PRIME — NORTH STAR (replaces plan/MASTER-PLAN-v4.md as the front page)

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
- THE MIND (later): today DeepSeek [RAN]; next the Nebius recursion model (Ornith) as a model provider, trained on her
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
