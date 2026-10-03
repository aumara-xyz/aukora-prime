> Copied 2026-10-04 from Peter's PRIME-NORTH-STAR.md; verbatim except one redaction marked [REDACTED: ...].

# AUKORA PRIME — NORTH STAR (replaces plan/MASTER-PLAN-v4.md as the front page)

ONE SENTENCE: a personal AI organism on a Linux server you control, reached from your own app, that can grow and
even change itself — and can never act past the boundary without its owner's approval, with a receipt anyone can check.

THE BODY (where each organ lives in Prime main; status = RAN on Nebius / SOURCE / NOT YET):
- Harness + Cordis (the body): DeepSeek Harness, every organ is a Cordis plugin. Genesis runtime zipped in at 7ae564b.
- Boundary (the floor): packages/boundary-gate — separate Linux users, OpenShell sandbox for Auma's hands,
  owner-only gate, signed hash-chained receipts, 815-attack corpus. The Genesis lab, in Prime.
- AUMLOK (who): the owner's identity (seven words + handle -> owner key). Approves exact bytes. On Linux the gate user
  holds signing authority; the owner approves in the popup in his Electron app (later: passkey/Touch ID on his Mac).
- KIRA (what she remembers): every turn hashed into a chain and indexed in OpenViking for recall. Tracked, never
  approved. Emoji-safe, junk and injection kept out of the index.
- AURA (what happened): the append-only record of every tool call, approval, memory write and self-change.
  Anyone can verify it with the membrane minimal verifier (vendor/aukora-membrane, minimal/verify.py, no deps).
- NOSTR (her voice to the world): the Aumlok identity's public key; encrypted messages and contacts with safety
  numbers; next: identity backup and home-anywhere sync.
- KERNEL + ACTION GATE + PHI-GUARD + PATH FENCES: every tool call judged before it runs; one-use authority.
- WASM CELL: proposals run in a sealed WebAssembly cell before they become effects (plugins/aukora-box/.../wasm-proposal-cell).
- SELF-CHANGE: Auma proposes a change to herself -> owner approves -> Cordis hot-reload -> receipt. Theme-only first.
- THE MIND (later): today DeepSeek; next the Nebius recursion model (Ornith) as a model provider, trained on her
  own verified life; routes to other models through a host-held, capped ask_model tool. The walls stay outside the model.

TODAY'S DEMO (the plane): Auma chats in the Genesis UI on Nebius -> her shell runs in OpenShell as `auma` -> she
cannot read the host or approve her own change -> owner approves a theme change -> hot-reload + receipt -> she
remembers across a restart -> a stranger verifies the receipts with minimal/verify.py.

AFTER THE DEMO (waves, one family per bee, queen merges, live on Nebius after each):
1. Wire every organ above that is SOURCE-only on Nebius into the running app (Nostr, WASM cell, membrane verifier
   in the Aura face, First Echo, governed recall, path fences/phi-guard).
2. Then the Honey Pot absorb order ([REDACTED: private operator path] HONEY-POT.md, 73 families; not in this repository), top-10 gems first.
3. Then Ornith as Auma's model.

RULES: HONEY-POT-PROTOCOL. "On main" = on GitHub Prime main. "Live" = running on Nebius at a named SHA.
Only Peter says "done". Safety lives inside AUKORA (no GitHub enforcement). Nothing old is left behind: every
family in the Honey Pot map ends either in Prime main, or on the map with the reason it was dropped.
Reference papers: docs/AUKORA-GOLDEN-BOUNDARY.md (Genesis).
