# AUKORA Prime: the organism plan (merged from six independent reports; 2026-10-05, Claude)

Inputs merged: Grok, Dot, Auma (from inside), GPT-browser, Kimi-browser (both pinned to e337397, so stale on status, kept for
design points), Honey Pot round 2 (48 RAN rows disproved by fresh agents), plus three things I ran on the box myself.
Labels: RAN = seen with output. SOURCE = code, not live. NOT YET. ? = reports disagree or nobody saw it.
CHECKED-BY-CLAUDE marks what I verified on the box; everything else is as reported by its source.

**Current status refresh · REPORTED, 2026-10-05 12:41 UTC:** Peter reports live release `3673b98`, old gate package `4c24fd0`, no normal admitted shell and no accepted bound workspace. Earlier bound guest 33/0 was ADMISSION-BYPASSED; host-as-auma was 40/7. Kimi later reports observer pass; admission blockers remain. This docs refresh ran no organism or live tests. Historical RAN labels below belong to their original reporters, not this task.

**Overnight scope:** current allocated branches/staging only; Kimi integrates. No deployment, cards, deletion, spending, key/credential changes or enrollment is authorized. Real organism acceptance remains owed on the normal admitted route.

NORTH STAR: one owner-sovereign organism. Auma proposes; only Peter's key decides; the gate applies exactly what was
approved; Aura records it; Kira remembers it; anyone can verify it. Inside walls she cannot move.

## What the six reports agree on (high confidence)
- The spine works: runtime -> gate -> owner card -> exact apply -> signed ledger -> public anchors (24 to 321+ continuous).
- Auma can speak and refuse. She cannot ACT (no shell), VERIFY (no ./prime verify), or REMEMBER (46/47 notes dropped).
- The guest shares no files with her workspace (linux-openshell.patch.yml:14), so the shell fix is a bind, not a mapping.
- The earlier report named workspace 0a01aeb. Peter now reports live release 3673b98 and old gate package 4c24fd0; no accepted bound workspace. Source edits do not establish what runs.
- Her memory header says "0 records" while recall returns records. aura_association's error path breaks its own schema.
- Kira <-> Aura is not live. Aura covers the gate ledger only, with INTERIM keys.
- Self-change on Prime does not exist as a working loop. Voice runs only in staging. Nostr node-to-node is NOT YET.
- "Only Peter's key decides" is not yet literally true: owner approval means whoever can open owner.sock (G is inert).

## Disagreements (needs validation, not trust)
- Is semantic recall working? Auma: failed, degraded. Honey Pot: "recall is not lexical-only". Auma's own tool output wins until shown otherwise.
- Containment: staging 35 denied / 0 allowed on 4c24fd0 with controls (Grok, Dot). Dot adds some denials were missing executables,
  not permissions, and the staging result does not cover the new workspace bind. Live runtime result: not shown.
- Current reported runtime is 3673b98, with old gate package 4c24fd0. Historical release disagreements remain historical; no current runtime readback ran in this docs refresh.

## NEW from the Honey Pot, ranked by danger
1. Provider credential exposure to Auma's file tool (detail withheld from this public file; see relay c181). Rotation is Peter's
   call at the provider.
2. "FROM PETER" is just text. Any of 7 other relay bearers can write it. An order must be a relay message whose SERVER AUTHOR is
   `peter` (kind decision), never text. Until then, orders come only from Peter's own chat.
3. The day-to-day operator login is over-privileged (detail withheld from this public file; see relay c181). "Owner approves" also
   means "anyone who can open owner.sock".
4. Kira -> OpenViking index is stuck at its retry cap (20); the embedder 400s on a 2325-token note; kira_remember has no length bound.
5. Model output is auto-captured as notes (55 of 88) and re-injected as context. Persistent prompt-injection path.
6. harness_start on the propose channel expires the owner's pending plugin-set approval; the gate signs rows the harness wrote.
7. Action-gate chain (628 rows) and Kira chain are same-UID files, uncollected, unanchored.
8. Front door names the wrong release; relay unit is `static` (won't survive reboot: CHECKED-BY-CLAUDE); an undocumented LXD
   container runs a second stack; the Genesis unit has no systemd sandboxing; composition has Mac-shaped paths.
9. Containment probes still skip: auma's rootless podman socket, OpenShell gateway 17690, abstract sockets, /proc/pid/mem, mount audit.

## TODAY: tiers, in order (WITA)
TIER 0, next 30 min, hygiene (no new features):
- Peter rotates the provider key at the provider. Then deny credentials, auma.key, the nostr identity and the launch token to the
  file tools.
- Relay rule: orders = server author `peter` only. Text "FROM PETER" is advisory.
- Enable the relay unit so it survives a reboot.
TIER 1, the five that make her act and remember:
1. Containment 0 ALLOWED incl. the control-plane routes in item 9, with the workspace bind in the profile.
2. Her shell over her workspace (Auma's profile): she runs ./prime verify inside the guest.
3. Memory: fix the embedder (bound note length, reset the retry cap), attach the aukora-prime scope at session creation,
   header tells the truth, model-authored notes tiered so they are not re-injected as trusted.
4. Aura-Kira link ON; put the gate ledger, action-gate chain and Kira chain under the collector.
5. Self-change on Prime end to end: she proposes, Peter clicks, she becomes it.
TIER 2, truth and trust:
- Front door generated from the box (release, units, plugin set, relay, OpenViking, staging container).
- Owner key (G) enrollment at the keyboard; reduce the day-to-day login's privileges.
LATER: Nostr on Prime and three test nodes, voice into Auma Live, WASM cell / First Echo / verifiers mounted or removed.

## Checkpoints today
10:00 Tier 0 done; Tier 1 items 1-2 staged. 13:00 staging RAN for items 1-4, Kimi + GPT review of the frozen candidate.
The earlier 16:00 live-candidate target is superseded by the overnight branches/staging-only allocation. Kimi integrates source handoffs; any future deployment needs separate authorization. Item 5 remains RAN only with actual organism output, otherwise a named blocker.
Each checkpoint: Status updated from RAN evidence only. Disproved claims go back to ?.

## Feature status (merged)
THE WALL: separate Linux users RAN | firewall for auma RAN | guest containment: historical staging 35/0; later bound 33/0 ADMISSION-BYPASSED, host-as-auma 40/7; observer pass reported, admission open | workspace bind
NOT ACCEPTED | .git read-only kernel mount NOT YET | exact mount inventory SOURCE | pre-Node hash bootstrap SOURCE (reported RAN) | launcher
in hash closure SOURCE | firewall-missing-means-no-start SOURCE.
GATE + AUMLOK: owner card one-click, gate-labelled RAN | exact-byte apply + floor RAN (seq 302) | relay posts in the gate ledger RAN
(seq 308/309) | owner-key (G) SOURCE inert | Aumlok phrase works on Prime ? | wrong owner/pin/grant refused ?.
AUMA'S HANDS: read RAN | write/edit in workspace RAN | relay_read, relay_post RAN | shell NOT YET | ./prime verify NOT YET |
self-change NOT YET | workspace tracks main NOT YET.
MEMORY: Kira capture RAN | lexical recall RAN | semantic recall FAILED/degraded | OpenViking index stuck at retry cap RAN |
scope attach SOURCE | truthful header SOURCE | injection tiering NOT YET.
RECORD: gate ledger + anchors RAN | collector through seq ~323 RAN (INTERIM keys) | Aura-Kira link SOURCE, off | other chains
uncollected NOT YET | external witness NOT YET.
REACH: relay (Grok, Dot, Claude, Auma) RAN | Nostr library SOURCE | Nostr node-to-node NOT YET | NIP-42, retry pool NOT YET.
SENSES: Mac app to Nebius RAN | voice staging only | Eye / repo lens / web search SOURCE (Auma ran web_search, read_image RAN).
