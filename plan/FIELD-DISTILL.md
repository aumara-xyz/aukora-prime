> Copied 2026-10-04 from Peter's PRIME-FIELD-DISTILL.md, verbatim. Directions, not claims: nothing here is RAN unless ARCHITECTURE.md or docs/CLAIMS.md says so.

# What Prime takes from the field (Hermes, goose, OpenClaw, and the harness-security research) — 2026-10-04

Rule: we take the PATTERN, never the trust model. Every borrowed capability runs under Prime's boundary
(propose -> owner decides -> gate applies -> Aura receipt). Queue AFTER the current cohesion joins unless marked NOW.

## From Hermes (compounding)
- SKILLS FROM LIVED EXPERIENCE: Kira notices repeated successful procedures and drafts a reusable skill; the skill is a
  PROPOSAL through the gate (owner approves before it persists or runs); Aura records its origin. Memory that becomes
  tested procedure, not just remembered text.
- SCOPED SUBAGENTS: delegated sub-agents hold scoped, expiring, revocable authority (Prime's grants / one-use kernel
  authority), each in its own sandbox.

## From goose (standards, survival)
- MCP + ACP mounted for real: external tools come in as MCP servers BEHIND the gate (each tool call judged, recorded);
  ACP so other agents can talk to Auma under scoped authority.
- PROVIDER ABSTRACTION: "models change, identity stays" must be true in code: DSH model registry; DeepSeek today,
  Ornith (Nebius) later, others via a host-held capped ask_model tool.

### goose, concretely (block/goose; Linux Foundation AAIF) — take the plumbing, run it through Prime's constitution
Tier 1: (1) MCP CLIENT LAYER: JSON-RPC sessions, tool listing, registry attaching external MCP servers; every MCP tool
call = authority check -> Aura entry -> execute (refused at the protocol layer without a grant). (2) BUILTIN-EXTENSION
PATTERN: Prime's own organs (Kira memory, Aura record, gate/approvals, Aumlok identity) exposed as MCP servers inside
Prime, so other agents can consume Prime's identity/memory/authority layer over MCP: the AAIF conversation in code.
(3) PROVIDER TRAIT: one model interface, capability flags, config-driven; DeepSeek -> local -> Nebius/Ornith swaps change
nothing above it.
Tier 2: (4) RECIPES as authority-scoped workflows (YAML lists tools AND the grants it requests; owner signs on import;
self-learned skills export as recipes). (5) TRACE SCHEMA: replayable structured event log; Aura is the signed superset.
(6) DAEMON + THIN CLIENTS: one authority/memory/identity backend, every interface (desktop, CLI, Nostr, voice) a client.
Tier 3: (7) ACP server mode (IDEs drive Prime). (8) Scheduled/debounced triggers that inherit a pre-signed scoped grant.
Not taken: the Rust core, goose's Electron app, its prompt orchestration.
STRATEGIC: an MCP-speaking Prime whose identity/authority/memory organs are themselves MCP servers is what makes a
Linux Foundation / AAIF conversation possible. Earn it with running code first.

## From OpenClaw (presence) — minus the recklessness
- PRESENCE LAYER: Auma lives where Peter lives. Nostr first (ours, encrypted, owner-bound), then other channels only
  through the same gate and record.
- THE NEGATIVE LESSON: skill-marketplace prompt injection. Every external skill/tool produces an auditable authority
  trail and runs sandboxed; nothing installs itself.

## From the harness-security research (hardening the core)
- TAINT-AWARE AUTHORITY (NOW, design): when untrusted content (web, inbound messages, external skill output) enters
  Auma's context, her available authority narrows automatically for that turn: no new egress, no host-affecting
  proposals marked routine; the owner card says "this proposal followed untrusted input". Provenance, not regex.
- STAGED EFFECTS: tool effects happen in a staging copy (sandbox workspace / copy-on-write) and are committed only
  through the gate; refused = discarded. (The theme gate already does this for its target; generalize.)
- KEY RESILIENCE: guardian/threshold recovery for the owner root (optional guardians from Peter's own graph; never
  2-of-2) + hybrid PQ signatures (already in source: Ed25519+ML-DSA-65).
- FORWARD SECRECY for any transport that carries private data (tunnel already SSH; future relay sync uses ephemeral keys).
- EXECUTION PROOF (later): reproducible release builds; hardware attestation / confidential VM on Nebius when available.
- WASM CAPABILITY CELLS for small tools (memory/syscall/egress limits per tool), extending the existing WASM cell.

## Owner card (Peter's rule, 2026-10-04)
NO typed codes, NO forced reveal/scroll/dwell. Instead CLARITY: one plain line "what this does", a ROUTINE / CRITICAL
label from the gate (plugin-set, code, keys, egress = CRITICAL), red outline for CRITICAL, blue for routine, gate facts
and from->to on top, model text fenced and labelled. One click to approve.

## Honest scope
These are directions with named mechanisms, not claims. Each lands only as: one owner, one pinned base, one real
Nebius result, labelled RAN / SOURCE / NOT YET.
