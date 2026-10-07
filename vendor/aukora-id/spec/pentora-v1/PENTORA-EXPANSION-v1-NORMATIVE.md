# Pentora Expansion v1 — NORMATIVE (2026-10-06)

Status: normative for AUKORA identity display. Data only; no lab code. Every value below was independently recomputed by the author on 2026-10-06 (5,360/5,360 vectors, Golay parameters, geometry counts) from the lab artifacts named in MANIFEST.sha256. Decisions (1)–(3) relayed from Peter via Genesis lead on 2026-10-06, reversible.

## 1. Input
- `head`: exactly 32 raw bytes, the SHA-256 head of the subject's authoritative journal. Reject any other length. Hex input must be strict lowercase/uppercase hex of 64 chars; reject otherwise.
- Domain string: ASCII `pentora.display.v1` followed by one NUL byte (0x00). 19 bytes total.

## 2. Expansion
```
digest = SHA-256( "pentora.display.v1" || 0x00 || head )          // 32 bytes
N      = big-endian unsigned integer of digest                      // 0 ≤ N < 2^256
digit[i] = floor(N / 3^i) mod 3        for i = 0..109               // i = 0 is LEAST significant
cell[i]  = digit[i] − 1                ∈ {−1, 0, +1}                 // balanced ternary value
```
- Exactly 110 digits are produced; the remaining high-order part of N is discarded.
- Wire form: 110 bytes, byte i = digit[i] ∈ {0,1,2}. Reject any byte > 2, any length ≠ 110.
- Display mapping: digit 0 → −1, 1 → 0, 2 → +1.

## 3. Geometry index table (normative: `data/geometry_index_table_v1.json`)
- 5 cubes × 27 cells = 135 slots occupying 111 distinct locations: 90 private, 20 shared corners (each in exactly two cubes), 1 centre shared by all five.
- Global indices 0..110, 0-based, in exact lexicographic order of real coordinates (field Q(φ), exact).
- Centre: global index **55**, fixed value 0, NOT part of the 110 mutable cells.
- Mutable cells: the 110 global indices ≠ 55 (`mutable_indices`). `cell[i]` for i = 0..109 maps to `mutable_indices[i]` in ascending order.
- Shared corners (`double_corner_indices`): 0, 1, 10, 12, 16, 18, 27, 28, 52, 53, 57, 58, 82, 83, 92, 94, 98, 100, 109, 110. One storage cell per location; both cubes read the same value.
- Local convention: cube order 0..4; local slot order = product((−1,0,+1), repeat=3); per-cube local→global in `data/cube_local_to_global_v1.tsv`.
- Translation appendix: the MASTER lab's table (centre = local 0 convention) is kept at `data/master_index_table_v0.1_TRANSLATION_ONLY.json`. It is NOT normative. Dated note: on 2026-10-06 the two labs agreed on physical geometry but differed on 107 of 111 indices; the TOY table was adopted because it matches the hardened display fixtures. Renderers translate; they never redefine indices.

## 4. Coherence pattern (12-point display checksum; `data/golay_generator.json`)
Inputs: the five ordered journal-projection heads, each 32 raw bytes, in this fixed order: **identity, delegation, actions, receipts, memory** — the five projections of the single AUKORA journal (Layer 0 decision D11). Order is part of the spec; changing it changes the pattern. Correction 2026-10-06 (later the same day): the first issue of this document listed gate, action, kira, aumlok, relay; superseded by CORE's confirmation, text changed in place before any downstream use, vectors issued under the corrected order.
```
D = SHA-256( "pentora.coherence.heads.v1" || 0x00 || h1 || h2 || h3 || h4 || h5 )
for counter = 0, 1, 2, ...:                                           // rejection sampling, unbiased
    x = big-endian uint16 of SHA-256( "pentora.coherence.payload.v1" || 0x00 || D || counter as 4-byte big-endian )[0:2]
    if x < 64881:  payload = x mod 729 ; break                        // 64881 = 89 × 729
payload → 6 base-3 digits d[0..5], least significant first
word[j] = Σ_i d[i]·G[i][j] mod 3   for j = 0..11                       // G = 6×12 generator in data/golay_generator.json
```
- The code is the extended ternary Golay code [12,6,6]: 729 codewords, minimum weight 6, weight enumerator 1 + 264z⁶ + 440z⁹ + 24z¹² (verified). Any ≤2-trit corruption of a displayed word is repairable by syndrome lookup (289 syndromes, verified exhaustive 210,681 cases).
- Known-answer vectors: `data/coherence_vectors_v1.json` (256 cases: all-zero heads, all-0xFF heads, byte-pattern heads, 253 seeded cases); each gives heads, D, rejection counter, payload, 12-trit word. Independently recomputed by the author.
- Placement (CONFIRMED by CORE 2026-10-06): word[j] on icosahedron vertex j, j = 0..11 (vertex order: the 12 dual-icosahedron points in the same lexicographic coordinate order as §3; see `data/geometry_index_table_v1.json` → `points` for the 20 dodecahedral corners; vertex j of the icosahedron is the centroid of dodecahedral face j in that order).
- Properties (measured): a single changed head is missed with probability 1/729 (135/100,000 observed). A chosen 12-point pattern was matched 145 times in 100,000 synthetic attempts. **The coherence pattern is a visual checksum only. It never authenticates and never authorises.**

## 5. Packed state (22-byte form of the 110 cells)
- Interpret digit[0..109] as a base-3 integer with digit[109] most significant; encode as exactly 22 big-endian bytes (3^110 < 2^175 ≤ 2^176). Reject any value ≥ 3^110 and any length ≠ 22.
- This is a lossless re-encoding of §2's wire form, nothing more.

## 6. Security boundary (normative statements)
- Pentora displays a public commitment (the head). It stores no content, keys, phrase, or inviter identity. Cells derive only from the head's hash.
- SHA-256 and the journal signatures are authoritative. No visual element authenticates or authorises.
- A photo of a Pentora reveals a fingerprint matchable against known candidate heads; it does not prove identity, inviter, authorisation, freshness or untampered history. Video additionally exposes activity timing.
- Pattern-only recognition of "my Aura" performed at chance in lab tests; copy must describe the Aura as activity (it moves on accepted signed exchanges), not as a recognisable face.
- Two invitees of one inviter must have uncorrelated patterns (measured: agreement 33.18% vs 33.64% unrelated, within ±1 point equivalence). Any renderer feature that correlates with inviter is a defect.

## 7. Known-answer vectors (`data/`)
- `expansion_vectors_1006.json` (1,006) and `expansion_vectors_4354.json` (4,354): each record {head hex, sha256 hex, wire_hex (220 hex chars), balanced…}. All 5,360 recomputed by the author from §2 with zero mismatches, matching the three lab implementations (Python, JavaScript, WASM).

## 8. Out of scope / not established
Pentora sponge hash (research only), cube turns as computation (no measured advantage, seven rounds), orientation registers and movable observer (lost their tests), VDF "birth"/lineage work (precompute by colluders unresolved without a public randomness beacon; no library available), recovery protocol (design brief assigned to MASTER lab), production Nostr verification and durable replay protection (unbuilt).
