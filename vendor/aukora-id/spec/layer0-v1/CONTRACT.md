# Layer 0 freeze — CLASSICAL / LOCAL skeleton v1

Frozen for W1–W6 implementation and independent W8 acceptance, 2026-10-06.
This is a contract, not implemented behavior, acceptance or permission for LIVE use.

## 1. Authority, inputs and precedence

This file plus `registry.json` is the small normative overlay on
[`overnight/inputs/LAYER0-BRIEF.md`](../../overnight/inputs/LAYER0-BRIEF.md).
The brief's **Closed record inventory**, nested inventories, canonical bytes,
role restrictions, commitment/domain registry, verdicts, journal/lifecycle and
privacy/provenance rules are incorporated with the explicit substitutions below.
Those incorporated proposals are frozen for this skeleton where no UNKNOWN is
listed here. This does not approve the brief's unreviewed features. Do not fork
schemas privately between workers. A contradiction outside these substitutions
is UNKNOWN and nonauthorizing; report it to the parent, continue unaffected work.

Precedence: Peter's delegated overnight decisions and all L0-A01–A18 obligations;
this freeze; compatible incorporated brief; pinned Pentora specification/data;
compatible PLAN. Source SHA-256 pins are in registry.json. The starting commit is
`505c42250d6853aba9a314de48b5e4a6b4de05fe`. The approved display-data source is
`46ef286bdf51edc01704a0d97292fb20620339a7`; leave its files and expected values intact.

Write fresh. No Prime/prior/lab implementation or algorithm imports. No recovery
algorithm, VDF/lineage work, sponge/hash experiment, orientation register, movable
observer, learner or geometry on any authority path. No real keys, network
emission, new infrastructure or public relay publication in this profile.

## 2. Exact bytes and active profile (D03, D05, D07)

The active identifier is **`aukora.classical.bip340.v1`** (ASCII, case sensitive).
Its descriptor has exactly `profile` equal to that identifier and
`bip340_public_key:H32`. There is no null/empty/optional PQ member. Every supported
application signer-plan entry has `algorithms:["bip340"]`; its sole proof is
`{signer_index:U,algorithm:"bip340",signature:B64}`, exactly 64 decoded bytes.
Descriptor digest is H(`aukora.key.v1`, canonical descriptor bytes), as in the brief.
All “composite” authority descriptors/proofs in the incorporated inventory mean
this exact CLASSICAL variant. Root and delegated roles obey the same rule.

Hybrid readiness means a closed discriminated profile union, jointly signed
profile/algorithm/role/key identifiers and no fallback. The reserved identifier
`aukora.hybrid.bip340.mldsa65.v1` is **unsupported** here. An independently expected
hybrid profile with a classical record is a downgrade: REJECT/WRONG_AUTHORITY.
An otherwise unrecognized/unsupported profile is UNKNOWN/UNSUPPORTED_PROFILE;
an independently detectable bad outer signature still wins as REJECT. ML-DSA-65,
its transcript/mode/lengths and migration remain a later profile, never optional
proofs under a hybrid name. No PQ-strength claim.

The brief's restricted RFC8785 canonical form is unchanged. R is canonical UTF-8
of unsigned record; T = ASCII `aukora.record.v1` + one 0x00 + R; D = SHA-256(T).
Application BIP340 signs the **32 raw bytes D**. Content is canonical UTF-8 JSON
of exactly `{record,proofs}` decoded as the Nostr content string. The envelope
preimage is the UTF-8 NIP-01 array `[0,pubkey,created_at,8790,tags,content]` with
NIP-01 escaping, no whitespace outside values. Outer sig signs the raw SHA-256
of that preimage; event.id is that digest's lowercase hex. Never sign hex text or
include a record's own ID/digest/signature in its preimage. Key and record domains
are exact strings in registry.json; the following NUL is one byte, not two text
characters. Transport formatting outside content may vary; decoded content must
be byte-for-byte canonical. No final newline belongs to canonical signed bytes.

Outer fields are exactly id/pubkey/created_at/kind/tags/content/sig. `kind=8790`,
`tags=[["aukora","l0-v1"]]`. Regular-event semantics only. On 2026-10-06 the
[pinned NIP kind table](https://github.com/nostr-protocol/nips/blob/c3fd9af17939316bf6d0d83a5759100f8b0a1bdb/README.md)
and [current machine registry](https://github.com/nostr-protocol/registry-of-kinds/blob/master/schema.yaml)
contained no 8790 entry; the current NIP table likewise contained none. This is a
limited collision check, not a reservation or exhaustive global proof. **Public
allocation remains UNKNOWN.** Non-AUKORA content at that kind grants nothing.
NIP-01/BIP340 source revisions are pinned in registry.json; no dependency is
installed or cryptographic implementation approved by those standard pins.

Every listed inventory field is required, with null only where explicitly allowed;
all objects are closed. Exact H32/U/U64/Text/B64 rules and all brief input bounds
are frozen. Sets sort by canonical UTF-8 bytes, with no duplicates. Signer plans
sort by `(role,key_id,certificate_ref)` ASCII lexicographic order, null before text;
proofs follow signer index, then the sole algorithm. Duplicate role/key entries
reject. Required role sets come from the body, never from a requester-supplied plan.
Common windows require issued_at <= not_before and, when nonnull, not_before < expires.
Null expiry means no upper time bound only for the expressly listed nullable kinds;
it cannot remove a certificate/card/request/intent expiry. Authority ancestry and
certificates must be valid at issuance; authorization-now
also checks all applicable current windows, active keys, revocations and grants.

Input means copied bytes, never an object to serialize. Reject proxies, getters,
toJSON, malformed UTF-8, duplicate keys after escape decoding, unknown members,
negative-zero/decimal/exponent/nonfinite/unsafe numeric tokens and out-of-bound
proofs without invoking caller properties/coercion, callbacks or nested verification.
Shared/mutable caller buffers must be snapshotted once before parsing. No lazy
fetches or executable policy objects. Trusted Node owns parser, canonicalizer,
SHA-256/BIP340 and context acquisition initially; WASM wrappers remain host-dependent.

## 3. Roles, bootstrap and policies

The brief's body/role matrix applies. A genesis root is independently anchored by
expected subject, chain, genesis event and root KeyID; self-signature alone establishes
none of those expectations. Genesis is epoch/sequence "0", root outer signature,
root application proof, and appoints initial_append_key. All subsequent envelopes
use the one append key; inclusion never substitutes for an application issuer proof.

For later root proofs, `key_source:"certificate"` references the anchored genesis
or accepted root-changing epoch_transition. For initial journal_append proofs its
certificate reference is genesis; later append certificates are earlier key_binding
events. This resolves bootstrap references without forward/self references.
key_binding.parent_certificate_ref follows the same rule and parent_key_id is the
current root KeyID. Every other role resolves its prior root certificate or human
agent card. A root grant to an agent key alone never replaces a human-issued card.
`agent_card_ref` is mandatory for agent emission_request and null only for a
certified human_approval requester within that certificate's scope and budget.
Intent authority_ref is that exact card or human-approval certificate, not the request.

Epoch transition occupies the old epoch, sequence previous+1, old append signature,
current root proof and next append key proof. That key's earlier certificate must
cover the new epoch. In this transition only, the next key
uses role journal_append as a possession/acceptance proof; it gains no append
authority in the old epoch. `to_epoch=from_epoch+1`; the next journal event uses the new
epoch and sequence previous+1. Old and next append keys must differ. Optional root
replacement additionally proves successor possession and must be allowed by the
independently pinned succession policy; root compromise/recovery cannot improvise
such a policy. The frozen succession policy permits append-only rotation with
next_root_key:null; all root replacement remains UNKNOWN. Root retirement and all consumption survive transition.

Policy document schema is exactly `{schema:"aukora.policy.v1",policy_type:Text,
policy_version:1,parameters:<closed variant>}`. registry.json defines the only
recognized parameter objects; algorithm, scope, time, control, custody and
admission and append-only succession are active; recovery/persona/assertion are inert
refusal policies; the object itself is the template/default policy DATA, not executable
code. Pin each selected canonical document's H(`aukora.policy.v1`,bytes) in trusted
bootstrap context and the root policy reference. `effective_sequence` equals its containing policy_commitment sequence;
there is no deferred/retroactive activation. The newest committed policy of each
type governs subsequent evaluations under the source lock. A new policy never expands
an existing card. Bootstrap policy_commitment validates using the independently
pinned policy document and anchored root with authority_refs:[genesis]; no self/future
policy reference is required or permitted. It is active at its effective_sequence
only after that event commits under the current append key. Later commitments cite
the prior governing policy and issuer references. Install time/control/scope/custody
policies and required role bindings before the first LOCAL request; then append the
first coherence checkpoint over that preceding prefix. Genesis alone cannot emit.
Admission numeric defaults may be changed explicitly in a new
pinned policy, never inferred. Unsupported policy types/digests are
UNKNOWN/UNSUPPORTED_PROFILE; a hash does not approve semantics. Inert policies may
be committed and historically verified, but a path requiring their unreviewed
behavior is UNKNOWN. Recovery/persona documents are genesis digest inputs, not
new policy_commitment policy_type enum members. Only the three admission numeric
fields are configurable U values; all other registry parameter members are exact
literals. Recompute and independently pin the digest of any selected configuration.

The custody policy describes **disposable LOCAL test keys only**. Its restrictions
must actually be enforced by W3's trusted boundary: proposal code gets no signer,
control mutation, dispatch or storage handles. Observer custody is separate from
requester custody; two differently named keys in the requester's process do not
prove it. Custody/confinement failure is REJECT/WRONG_AUTHORITY; evidence unavailable
is UNKNOWN/MISSING_EVIDENCE. No sandbox, biometrics or hardware-key claim follows
from this schema. A test human_approval role signature is not evidence of Peter
clicking approval. P-256 descriptor/WebAuthn shapes remain recognized reserved
variants from the brief; assertion policies are unsupported, so operations needing
them return UNKNOWN/UNSUPPORTED_PROFILE, never substitute BIP340 consent.

Admission configuration fixes UTC calendar-month counting by the labelled source,
unique `(inviter_subject,invite_slot)` lifetime consumption and one counted directed
edge per inviter/invitee. Repetitions/cycles contribute no additional independent
support. The exact outside-subtree and independent-path predicates remain UNKNOWN:
no positive tier unlock until separately pinned. Revocation effective_sequence/effective_epoch must equal its containing record
sequence/epoch; deferred/retroactive revocation is outside this lane. Once committed,
its target stays revoked permanently. Vouch withdrawal only changes its
named admission predicates, never identity or Kira access. No claim of physical
presence, unique humanity or persona unlinkability is inferred from a signature.

## 4. LOCAL adapter and D08 boundary (D12)

The sole accepted Scope is the exact registry.json `local_scope` object:
`adapter_profile:"aukora.local.fixed-message.v1"`,
`site:{scheme:"local",endpoint:"aukora-test-sink-v1"}`, `resource:"sink"`,
`operation:"emit"`, `payload_class:"aukora.local.fixed-message.v1"`.
This replaces the older HTTPS-only Site for the active LOCAL variant. It denotes
one trusted in-process test sink, not a URI, hostname, port, file path, relay, shell
command, network socket or configurable callback. No normalization/aliases, redirect,
query, wildcard or alternate spelling. Any mismatch is REJECT/SCOPE_MISMATCH.
Even loopback HTTP is outside this profile. LIVE mode always refuses before signing,
reservation or dispatch (REJECT/WRONG_AUTHORITY).

Dispatch bytes are exactly the 18 bytes hex `41554b4f5241204c4f43414c20544553540a`
(ASCII `AUKORA LOCAL TEST` and one LF). Request/intent budget is exactly the sorted
array `[{unit:"bytes",maximum:"18",currency:null},
{unit:"requests",maximum:"1",currency:null}]`. Issuer ceilings may be larger but
must explicitly include both dimensions. No money units or dimensional conversion.
Both balances decrease atomically, with no refund for failure or expiry after reserve.
Budget buckets are keyed by immutable grant/certificate Ref plus unit/currency. Debit
authority_ref and every ancestor/certificate whose ceiling constrains this operation,
including the aperture certificate and human issuer certificate; two descendant cards
share their issuer ceiling. Reconstruct buckets from exact intent ancestry and permanent
reservations. No operation/epoch/import reset; a renewed certificate is a separately
authorized grant, not a way to revive the prior one. Invitation monthly caps are
separate buckets keyed by inviter/certificate and UTC year-month; invite_slot uniqueness
is lifetime, so a month change never reuses a consumed slot.

Payload commitment remains H(`aukora.payload.v1`, raw 32-byte fresh secret salt ||
exact dispatch bytes). Byte-parsed PayloadEvidence has exactly operation_id, salt
(B64 of 32 bytes), payload (B64 of those 18 bytes). Only the trusted aperture holds
this opening **in volatile memory**; compare it to the fixed literal, exact operation
and signed commitment at authorization and immediately before crossing. No plaintext
persistence/log/export of salt or payload. Lose it on crash: do not reconstruct,
resume, regenerate a salt or resend. Only public commitment/reservation/intent persist.
This narrow volatile input path selects no storage cipher and waives no D08 rule.

**No cipher or Observation statement profile is approved.** W5 may propose standard
AEAD for review. EncryptedEnvelope framing, key wrapping, nonce/AAD lifecycle and
persistent payload/evidence storage remain UNKNOWN/UNSUPPORTED_PROFILE. No plaintext
substitute, placeholder cipher, claimed authenticated import/export or `done` receipt.
Kira/provenance schemas and parsing can be built, while encrypted completion remains
unaccepted. Plaintext source hashes/provenance graphs stay private; no phrase-only
public/backup guess verifier may be created.

After an authorized attempt, a separately certified observer can sign an uncertainty
statement: receipt outcome `unknown`, dispatch_state `dispatched_uncertain`, evidence
`[]`, exact operation/intent/digest/actor/observer bindings, observed_at from the source.
An observer certificate with this adapter in adapter_profiles and statement_profiles:[]
permits only this empty-evidence uncertainty receipt, never an Observation/completion
claim. It proves that uncertainty was stated; it proves no completion. Such a receipt may
verify historically as valid. A candidate done/refused receipt needing unresolved
encrypted observation evidence is UNKNOWN, unless already conclusively malformed/
false (REJECT precedence). Definitely-not-dispatched after a protected pre-marker
crash is retained as local lifecycle/audit data; do not manufacture an intent-bound
completion receipt or encrypted artifact. A preauthorization refusal has no intent
and therefore no receipt. No recursive bookkeeping receipts.

## 5. One labelled time/control authority (D04, D06)

Source ID is `aukora.local-test-control.v1`, mode **LOCAL_TEST**. It is one trusted
Node service with one journal/control/lifecycle writer lock and one manually
advanced logical Unix-second clock for all participating LOCAL test subjects;
snapshots/floors are subject-specific. It is a deterministic test authority,
not actual wall-clock freshness, distributed control or independent witnessing.
Bootstrap time must be supplied explicitly; never derive it from issued_at or grant
content. Advancing time requires the trusted test controller under the same lock;
it can only increase. The authenticated current interval is [now,now]. The verifier
also accepts wider trusted test intervals to represent uncertainty; no skew grace.
The entire interval must satisfy every applicable not_before <= t < expires.
If lower >= expires: REJECT/EXPIRED. If upper < not_before: REJECT/NOT_YET_VALID.
Otherwise a straddled boundary: UNKNOWN/TIME_UNCERTAINTY. Missing source:
UNKNOWN/UNTRUSTED_TIME. LIVE always refuses regardless of these values.

Exact ControlSnapshot fields: source_id (the literal above), mode:"LOCAL_TEST",
boot_id:H32, revision:U64, time_policy_digest:H32, control_policy_digest:H32,
now_lower:Time, now_upper:Time, subject_id:H32,
chain_id:H32, epoch:U64, sequence:U64, head:Ref, checkpoint_ref:Ref|null,
control_state_digest:H32, floor:RollbackFloor. checkpoint_ref may be null only during
trusted genesis/bootstrap or historical evaluation; a LOCAL effect requires a prior
accepted nonnull checkpoint. RollbackFloor has exactly source_id,
subject_id, chain_id, revision, time_floor:Time, epoch, sequence, head and
control_state_digest with those same types. Snapshot/control-state/floor epoch means
the currently active append epoch after a committed transition, although head may
still be that transition event recorded in the old epoch. Checkpoint basis_epoch
is the epoch actually recorded on its basis event. revision increases for every committed
journal/control/lifecycle mutation or clock advance (including reservation/marker);
its overflow refuses. Each subject revision tracks mutations affecting that subject;
a clock advance updates every enrolled subject's time/floor/revision under the lock.
Both policy digests equal registry.json pins. Require
now_lower <= now_upper and floor.time_floor <= now_lower. The source commits its
current revision/head/digest into the floor and advances time_floor to now_lower.
boot_id changes on trusted restart; it is not a rollback proof.

The source retains the floor and complete revocation/consumption state outside every
identity/Kira backup/import/restore set. Reopening an existing subject requires that
independently retained floor and matching durable state; lower revision/time/epoch/
sequence, same-position different head/digest or unverifiable continuity freezes
current effects: UNKNOWN/ROLLBACK_UNRESOLVED (known competing journal heads are
REJECT/JOURNAL_CONFLICT). Never silently initialize empty state for an existing ID.
Only explicitly trusted fresh-genesis bootstrap creates a first floor. Atomic writer
storage must persist floor/state together or fail closed on uncertain commit. Loss,
whole-host rollback or untrusted writer protection is not solved: effects UNKNOWN.

Freshness has **zero cached age**: source snapshot is acquired within the current
writer lock, with exact current boot_id/revision/state. Context from a caller,
relay, prior boot or cache cannot attest freshness. The pure verifier can evaluate
supplied context, but only this source's trusted caller can use it for an effect.
Current snapshot reconstructs latest accepted epoch, active certificates/policies,
revocations, spent operations, nonces and budgets from the full authenticated prefix
and permanent protected execution ledger. Signed checkpoint alone is never currentness.
At initial authorization expected_control_checkpoint must equal the source's latest
accepted checkpoint; source also validates all descendants to current head.

Retain the brief's transaction verbatim in meaning: successful effect policy first;
then **permanent consume + every budget reservation + exact signed intent + initial
reserved_not_dispatched entry atomically durable**. Consumption is `(subject_id,
operation_id)` and separately `(subject_id,nonce)`, independent of event/epoch/backup.
An uncertain commit means no dispatch and reconciliation of that same entry, never
another intent or reset. Signing alone grants no dispatch capability.

Before the protected boundary, under the same single writer/control lock, acquire
current snapshot again and recheck time, current epoch/revocations/policies, exact
scope/opening, custody/confinement and exact reserved entry. Reservation has advanced
revision: validate its ownership against the **new** snapshot, not equality to the
old revision. The signed checkpoint reference remains the immutable authorization
basis; validate its ancestry plus subsequent control changes. Epoch change while
reserved blocks old-epoch dispatch; revoked/expired grants stay spent.

Durably mark dispatch_started before entering the sink. Marker write, final recheck
and synchronous sink entry remain inside that lock, with no await, user callback,
clock advance, control mutation or lock release between them. Maximum check-to-entry
gap is **zero logical clock ticks / zero intervening control revisions**, except the
marker's own revision. If this cannot be guaranteed, do not enter. This establishes
one LOCAL ordering point: a revocation/rotation committed before it prevents dispatch;
a mutation after it cannot unsend. It makes no real-time/network cancellation claim.

A crash with proved commit and no marker is definitely not dispatched. A marker
without conclusive operation-bound evidence is UNKNOWN, including crash before the
physical sink call. Every restart leaves consumed operations consumed and performs
**zero automatic resends**, including reserved_not_dispatched. Later reconciliation
must bind that same operation/intent; under D08 it cannot currently claim completion.
A new owner-reviewed operation would need a distinct authorization and explicit
uncertainty context; there is no retry shortcut or exactly-once-effect guarantee.

## 6. Shared data/API seam and projections

Implement these logical entry points; workers may choose packaging, not byte shapes:

| Interface | Exact boundary |
| --- | --- |
| `canonicalRecord(recordBytes)` | Strict supported record bytes -> canonical R bytes; no signing/state effects. |
| `applicationDigest(recordBytes)` / `keyId(descriptorBytes)` | Strict bytes -> 32 raw digest bytes using the frozen domains. |
| `nostrPreimage(eventBytes)` | Strict envelope bytes -> exact six-element preimage bytes; does not certify authority. |
| `verifyEvent(eventBytes,contextBytes,evidenceBytes)` | Bytes only -> exact brief VerificationResult below; pure, deterministic, no fetch/sign/dispatch. |
| `submitLocal(requestEventBytes,payloadEvidenceBytes)` | Trusted aperture service; obtains its own context/evidence. Returns OperationResult, never a dispatch token. |
| `recover(requestBytes)` | Always `{verdict:"UNKNOWN",reason_codes:["RECOVERY_UNREVIEWED"]}`; zero keys/shares/attempt-ledger/recovery mutations. |

Context is closed: `schema:"aukora.verify-context.v1"`, `purpose:historical_integrity/
authorization_now`, `expected_subject_id:H32`, `expected_chain_id:H32`,
`expected_genesis:Ref`, `expected_root_key_id:H32`, `expected_profile:Text`,
`expected_kind:Text`, `expected_signers:[{role:Text,key_id:H32}]`,
`policy_pins:H32[]`, `control:ControlSnapshot or null`,
`additional_anchors:[{subject_id:H32,chain_id:H32,genesis:Ref,root_key_id:H32,profile:Text}]`,
`additional_control:ControlSnapshot[]`. Both additional arrays are required (empty
allowed), sorted unique by subject_id/chain_id. Cross-subject vouches/certificates
resolve only against these independently supplied anchors, never self-asserted
foreign roots. Current foreign authority additionally needs its matching current
source snapshot; absent anchors/evidence -> UNKNOWN/MISSING_EVIDENCE, absent current
control -> UNKNOWN/STALE_CONTROL. Acquire/recheck every needed snapshot under the
same source lock. Historical foreign proofs need anchored historical evidence, not
a fabricated currentness statement. Signer expectations are
independently provided mandatory application roles, sorted by role/key_id; null is
not a wildcard. Genesis/current root expectations are distinct: expected_root_key_id
is the founding root, current root must have a validated succession chain. Historical
verification uses record issuance context/evidence, not current expiry; historical
valid never authorizes now. Historical records cannot establish current control.

EvidenceBundle is closed: `schema:"aukora.evidence.v1"`, `events:B64[]`,
`policies:[{digest:H32,document:B64}]`, `control_state:B64 or null`,
`artifacts:[{digest:H32,blob:B64}]`. Events preserve original bytes and are sorted
by event ID; policies/artifacts sort by digest, unique. Every decoded member reenters
the strict byte parser/profile validator. Digests and references must actually resolve.
No digest/key/profile supplied by this bundle becomes a trust anchor. Cipher artifacts
cannot be interpreted before D08. The total bundle bound includes decoded bytes.
`control_state` is the brief's exact ControlState encoding, matching the snapshot and
reconstructed prefix, never an alternative writable authority state.

VerificationResult has exactly verdict, reason_codes, record_digest:H32|null,
event_id:H32|null, validated_through:Ref|null, missing_evidence:MissingEvidence[],
conflicts:[[Ref,Ref]]. Vocabulary is frozen in registry.json/the brief; lists sort
and deduplicate by canonical bytes, each conflict pair smaller ref first. Report
all safely established reasons. Unknown digest/validation extent is null, not a
fabricated value. Conclusive supported rejection wins over UNKNOWN, then explicit
structurally valid DRAFT, then valid. Missing committed proofs are REJECT, never DRAFT.
Reason mapping: byte/UTF-8/JSON/scalar-token violations -> MALFORMED_BYTES; decoded
duplicate member -> DUPLICATE_KEY; closed-field/type/encoding/profile-shape violation
-> CLOSED_SCHEMA; size/depth/work bounds -> LIMIT_EXCEEDED; event-ID mismatch or
supported false signature -> BAD_SIGNATURE; absent mandatory proof ->
MISSING_REQUIRED_PROOF. Wrong expected subject/chain/epoch or role authority ->
WRONG_AUTHORITY; a substituted signer/key -> WRONG_SIGNER; kind/domain mismatch ->
WRONG_DOMAIN. Explicit scope/time/replay/revocation/conflict and unsupported cases
use the matching named code. A valid result returns no permission, signer or callback. UNKNOWN/DRAFT/REJECT cause
zero authorization, zero owner-signing and zero dispatch for that evaluation.

OperationResult is closed: operation_id:H32|null, intent_ref:Ref|null,
receipt_ref:Ref|null, state:`refused|reserved_not_dispatched|dispatch_started|unknown`,
reason_codes:the frozen code array. It reports lifecycle, not an authorization token.
Operation state `unknown` is outcome uncertainty after valid authorization; it
is distinct from verifier verdict UNKNOWN, which always blocks authorization.
An attempted operation returns reason MISSING_EVIDENCE until resolved. An attempt
is `unknown` until independently resolved; no settled-success return in
this freeze. After a failed recheck the already committed intent remains historical,
no new owner signature is made and no dispatch occurs. Audit/observer roles must not
be counted as signing a fresh owner intent. DurableOperation and ReservationDescriptor
are exactly the brief's inventories; caller-controlled writes to them are prohibited.

Projection assignments are now frozen: identity/key_binding/epoch_transition/
policy_commitment/recovery_policy and root/device/key_binding revocations -> identity;
vouch/vouch_accept/agent_card and vouch/agent_card revocations -> delegation;
emission_request/intent -> actions; receipt -> receipts; kira_map -> memory.
coherence_checkpoint is excluded from all five. Each head is the latest qualifying
**event ID** and sequence in one verified basis prefix. Null head/sequence means
no member; missing prefix evidence is different (UNKNOWN). Ordered heads are always
identity, delegation, actions, receipts, memory. No independent projection writes.
Checkpoint basis must precede itself, with exact basis epoch/sequence/event and
previous checkpoint link; reconstruct all heads/control rather than trust declarations.
Any fork freezes effects; sorting evidence never selects a winning branch.

Display consumes bytes independently. Freeze raw32 -> wire110/balanced110 and strict
wire110 <-> packed22 exactly as pinned data; center global55 is fixed balanced0.
No authority module depends on display output, exceptions or function identity.
No textual hex adapter in the initial public display API (mixed-case policy UNKNOWN).
Missing any projection head makes coherence unavailable, never zero-filled. Preserve
256 coherence vectors for later independent reproduction, but the production checksum
entry point remains unavailable pending finite counter/exhaustion policy and exact
12-point placement. Full110 renderer proceeds; no guessed placements or lab code.

## 7. W8 handoff, open gates and evidence

W8 owns independent corpus, expected bytes/digests/verdicts, hostile cases and grading.
W0/W1–W6 must not write acceptance tests, regenerate goldens on failure or treat
builder self-tests as acceptance. Preserve **every** brief acceptance obligation:

| IDs | Required coverage remains |
| --- | --- |
| L0-A01, L0-A02 | Canonical bytes/signatures; wrong role/subject/chain/epoch/site/key refusal. |
| L0-A03, L0-A04 | Exact expiry/intervals/currentness; exact LOCAL scope and budget attenuation. |
| L0-A05, L0-A06 | Concurrent/restart permanent consumption; current revocation and rollback refusal. |
| L0-A07, L0-A08 | Distinct pre/post-marker crashes; no resend; nonvalid and merely-valid grant no effects. |
| L0-A09, L0-A10 | Plain byte data, hostile parser/reentrancy/bounds; forks and single-prefix projections. |
| L0-A11, L0-A12 | Domains/profile downgrade/mandatory proof closure; exact independent receipt semantics. |
| L0-A13, L0-A14 | Authenticated encrypted Kira/provenance/no restored authority; no phrase oracle/recovery. |
| L0-A15, L0-A16 | Frozen display vectors/strict codecs/authority isolation; admission-only revocation/graph abuse. |
| L0-A17, L0-A18 | Stable unsupported-vs-false precedence; alternate verifier and honest Node/WASM boundary. |

This table is an index, not a weakening or replacement of the full A01–A18 text and
its additional variants in the pinned brief. Positive cases blocked by UNKNOWN remain
unfulfilled acceptance obligations, not skipped passes. Missing PQ proof can never
be accepted under a purported hybrid profile even though classical is the active lane.
W8 should independently cover new source-floor/revision races and exact LOCAL bytes.

UNKNOWN gates: D08 AEAD/key wrapping/persistent payload and observation profiles,
encrypted Kira roundtrip and done/refused evidence; actual wall/global freshness,
strong whole-host rollback protection and LIVE; reviewed succession/compromised-root
and WebAuthn policies; admission subtree/path independence/tier unlock; ML-DSA65 and
standalone WASM; twelve-point placement and bounded counter/text decoder; global
kind8790 allocation; vetted crypto dependency pins/licensing; real confinement/custody,
atomic persistence and alternate-verifier acceptance until builders demonstrate them.
Recovery stays schema + always-refusing stub, including reviewed resets/attempt ledger.

RAN before freeze: clean requested branch/base; >20 GiB disk and adequate memory;
read PLAN/brief/spec and vector DATA inventory; all eight manifest hashes matched,
5,360 expansion and 256 correctly ordered coherence rows counted; kind lookup above.
No project AGENTS.md/.agents/skills existed; global live-delivery instructions read.
No Prime/candidate-3/pilot/live/lab-code access or writes; no relay attempt. Parent
integrates and records LIVE.log. Not shown: implementation, signature/vector
reproduction, encryption, crash behavior, independent acceptance or installed runtime.

## 8. Explicit product overlay — 2026-10-07 sprint

Peter's direct product sprint authorizes only the extensions below. The frozen
V1 transcript, closed fields, policy-document bytes/digests and acceptance corpus
are unchanged. Registry `product_extensions` pins the exact added discriminants.
This section defines wire/authority requirements, not a runtime or acceptance grade.

**V2 approvals, root cards and intents.** Schema `aukora.record.v2` retains the
same required common fields and CLASSICAL profile. Its only kinds/domains are
`owner_approval`/`aukora.owner-approval.v2`, `agent_card`/`aukora.agent-card.v2`,
and `intent`/`aukora.intent.v2`. Application signatures cover the 32 raw bytes
`SHA256(UTF8("aukora.record.v2") || 00 || canonical_unsigned_record)`. V1 continues
to use `aukora.record.v1`; no cross-version signature fallback exists. Nostr kind
8790 and its six-element preimage remain unchanged. The outer append key signs
that envelope separately from the application signer.

V2 requires nonnull `previous_event` and `expires`, positive `sequence`,
`issued_at == outer_context.created_at`, `issued_at <= not_before < expires`,
and `consent_context:null`. Exact ordered tags are `[["aukora","l0-v2"],
["prev",previous_event],["seq",sequence]]`, identical in record and envelope.
V2 root cards alone append exactly one 12-string tag in this order:
`["aukora-delegation-v1",agent_key_id,adapter_profile,scheme,endpoint,resource,
operation,payload_class,not_before,expires,revocation_handle,"false"]`.
Every value equals the signed body/window; times use canonical nonnegative
decimal strings. This is an AUKORA tag, not NIP-26. V1 tags remain the exact
singleton `[["aukora","l0-v1"]]`, with no root-card variant.

An approval's closed body has exactly `operation_id`, `nonce`, `request_ref`,
`requester_key_id`, `scope`, `payload_sha256`, `payload_commitment`, `journal_head`.
All except Scope are H32. `journal_head == previous_event` must equal the retained
current head at admission. Approval and V2 card require exactly one current root
application proof, using the existing certificate source and resolved root
certificate/genesis reference. V2 card body is the unchanged closed card body,
with no onward delegation. Approval advances actions; card advances delegation.

V2 intent retains the closed intent body and aperture-authority application role.
Its signed `authority_refs` resolves exactly one accepted V2 approval; its
`previous_event` is that approval's ID and its sequence is approval sequence+1.
Subject, chain, epoch, operation, nonce, request, requester, exact scope, payload
commitment and current root must match. The intent window must be contained in
the approval and applicable request/certificate windows. The trusted opening
must match both approval payload SHA-256 and the existing salted commitment.
Any intervening write requires a fresh approval. `authority_ref` remains the
budget card/certificate; approval does not replace grant narrowing, currentness,
custody or permanent consumption. Root-card and aperture ceilings both apply;
legacy human-card issuer ceilings remain. Unsupported V2 kinds stay UNKNOWN.
The frozen future-schema case (unsupported V2 kind with exact legacy V1 tags)
keeps `UNSUPPORTED_SCHEMA`; a V2-tagged unknown kind uses `UNSUPPORTED_KIND`.

**Trusted startup discriminator.** `aukora.local-host.v2` has exactly the existing
fields `schema,mode,directory,anchor,request_signers,append,aperture`, with
`mode:"LOCAL_TEST"`. Every submission requires current root approval and creates
a V2 intent. `aukora.local-host.v1` remains an explicitly selected legacy test
configuration only. There is no default, automatic fallback or proposal-selected
mode; the proposal still supplies only request and opening bytes. LIVE is blocked.

**Kira AES profile.** `aukora.kira.aes256gcm.v1` uses Node/WebCrypto AES-256-GCM,
32-byte random keys, 12-byte nonces and 16-byte tags appended to ciphertext.
Plaintext is at most 6128 bytes; ciphertext with tag is at most 6144 bytes.
Each fresh process-local writer has an independent random key/reference and burns
a monotonic 96-bit big-endian nonce before sealing, starting at zero, with at most
1048576 seals. Writers cannot be imported/resumed. AAD is
`UTF8("aukora.kira.aad.v1") || 00 || canonical(AAD-context)` with the unchanged
closed fields `schema:"aukora.kira.aad-context.v1",subject_id,chain_id,map_id,
revision,piece_id,key_ref,cipher_profile`; manifest piece_id is null.
Envelope/AAD/custody profiles must agree. Full tag verification precedes release.
Existing envelope/private/archive shapes do not change. The byte-exact legacy
`aukora.kira.chacha20poly1305.v1` is decrypt-only, never a new writer or active
signed-map profile. This Kira piece format is not NIP-44. For the active single-map
profile, the storage certificate's `restriction.namespace_id == map_id`.
`aukora.kira.provenance.claims.v1` authenticates stored metadata claims through
AEAD; it grants no authority or independent support absent separate evidence.
Recovery, production wrapping/custody and authority restoration remain unavailable.

**Narrow public LOCAL observation.** Only
`aukora.local.fixed-message.observation.v1` is an explicit public metadata
exception to the otherwise encrypted-only observation rule. Its exact canonical
artifact fields are pinned in the registry and parsed by the core observation
helper: schema `aukora.local.observation.v1`, fixed LOCAL adapter, subject/chain/
epoch, operation, intent reference/digest, actor, observer key/certificate, time,
`received_bytes:18` and `claim:"completed"`. No payload, salt or private provenance
is included, and this profile has no cipher dependency. Artifact digest is SHA-256
of its exact canonical bytes. Only `done`/`observed` with exactly one matching
`local_boundary_record` evidence item can use it. The verifier must resolve the
signed intent, recompute every artifact/receipt binding, and validate the current
root-certified observer's exact role, scope, epoch, window and revocation. Observer
key differs from requester, actor, append and root keys. Actual independent
receiver acceptance of the complete fixed message precedes its proof; a caller
claim or instrumentation notice is insufficient. Atomic receipt/artifact settlement
and no-resend behavior remain required. Failure or missing evidence remains UNKNOWN;
this exception grants no general provider-completion, private-data or LIVE profile.
