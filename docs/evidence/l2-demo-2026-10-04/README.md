# L2 demo evidence — 2026-10-04 (pilot, boundary gate)

What happened, live on the pilot (times UTC+8):

- 11:08:04 Auma, in a chat session, called her one gate tool `aukora_gate_propose` with accent `#FFD700`
  (ledger #21 `propose`, proposal `b9187db9`). The gate answered `PENDING_OWNER`; she cannot approve.
- 11:08:06 the approval popup opened on the owner's desktop (#22 `review-issued`, a 120 s review challenge).
- 11:08:19 the owner clicked **Approve** (#23 `decide`, `allowed-once`, spent) and the gate applied the change
  (#24 `apply`), signing the receipt in `receipt.json` / `receipt.sig`. The running interface picked up the gold
  accent without a restart (the theme route then answered `{"accent":"#FFD700"}`).
- Refusals are in the same signed chain: #12 and #15 are owner **Refuse** decisions (`rejected`; nothing applied),
  #5 and #14 are refused decide attempts (malformed, and an approval tried on the propose channel).

## Check it yourself (Node 18+, no dependencies, no network)

    node verify.mjs

It checks against `gate-ed25519.pub.pem` (fingerprint `6cdce2bbeb7b725c`): the receipt's Ed25519 signature over its
exact bytes; every ledger entry's hash (sha256 of `[seq, at, event, proposal, target, base_sha, new_sha, detail, prev]`)
and Ed25519 signature; the chain from #1 (`prev = "GENESIS"`) with no missing entry; and that the signed apply
entry matches the receipt. Changing any byte of the receipt, its signature or an entry, or removing an entry, makes
it print `NOT VERIFIED`.

## What this does NOT prove

- Not that this is the gate's whole ledger: entries after #24 are not here, and dropping entries off the END is not
  detectable from these files alone (no head hash is published elsewhere).
- Not who sat at the desktop: "owner" means the owner socket (0600, gate user/root) reached through the owner's popup.
- The key is the pilot gate's own key; publishing it here is what lets a stranger check, not an outside attestation.

Exported read-only from the gate database (`export-evidence.mjs`, run as the gate user).
