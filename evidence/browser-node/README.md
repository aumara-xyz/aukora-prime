# Browser node records

No real-run record is supplied by the source tests. An operator collects a new
file with `bash ops/node-spawn/browser/acceptance.sh --name N --phase after --evidence OUT.json`,
then runs `node scripts/audit/browser-node-evidence.mjs OUT.json` and reviews it
before committing here. Keep the signer fingerprint separately for comparison.

| Row | What a committed record supports | What it does not prove |
| --- | --- | --- |
| Each operator-collected JSON record | Its embedded Ed25519 key signed the exact approval receipt and apply ledger row; release/plugin-set/record digests and the floor's core fields agree. Named check outcomes are retained as observations. | That key belongs to a real node; checks ran; current or installed bytes, TLS/browser behavior, containment, owner presence/identity/device custody, full ledger integrity or latestness. The record, checks, time and installer digest declarations are unsigned. The floor has no standalone signature; history, epoch and protected custody remain unverified. Committing the file preserves supplied evidence and adds no runtime attestation. |

The exporter includes no hostname, address, origin, private key, bearer, cookie,
claim link, journal or command output. A valid failed-observation prefix ends in
FAIL; later checks were not run. Do not turn a fixture into a real-run row.

## Records

- `2026-10-13-rehearsal-r1-38004c5.json`: collected from a REHEARSAL node (`aukora-r1`) on the test machine at
  revision `38004c5`, after-approval phase, 22 checks PASS. Its approval was made by a stand-in through the gate's
  page (the receipt's approver label says which channel), not by the owner, and the node was never bound.
  `node scripts/audit/browser-node-evidence.mjs evidence/browser-node/2026-10-13-rehearsal-r1-38004c5.json`
  verifies the receipt signature, the approval bindings, the signed apply row and the floor binding, and lists
  what it cannot verify. The exporter that wrote it was the working copy later committed with this record
  (run from outside the node's installed checkout, which was one revision older).
