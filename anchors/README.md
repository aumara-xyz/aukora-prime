# Gate ledger head anchors

One JSON line per new verified head of the pilot boundary gate ledger, published from the owner machine (not the pilot) after each decision by packages/boundary-gate/anchor/publish-anchor.py on main.
Check an evidence export: node verify.mjs --anchor gate-ledger.jsonl --whole (docs/evidence/l2-demo-2026-10-04/).
This branch is append-only by convention; every change is a commit adding one line.
