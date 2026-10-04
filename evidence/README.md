# Current evidence account

`current.json` is the canonical source for the current revision, claim and component/status tables in the root README, `docs/CLAIMS.md`, `SECURITY-BOUNDARY.md` and `ARCHITECTURE.md`. It separates source-account base, observed public main, operator-reported deployment and actually tested revision. It contains neither authority nor an implicit PASS. A newly received HEAD must be checked explicitly.

```sh
node scripts/audit/render-evidence.mjs --write
node scripts/audit/render-evidence.mjs --check
./security-review --list
```

Change facts only when the exact selected source or retained receipt supports them; keep historical failures and original evidence bytes. Operator Room reports are labeled REPORTED and are not independent deployment attestation. The signed public L2 export is a retained prefix with its own verifier/limits. Research reports and sanitized digests have RESEARCH scope, separate from deployed product evidence.

`face-copies.json` declares `plugins/aukora-face` the canonical shared face source and inventories 364 byte-identical preserved copies under `packages/ui/faces`. NEXT's frozen baseline and compiled donor bundles remain intact. The checker reads and compares complete bytes and membership; it writes no copies. Regeneration, removing snapshots, changing mounts or rebuilding would be a separate source/build change, outside this cleanup. Canonical-only plugin additions are not silently copied into NEXT.

`frontdoor` selects shared claim rows for the boundary summary and component map. `observations` retains timestamped floor, landed-card, INTERIM collector, failed-containment and start-gate facts. Their timestamps describe supplied evidence, not checks executed by a renderer. Public prose and this data omit internal transport/message identifiers.

Timestamp basis is explicit in `observations.timestamp_basis`. The floor/package/collector report arrived at 10:44:52 UTC and stated a 10:55 UTC check time; its evidence timestamp uses receipt time and preserves the stated check time separately. This account does not attest the operator clock or resolve that ordering.

The README containment summary is also generated from `observations.containment`. The [dated disposition record](containment/2026-10-04.md) preserves the original failed run, later host-firewall follow-up and three findings, including the guest finding still OPEN. It is a retained operator account, not a live-check receipt created by this task.
