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

## Typed evidence maintenance

Every claim declares `evidence_kind` and `scope`. OPERATOR_REPORT, RETAINED_RECORD, SOURCE_RECORD and RESEARCH_RECORD describe the basis; SOURCE, STAGING, LIVE, HISTORICAL, RESEARCH and UNQUALIFIED describe its subject. A source check cannot be rendered with installed scope. The renderer rejects future evidence timestamps before writing any section. A missing exact run time is `null`, displayed as not supplied; do not substitute a planned time or the docs commit time. Historical operator-clock discrepancies remain explicitly described.

The existing `observations.containment.named_exceptions` uses `aukora-containment-exceptions/v1`. Each unique route requires a nature, risk, status, owner approval and expiry. `DISCLOSED_ONLY` with `owner_approval: null` and `expires_at: null` preserves missing evidence. A report that a candidate is nonblocking does not supply a route approval or expiry. `APPROVED_EXCEPTION` requires a retained Peter approval reference and an unexpired timestamp; renderer validation checks shape and presence, not signature validity or owner identity. No exception clears the unchanged ANY ALLOWED = FAIL rule.

Attach only existing publication-reviewed raw transcripts through `raw_transcripts`, with a repository-relative `path` and SHA-256. For a local `path`, the renderer requires matching bytes. `REMOTE_REFERENCE` retains the exact durable `source_uri`, SHA-256, line/byte counts and inspection limit; the renderer validates metadata but does not contact the server or verify remote bytes. The inspected raw transcript remains outside the public tree to preserve account paths and runtime identifiers. Until supplied, an empty list renders UNPERFORMED; the dated disposition summary is not a raw transcript. No new proof packet or private output should be created to fill that gap.

Run the renderer write/check commands above against the actual allocated repository tree, then Kimi's qualification gate when its command and environment are supplied. Renderer PASS proves documentation consistency only. Host schema subset, custody, accepted pins, real DSH and organism containment qualification remain UNPERFORMED for this docs lane until actual output exists. Do not run the install README recipe as a documentation check; H/Kimi own that recipe.
