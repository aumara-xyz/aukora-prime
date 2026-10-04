# Current evidence account

`current.json` is the canonical source for the current revision and claim tables in the root README and `docs/CLAIMS.md`. It separates source-account base, observed public main, operator-reported deployment and actually tested revision. It contains neither authority nor an implicit PASS. A newly received HEAD must be checked explicitly.

```sh
node scripts/audit/render-evidence.mjs --write
node scripts/audit/render-evidence.mjs --check
./security-review --list
```

Change facts only when the exact selected source or retained receipt supports them; keep historical failures and original evidence bytes. Operator Room reports are labeled REPORTED and are not independent deployment attestation. The signed public L2 export is a retained prefix with its own verifier/limits. Research reports and sanitized digests have RESEARCH scope, separate from deployed product evidence.

`face-copies.json` declares `plugins/aukora-face` the canonical shared face source and inventories 364 byte-identical preserved copies under `packages/ui/faces`. NEXT's frozen baseline and compiled donor bundles remain intact. The checker reads and compares complete bytes and membership; it writes no copies. Regeneration, removing snapshots, changing mounts or rebuilding would be a separate source/build change, outside this cleanup. Canonical-only plugin additions are not silently copied into NEXT.
