# ADR: evidence needs identity and bounded paths

Status: existing exporter behavior documented; no executable change. Source account: `6750564abafca58a1f785ef5fe158940ff959012`. Relevant module: `scripts/kira/public-evidence.mjs`; existing offline controls: `tests/public-evidence.test.mjs`.

The retained exporter comments described three earlier lessons. A materialized release can have a different record digest at another absolute path, so a bare digest is not portable provenance. A strict-read helper returns `{bytes, text}`, so returning that wrapper instead of its bytes breaks the caller's hash/parse contract. A manifest-supplied path can escape an export even when its digest is correct; an independently enumerated file list alone does not constrain that supplied path.

The existing decisions are preserved: publish producer commit, relative member path and byte count with each digest; hash/parse bytes from one strict read; validate member paths before reads and listing comparisons. Comments now state invariant, threat and reason at those guards. This ADR records the history without keeping debugging anecdotes in the guard itself. No new exploit, test case, live probe or acceptance claim is introduced.

The duplicate Apps face also carried historical private session metadata in a comment. Its canonical source now uses the already sanitized frozen NEXT wording; executable text and frozen NEXT/build artifacts are unchanged. Source bytes and any future source/build identity still change when comments change. An operator must not relabel an old deployment or receipt for that new source.
