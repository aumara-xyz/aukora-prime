# Auma Lingwa source and content-license distinction

This notice records the retained Auma Lingwa source and the limits of the available license evidence. It does not grant new rights or relicense language content as software.

## Included files and source

The selected Prime tree contains eight Auma Lingwa runtime and asset files. Its language canon, graded readers and browser implementation include:

| File under `packages/ui/faces/apps/vendor/auma-lingwa/runtime/app/auma/` | Bytes | SHA256 |
| --- | ---: | --- |
| `canon-v16.json` | 893,781 | `2d9ffed46912a7860b16c282d071bfed4c5555ee78c0bf8623e77d793531eb7e` |
| `readers-v1.json` | 9,344 | `e4c1b35fa4087cb2f692e1c3f4a831d3ef39b22ddef21849c56634b9bda1224c` |
| `auma.js` | 38,287 | `81f8ae277451a1360c58f69801c0ff12f48b9bf855781c5a50702365e2f68d36` |

Prime's [UI baseline manifest](../packages/ui/baseline-manifest.json) records donor `aumara-xyz/aukora-genesis` at `645d3213b8aede3b544269b4224ae09df06b0a42`. These three files match the recorded donor bytes. The imported vendor README also records earlier Aukora revision `b413a89b109900a9037a9ed725b0d1b474e4f550`; that historical identifier is provenance rather than a new license grant.

The runtime `canon-v16.json` is byte-identical to the donor's `plugins/aukora-face/apps/vendor/auma-lingwa/canonical/auma-canon-v16.json`. The [preserved canonical README](upstream/auma-lingwa/CANONICAL-README.md) describes the language, 948 vocabulary entries, 84 lesson days and six readers, and states that the application loads a byte-identical canon copy. Its exact donor bytes are preserved: 3,516 bytes; SHA256 `62a6408ead5455cc8c6beb27e64f100dd78baf071a5218b17594722ed6ca8514`.

The historical canonical and tooling directories are not included in this selected Prime runtime tree. Their excluded source pins remain in the baseline manifest. The preserved README is attribution and source context; it contains no CC license grant or version.

## Retained source license declarations and attribution

The [pinned donor repository README](https://github.com/aumara-xyz/aukora-genesis/blob/645d3213b8aede3b544269b4224ae09df06b0a42/README.md#license) declares `AGPL-3.0-or-later` and records: “Copyright (c) 2026 Aumara and Peter Viviani (the named owner).” It also states that third-party components retain their own licenses and notices. The full AGPL text is retained in Prime's [root LICENSE](../LICENSE).

The pinned donor vendor README also explicitly states: “The package and these sources are distributed under `AGPL-3.0-or-later`.” Its Auma Lingwa row names the language runtime, canon and readers. This is positive retained source-license wording for that included material. This inspection found no competing Auma-specific CC declaration, third-party licensor or separately licensed input in the inspected source records. It does not independently prove authorship or copyright ownership.

Those retained declarations are preserved. They do not establish a separate or alternate Creative Commons grant for the Auma language canon, lesson content or reader corpus.

## Current license scope

The retained donor declares the package and its bundled sources under `AGPL-3.0-or-later`, including the named Auma Lingwa source. The project owner has confirmed Auma as first-party material and directed preservation of the existing licenses. This notice records that existing source declaration; it assigns no new Creative Commons grant.

No separate CC license/version or competing third-party terms were identified in the inspected canon, readers, browser source or retained canonical documentation. A review description without an original license declaration does not replace the retained AGPL source terms. Third-party components retain their own licenses and attribution. This is a bounded source record, not an independent legal ownership guarantee.

No canon, reader, executable source, runtime asset, donor manifest or security pin was changed to prepare this notice. It does not claim a new build, complete legal clearance or runtime qualification.
