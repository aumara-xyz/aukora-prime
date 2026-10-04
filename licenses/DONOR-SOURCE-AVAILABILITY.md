# Donor source availability

Selected donor material already included in Prime stays in this repository. Zeta Harp and historical Membrane repository names record provenance; neither donor checkout is required at build or runtime. See the [build and composition scope](../docs/PRIME-NEXT-ARCHITECTURE.md#build-and-operator-interface) and the [retained historical vendor README](../packages/ui/faces/apps/vendor/README.md).

The vendor README is retained byte-for-byte under the UI baseline manifest. Its donor-era manifest-generation commands, inventory descriptions and runtime mappings are historical. Use the [selected-file baseline](../packages/ui/baseline-manifest.json), [Prime architecture](../docs/PRIME-NEXT-ARCHITECTURE.md) and [current known gaps](../README.md#known-gaps) for the selected Prime scope. This disclosure does not modify that donor file or its pin.

Anonymous reads of the provenance-named Zeta Harp and Aukora Membrane GitHub repository pages on 2026-10-02 returned HTTP 404. That response does not distinguish a private repository from a missing one. Their external source availability is **UNQUALIFIED**; a donor identifier is not a verified public source-download promise.

| Donor reference | Current local source and provenance | Limit |
| --- | --- | --- |
| Zeta Harp | The 13 selected files are retained in [`packages/ui/faces/apps/vendor/zeta-harp/`](../packages/ui/faces/apps/vendor/zeta-harp/), with per-file hashes in the [UI baseline manifest](../packages/ui/baseline-manifest.json). The [vendor source account](../packages/ui/faces/apps/vendor/README.md) records commit `aa1100fa56e2a86ccd181cb39d13122e62abdf9f` and tree `8c2f47d67479c19ce98e0c8d57916fd6d86feb34`. | Local preservation does not establish current external repository availability or a new source build. |
| Membrane | The copied [Genesis notice](Genesis-NOTICE) retains historical `vendor/aukora-membrane/` references from its donor tree. The [component ledger](../provenance/core-ledger.json), row `core-15`, records the minimal consumer and Aura bridge as absent from the bounded Prime comparison, with restore/defer disposition pending. | Those historical paths are not current Prime source locations. No complete Membrane source closure or implemented consumer is claimed. |

The retained source bytes, copyright and license notices, and provenance pins are unchanged. This disclosure does not supply missing source, establish full corresponding-source or build equivalence, or qualify an installed runtime.
