# Proposed harness build guards — not applied

The parked check-registration patch also replaces the harness build pipeline.
This extraction leaves that implementation, launcher pins and every existing
build format unchanged. The two associated courts remain unregistered:

- `scripts/check-pristine-inventory.py`: **depends on a proposed build change**.
  On this revision its first synthetic extraction invokes the forbidden `tar`
  sentinel and fails. The proposed producer replaces external extraction with
  validated archive extraction and a complete inventory comparison. It refuses
  unsafe or duplicate paths, multiple roots, special members, escaping/dangling
  links, unexpected or missing inputs, type/mode/hardlink changes and changed
  bytes before package-manager execution. It also refuses a full build using
  the fixture-only `--skip-pristine` bypass. Current archive and regular-file
  digest checks do not establish that entire inventory property.
- `scripts/check-harness-identity.mjs`: **depends on a proposed build change**.
  On this revision it cannot import `HARNESS_COMPILER_REQUIRED`. The proposal
  adds a stable identity over archive/patch/lock pins, compiler inputs, complete
  host/client output sets and coverage rules, keeping producer commit/platform
  metadata as separate provenance. Its consumer re-derives those bytes rather
  than accepting an edited identity document. Current format-v1 verification
  still binds the successful build receipt to its recorded compiled inventory;
  it has no separate identity document or compiler-input closure.

`harness/check-release-integrity.mjs` also depends on the proposed identity
exports and remains unregistered; its import fails on this revision. This is
not a missing local build that can be filled by copying a historical receipt.

The proposed successful-build binding changes from format 1 to format 2 and
adds `.dsh-build/pinned-harness-identity.json`. It explicitly refuses historical
format-v1 receipts; rewriting those receipts would not qualify an old build.
That would invalidate all already-built harnesses on the three machines in the
release rehearsal. **Every built harness must be rebuilt**, its downstream
owner/UI build bindings reviewed, and the gate package **re-approved** because
its bootstrap pins `scripts/lib/artifact-integrity.mjs`.

The owner must decide whether and when to schedule that separate build-format
change, review the exact producer/consumer diff and move the launcher pin
through its existing review mechanism. A compatible transition is a separate
design decision, not implemented here. Run these unchanged courts after that
decision; do not weaken their expectations to register them now.

The proposed source guards and synthetic courts would not prove a reproducible
compiler, an honest same-UID producer, installed containment or owner approval.
