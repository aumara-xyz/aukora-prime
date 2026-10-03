# Evolution Lab — read-only source plugin

Separate client package at source base `ad03573dbaf0b22a93ee02bfb2efffd7be47eccb`. Only `packages/evolution-lab/**` is changed. H owns build/composition; B/H own the shared browser. No mount or current runtime qualification is claimed. For public integration, H must apply the package-only patch onto sanitized base `862bde766c35667816dc5e9fb575f065f88c5655` after review. Do not merge, cherry-pick or push this private old-base ancestry.

The default is unavailable, with zero entries. The viewer receives bounded JSON **text** through `createEvolutionController(manifestJson)` or the client plugin's `apply(ctx, { manifestJson })`; invalid updates clear prior results and show a fixed refusal. `controller.updateManifest(jsonText)` updates the displayed reference, and `controller.dispose()` stops updates/subscriptions. There is no transport, file picker, browser request, model call, command runner or permission/effect API. Commands and evidence instructions are inert text. Repository links are passive navigation to a fixed public repository origin; the plugin never fetches them.

All entry fields visibly inherit the entry's explicit evidence class (`measured`, `synthetic`, `historical-reported`, `proposed`, `unperformed`); artifacts, prediction, outcome and model provenance have their own classes. Execution is separately `RAN`, `SOURCE-ONLY`, `RECORDED` or `UNPERFORMED`. A recorded experiment is not a new measurement. Null cost/time means unmeasured; zero remains zero. Missing failure reports do not establish zero failures. Preregistration is unestablished unless a timestamp, pinned source and retained receipt are supplied; supplied references are not independently verified here. Registration and model provenance are not safety certification.

`schema/evidence.schema.json` is a portable closed JSON Schema (2020-12). `src/manifest.mjs` adds strict textual recognition, duplicate-key refusal, a 64 KiB UTF-8 cap, nesting/field/list bounds, finite metrics, real UTC dates, unique IDs, acyclic/dangling-reference checks and a strictly earlier preregistration timestamp when both reported dates are supplied. Entry and artifact IDs have distinct global namespaces. Receipt paths are restricted to `docs/evidence/**` and `research/evidence/**` with pinned 40-hex revisions. Basic private-path, IP, credential and invisible-character checks supplement upstream sanitation; they do not prove a manifest is privacy-safe. H must authorize a sanitized reference before supplying it. Unknown fields and versions refuse. Neither parser nor renderer executes evidence instructions; React escapes all text and attributes, without raw HTML insertion.

`fixtures/synthetic.json` is an opt-in invented parent/child viewer fixture. It is visibly marked **SYNTHETIC FIXTURE** and is never loaded by default. `fixtures/historical-memory.json` is an opt-in projection of the authorized sanitized `docs/evidence/bounded-memory-experiment.json` at the base pin. It preserves the older experiment source, synthetic signer/data, absent command/cost/timing/preregistration, pending indexing and qualification limits. It contains no raw private artifacts. After the publication history transition, its receipt link is intentionally unavailable: the sanitized publication revision is not present locally. H must verify the retained summary digest/path and add its sanitized revision before public import; no old-history public link is emitted. The separate reference recursion lab supplies no approved metrics to this package: its source inventory and synthetic scorer are not model results. No nine-generation metrics are invented.

Integration seam for H:

1. Build `src/client/index.mjs` with the existing pinned React 18.3.1/Layout/Cordis closure; the current owner-only UI recipe does not yet select this package. No install, new library or shared build-recipe edit is included here. This source export has no compiled receipt yet.
2. Register `apply(ctx, { manifestJson? })` as a **separate** client plugin. It registers `shell.surface` and `shell.menu.system`, id `evolution-lab`, order 80. The menu calls `openSurface('evolution-lab', undefined, 'contained')`. Optional JSON text must be injected by trusted integrator code; omit it for the truthful unavailable default. No owner/authority binding is required.
3. Keep the frozen faces unchanged. Existing `Card`, `SectionHeader`, `PortalButton` and `ActionButton` provide palette/disclosure/navigation. Scoped CSS inherits foundation tokens, keeps one-column content and uses a scroll viewport inside the shell's 74px+10px corner insets. Shell owns contained two-thirds/narrow geometry. No floating controls or shell geometry overrides are added.
4. H/B verify the actual composed release: wide/narrow contained measure, scroll extremes, keyboard disclosure/links, computed tokens and visible `[data-corner]` rectangle intersections. Build, browser rendering, screenshots and installed-app effects are **UNPERFORMED** by this task.

Source checks:

```sh
node packages/evolution-lab/checks/check.mjs
# Optional real pinned React server rendering; Layout primitives are represented by inert test wrappers.
node packages/evolution-lab/checks/check.mjs --react-runtime <pinned-react-directory> --react-dom-runtime <pinned-react-dom-directory>
```

The second command verifies HTML/attribute escaping and read-only presentation through actual React server rendering; it does not establish Layout pixels, browser behavior or live mounting.
