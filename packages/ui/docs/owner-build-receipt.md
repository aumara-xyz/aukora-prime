# Owner client build receipt

Build the separate owner client from a Prime-owned, already materialized pinned DSH harness:

```sh
node packages/ui/scripts/build-client.mjs --dsh vendor/dsh --only prime-authority --output .runtime/owner-client
```

The compiler runs in a fresh disposable overlay. The recipe clears only the overlay's owner `lib/types` and incremental cache, copies adapters and their declarations into both source-typecheck and compiled-bundle resolution seats, then typechecks and bundles. It performs no install and never writes donor faces or the input harness.

The generated `.runtime/owner-client/build.json` is receipt version 3. `source_commit` retains its historical meaning as the pinned DSH upstream commit. `upstream_commit` repeats that pin and `source_commit_attribution` explicitly excludes a Prime/UI commit claim. Source identity is the actual input path, byte count, and SHA256 closure under `owner_build`.

`owner_build` version 2 records:

- `source_inputs`: independently discovered owner `src`, package/config, all top-level adapter `.mjs` and `.d.mts` files, build recipe/verifier, compatibility/baseline pins, available capture-review provenance, and frozen Layout source/config/bundle dependency. Paths are relative to `packages/ui`.
- `source_inputs_before_sha256` and `source_inputs_after_sha256`: equal hashes of that ordered record array before and after compilation. Both actual overlay adapter seats must match the local UI closure. A changed input refuses the build receipt.
- `build_inputs`: hashes of the actual overlay's shared DSH `clientBundle` helper and its runtime helper imports, compiler configuration, lock and verified stable pinned-harness identity; the generated owner config; and separate declared dependency/build tool package metadata and versions. Paths are relative to their stated Prime UI or pinned-harness origin.
- `build_inputs_before_sha256` and `build_inputs_after_sha256`: equal hashes before and after compilation.
- `output_artifacts`: client JavaScript, sourcemap, every regular file in the generated `lib/types` (including declarations, JavaScript/maps, and source-copied controller files), and the copied Prime no-op host. `path` is the canonical package path, such as `prime-authority/lib/client.js`; `output_path` is its location relative to the recipe output, such as `prime-authority/client.js`. Copied controller runtime and declaration bytes must exactly match their source inputs.

Copy the generated owner client/map/no-op host into `packages/ui/prime-authority/lib`, the generated `prime-authority/types` files into `lib/types`, and the generated `build.json` into `lib/build.json`. Preserve the source files used for that build. The receipt contains no temporary absolute paths or credential values. This document is guidance, not a compiler input.

Verify the canonical source and package output files:

```sh
node packages/ui/scripts/verify-owner-build.mjs --ui packages/ui
node packages/ui/scripts/verify-owner-build.mjs --ui packages/ui --dsh vendor/dsh
node packages/ui/scripts/check-owner-build.mjs
```

The optional `--receipt` accepts another receipt file. The exported API is `verifyOwnerBuild({uiRoot, receiptPath?, dsh?})`. Without `dsh`, it re-derives the complete local source and output path lists and checks their hashes, while reporting pinned build inputs as recorded and not rechecked. With `dsh`, it also rechecks the recorded pinned helper and package metadata bytes. Missing/omitted input, changed source/bundle/type, missing bundle/receipt, and false source attribution are refused in disposable copies of the genuine compiler receipt and bound source/output files. The mutation check does not create or repair a compiler receipt.

The foundation retains its exact historical donor `lib/build-manifest.json`, including excluded donor-host hashes. That receipt does not bind `package.json`; it must not be rewritten to describe Prime's no-op host or an unperformed rebuild. `prime-import-manifest.json` records six exact donor files and one license-only package adaptation, with separate original donor and current hashes. `check-foundation.mjs` verifies the combined seven-file closure and recovers the original donor package bytes by removing only the added `AGPL-3.0-or-later` line. Expected foundation client remains 25,299 bytes, SHA256 `2f8c54346a033f8b213985d541544e868912a7cf49cd07a8b3469e509f6edc16`. Composition must regenerate its snapshot pins for the adapted package and import manifest; source consistency does not establish a new compilation or installed result.

H must independently compare the release file and guarded HTTP response bytes with the expected foundation/owner client hashes, record the actual served URLs without connection credentials, and observe both exact native module IDs loaded without plugin failure: `@aukora/dsh-plugin-foundation` and `@aukora/prime-authority-ui`. Record the release/source identity and runtime PID alongside those results. Source receipt PASS does not prove served bytes, an active palette, loaded memory, or an authenticated owner. Browser acceptance remains separate.
