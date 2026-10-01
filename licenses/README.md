# Licenses and upstream notices

AUKORA Prime's existing package declaration is **AGPL-3.0-or-later**. The full GNU Affero General Public License v3 is in the root [LICENSE](../LICENSE). Third-party source retains its original licenses, copyright lines, notices and provenance.

This directory is an additive source-license index. Original notices remain beside imported source. The exact copies under [`upstream/`](upstream/) carry the same bytes; their source paths, hashes, archive integrity and selected versions are recorded in [`inventory.json`](inventory.json). That inventory describes its named source commit, not a future release.

## Owned package declarations

At the source commit recorded in the inventory, 20 of 22 Prime-owned package manifests declare `AGPL-3.0-or-later`. Two owned manifests omit the field:

- `packages/ui/foundation/package.json`
- `runtime-dependencies/pg/package.json` (and the corresponding root entry in its lockfile)

The existing root license and declared variant remain in place. The missing metadata should use the same variant. The foundation's package bytes are bound by content/provenance manifests and build receipts; its owner must refresh those bindings when adding the field. The third-party jsQR module shim also omits a package field, and retains its Apache-2.0 license beside the source.

## Upstream source

| Source or dependency | License | Notice and provenance |
| --- | --- | --- |
| Prime-owned source | AGPL-3.0-or-later | [Root license](../LICENSE); owned package declarations |
| Imported AUKORA kernel and memory verifier | Original AGPL terms and notices preserved | [`upstream/prime-source/packages/`](upstream/prime-source/packages/); per-package provenance manifests |
| DeepSeek Harness, pinned commit `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720` | MIT | [DSH MIT license](DSH-MIT-LICENSE); [upstream notices](DSH-THIRD-PARTY-NOTICES.md); [`upstream-dsh.json`](../upstream-dsh.json) |
| DSH native system / Landlock launcher and platform packages | BSD-3-Clause | [Native system license](upstream/dsh/native/system/LICENSE); source and platform notices in [`upstream/dsh/native/system/`](upstream/dsh/native/system/) |
| DSH Cordis and foundation libraries | MIT | Original licenses in [`upstream/dsh/vendor/`](upstream/dsh/vendor/) |
| NVIDIA OpenShell `v0.1.2`, commit `6648bd0c290efbc41ba131ee9831ee45cd431f94` | Apache-2.0 | [License](upstream/prime-source/packages/execution/licenses/Apache-2.0.txt); [SDK provenance](../packages/execution/provenance.json) |
| Noble ciphers, curves, hashes `2.2.0`; post-quantum `0.6.1` | MIT | [Exact licenses](upstream/prime-source/packages/authority/upstream/vendor/authority/deps/); [pinned dependency provenance](../packages/authority/upstream/vendor/authority/deps/PROVENANCE.json) |
| Three.js `0.180.0` / `r180` | MIT | [License](upstream/prime-source/packages/ui/faces/apps/vendor/three/LICENSE); [upstream file hashes](../packages/ui/faces/apps/vendor/three/upstream-three.json) |
| Nayuki QR Code generator | MIT | [Original notice](upstream/prime-source/packages/ui/faces/aumlok/src/vendor/qrcodegen/LICENSE) |
| jsQR | Apache-2.0 | [Original license](upstream/prime-source/packages/ui/faces/messages/src/vendor/jsqr/LICENSE) |
| pg `8.16.3` and 13 selected npm dependencies | MIT / ISC, per package | [Exact notices](upstream/npm/); [lockfile](../runtime-dependencies/pg/package-lock.json); [driver provenance](../runtime-dependencies/pg/PROVENANCE.json) |
| Electron `44.4.3` npm installer closure | MIT / BSD-2-Clause / ISC / Apache-2.0, per package | [Available exact notices](upstream/npm/); [lockfile](../packages/desktop/package-lock.json); [desktop provenance](../packages/desktop/PROVENANCE.json) |

The copied [DSH third-party notice](DSH-THIRD-PARTY-NOTICES.md) is unchanged from the pinned DSH archive. Its internal paths are relative to that archive's root, materialized at `vendor/dsh/` by the build. It lists direct runtime/development dependencies; the DSH pnpm lockfile and Python `uv.lock` contain the version closures. DSH's own Python SDK declares MIT. Prime's Python tooling uses the standard library and preserved AUKORA verifier source.

[Genesis-NOTICE](Genesis-NOTICE) preserves historical donor attribution. Its old paths and inventory statements describe the donor tree. The kernel's original NOTICE also preserves a historical Convex reference; Prime's selected kernel dependency closure is the four pinned Noble packages shown above.

The tracked repository contains source, browser assets and selected lockfiles. Native executables, `.node` binaries, npm archives and Electron/Chromium distributions are outside the tracked source. A binary release requires an inventory for its actual output: Chromium notices, statically linked libc/toolchain notices, OpenShell gateway image dependencies and any optional provider payloads. The selected `@electron-internal/extract-zip@1.0.5` npm archive declares BSD-2-Clause but omits its full copyright/license text and Rust/native dependency attribution; obtain those before redistributing its binaries. The exact missing-observation scope is recorded in [`inventory.json`](inventory.json).

When updating a dependency, retain its original notice and regenerate the source inventory against the new exact pin. Preserve upstream copyright/contact lines as attribution.
