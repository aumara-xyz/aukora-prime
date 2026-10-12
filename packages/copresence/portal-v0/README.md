# Co-presence portal v0

Source import from `aumara-xyz/aukora-contact` commit
`c5d315c117366892826bb60bc5743e674664c970`, subtree `copresence-portal-v0`
(AGPL-3.0-or-later). The donor subtree was clean. The page, vendor JavaScript,
SPEC and physical-test notes retain their original bytes. Statements and URLs in
those notes are historical donor claims, not observations from this import.

From the repository root with Node v24.11.1 and Python 3:

```sh
node --test --test-reporter=tap packages/copresence/portal-v0/tests/*.test.mjs
node packages/copresence/portal-v0/tests/stamp-csp.mjs --check
```

`portal/vendor -> ../vendor` preserves the page's resource paths. The vendor-only
CommonJS package marker lets the unchanged UMD jsQR load in Prime's ESM repository.
See `vendor/NOTICES` and the complete Apache-2.0 and MIT licence texts; the page's
SHA-384 SRI pins match the imported libraries.

The tests use Prime's existing sibling receipt/intent checkers and vectors.
`tests/data/toy/sim.py` is the unchanged donor Python oracle. Missing donor
`runtime/schnorr.py` comparisons now use Prime's existing independent Noble code
in `plugins/aukora-nostr/lib/vendor/noble-curves/curves/secp256k1.js`, with the same
25 deterministic differential inputs. No new dependency was added.
The optional three Pentora module comparisons retain their original skip behavior;
the default now points inside this unit (`tests/data/identity`, not included).
Known-answer vectors and independent mathematical geometry checks still run.

The maintained derivation is now `apps/aukora-desktop/pentora.mjs` (relative to
the repository root), promoted from `tests/pentora-port.js`: SHA-256 of
`pentora.display.v1`, NUL, and a 32-byte head, expanded to 110 base-3 digits,
least significant first. Its five-cube geometry has 111 points and a fixed centre.
The unchanged portal is a frozen caller checked through `tests/load-core.mjs`;
the desktop's `pentora-view.mjs` uses the shared module for its approval Details
picture. `aumlok-draw.mjs` draws identity words, not Pentora. Frozen UI face
snapshots contain no Pentora caller. The desktop picture compares the displayed
operation digest (gate mode: proposed content SHA-256), not the whole gate review.
It grants no authority and does not change approval eligibility.

`pentora-port.test.mjs` checks the 64 imported vectors and agreement on another
200 deterministic heads. `pentora-display.test.mjs` checks the desktop's rendered
cells and palette against those vectors and the frozen portal. The desktop view
is static; the portal rotates, so this is not pixel equality or a tested human
comparison. The three external-reference
checks still require `PENTORA_IDENTITY_ROOT/src/pentora/{expansion,geometry,pinned-data}.mjs`
and `spec/pentora-v1/data/geometry_index_table_v1.json` with the original pinned
hash. SPEC-v1 describes the ceremony; it cannot reconstruct those original JSON
bytes or establish their provenance. No replacement reference was fabricated.

This is source only. `scripts/materialize-aukora-release.py` neither carries this
portal in `LANE_PLUGINS` nor mounts it in its composition rows. The separate
desktop package includes both shared/display modules. An operator can run
`node --test packages/copresence/portal-v0/tests/pentora*.test.mjs`: expect 13 pass,
0 fail, 3 skipped without the outside reference. After an authorized desktop
build/install, open an ordinary approval's Details: a valid 64-hex digest should
show a Pentora picture. No approval click is required to inspect it. Linux node
portal hosting, two real devices and installed desktop observation remain undone.
Matching pictures support byte comparison, not who is looking; the 110-trit
display is a lossy fingerprint, not a proof of byte equality or human presence.

Not imported/run: browser-dependent gate3-twin and its harness. Gate2 optical,
servers, fixture generators and other donor tools are outside the requested set.
No physical device, trusted approval click, relay publication, installed application,
full `./prime verify`, or full `scripts/check.sh` run is established here.
A receipt is evidence, grants nothing, and does not prove a unique person,
physical co-presence, owner enrollment, one-time use, or runtime containment.

Mutation checks: 30 portal guards and four BIP-340/Pentora guards were removed
individually and restored; all 34 caused their targeted tests to fail. The first
portal run exposed missing coverage for stripping private intent when publishing;
one gate1d assertion now catches that deletion. These are sampled source guards,
not exhaustive mutation coverage or browser enforcement evidence.

## Imported file SHA-256

Paths are relative to this directory; hashes are the imported bytes. The old
`tests/pentora-port.js` was promoted to the shared desktop module above; its row
records provenance, not a current file. The README
itself is excluded. Licence text whitespace may differ from upstream web sources
as disclosed in `vendor/NOTICES`. The symlink's text is `../vendor`.

| File | SHA-256 |
| --- | --- |
| `PHYSICAL-TEST.md` | `d19f9566d2f0a024e3c9e10168f4a5c43a0a2699e4d91aa7bc005f6050a589da` |
| `SPEC-v1.md` | `3bbf657e8129893c033078c1aaaa56701c7cabb564fbdce654c1a9af0039b2d7` |
| `portal/index.html` | `4af63d0e2616684a09c3f43adc1c1f4a876a97e73dd8ed783ca06229aa1ecd9e` |
| `tests/bip340-port.js` | `6576d63474497c832be47e705faa720ed94c3da966d939666452648e3efb6248` |
| `tests/bip340-port.test.mjs` | `fcbf78ac9da0988bd7c4d790068a2fd9de46a9ab36f628f30d38524c7bd9cbff` |
| `tests/data/toy/sim.py` | `fc8f87c5930224412855fbe6ff0ae98ca273bb9bcbf19e6382ab4cf614eb6a40` |
| `tests/gate1-core.test.mjs` | `ed799ce4c1878981d19a0ad58333f1f13703969217e2f3595f1ceacf71089cbc` |
| `tests/gate1b-publish.test.mjs` | `2142d9ef00d06580d0a3f009e66b0bbaa031f06c4b561152e321f38c51ad54f9` |
| `tests/gate1c-senses.test.mjs` | `964b8e69a1d5fd34d4b9fa65832f4fd041adce292a045e90b92f96db7d058bc8` |
| `tests/gate1d-approval.test.mjs` | `b6517def1d41f95c0f7ecc721959d24c7b6fd9307ae3ba91020060d55012a26d` |
| `tests/load-core.mjs` | `f49f44f738b4849e54d0a4639917d688f58135c7aff8d116c59ec067f57c7ffe` |
| `tests/pentora-port.js` | `048c8b41b6c469352f02d8b55ce087bea336e8364e857bb3f7a3a151874cd0a1` |
| `tests/pentora-port.test.mjs` | `92a0ccbd5e9dd3212735043113c5e4acde2a0aa969f369eda41ec705246913ba` |
| `tests/pentora-vectors.json` | `0ea49c847a342ffb8b4b6dca6fbd4e4520bcc99d2f8b660fe9a3d93109408207` |
| `tests/stamp-csp.mjs` | `aedcaae6835fd3818c0d612713477909abe2f9f717c127215a3a00488c36c829` |
| `tests/verify-intent.test.mjs` | `70c1d4936c8bf326f7e3af7ac2dded01bab313c6a423572a59b09c30619869e0` |
| `vendor/NOTICES` | `89d86fbbab3d687a185614d330fe12ce9d4a5d4711ee4ed3567183c0a8111681` |
| `vendor/jsQR.LICENSE` | `53ce7dd3177601bf3359ae949a6d018d66e0f60afaa0c7c8d64eece8a557754e` |
| `vendor/jsQR.min.js` | `32214c74ee92d37de6d88276987690d996ce757668e82ca1709dba5e0be9fcce` |
| `vendor/package.json` | `dbf8353f77358bc12169b7bb7301e1978d5b503e002ee927229a8993672818fc` |
| `vendor/qrcode.LICENSE` | `470cb367c0231951b7d2ddf4b45731e095b9ecdcaccf684b2415baea11d890d8` |
| `vendor/qrcode.min.js` | `bb2365e4902f4f84852cf4025e6f6a60325a682aeafa43fb63b7fc8f098d1ef2` |

## Changes from donor

Every changed line is enumerated below (inclusive ranges; insertion/deletion
points use “after”). Unlisted donor files are byte-identical; new files are the
licences/notices and CommonJS marker above. The only change outside this unit is
one `check_tap` invocation in `scripts/check.sh`.

| File | Donor lines | Imported lines |
| --- | --- | --- |
| `tests/bip340-port.test.mjs` | 5 | 5 |
| `tests/bip340-port.test.mjs` | 17 | 17 |
| `tests/bip340-port.test.mjs` | 102-105 | 102 |
| `tests/bip340-port.test.mjs` | 107-131 | 104-127 |
| `tests/bip340-port.test.mjs` | 134 | 130 |
| `tests/bip340-port.test.mjs` | 137-138 | 133 |
| `tests/bip340-port.test.mjs` | 142 | 137 |
| `tests/bip340-port.test.mjs` | 167 | 162 |
| `tests/gate1-core.test.mjs` | 64 | 64 |
| `tests/gate1b-publish.test.mjs` | after 8 | 9 |
| `tests/gate1b-publish.test.mjs` | 11 | after 11 |
| `tests/gate1b-publish.test.mjs` | 35-36 | 35 |
| `tests/gate1d-approval.test.mjs` | after 124 | 125 |
| `tests/load-core.mjs` | 12-13 | 12-13 |
| `tests/pentora-port.test.mjs` | 18 | 18 |
| `tests/verify-intent.test.mjs` | 12 | 12 |

Donor SHA-256 for modified files (the source commit also pins their contents):

- `tests/bip340-port.test.mjs`: `d8358360967e2e59a9e5b5dc213e22c37a7b4c6420e07563b197f2ca0eb820ba`
- `tests/gate1-core.test.mjs`: `154cabd26861ab2dd6f0e4304cfb6b78940aadf20ad358442289357d30a7679f`
- `tests/gate1b-publish.test.mjs`: `c0e4bca06d8a44a00a6397764b796f91e28d3c7d195785402626a1444a0285fd`
- `tests/gate1d-approval.test.mjs`: `87127a491d4a8c8bd01551ca9e81b2a6d6ffc5debb2384ceb6b116c3bcefcba9`
- `tests/load-core.mjs`: `3c30817c0692608314b1c8ce547ce42b6fb6186cb4b18f6142d913684460da48`
- `tests/pentora-port.test.mjs`: `781c92dd5b37d30422505d8ff4a08f3e0426b24803b4ff25052d07507e69c465`
- `tests/verify-intent.test.mjs`: `108e94d965ba3fe7e8771801832293405aaa35dc1a4e5e1d3ca512aff9ada405`
