AUKORA source-only vendor packet

Source commit: 1db778d16155f60336e411bc31d3d8ff6d748be7

All tracked files retain their exact Git blob bytes. VENDOR-MANIFEST.json lists
SHA-256 hashes, Git blobs, file modes, the source tree and exact dependency pins.
No external dependencies are bundled or installed. A compatible Node runtime
(including node:sqlite) and the package-lock.json dependencies remain required.
The preserved package scripts are upstream development commands: run npm check
and pack:vendor from the full Git checkout, not this source-only packet.

This artifact makes no acceptance, OS confinement, production key custody or
Prime installation claim. Integrators must preserve the existing notices and
review the declared trusted adapters. No UI, test keys or operational data is
included. Rebuild twice at this commit and compare the complete tar SHA-256.
