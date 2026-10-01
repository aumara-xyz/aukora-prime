# Frozen foundation client

Exact selected client closure from Genesis `645d3213b8aede3b544269b4224ae09df06b0a42`, recorded in `prime-import-manifest.json`. The native bundle ID is `@aukora/dsh-plugin-foundation`. It injects only slots and theme, supplies the donor brand assets, and calls the theme service's `overrideTokens` with the donor palette. Mount before the native client renderer using the existing Cordis client descriptor seam. The package's host export is a Prime-owned no-op; the donor host was excluded.

This restores the donor theme dependency without editing any of the nine frozen faces. Current preview computed aliases were gray (`#151517`, `#232324`, `#2c2c2e`, `#353638`); the exact donor palette provides `#111520`, `#1B1F2A`, `#1F232E`, `#252834`. The user-supplied Media and Models screenshots were materialized and inspected before this import. Runtime confirmation after composition remains required.

Rebuilding is separate qualification: use the copied donor config with pinned Prime tsdown and `AUKORA_BUILD_FACE=client`; supply `AUKORA_ICON_DATA_URI` from the exact copied 96px PNG. No icon derivation or source mutation is needed to mount the committed donor bundle.
