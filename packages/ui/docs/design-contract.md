# Prime app design contract

Peter's standing direction, October 1, 2026: future Prime apps share the foundation background, highlights, and portal expansion behavior unless he requests an exception. Repairs preserve the frozen donor UI; this contract does not authorize a redesign of those faces.

- Use the shared foundation and spatial tokens. Dark background layers are `--dsw-alias-bg-base`, `--dsw-alias-bg-layer-1/2/3`; cards, text, borders, radius, and accents use the existing `--aukora-*` tokens and Layout primitives. Do not invent an app palette.
- Green, blue, purple, and gold are primary accents. Red denotes warnings; use yellow selectively. Pair color with text or an accessible icon, and preserve readable contrast, focus indication, and keyboard operation.
- Use the existing portal launcher and shell navigation behavior for app expansion. Ordinary actions use the shared button primitives. Default contained expansion keeps the wide shell's two-thirds content measure; fuller websites or apps require an explicit exception. Preserve the shell's actual responsive presets and its narrow/mobile one-column behavior.
- Keep every interactive control clear of the shell's hot-corner hit rectangles, including the narrow view. The frozen frame defines a 74px corner size plus a 10px gutter; these are shell-owned tokens. Do not place floating buttons over them. The separate capability badge is centered near the bottom and its expanded panel leaves at least 84px at the top.
- Disabled capabilities explain what is unavailable. Source commit, PID, and release metadata do not prove successful authentication, execution, loaded memory, or a qualified backend. Pending or uncertain actions retain their explicit state until the host confirms a result.

Visual acceptance uses `visual-acceptance.json`. Check the actual composed release at narrow and wide viewports, the contained expansion, keyboard navigation, and rectangle intersections with every visible `[data-corner]`. Record actual computed background tokens and screenshot evidence. Source/render checks alone do not establish live visual parity.
