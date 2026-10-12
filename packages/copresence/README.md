# Co-presence receipt checkers

Two standalone checkers and their data, copied unchanged from `aumara-xyz/aukora-contact`
(`copresence-portal-v0`, last changed there at `aa8539c1de2994b6a3c52bbeb30d421e98bba9f3`, AGPL-3.0-or-later):

- `verify.mjs`: a receipt from the light handshake (two P-256 keys signing the same moment, a ten-second window).
- `verify-intent.mjs`: that such a receipt approves one exact text, signed by the approving device's key.
- `vectors/`, `fixtures/`: made with throwaway keys; `fixtures/ENCODING.md` says exactly which bytes are signed.

`node packages/copresence/check.mjs` runs both over every vector and fixture and compares each outcome.

The page that makes receipts (the portal) is not here yet, and nothing in this repository calls these checkers yet.
Say plainly: a valid receipt is evidence that two keys signed the same moment after two screens exchanged light; it is
not proof that a person was present or who they were, and it grants nothing. Single use is the caller's job.
