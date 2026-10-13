# Co-presence receipt checkers

Two standalone checkers and their data, copied unchanged from `aumara-xyz/aukora-contact`
(`copresence-portal-v0`, last changed there at `aa8539c1de2994b6a3c52bbeb30d421e98bba9f3`, AGPL-3.0-or-later):

- `verify.mjs`: a receipt from the light handshake (two P-256 keys signing the same moment, a ten-second window).
- `verify-intent.mjs`: that such a receipt approves one exact text, signed by the approving device's key.
- `vectors/`, `fixtures/`: made with throwaway keys; `fixtures/ENCODING.md` says exactly which bytes are signed.

`node packages/copresence/check.mjs` runs both over every vector and fixture and compares each outcome.

`verify.mjs` and `verify-intent.mjs` here are canonical. The portal tests call these
same sibling files; there is no second tracked standalone checker copy to compare.
`portal-v0/tests/gate1-core.test.mjs` already checks the page verifier's outcomes
against `verify.mjs`, including mutated receipts.

`receiver.mjs` calls the frozen checkers as subprocesses. `receiveReceipt(receipt, options)` requires `now`
(caller Unix seconds) and `store`; optional `maxAge` defaults to 300 seconds, with 5 seconds of future slack.
`expectedText` enables intent verification; `expectedAsker` and `expectedApprover` require it. The result is only
`{core, keys: {A, B, asker?, approver?}, t_B, textDigest?}`; the core is recomputed, never trusted from the input.
`store.consume(core)` must atomically return true exactly once, false on replay, and throw on storage failure.
`createFileStore(directory)` uses an existing caller-owned durable local directory, exclusive empty digest-named
markers and file/directory fsync. Keep that directory across restarts; do not prune or roll it back.
`createMemoryStore()` is for tests and has no restart durability. Every caller must share the same durable store.
Only core digests reach the store. Location fields are stripped and ignored. The frozen file-based checkers need
private transient sanitized receipt files, removed in `finally`; `scratchDir` selects their parent (default OS
temporary directory). A process crash can leave scratch behind; use a private volatile scratch directory when
receipt retention is unacceptable. No location is written there. `node packages/copresence/receiver.test.mjs` tests
the receiving library with fixtures and disposable keys.

`verifyDeviceBinding(receipt, {...options, memberPubkey, deviceKey, event})` verifies the self-ceremony. The expected
intent is `aukora-device:v1:<memberPubkey>` (64 hex, normalized lowercase); `deviceKey` must be the approver's P-256
key. The member signs a NIP-01 kind-1 event with empty tags and content
`aukora-device:v1:<memberPubkey>:<core>` using `plugins/aukora-nostr/lib/event.mjs`. Both checks precede consumption.
The caller decides whether this is a new member and whether to enroll the device; this library grants nothing.

The portal and enrollment integration are not here. A valid receipt is evidence two keys signed the same moment
after two screens exchanged light; a video call can pass the light check. It is not proof of presence or of a
unique person. Single use is the receiving store's claim, not something an offline receipt proves.
