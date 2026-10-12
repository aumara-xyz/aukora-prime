# Invites v0

Pure Node 24.11.1 library; no relay, door, UI, ceremony or provisioning integration.
This keeps out keys nobody vouched for; it does not prove a member is a unique human.

`createInvite({root, secretKey, now})` signs an invite using the existing Nostr
helper. `root` is the network creator's lowercase public key. Times are integer
Unix seconds. The bearer code is the **whole signed invite**, containing network,
random 128-bit `codeId`, `issuedAt`, and `expiresAt = issuedAt + 172800`, with no
invitee. Transfer it privately; anyone holding it can redeem first. Code theft
cannot be distinguished from the intended recipient. Publishing it exposes it.

`redeemInvite({invite, secretKey, now})` signs the invite event id with the new
member's key. A different valid key may redeem first; changing the claimed key
without its signature, or redeeming again after consumption, is refused.

Kinds **39701** (invite), **39702** (redemption), **39703** (grant) were unused as
event kinds in this checkout. They are local allocations within Nostr's
30000–39999 parameterised application range, not global reservations. Each has
one `d` tag (code id, invite event id, member key respectively), and closed JSON
content. Retain events by **event id**, even if a relay replaces an address.

```js
const state = createFileStore('/private-store/admissions.sqlite')
const result = verifyAdmission({ root, invite, redemption, chain: [], state, now })
// result.member; result.record.chain becomes the next member's ancestry.
verifyRecord({ root, record: result.record }) // { member }, offline signed path only
state.close()
```

`verifyAdmission` accepts a root-first, contiguous `chain` of earlier
`{invite, redemption}` pairs. Every ancestor is signature-checked **and must
already match the authoritative store**. This prevents inventing an expired,
backdated parent admission. Ancestors do not expire after admission. Records
contain only the signed pairs; retain them separately to furnish future chains.
The current path is bounded to 128 admissions. Repeated members are refused.
The verifier supplies `now` from its trusted clock: expiry is exclusive, with
no expiry grace; either signer may be at most 300 seconds ahead. Redemption
must be at or after issue and before expiry. Parent-to-child ordering allows
the same 300-second skew. Exceptions have named `REFUSE` codes.

Each inviter has three **lifetime redeemed** invites, including the root;
creating unused invites costs nothing. Optional `grant` is made with
`createGrant({root, secretKey, member, allotment, sequence, now})`, signed only
by the root. Allotment is an absolute nonnegative total, never additive.
Increasing positive sequence numbers replace known policy; stale or omitted
grants cannot undo it, and conflicting equal sequences refuse. A valid newer
grant persists even when it causes admission refusal. Unseen grants cannot be
enforced: the operator must distribute root policy to the authoritative store.
Lower totals do not remove existing members.

`createMemoryStore()` is SQLite in memory. `createFileStore(path)` uses Node's
built-in SQLite, no added dependency. Keep the file in a private local directory.
Files are mode 0600. SQLite `BEGIN IMMEDIATE`, full synchronous writes and rollback
journaling serialize quota, atomic `consume(inviteId)`, and record insertion.
No successful consumption may commit without its record. A crash before commit
rolls back both; after commit both survive, even if the caller missed the return.
Busy, corrupt or failed storage refuses; power-loss durability depends on SQLite,
the filesystem and hardware. Do not restore old backups to reset spent state.

An injected store implements synchronous `transaction(callback)` and `close()`.
Its transaction exposes `consume(id) -> boolean`, `record({root, inviteId,
redemptionId, inviter, member})`, `admission(root, member)`, `count(root, inviter)`,
`grant(root, member)`, and `setGrant({root, member, id, allotment, sequence})`.
All methods share one atomic transaction; thrown errors roll it back. Transaction
handles must not escape their lifetime. This is trusted operator code, not an
untrusted write API. Separate stores do not provide shared spend accounting.

The store operator sees **who invited whom**: root/network keys, inviter/member
keys, invite/redemption/grant ids, grant totals and sequences, and derived counts.
The store retains no free text, invite code, full events, signatures or secret keys.
Shared admission records reveal the ancestor graph and signed times as well.
Offline verification proves signatures and the vouching path, **not** historical
clock accuracy, authoritative admission, complete quotas, global single use,
unique humans, or enforcement by any running app. New nodes need the same trusted
accounting state; a caller-supplied offline chain cannot bootstrap that state.

Run `node --test packages/invites/index.test.mjs`; run
`node packages/invites/index.test.mjs --mutations` for guard-removal checks.
Mutation checks temporarily edit only `index.mjs`, restoring it in `finally`.
Fixtures use synthetic keys and local disposable databases, including process
crash and competing-writer checks. They do not qualify an installed network.
