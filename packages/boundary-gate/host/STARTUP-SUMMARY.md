# Gate startup and redacted diagnostic source

These helpers implement source behavior. Synthetic checks do not establish an
installed protected registry, real owner enrollment, native signing custody,
service behavior or current release acceptance.

`bin/gate.mjs serve` always supplies the synchronous `readOwnerState()` from
`host/owner-state.mjs`. That adapter reads only the existing public
`/etc/aukora-boundary-gate/owner-state.json`; it accepts no CLI, environment or
request-selected path. It uses the existing owner-key eight-field validator,
rejects duplicate decoded JSON keys and ambiguous numeric tokens, and checks
root-owned ancestors without group/other write, a single-link regular file,
bounded no-follow reads and stable descriptor/path identity. It creates no owner
registry, enrollment, activation or key material. A registry's valid structure
does not independently prove enrollment.

Registry refusal stops before mutable gate startup. A failed initial ledger
verification stops before bearer rotation or sockets; a failed `startup()` result
stops before sockets and closes the gate. Supplying the reader keeps the core's
durable owner-authorization requirement active; missing state cannot restore the
legacy HMAC approval route. The owner secret remains part of bearer handling.

Immediately after registry validation, the ordinary entry requires the named
readonly core export `ownerAuthorizationReadiness({ home, readOwnerState })`
with the full closed D readiness profile. Missing, asynchronous or failed
readonly readiness stops before owner-secret loading, key creation or mutable
gate construction. The constructor's enforcement-latch writes are therefore
unreachable when the required readonly verifier is absent.

The ordinary entry then also requires the core's synchronous
`gate.readiness()` result with no arguments,
before bearer/startup work and again before sockets. Missing, asynchronous or
failed readiness refuses. The core owns retained-proof verification; this host
entry supplies no replacement verifier or readiness boolean.

`host/readiness.mjs` applies the same closed-profile validator to the readonly
preflight, readonly CLI and instance checks. It reads normalized current owner
state and the latest explicit row of the independently protected public signer
epoch registry before and after each call. The profile must literally match that
gate pin and owner subject/root/epoch/registry/activation, including
`sha256(JSON.stringify(normalizedOwnerState))`. It requires `ready: true`, an exact
safe-integer observation time inside the five-second call bracket, a valid ledger
count/head and zero unresolved/applying/incomplete/conflict effects. Unknown
fields, accessors, functions, promises, thenables and coarse `{ok:true}` responses
refuse.

The same bracket also reads only the fixed protected
`/etc/aukora-boundary-gate/gate-package-manifest.json` (at most 2 MiB) and
`/etc/aukora-boundary-gate/aura-context.json` (at most 1 MiB). The required v2
manifest's `profiles.boot.files` carrier record must have exactly `source`,
`source_sha256` and `sha256`, the literal source `operator-data:aura-context/v1`,
and equal valid source/installed hashes. The carrier's raw UTF-8 bytes must match
that independent expected hash. The host never learns the expected pin from the
carrier or readiness response. It checks the carrier's closed eight-field public
configuration and seven-field source projection, current owner subject, and a
public Ed25519 SPKI whose DER hash and declared key hash equal the latest signer
pin. D retains the actual home/database match and full readiness verification.
The host follows no path from the carrier and validates no Nostr or BIP340
semantics.

Mandatory Python bootstrap strict parsing and complete manifest/BootIdentity
verification must precede every gate entry dispatch, including `serve` and
`check-ready`; the carrier is mandatory independently of the optional Aura
collector profile. This Node helper's bounded `JSON.parse` and selected manifest
record checks are a secondary guard within that path. They replace neither the
strict parser nor complete boot digest/inventory verification, and do not form a
standalone enrollment or admission authority. Protected owner, signer registry,
manifest or carrier byte drift refuses. These checks bind D's selected source
observation; they do not establish installed custody or future database state.

The fixed readonly CLI is `bin/gate.mjs check-ready` without arguments or options.
It calls the required core export
`ownerAuthorizationReadiness({ home: '/home/aukora-gate', readOwnerState })` and
prints only `OWNER_AUTHORIZATION_READY` on success. It constructs no mutable gate
and invokes no owner-secret/key-creation APIs. The core export is the required
readonly implementation join; until it exists, the command refuses before
reading the registry or gate state. Its absence is not a successful package check.

The host-only `readRedactedGateSummary(snapshotOptions)` calls the existing
`scripts/aura/gate-snapshot.mjs` static import. It requires the full selected
signature/sequence/chain snapshot and independent public key pin accepted by that
verifier. Counts come only from its verified records. Only known public event
types are count keys; an unknown signed event refuses. The result carries event
counts and the selected head plus fixed diagnostic labels. It contains no target,
proposal/source/owner identifier, details, proof, receipt or raw source rows.

`writeRedactedGateSummary({ releaseRoot, snapshotOptions, readerGid })` requires an
explicit canonical absolute release root and explicit reader group. It writes
only `<releaseRoot>/.dsh-build/host-ledger-summary.json`. The diagnostic directory
must already exist with root custody, no group/other write, the configured reader
group and group read/traverse access. Its protected ancestors must permit that
group's traversal. The writer must be root. The helper provisions no directories,
accounts, ACLs or services. It stages a new private `0600` file, flushes it, sets
root/configured-group ownership and `0440`, then atomically renames and flushes the
directory. Existing symlinks, hardlinks or incompatible output metadata refuse.
Temporary files left by an interrupted publication remain in the protected
directory; this helper never deletes files.

Verification failure does not overwrite the last verified summary. Every output
states `freshness: selected-snapshot-only`; a retained file does not claim the
current journal head. A publication error is not a successful publication
acknowledgement. The summary is diagnostic and grants no authority. Its
`.dsh-build/**` location is excluded from the declared release artifact coverage;
the output is not release evidence, BootIdentity or whole-system acceptance.
`releaseRoot` selects the output destination and never selects executable code.
Host execution requires separately reviewed, deployed and pinned helper bytes and
their complete static import closure. No new bootstrap role is introduced here.

RAN source command: `node --test packages/boundary-gate/checks/host-startup-summary.mjs`.
It creates retained synthetic subruns only under a preexisting user-owned `0700`
`~/.aukora-h-startup-fixtures` directory. Real tiny files and signed SQLite rows
exercise source I/O; root metadata and root publication identity are simulated
in memory, and no real owner/group changes occur. Removed file-write, pre-start
verification, startup-result and exact snapshot signature guards admit the
corresponding prohibited fixture behavior. Removing the readonly readiness
preflight admits secret loading and mutable gate construction even when the
readonly verifier is missing or reports failure. Fixed carrier checks cover
missing/malformed manifest and carrier, record omission, tampered raw bytes,
current owner/key mismatch and manifest/carrier bracket drift. Removing only the
expected carrier SHA comparison admits changed bytes with the same parsed
projection; removing the bracket admits consistently repinned carrier changes
during the call. Live gate, sockets, systemd, enrolled owner data and operational
publication remain UNPERFORMED.
