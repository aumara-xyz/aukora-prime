# Private retained memory composition

This H source selects the existing C98dd, D527 and Bridge96 implementations on
the coherent `07be335` input and frozen decision `95fcc9d4fb4420e2dbc13ba28b8332968b4b36e71f069a233847c23932a1c3b9`.
It changes no original verification input, public wire schema, closure stage,
SQL descriptor, authority kernel or retained identity.

`createRetainedMemoryComposition` takes exactly the owned `pool`, `retention`,
`publisher`, `authorityConfig`, `registryEntries`, `bindings` and `closureProfile`.
A successful return transfers Pool ownership to the composition. If construction
throws, the caller retains that ownership. No Pool or configuration is discovered.
`retention` is the existing D file-reader configuration's directory and assigned
publisher UID, retention GID and reader UID. `publisher` must be the actual
already authenticated private publisher transport with the four D methods
`beginTyped`, `retainPrepared`, `publishPrepared`, `clearMatchingPending`.
This factory does not create that transport, its credentials or its protection.
Missing transport or protected storage/baseline/guards refuses; no legacy
fallback, setup, migration, directory creation or qualification is performed.

The factory constructs D's genuine protected file reader and v2 coordinator,
then its actual memory service with Bridge's exact nine descriptor exports.
Stable forwarders close the construction cycle to the real C service. C receives
the original branded `memory.retainedMemoryParticipant`, the immutable owned
Task registry and D's actual target observation. Bridge receives the complete
same-instance D service before narrowing it, preserving its distinct journal
and pending-recovery participant. A remote proxy cannot replace either brand.
The two existing store IDs are selected in protected configuration, never from
returned evidence. The C closure profile and D/Bridge closure profile remain
their separate, matching formats.

Ordinary approved save/forget and explicit receipt/pending recovery use those
existing implementations. Recovery is effect-capable: it is never exposed as a
passive observation. No observer schema or gate writer is selected here. Full
restore remains outside the unchanged app method allowlist and unavailable;
the in-progress restore-event join is not bypassed.

`startRetainedMemoryIpc({composition,ipc})` uses the original bounded authenticated
Bridge app IPC implementation and exact roles/methods. It requires the actual
operator-supplied credentials and protected socket configuration. It is an
explicit start API, not a default plugin or boot hook. This source does not call
it. Public acceptance remains unavailable under the frozen retained contract.
No legacy acceptance object can qualify it.

Close first withdraws new admission, waits for any owned pending IPC start,
closes the app transport and joins every
actual admitted handler through D's final session inspection/unlock and C
settlement before ending the owned Pool. A response timeout or disconnection
does not terminate that ownership. It establishes no crash containment or
independent custody. SQL plus retained files remain an ordered fail-closed
protocol, not a cross-store ACID commit or digest-only rollback proof.

Later UI/E/H source stays in its separate checkout. Actual protected publisher
transport, configured state/credentials/enrollment, PostgreSQL guards, process
and group custody, runtime serving and effects remain operator prerequisites;
none is manufactured by this source composition.
