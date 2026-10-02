# Native pilot UI source handoff

Base: `fbbb1ae43026cb1567afd3f02a28b8bec69f2351`.
Branch: `prime/ui-pilot-next`. Evidence: **SOURCE-ONLY**.

This change adds a visible sequence to the separate native Owner access surface:
existing owner login, Models status and limits, one provider reply, exact memory
review, and memory recovery. The nine frozen faces and their bundles are unchanged.
The Models link uses the existing `openSurface('settings', 'models', 'contained')`
navigation seam. Existing login, approval and provider transport contracts remain
unchanged.

## Memory composition

The optional Cordis service `primePilotMemory` accepts:

```ts
{ ownerController: controller, client }
```

`client` is the existing H `createOwnerMemoryClient` result. H first supplies its
trusted `binding` as `primeAuthority`, waits for the same native controller to
connect with the exact-binding acknowledgement below, calls `client.attach()`, and then provides `primePilotMemory`. Disposal of
the service removes the UI projection. This UI neither constructs nor attaches a
client and makes no automatic memory request.

`PilotMemoryPanel` uses the existing `proposeSave`, `refresh`, `recover` and
`recoverForget` methods and reads their workflow stores directly. Recovery facts
can therefore appear after a fresh session even when the controller has no
retained approval action to reconcile. The panel requires the same controller,
configured owner and current unexpired owner object. Logout, binding replacement
and late replies invalidate the projection; the statement draft lives only in
the transient textarea.

Explicit proposal preparation sends the exact textarea statement as
`extraction_json: JSON.stringify({statement})` with one fresh UUID. The existing
worker supplies the source, attribution and fixed metadata. The existing Exact
operation card still requests review and approval separately. Unresolved effects
disable a new proposal. Recovery reads existing facts and may deliver an already
committed settlement receipt; it does not dispatch another save or restore data.
Canonical bytes and source quotations render as escaped text. Storage, indexing,
citation, logical forget and authority settlement remain distinct displayed facts.

## Exact native binding acknowledgement

The separate B client provides the read-only Cordis service
`primeOwnerNativeConnection`:

```ts
interface NativeOwnerConnection {
  readonly controller: Controller
  readonly isConnected: (binding: Binding) => boolean
}
```

`isConnected(client.binding)` is true only after B's active native
`primeAuthority` injection has completed `controller.connect` for that exact
object and the returned connection witness is still current. It is false while
connecting, for a different object with the same owner ID, after failed setup,
binding replacement, disconnection or disposal. Reconnecting even the identical
binding object invalidates the prior witness. There is no public acknowledgement
setter. No binding, token, credential, proof or capability is serialized.

The controller's `connect(binding)` now returns an opaque frozen
`ConnectionWitness` with only `isCurrent(): boolean`, or `null` if no completed
connection can be acknowledged. Existing callers can continue ignoring the
return. The witness uses a separate connection generation; logout and capability
changes do not by themselves claim that the transport disconnected. Owner
authentication and runtime qualification remain separately required.

B registers native injection cleanup before connection notifications can
reenter the lifecycle. Removal invalidates acknowledgement first. Cleanup for an
old injection cannot disconnect a replacement. Generation checks prevent a
reentrant replacement from inheriting an unfinished connection or being cleared
by that old connection's catch path. A disposed controller cannot reconnect.

The native injection retains its witness immediately through
`connect(binding, {onConnection})`, before synchronous connection callbacks. That
witness's `isCurrent()` stays false until connection finishes. Removal calls
`disconnect(retainedWitness)`, which recognizes the private generation even
during that pending connection. Unknown or superseded witnesses return
`UNAVAILABLE` without touching the current connection. Thus removing a native
binding cannot disconnect a newer direct connection, including same-object
reconnect or replacement during the old connection's notification. Checking
only the active native injection record is insufficient for that ownership.

H integration at the current `createOwnerMemoryNativeBinding` seam must read this
service from its trusted scope, require `ack.controller === scope.primeOwnerUi`,
and require `ack.isConnected(client.binding) === true` before
`attachAfterNativeConnection`. The existing native service identity check remains
required. Recheck the same acknowledgement service identity and fresh predicate
after hook/panel registration and before each later attached-client or capability
operation. A cached `true`, owner-ID equality, a capability row or a normally
returned `connect()` call does not satisfy this join. H owns that helper patch;
this B change does not edit or mount it.

H must also fence each internal `client.attach()` hook step with the fresh native
acknowledgement: `setApprovalAction()` synchronously notifies observers, so a
replacement there must prevent installing `setForgetAction()` on the new
connection. A wrapper-only post-attachment check occurs too late. Client rollback
and teardown likewise must preserve a replacement connection's hooks/lifetime.

The lower-level `createOwnerMemoryClient` remains a trusted composition API; its
owner-ID check alone is insufficient for connection ordering. Use the native
acknowledgement before its attachment as well. Missing B service or false
acknowledgement must keep native attachment unavailable. Providing the service
creates no login, assertion, capability read, workflow attachment or request.

## Provider and reply dependencies

The credential controller now rejects keys outside the separated worker's exact
admission policy (8–4096 non-space printable ASCII characters) before consuming
its ready ticket. It clears the input without trimming or normalizing it. A valid
correction still requires an unexpired, unused ticket. Qualified HTTPS remains
required for key entry; the localhost passkey profile does not enable it.
The input has no browser length truncation; the controller examines the complete
entered value and refuses an invalid value before dispatch.

The frozen provider seam remains:

- Owner metadata from the existing provider `status` method.
- `prepareCredentialEntry({expected_generation, approval_proof})` after a fresh
  exact-operation approval supplied by H/E.
- Direct, single-use credential-worker entry; no generic credential setter.

The credential-entry proposal action and its owner-review callback are not yet
supplied to this UI. No new approval method or operation schema is invented here.
The existing key field remains disabled until that approved handoff arrives.

`AumaReplyView` is an exported read-only projection of E's existing gateway
`InferenceResult` completed/unknown union, with a synthetic label for mock output.
It escapes model text, reports token/cost facts, and presents the receipt without
claiming saved memory or authority. It does not accept the distinct DSH stream
finish metadata as a gateway result. It adds no browser request or owner/task
validation. The owner/task-bound producer must validate and fence its result
before passing it to this view.

There is no agreed browser one-reply method in the frozen bridge allowlist.
Accordingly the native surface presently supplies `result={null}` and leaves
Request one Auma reply disabled. E/H/bridge must provide the exact request/result
and session replacement rules before a send control can be connected.

## Focused validation

Peter approved the necessary keyless local checks. **RAN** evidence is recorded
in the task handoff, with exact commands and artifact hashes:

1. `checks/provider-controller.mjs`: six selected cases, 345 assertions, no
   failures. Invalid short/long/space/control/non-ASCII input retains the unused
   ticket; corrected synthetic input dispatches once. Expiry, unknown outcome and
   exact HTTPS guards passed. Twenty unrelated cases were excluded.
2. `checks/native-connection.mjs`: sixteen source cases passed across scoped
   runs. One initial timer expectation was corrected; only affected cases were
   rerun. Early owned cleanup and forged/foreign/stale witness refusal passed.
   The complete final collection was not rerun merely to repeat passed cases.
3. `checks/native-join.mjs`: eleven groups passed against the genuine rebuilt
   client, pinned Cordis 4.0.2/React 18.3.1 and H's exact held guard sources.
   Actual native injection, same-object reconnect, direct replacement removal,
   replacement/removal during connect, hook-step replacement and teardown were
   exercised. HTTP requests and credential assertions were both zero.
4. `checks/pilot-render.mjs`: four SSR groups passed on pinned React and a genuine
   fresh owner build. Missing/mismatched/unattached sessions hide private stores;
   fresh-session workflow facts render without a retained controller action;
   model and saved text stay escaped; malformed replies remain unconfirmed.
   Rendering scheduled no recovery, proposal, save or provider call. Browser
   event/user-presence acceptance remains unperformed.

The initial owner-only build found two optional-prop type errors, now fixed by
omitting absent props. A later native cleanup regression required early witness
retention and conditional disconnect; both interleavings passed in the corrected
compiled build. No unchanged full gate was repeated. The recipe type-checked and
compiled one separate plugin, with zero frozen face bundle rebuilds or dependency
installs, and emitted a genuine source/input/output receipt. Example command:

   ```sh
   node packages/ui/scripts/build-client.mjs \
     --dsh <original-pinned-Prime-harness> --prime-root <same-Prime-root> \
     --only prime-authority --work <new-owned-work> --output <new-empty-output>
   ```

Fresh output and its receipt stay in the owned build directory. Historical
tracked `lib` output is unchanged and does not bind the new source. H owns
consumer integration and qualified private composition. Browser login, real
credentials, protected memory/runtime effects, paid inference and public
deployment remain **UNPERFORMED**. These local checks establish neither real
owner authentication nor a working protected memory/provider path.

## Evolution Lab mount advice

The proposed separate Lab `apply(ctx)` using `shell.surface` and
`shell.menu.system`, id `evolution-lab`, order 80 and contained navigation is
compatible with the existing Owner surface's id `prime-owner`, order 70. Its
launcher should call `openSurface('evolution-lab', undefined, 'contained')` and its
surface should hide unless `activeSurface === 'evolution-lab'`. Use existing
`PropsRuntime` from the pinned slots package and import the Layout client's
existing SlotMap augmentation; no stock SlotMap redeclaration is needed. Use
existing Layout primitives and scoped CSS. H owns descriptor composition. The Lab stays
a separate read-only, explicitly synthetic/historical view with no product-path
dependency or authority controls.
