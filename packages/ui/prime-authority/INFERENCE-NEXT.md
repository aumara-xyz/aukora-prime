# Native one-reply UI join

Base: `c04c46a44841d89953eb0fa4afd4321d519bc302`. **SOURCE-ONLY**.
This ordinary UI extension uses the existing trusted native owner connection.
It defines no authentication, authorization, IPC or public HTTP boundary. H owns
the host/client composition; missing dependencies remain unavailable.

The separate native client optionally consumes `primePilotInference`:

```ts
interface InferencePilotBinding {
  readonly ownerController: Controller
  readonly client: {
    readonly binding: Binding
    readonly context: {
      readonly owner_id: string
      readonly task_id: string
      readonly conversation_id: string
    }
    readonly availability: {
      getSnapshot():
        | {state: 'unavailable'; mode: null; reason: string}
        | {state: 'ready'; mode: 'mock' | 'production'; reason: string}
      subscribe(listener: () => void): () => void
    }
    requestOne(
      draft: Readonly<{request_uuid: string; text: string}>,
      options: {signal: AbortSignal}
    ): Promise<PilotInferenceResult>
  }
}
```

Exact exported types are in `src/client/inference-controller.d.mts`. The binding
is the same existing `primeAuthority` object, acknowledged through the existing
`primeOwnerNativeConnection`. The owner controller must be this native surface's
controller. H supplies fixed task/conversation context and a stable availability
snapshot; the browser chooses neither policy, route, caps nor authorization.
The store returns the same snapshot object until a capability/context change is
notified. Its readiness must not be toggled for its own pending review progress:
the UI already gates pending requests, and a changed readiness fences the attempt.
An absent, disconnected, mismatched or unauthenticated client stays disabled.
An unrelated pending or unresolved owner operation also disables a new request.

`requestOne` is a presentation adapter over H's existing approved inference path,
not a second agent loop. H retains owner/task/conversation validation, exact
request/body binding, model configuration, numeric limits and the existing
proposal/review/approval/admission sequence. This UI does not call `approve`, sign,
create a grant or add a route. The pending promise may span the existing explicit
Exact operation review. If that join is missing, availability remains unavailable.
Ready mock mode is visibly synthetic and does not qualify a live capability.

An explicit click captures the exact textarea text with one fresh UUID in an
immutable draft before callback entry. Additional pending clicks coalesce. There
are no automatic requests, retries or recovery calls. New owner or native client
lifetimes remount the transient textarea. The nine frozen faces, their assets,
bundles, styles, sliders and chat transport remain unchanged.

The supplied result is the existing E gateway `InferenceResult` union, preserved
as a detached immutable value and rendered by `AumaReplyView`. The distinct DSH
stream finish metadata is not accepted as that result. Result and receipt UUIDs,
receipt conversation IDs and completed mode must match the captured attempt.
`source_citation.requestId` is the existing recorded model-request ID, not the
request UUID. The result grants no authority and is not saved as memory.

Replacement, disconnect, logout, expiry, a fresh same-owner session or changed
availability fences late presentation and aborts the UI wait. Aborting a wait
does not establish that provider execution stopped. Once the callback was
entered, a thrown, interrupted or incompatible reply retains a same-context
unconfirmed request identity. No reservation receipt is invented. An actual E
unknown result retains its exact receipt and reservation fact. Both disable blind
retry, including after logout/rebinding to that owner/task/conversation. Existing
host reconciliation remains a dependency; this patch supplies no new recovery
or reset method.

Native injection cleanup is registered before connection notifications. An old
cleanup, abort listener or availability unsubscribe cannot clear a replacement
view lifetime. Source tests exercise these ordinary UI interleavings with injected
synthetic callbacks only. Focused build/test evidence is in the task handoff;
no installed system, browser credential, real key, provider network or paid call
is qualified by this source patch.

## Focused evidence

**RAN · synthetic source checks:** 21 relevant `node:test` groups passed across
focused runs of `checks/inference-controller.mjs`. Five initial callback-count
assertions assumed synchronous entry; the fixture now waits for the callback's
microtask and retains a separate zero-dispatch removal case. Only affected and
new cases were rerun. Reentrant replacement and logout defects were repaired and
their focused regressions passed. No unchanged broad gate was repeated.

**RAN · fresh compiled native/SSR join:** `checks/inference-native-join.mjs`
passed eight groups with pinned Cordis 4.0.2 and React 18.3.1. The actual registered
surface/button callback consumed the injected service, sent frozen UUID/literal
text once, rendered the unchanged escaped result and fenced late replies. Six
synthetic host callbacks, zero network calls and zero credential assertions.
An initial fixture login-return assumption was corrected. The check supplies a
synthetic textarea ref during SSR; it establishes no DOM/browser event acceptance.

**RAN · owner-only build and receipt:** the existing pinned build recipe
type-checked and compiled one separate plugin, with no installs or frozen-face
builds. The official receipt verifier matched 90 source inputs, 52 output artifacts
and the pinned build inputs. Fresh owner client SHA256:
`64af894c46d72219bb01b12f53ab1067aed963de6163d6a799b9cebe53a9c691`.
The genuine output/types/receipt are included under this package's `lib` directory.

**UNPERFORMED:** H's new host/client glue, guarded served bytes/descriptor, actual
browser acceptance, real owner credentials, provider network, paid inference and
installed/runtime qualification. No activation or publishing was performed.

## CSS provenance followup

The existing owned `scripts/build-client.mjs` now replaces the two generated owner
CSS region comments with relative `packages/ui/prime-authority/src/client/` paths.
Only the build recipe changed among the 90 receipt-bound source inputs; all other
inputs, CSS sources, frozen face assets/bundles and pinned build inputs match.
Fresh owner client SHA256:
`4335a321a639a7b32e76fe0bca61cfdc0da8b5932cdd7de1725985d51a97710d`.

**RAN:** one fresh owner-only build and the official 90-input/52-output verifier
passed. `checks/css-provenance.mjs` compares that compilation's raw client with
its normalized output: exactly two comment lines change; all other client bytes,
CSS payloads and source-map bytes match. The changed map lines have no segments.
The initial cross-build comparison failed correctly on 78 generated CSS class
hash lines: the pinned compiler hashes the physical overlay filename. That input
was corrected to the same build without weakening the check. Separate builds may
therefore retain different generated identifiers; their source/declarations do
not change through this correction.

**UNPERFORMED:** composed-host served-byte/descriptor and actual DOM acceptance
of request, immutable UUID/text, cancellation and result lifecycle. No approved
running host or browser acceptance connection was supplied for this followup.
No substitute demo or screenshot is runtime evidence. The Peter-relayed GLM verdict
and publisher candidate permission remain pending; no push or activation occurred.
