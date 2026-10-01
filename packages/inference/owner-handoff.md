This is a source handoff for restoring the Models/settings feature and then accepting one real reply. No key input, credential service, owner enrollment or paid route was enabled by this lane. The numeric scope below is a concrete proposal for owner review, not an approved deployment configuration.

Current canonical assessment was read at integration commit `e736ae5b82ff23cd0768346cbbfbf47b7dd3ff3c`:

| Owner | Exact source interface and remaining work |
| --- | --- |
| H | `harness/host.mjs` already imports E catalog and B `providerNamespaceView`, registers `prime-inference`, and guards GET `/api/prime/inference/catalog` with preview access. The `/api/prime` fallback still returns 503 for owner routes. A preview cookie does not authorize entry/configuration/inference. Running deployment and visual checks remain H-owned. |
| B | `packages/ui/adapters/provider-settings.mjs` serializes the nonsecret namespace correctly. Pinned `vendor/dsh/packages/client/ui-settings-models/src/client/ProviderEditor.tsx:layoutOf` recognizes only `llm-deepseek`/`llm-pi-ai`; `prime-inference` gets the unknown-editor hint and cannot apply. An owned `prime-inference` editor/controller must render provider/model/caps and use E's separate owner handoff. Keep the legacy derived `EXTERNALDEEPSEEK_API_KEY` describe/set/unset refusal. The frozen store degrades a describe refusal to a badge; it need not make the catalog blank. |
| C | `authenticateSession({session_token})` now returns `{ok,owner_id,subject,authorization_epoch,expiry}`. E's `createAuthorityOwnerAuthenticator` sanitizes this exact private read. Public owner enrollment remains unresolved. `packages/runtime-bridge/src/worker.mjs` currently requires `memory.save`, memory targets and `memory_effect` ACL; it is not an inference approval/claim channel. Add only a separately reviewed inference-specific private join; never relabel inference as memory/executor evidence. |
| E | Catalog includes documentation-confirmed model metadata; readiness binds credential generation; the worker shares a pure checked dispatch verifier; DSH finish carries mode, scope, model, cost and receipt/citation links. Existing configuration/entry/dispatch callbacks still require qualified H/C services. Root source exports neither the vault nor HTTP key accessor. |

The minimum deployable source increment now is the visible provider row plus B's owned nonsecret editor, showing unavailable status and the verified model choice. H can integrate that increment under the existing protected preview boundary. Key input remains disabled until the separate entry boundary below is independently qualified. Mounting the generic credential provider or merely changing the namespace to `llm-deepseek` is not an acceptable join.

DeepSeek's current official changelog identifies Peter's “DeepSeek flash4.1” as API model `deepseek-flash`, display name DeepSeek V4.1 Flash. No ambiguous alias or new model recommendation is needed. The API base remains `https://api.deepseek.com`; the owned wire destination is exactly `/chat/completions`. The source request uses JSON output, no tools and `thinking:{type:'disabled'}` so the bounded first reply does not inherit the provider's current default thinking mode. Official model/JSON/thinking references: [changelog](https://api-docs.deepseek.com/updates/), [JSON output](https://api-docs.deepseek.com/guides/json_mode/), [thinking mode](https://api-docs.deepseek.com/guides/thinking_mode/). Model documentation is not proof of the actual returned model revision or an enabled account route; pin the exact acceptable `wire.model` in qualified configuration before dispatch. No authenticated model-list or inference request was made.

The exact first-reply scope proposed for Peter's approval is:

| Field | Proposed value |
| --- | --- |
| Provider / route / model | `deepseek` / `externalDeepSeek` / `deepseek-flash` |
| Requests | One total attempt, including an unknown outcome; retries and provider fallback disabled |
| Input ceiling | 4,096 tokens, admitted using UTF-8 body bytes plus conservative framing |
| Output ceiling | 256 tokens |
| Aggregate task tokens | 4,352 |
| Task and route hard spend ceiling | USD `0.010000` |
| Timeout | 15,000 ms |
| Allowed data classes | `conversation` only, selected from the authenticated owner/task/conversation; no memory, screen, repo, secret, image, voice or tool inputs |
| Conservative accounting rates | Proposed integer upper bounds of 1 microusd/input token and 2 microusd/output token; worst reservation at the token ceilings is USD `0.004608` |
| Tools / automatic effects | None; reply remains an inert proposal |

The integer rate proposal rounds above the currently documented peak cache-miss input/output rates, but it is not a provider bill or an approved cap. H must retain current pricing evidence and C must bind the exact numeric configuration before enablement. A provider dashboard “maximum spend” assertion without a verified number does not substitute for this task/route/ledger ceiling. If qualified rates make the worst reservation exceed the approved ceiling, refuse before HTTP rather than reducing scope silently. See the current [official pricing table](https://api-docs.deepseek.com/quick_start/pricing/) and recheck it at qualification.

Secure owner entry requires these concrete joins:

- The exact trusted owner HTTPS origin must be confirmed by H. The entry destination is that same origin plus `/api/prime/inference/credential-entry`, routed directly to a separate non-root Linux credential UID. No new origin, DNS/TLS resource, UID or persistent security setup was installed here.
- C authenticates an actually enrolled owner and verifies/consumes exact configuration and credential-entry operations. `createAuthorityOwnerAuthenticator` alone performs only the session read. No preview cookie, fake session or private key from chat can satisfy this boundary.
- The app sends owner POST `/credential-handoff` with `{expected_generation,approval_proof}`. The credential service independently verifies the owner/provider/generation operation and issues its one-use 60-second ticket.
- Only the direct worker receives POST `{ticket,secret}`. The renderer clears its transient field; the proxy and worker log neither body, token nor authorization header. The app host refuses the entry path before reading its body. Response is only `{configured:true,generation}`.
- Stable AES-256-GCM encryption-key custody and private authenticated IPC must be held outside the app/planner UID. No API key enters an agent environment, generic settings document, C operation parameters/proof/state or renderer response. A fresh key is entered by Peter through the qualified control; a pasted chat key is not read, copied or reused.
- `qualifiedDispatchStatus(owner_id,config_digest,credential_generation)` must return the same digest and current positive generation with `ready:true`. Rotation invalidates stale readiness. Worker admission independently binds scope, UUID, exact body/citation/binding hashes, numeric reservation, generation and configuration; C verification and durable claim occur before its own ledger reservation/HTTP.

After owner enrollment, entry custody/routing, exact numeric/data/route approval and H's protected mount are all qualified, the live acceptance is one short owner-entered prompt in the new Prime UI. Use one host UUID and exact body receipt bound to the same owner/task/conversation. Independently observe one production worker dispatch to the fixed endpoint, a known valid sourced-note JSON reply in that UI, and matching adapter mode `production`, provider/model/config digest, usage/cost and UUID/body/citation links. Retain the matching durable app and worker ledger evidence with request count 1 and charge within USD `0.010000`. Do not collect key/authorization-header traces. A synthetic transport or `mode:'mock'` reply cannot satisfy this check. Empty/invalid response, transport failure, cancellation or timeout retains the request slot and worst-case reservation as unknown; report that outcome and reconcile factual evidence without another call or new UUID.

Remaining blockers are therefore specific: B's owned editor/controller for `prime-inference`; H's reviewed mount and actual running visual check; enrolled-owner authentication; an inference-specific private C grant/claim/evidence join rather than the current memory-only worker; direct HTTPS credential UID/custody/IPC qualification; Peter's approval of concrete numeric/data scope; and one approved live reply. This handoff does not claim those steps are complete.
