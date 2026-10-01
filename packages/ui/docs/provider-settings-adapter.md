# Provider settings join

`adapters/provider-settings.mjs` converts E's public or owner-scoped `providerNamespace` into the pinned DSH `SettingsNamespaceView`. H supplies its already pinned Schemastery constructor and browser-safe contracts, then calls `providerNamespaceView(input, {Schema, contracts, revision})`. The input is the closed nonsecret `{namespace:'prime-inference',section:{providers:{externalDeepSeek:{...}}}}` read shape. The output carries serialized schema, value/base, no secret slots, and the host-supplied revision. The default revision is zero for the disposable public read view.

The fixed directory is `externalDeepSeek` / `DeepSeek`, namespace `prime-inference`, path `providers.externalDeepSeek`. Namespace and profile presence produce a visible configured row in the frozen Models store; an empty provider catalog produced the previous blank list. The public defaults have an empty model/region, zero token/request caps, null spend ceiling, and false enabled/credentialConfigured. They do not imply a usable paid route.

Every schema field is read-only. H must preserve read-only presentation and refuse generic settings mutations for this namespace. Approved configuration uses E's separate owner API with a complete frozen route, qualified pricing evidence, and an exact approval proof. This adapter implements no writes.

The frozen store derives `EXTERNALDEEPSEEK_API_KEY` even when the directory has no credential reference. Route that generic describe/set/unset request to `refuseGenericProviderCredentials`, mapped through H's existing typed Remote error boundary. Never turn it into a lookup of a root key, a filesystem read, or the separated credential service. Confirmed credential state comes only from the owner-scoped nonsecret status. The separate entry remains unavailable until H/C qualify owner approval, custody, and routing. This adapter enables no key input or HTTP endpoint.

The disposable check uses actual pinned Schemastery 3.18.2 to serialize, rehydrate, and validate both public defaults and synthetic owner metadata, and verifies generic credential refusals and secret-field rejection. No external request or live key is used.
