# Prime owner client

Separate web-only Cordis client `@aukora/prime-authority-ui`, mounted as `prime-owner` in `shell.menu.system` and `shell.surface`. It uses the frozen Layout's exported `ActionButton`, `Panel`, and `SectionHeader` and existing tokens. No frozen face is edited or replaced. `lib/index.js` is deliberately a no-op host.

H serves `/prime/contracts/browser.mjs`, `shared.mjs`, and `json.mjs` through the existing DSH connection gate. The default client POSTs the exact C method envelopes to `/api/prime/authority/{loginChallenge,loginComplete,approvalChallenge,approvalComplete,declineApproval}`, with same-origin credentials, no cache, and refused redirects. Responses use `response.text()` and the shared `parseStrictJson` helper, preserving duplicate-key checks before parsing. Challenge templates use `validateApprovalTemplate`; signed proof validation rejects placeholders. These routes stay `503 UNAVAILABLE` until the host has an explicitly configured verifier. No enrollment, signing key, email login, storage token, reserve, or executor is implemented here.

An optional trusted client service `ctx.primeAuthority` may inject `{authority,contracts,owner_id,loginKinds,ownerSigner,passkeySigner,operation}`. Defaults allow only passkey. Owner-key compatibility requires an explicit allowed kind and injected signer; it never serves as a passkey fallback. The plugin provides `ctx.primeOwnerUi`; H can deliver a validated host proposal with `setOperation(operation)`. Removing the injected authority disconnects the UI. The default HTTP binding also exposes the same observable controller.

The view renders every frozen proposal field, canonical operation, digest, and fresh review challenge read-only. It waits for C confirmation before displaying an authenticated owner or approved/declined result. A confirmed approval says execution is unconfirmed. Expired, unavailable, credential cancellation, pending, and uncertain responses stay visible; unknown results disable approval retries and require reconciliation. Session tokens and signature material are excluded from presentation.

Clean client-only build (Prime-owned pinned DSH required):

```sh
node packages/ui/scripts/build-client.mjs --dsh vendor/dsh --only prime-authority --output .runtime/owner-client
```

Without `--only`, the recipe also builds the nine frozen faces in a fresh overlay. First G1 may mount exact donor client bundles without recompiling them. Donor host bundles remain unmounted. The Linux overlay preserves relative PNPM symlinks with `verbatimSymlinks:true`.

Disposable checks:

```sh
node packages/ui/prime-authority/checks/controller.mjs packages/contracts/src/browser.mjs
node packages/ui/prime-authority/checks/render.mjs vendor/dsh packages/contracts/src/browser.mjs
node packages/ui/prime-authority/checks/render-fixture.mjs --dsh vendor/dsh --client-dist .runtime/client-dist --contracts packages/contracts/src --output .runtime/owner-fixture
node packages/ui/prime-authority/checks/serve-fixture.mjs .runtime/owner-fixture
```

The generated fixture loads the actual production client factory and frozen native primitives with pinned React 18.3.1, but injects explicitly synthetic C-shaped responses and assertions. Its permanent banner identifies these as synthetic; no credential is enrolled or requested, no real identity is authenticated, and no operation is executed. It is excluded from the production client bundle. Browser checks use visible controls to verify pending host confirmation, full exact rendering, approval, denial, expiry, and an unknown reply. Stop only the named fixture server after checks.

`render.mjs` separately checks five native-component server-render groups: all exact fields, literal markup escaping, no token/signature leak, disabled duplicate approval, pending login without identity claim, denial, expiry, and an unknown result with retry disabled. This is component render evidence; it does not substitute for browser observation or real owner authentication.

The separate `shell.overlay` capability badge reads guarded GET `/api/prime/capabilities` and shows exact source commit, runtime PID, release digest, pending qualification, and unavailable capabilities. Metadata does not prove loaded memory or successful backend behavior. HTTP owner controls stay disabled while status is pending/unavailable or owner-passkey is unavailable. The badge is centered near the bottom; its expanded panel reserves the shell hot corners. New components follow `../docs/design-contract.md` and composed-browser checks in `../docs/visual-acceptance.json`.
