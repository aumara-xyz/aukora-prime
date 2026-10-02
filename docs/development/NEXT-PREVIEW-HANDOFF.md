# Prepared NEXT preview and later owner setup

The composed source checkpoint is `baef86251af101c417d51fe666d0dc17da24a98d`.
Its local release is `.runtime/next-preview-3f71aab`; the directory label names
the starting checkpoint, while `prime-release.json` binds the exact source above.
It has not been booted or installed. [Evidence](../evidence/next-preview-baef862.json)
records its release/UI digests, actual import check and separate synthetic
browser inspection. Later E/F source and integration commits do not change that
artifact; it predates the continuation and guardian imports.

## Assembly and inspection now available

Composition reused an isolated copy of the locally verified pinned DSH build:
8,389 built artifacts and four pinned patches. No install or full rebuild ran.
The owner build remains the verified 87-input/46-output build. Composition
preserved all nine frozen face bundles, bound 152 UI files and retained the
83-entry disabled plugin set. It now supplies C's optional E helper peer from
inside the release and copies the unmounted Cordis provider. Neither change
supplies configuration, a listener or permission to execute.

The first compose attempt rejected a stale integrator-owned publication-recipe
pin. The repaired verifier pins the exact reviewed recipe and independently
checks its save-recovery adapter output. Its fixture now loads the real helper;
the focused regression passed 30 assertions, including altered and missing
publication refusal. No lane UI source or output was changed for this repair.

From a clean checkout with verified local build inputs, these existing commands
prepare a fresh destination and check its imports; they do not boot it:

```sh
./prime compose --release-dir .runtime/next-preview-NEW
node scripts/check-next-composition.mjs .runtime/next-preview-NEW
```

The browser inspection used the existing `render-fixture.mjs` and
`serve-fixture.mjs`, the exact compiled owner bundle and synthetic authority.
Safari rendered the unavailable capability/reply/memory states. Synthetic sign-in,
exact review, expiry refusal and sign-out events were observed. The fixture tab
and temporary loopback listener were then closed. No real authenticator was used.
This is an owner UI fixture, not a running Prime conversation or custody check.

To repeat only when a changed browser path warrants it:

```sh
node packages/ui/prime-authority/checks/render-fixture.mjs \
  --dsh vendor/dsh --client-dist /absolute/verified/owner-build-output \
  --contracts packages/contracts/src --output .runtime/owner-fixture-NEW
node packages/ui/prime-authority/checks/serve-fixture.mjs .runtime/owner-fixture-NEW
```

The build-output directory must contain `prime-authority/client.js` with the
verified receipt's hash. The server prints its temporary loopback origin and
serves static GET/HEAD only. Inspect the clearly labeled synthetic page, then
close its tab and stop only the process started by that command. Do not put real
credentials, owner state or private conversation in this fixture.

## Remaining native mock conversation work

The connected keyless smoke at `e994789` now reaches the existing DSH stream
through actual C/Bridge and E shared continuation. Its unchanged mock result was
observed in B's compiled `AumaReplyView` using the static disposable fixture
`.runtime/next-reply-fixture-e994789`. [Evidence](../evidence/next-dsh-pilot-e994789.json).
The page labels the synthetic provider explicitly without rewriting the result's
production-shaped admission metadata; it cannot request or save anything.

B's native interactive reply component has no producer and its request button
remains disabled.
The next integration must connect the existing E/DSH route to an exact
owner/task/conversation context and stable request UUID, then supply the bounded
result through the agreed native UI interface. It must keep the mock route
explicit and disposable. No generic send endpoint or second inference loop is
introduced here. E's `3ca1cdf` continuation and durable pre-C-reserve guard are now
imported source. Connected evidence and later protected custody remain separate
from the prepared `baef862` artifact, which predates this increment.

For ordinary memory, the existing native helper provides the exact binding and
waits for B's fresh connection acknowledgement before attachment. The protected
host must supply its authenticated channel, deployment pins, exact owner/Task
mapping and independently observed capability status. A browser connection is
not owner authority. Unknown and reviewed-unsent outcomes stay fenced; Bridge's
fixture correction `5474326` now asserts that refusal without new effects.

## Later protected preview setup

1. The operator selects the approved release and platform build, verifies the
   complete dependency closure, and places it beyond the app identity's write
   authority. This Mac assembly is not a Linux deployment artifact or a host
   qualification record.
2. Independently retain `preview-deployment.json` outside the release, with
   root-owned protected ancestors and root-owned mode 0644 or 0444. Its closed
   fields are `version:1`, `kind:'prime-preview-deployment/v1'`, exact
   `source_commit`, canonical `release_dir`, full `release_digest`,
   `ui_integrity_sha256` and `qualification:'PENDING'`. A user-owned temporary
   manifest cannot satisfy this guard. Host ownership/security setup remains a
   separately approved operator action; this preparation performs none.
3. Select fresh private app state and an available authorized port, preserving
   existing previews. The retained launcher command is:

   ```sh
   ./prime boot --release-dir /absolute/protected/release \
     --state-dir /absolute/private/state \
     --deployment-manifest /absolute/protected/preview-deployment.json \
     --port 18731
   ```

4. The launch descriptor is a private `launch-url.json` containing `{url,pid}`;
   do not print its token or pass it to the renderer. The existing desktop entry
   exchanges it in the main process:

   ```sh
   node packages/desktop/run.cjs \
     --access-file /absolute/private/launch-url.json --expected-pid PID
   ```

   It requires pinned Electron 44.4.3. The HTTP desktop profile permits exactly
   `127.0.0.1:18731`; the existing owner passkey localhost profile uses
   `http://localhost:18731`, RP `localhost`. Neither `127.0.0.1:18732` nor a
   hostname substitution preserves that identity. A real same-origin HTTPS
   deployment requires an explicitly matched RP/origin, routing and desktop
   profile. No origin or transport guard is relaxed here.

## Peter's later owner and credential actions

These steps become actionable after the missing host/route joins exist; there
is no setup button that completes them today.

1. Select the actual owner identity and exact RP/origin with the operator.
   Supply independently authenticated public identity pins and an enrolled
   ES256 credential's public metadata through the approved enrollment process.
   C has no registration/attestation endpoint. No private signing key is needed
   by this repository, and a synthetic fixture credential cannot be promoted.
2. The protected operator invokes `provisionNewAuthorityStore` once with
   `provisionTrustedState:true`, absent state and a pristine dedicated witness
   namespace, before normal `createAuthorityService`. An existing or uncertain
   history requires reconciliation; never reset its state or witness to enroll.
   Then Peter signs in using the actual authenticator and exact configured origin.
3. Review the separate provider configuration and numeric budget approval:
   owner/Task/data scope, request bounds, total budget, route, current credential
   generation, rates, terms and served-version evidence. The proposed USD 10
   testing total / USD 0.01 first request are ceilings to review, not loaded
   permission. Saving settings or choosing a model does not enable dispatch.
4. Once a separate non-root Linux credential UID, stable encryption-key custody,
   private authenticated transport and direct same-origin HTTPS routing exist,
   request the separately approved credential handoff. Peter enters the API key
   directly into the worker's `/api/prime/inference/credential-entry` using its
   owner/generation-bound 60-second ticket. The app host refuses that path before
   body read; its `/credential-handoff` contains no secret. Do not paste the key
   into chat, this checkout, an environment variable or app RPC. macOS has no
   supported production-worker bypass.
5. After the actual runtime path is qualified, request one non-sensitive reply
   under the exact approved operation. Memory save is a separate explicit review
   and approval; recovery may deliver retained evidence but cannot repeat a save.

OpenShell remains independently unavailable. F's `78dae94` guardian monitor now
persists deadlines and watches late resources in a separate fixture process;
terminal target fencing, atomic configuration, immutable reclamation and complete
cleanup mechanisms and their later Linux evidence remain missing.
No owner ceremony, paid request, gateway start, UID change or deployment was
performed in preparing this handoff.
