# NEXT host composition

This source joins the existing native owner controller to the existing memory
client and exposes one text-only inference presentation path. Default services
remain absent; the composed release continues to report its protected
capabilities unavailable. It does not enroll an owner, start workers, create a
provider, import credentials, or qualify an installed runtime.

The native metadata package is `@aukora-prime/native-host`. Its authored
`client.js` registers a native module descriptor and imports the guarded browser
assembly. It is source JavaScript, not a newly compiled UI bundle. B's separate
owner bundle and genuine receipt remain unchanged. The nine donor faces remain
unchanged.

## Genuine host inputs

An independently provisioned, reviewed host plugin may supply the Cordis service
`primeNextHostServices` inside its own lifetime. No default provider or config
loader is introduced here. Its optional fields are:

- `browserBinding`: closed `{ownerBinding:{owner_id,passkeyProfile},context}`;
  context is the fixed `{owner_id,task_id,conversation_id}` from the trusted host.
  The profile must match C's selected HTTPS or exact localhost pilot profile.
- `ownerMemory`: the existing `mountOwnerMemoryHost` inputs: actual channel,
  protected deployment and request guard. Host routes retain the preview
  connection guard. Existing private IPC qualification remains authoritative.
- `inference`: `{producer,authenticateOwner,guardRequest}`. The authenticator
  verifies the opaque session through actual C and returns its owner/expiry.
  The producer is `createDshOwnerInferenceProducer`, supplied the actual pinned
  LLM service/adapter class, existing E gateway and its same durable ledger,
  trusted exact-review request resolver, actual E owner-settings observation,
  and pinned attribution headers. No route, credential or numeric cap comes
  from the browser draft.
- `providers`: actual `createProviderSettingsHandler` inputs: E's owner settings,
  selected owner origin and authenticated owner-context resolver. The separate
  credential worker and direct-entry custody path are not mounted by this code.

A memory login session is not presumed portable to a separately configured
inference authority audience. That requires a genuine reviewed service join;
otherwise inference refuses. Service presence and a preview cookie supply no
owner proof or installed qualification.

## One reply and lifetime

The UI binding is the exact `primePilotInference` shape required by B, with B's
actual controller, the same `primeAuthority` object and native connection
acknowledgement. H observes a login reply privately, then stages its token until
B accepts a distinct matching owner lifetime. Calls retain that exact owner;
logout, replacement and disposal fence local waits. Token contents are never
rendered or included in evidence.

The browser supplies only a literal text draft and UUID. The host resolver must
select exactly one fixed-scope `conversation` user fragment and matching native
DSH user text message. This bounded producer does not select hidden history,
files, images, memories, tools or a system prompt. It freezes the request and
message preimages, uses the existing E adapter through `ctx.llm.stream` once,
and requires its own current gateway result plus the matching retained E row,
receipt, scope and body/binding digests. A DSH finish projection or prior stored
reply cannot substitute for that result. Completed rows require the matching
stored result; unknown rows retain E's original receipt and accounting.

An attempted UUID remains fenced. Withdrawal or interruption never proves
provider cancellation, clears authority consumption, or automatically retries.
Late content is withheld after service withdrawal or failed owner revalidation.
Known-unsent closure remains owned by C/D/Bridge and is not implemented here.

The native bootstrap registers one owning cleanup before awaits; it fences
first and attempts all removers. Failed removers remain owned for a later
explicit cleanup attempt. Cordis disposal is not independent evidence of
external cleanup or crash containment.

## Verification and delivery limits

Scoped commands from the Prime source root:

```sh
node --test harness/check-next-host-bindings.mjs
node harness/check-owner-memory-client.mjs
python3 scripts/build-dsh.py --verify-built
node packages/ui/scripts/verify-owner-build.mjs --ui packages/ui --dsh vendor/dsh --prime-root .
./prime compose --release-dir .runtime/next-host-release
node scripts/check-next-composition.mjs .runtime/next-host-release
```

The focused fixtures use explicit test-only function doubles and actual pinned
DSH registration. They start no listener, worker, provider, database, signer or
owner ceremony. They do not establish installed custody, private UID separation,
PostgreSQL/OpenShell acceptance, or the Desktop v0.3 independent renderer,
witness and off-box anchor design.

Composition may reuse a locally verified pinned build closure. Report reuse
separately from a fresh compiler run. The full release digest covers the authored
host modules and metadata as well as copied pinned bytes. Composition and import
checks establish neither guarded HTTP delivery nor native DOM behavior.

The existing boot command remains:

```sh
./prime boot --release-dir .runtime/next-host-release --deployment-manifest /etc/aukora-prime/preview-deployment.json
```

Boot requires the exact protected deployment manifest and release/UI pins.
Creating that manifest, configuring genuine services, or activating a preview
requires the relevant approved environment. This source change performs none
of those actions. Existing access refusals and blocked service checks stay
stopped; no alternate transport, port or origin is used.
