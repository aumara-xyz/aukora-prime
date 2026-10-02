# Ordinary UI acceptance

These checks use committed owned UI bytes and the already built pinned DSH
witness. They do not launch a browser, enroll an owner or qualify a deployment.

```sh
node packages/ui/prime-authority/checks/ordinary-lifecycle.mjs vendor/dsh packages/contracts/src/browser.mjs
node packages/ui/prime-authority/checks/ordinary-render.mjs vendor/dsh packages/contracts/src/browser.mjs
node --test packages/ui/prime-authority/checks/ordinary-recovery.test.mjs
node --test packages/ui/prime-authority/checks/ordinary-hook.test.mjs
PRIME_RECOVERY_DSH=vendor/dsh node --test packages/ui/prime-authority/checks/ordinary-recovery.test.mjs
```

The lifecycle fixture supplies a synthetic logout acknowledgement. The native
render check uses pinned React and Schemastery with an injected public catalog;
owner configuration and key entry remain unavailable. The recovery check uses
actual C/D code with synthetic P-256 credentials and a disposable SQLite dialect
fixture. This establishes source behavior, not PostgreSQL durability, actual
worker isolation, human presence or real credential enrollment.

## Recovery join owned by composition

The native controller exposes:

```ts
reconcileApprovalAction(snapshot: unknown):
  Promise<ApprovalActionResult | ForgetWorkflowSnapshot | null>
```

After the existing workflow has recovered host facts, composition must await
`controller.reconcileApprovalAction(snapshot)` before admitting another
proposal through that same controller. For example:

```js
const snapshot = await workflow.recover(input)
await controller.reconcileApprovalAction(snapshot)
return snapshot
```

Use the same join for `forgetWorkflow.recover(input)`. A null return keeps an
unresolved controller fenced. The method sends no approval or effect and only
releases a retained uncertain action after its exact original approval, operation
and completed receipt match. Missing receipts, unknown settlement, idle replies,
changed bindings and lost owner access do not release that latch. A fresh binding
with no retained uncertain action continues to use its separate recovery flow.

Original donor-format `canonical_bytes` remain unchanged, including decimals,
literal whitespace and Unicode. The strict outer transport still treats them as
a string. A recovered consumed review can remain visible while its obsolete
review expiry no longer disables new proposals; current owner-session expiry
still applies.

## Required approval hook

`submitApproval()` reserves the memory workflow flight. During that flight,
public `approve()` returns null without changing the pending workflow. Its
handler receives `{signal, approve}`; only this zero-argument private callback
can return the proof for that captured flight. It coalesces calls and checks
the original owner, binding, review and handler before and after awaiting.

H must pass these invocation options into the actual save/forget workflows:

```js
controller.setApprovalAction((_view, options) => workflow.approveAndSave(options))
controller.setForgetAction((_view, options) => forgetWorkflow.approveAndForget(options))
```

That production bridge join requires its corresponding callback input. Ordinary hook
and recovery checks call the native owned controller directly and forward its
exact invocation options. Default checks require the owned controller and actual
bridge fixture; absent dependencies fail rather than skip. An explicit absolute
`PRIME_OWNER_JOIN_ROOT` can select a task-owned source consumer with the expanded
D/bridge join for qualification. Its copied pins and any TEST-only bridge
adaptations must be recorded; this does not establish production integration.
The separate H-owned `owner-memory-hook.test.mjs` default and aggregate check
manifest still require their owner's integration.

For a fresh source-only qualification build, compiled checks accept explicit
`PRIME_HOOK_CLIENT` and `PRIME_RECOVERY_CLIENT` paths alongside their pinned DSH
witnesses. This avoids presenting an older tracked bundle as the latest source.

## Expanded NEW-capture review

D checkpoint `6326a4c928a7d14ab7e9ef7a7da626a6a6322d22` freezes the independent
closed draft `{statement,attributed_to,capture_metadata,evidence_quote}` and the
seven operation parameters containing those four fields plus capture hash,
idempotency hash and heads. B copies its browser-safe helper byte-for-byte
(SHA256 `d82eda5f8ae0fefa02f182fac80480d82a7c88fd6148beadabde5cd8480472d7`).
Composition must preserve the independently prepared full draft through proposal,
challenge, completion and save. B compares all six metadata fields and the full
selected source quotation, and renders them as escaped text before approval.
The optional separate metadata sibling must match; the expected quotation is
never reconstructed from a hash or the proposed parameters.

NEW statement and quote must already be NFC with visible nonblank content. D's
helper refuses its exact unsafe control, filler and line-separator set. Valid
scripts, combining marks, emoji and visible ZWNJ/ZWJ content remain permitted.
No accepted text is replaced or normalized. Existing hint diagnostics label the
statement and source quote separately; they are not a complete confusable detector.
Historical saved/imported bytes remain opaque original donor strings, including
NFD, literal whitespace and decimal confidence. Saved-content comparisons bind
the reviewed fields to the exact original record and evidence rather than
rewriting or applying NEW admission to historical records.

Focused source checks:

```sh
node --test packages/ui/prime-authority/checks/capture-review.test.mjs packages/ui/prime-authority/checks/expanded-transport.test.mjs
```

The expiry regression obtains an actual verified recovery result before the
old review timer fires. Starting the bridge workflow's recovery read after its
combined `expired` flag is already set needs a separate composition/workflow
review; this patch does not change that workflow guard.

## Composed browser acceptance pending H

- Open Models through the native System menu. Observe the DeepSeek row and
  keyed companion, fixed endpoint, local model draft, read-only zero caps and
  absent spend ceiling. Key entry must remain disabled with an unavailable reason.
- Observe the exact original record, nullable attribution, operation, digest and
  fresh challenge before logical forget. Its completed result must distinguish
  removed visibility from retained canonical payloads, backups, WAL and media.
- Observe pending/repeated clicks, confirmed sign-out and local owner loss on
  disposal through the composed surfaces.
- Check the donor foundation palette, contained launch behavior and small/large
  viewport clipping. These Node checks do not establish pixels or served bytes.

Optional Evolution Lab composition remains deferred while the core join is integrated.
