# Ordinary UI acceptance

These checks use committed owned UI bytes and the already built pinned DSH
witness. They do not launch a browser, enroll an owner or qualify a deployment.

```sh
node packages/ui/prime-authority/checks/ordinary-lifecycle.mjs vendor/dsh packages/contracts/src/browser.mjs
node packages/ui/prime-authority/checks/ordinary-render.mjs vendor/dsh packages/contracts/src/browser.mjs
node --test packages/ui/prime-authority/checks/ordinary-recovery.test.mjs
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

An additive Evolution Lab plugin uses `shell.surface` and `shell.menu.system`
with a distinct `evolution-lab` ID, order 80 and contained navigation. Hide its
persistent surface when inactive. Use Layout `ActionButton` for navigation and
`PortalButton` for an inline disclosure. Dispose only Lab-owned registrations and
resources; H owns descriptor registration and release composition.
