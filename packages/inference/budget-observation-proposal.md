# Independent worker budget observation — design pending approval

This is a proposed private host interface, not an implemented accessor, frozen contract extension, protected IPC method, deployment permission or runtime qualification. No shared-contract adoption is authorized by this document. H/Bridge and the integration owner must review the shape and Peter must approve its custody/access consequences before adoption. All completion also awaits Peter-relayed GLM verdict.

The existing Bridge observer needs the authoritative worker's exact stored seven-field `TotalTestingBudget` and its independently observed live credential generation. `SeparatedCredentialService` owns both privately. `status(owner, context)` provides credential generation after owner authentication; `totalUsage` gives accounting, not the stored descriptor. Reusing constructor configuration or deriving values from an operation does not supply the requested independent current read.

## Proposed shape

```ts
type WorkerBudgetLookup = Readonly<{owner_id: string; task_id: string}>;
type WorkerBudgetFacts = Readonly<{
  total_budget: Readonly<TotalTestingBudget>; // exact stored seven fields, already normalized
  credential_generation: number;           // actual vault generation, positive safe integer
}>;
type WithIndependentWorkerBudget = <T>(
  lookup: WorkerBudgetLookup,
  consume: (facts: WorkerBudgetFacts, assertScope: () => void) => Promise<T>
) => Promise<T>;
```

The consume callback is invoked and awaited once. A host-held scope must cover independent reads, C's claim, and the existing E HTTP/evidence continuation. `assertScope` refuses after admission-generation withdrawal or scope closure. It is not a boolean approval flag. Returned data contains no key, encryption material, proof, prompt, raw reply, remaining allowance or eighth `ceiling_microusd` accounting field. The interface grants neither spend nor owner authority.

## Trust and custody implications requiring decisions

1. Select the actual private caller role and process owner. The application/planner/browser/guest must not receive this capability or the vault/store handles. The operation's owner/task strings are lookup candidates, never an authentication source.
2. Require the worker to bind the lookup to independently registered owner/task policy and the protected ledger's stored budget owner. Reads must use `storedTotalBudget()` and actual vault status under approved custody, not caller-supplied data, cached configuration or operation fields.
3. Specify the serialized owner/configuration/credential-generation admission fence shared with credential entry and dispatch. Revoke admission generation before draining existing work. A value snapshot alone does not hold that fence. Original unknown work retains its existing allowances and identities.
4. Decide where the fence lives and how its scope crosses any process boundary. JavaScript callbacks and process-local brands cannot be serialized. An eventual authenticated protocol needs reviewed lifecycle correlation and scope revocation semantics; adding it to the authority IPC profile is a separate shared decision.
5. Specify restart and custody evidence: one authoritative worker/store, protected live generation, anti-rollback and bounded independent reads. A copied descriptor, matching hash, local fixture or provided callback does not establish these runtime facts.
6. Confirm whether this shape remains a private host interface or must become a shared contract. If shared, the contracts owner owns versioning, exact fields, parser/types and adoption. E will not add fields to frozen `OperationProposal`, `ConsumedGrant`, `Task` or `ModelRoute`.

Bridge would merge these two facts with its independently qualified route, effective task, approved configuration and registered C owner mapping, then reuse existing E `inferenceBudgetState`. The immutable budget-policy digest and state-version formulas remain unchanged. This proposal does not expose or derive spend availability and cannot release an unknown reservation.

## Reference and evidence limits

Desktop v0.3 is requested at SHA256 `0b1a334ff4854553c7bec4eab3b499dd556ef144f619273c5e931b70bd323d31`. The exact bytes/path were not available in the supplied references or targeted Library searches during this increment. A reference location has been requested; verification and exact-spec review remain pending. No CP/TR numbering or conformity is claimed. Exact-spec assessment remains pending that reference; the existing operation/grant/digest bindings and worker lifecycle are preserved.
