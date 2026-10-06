# Approved scope alias composition

The owner preview remains the single approved old-hash to target-hash edge in
`owner-review-46-note-alias.preview.json`. Its 46-note packet is supplied metadata,
not a new memory measurement. The target's approved snapshot is 85 notes; a later
reported count of 87 changes no scope permission. No note bodies or record IDs
are needed to compose this scope-wide read projection.

Kira accepts that preview as the trusted plugin configuration field
`approvedScopeAliases`. It validates and snapshots the preview through
`createApprovedScopeAliasResolver`. A draft preview resolves nothing.

The mounted join is:

```js
apply(ctx, configWithApprovedScopeAliases, existingGateCaptureHost, projectReadHost)
```

`projectReadHost` is a direct trusted-host argument with exactly two callbacks:
`contextFor(agent)` returns the existing `{ attachedProjects, projectAliases? }`
context; `scopeFor(agent)` returns the existing selected project scope or null.
These callbacks are never plugin configuration, model arguments or an RPC method.
The third gate-capture argument keeps its original meaning.

The read context is decorated once at each recall boundary. The approved target
must already appear in the host's attachment list. Selection alone, the preview,
the session cwd and note metadata cannot create an attachment. Context fields
that would replace the owner policy or session binding are refused. Both read
callbacks default to the existing project identity when no host is supplied, so
this hash-to-hash preview is safely inactive under a stable-ID-only context.

Capture retains the original project identity resolver. The alias does not
rewrite IDs, canonical bytes, scopes, capture metadata or the stored chain. It
creates no reverse link or alias chain. Unrelated, detached and unreviewed
project scopes retain their ordinary `scope-not-attached` refusal.

Synthetic SOURCE and mounted pinned-DSH checks are separate from deployment
acceptance. Integrator composition must supply the actual existing attachment
resolver. Long-note staging save/restart/recall requires an allocated synthetic
namespace and isolated lifecycle; this source change authorizes no shared
service restart.

The unresolved-scope recovery hook now emits the fixed warning
`aukora-kira: capture recovery skipped (project-scope-unresolved); no notes recovered`
before its unchanged early return. The warning includes no paths, sessions,
record IDs or note text. Ordinary saves on this base retain unresolved scope;
recall subsequently refuses it. The warning does not turn that scope into owner
or attached-project memory.
