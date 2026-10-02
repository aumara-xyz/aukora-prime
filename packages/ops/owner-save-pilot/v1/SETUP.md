# Owner-save pilot v1 setup packet

This is approved **SOURCE PREPARATION** for a separate, versioned interim owner-save pilot. It supplies operator requirements and an incomplete input template, not an installer or runtime configuration. Runtime activation, installation, credentials, enrollment, database changes and filesystem/security changes require their own action-time approval. The existing 146 evidence rows and two red rows remain frozen; this pilot does not supersede them.

Every pilot status and receipt envelope must carry these literal scope fields:

```json
{
  "guarantee_profile": "reduced-guarantee-owner-save-pilot/v1",
  "scope_label": "REDUCED-GUARANTEE",
  "missing_guarantees": [
    "independent_witness",
    "second_host_anchor",
    "hardware_hash_display"
  ],
  "public_qualified_factory": "closed",
  "v03_conformance": "NOT_CLAIMED",
  "qualification": "UNPERFORMED",
  "grok_review": "PENDING_ACTUAL_BYTES_REVIEW"
}
```

The scope sidecar binds the exact unchanged canonical public-receipt byte SHA, its existing domain receipt digest, the operation digest and the external deployment manifest's source commit, release digest and byte SHA. The operation's owner subject is bound through `target_identity.owner_subject`. The sidecar accepts no approval or authentication material and does not verify a signature, authorize an effect, assert a verified effect or establish completion. The H/Bridge/B pilot envelope, capability and client agreement remains a separate source gate. A successful local constructor or private IPC response cannot clear the public guard. These fields remain visible after any narrow pilot acceptance result.

## Reviewed source and current gates

This packet inspected H assembly `251fdb5776daa90aab37251e56b73758a633d67c` at `harness/retained-memory-composition.mjs`, C `service.mjs`, `webauthn.mjs`, `state-store.mjs`, and the exact D/Bridge files listed in `bootstrap-requirements.json`. D core1d is `1d395db6c07551a7afc9382fce16799b03ab61de`; the named D files were compared at those pins. Reading pinned source establishes SOURCE-ONLY evidence. No constructor, test, registration, PG query, listener or host action was run for this packet.

H's `createRetainedMemoryComposition` constructs D memory and C authority in the same process (lines 59–63), owns the supplied real Pool, and rejects setup-only `provisionTrustedState` in runtime configuration (41–42). Its current status is UNPERFORMED with public and restore routes unavailable (79–81). `startRetainedMemoryIpc` is an explicit private boundary, not the default composition (101–126). Retained Bridge `accepted()` refuses runtime acceptance (`packages/runtime-bridge/src/index.mjs:97–100`). This packet does not modify any of these guards.

The source accepts publisher UID995, reader UID994 and retention GID984, provided the actual real/effective UIDs and group membership match. Both source constructors check that identity, not a caller assertion. Numeric acceptance does not establish current NSS, ACLs, process isolation or account ownership.

## Concrete proposed roles and paths

Reuse the existing identities only after a bounded read-only operator observation confirms their current UID/GID mapping and process groups. No new account or global membership change is proposed by this packet.

| Role | Intended account/UID | Intended access |
| --- | --- | --- |
| App | `prime-app` / 997 | Separate pilot client only; excluded from GID984, C state, retention publication and PG socket access. |
| H, embedded C, D SQL and retained reader | `prime-memory` / 994 | Existing peer PG role `prime_memory`; GID984 for retained read/IPC; existing `prime-pg-socket` group for the private PG socket. |
| Retained-file publisher | `prime-authority` / 995 | GID984 `prime-authority-ipc`; writes only the selected new retained leaf through the future fixed publisher profile. |
| PG | Existing distro postgres identity | Existing private Unix socket; no public listener or new global group membership. |

UID995 is a reused historical authority UID, not an independent witness identity. DAC alone cannot distinguish this publisher from other UID995 processes or deny it access to historical UID995-owned files. A future bounded service/filesystem confinement plan must exclude historical custody and unrelated writable paths and must be observed on the actual process before an isolation claim. Source preparation makes no such claim.

| New pilot location | Proposed owner/group and mode | Gate |
| --- | --- | --- |
| `/var/lib/aukora-prime/memory/owner-save-v2` | UID994, its verified primary group; 0700 | New C restore root; exact `statePath` filename remains null until the reviewed bootstrap agrees. |
| `/var/lib/aukora-prime-witness/owner-save-v2-authority` | UID994, its verified primary group; 0700 | C witness outside that restore root; same UID as H/C. |
| `/var/lib/aukora-prime-witness/owner-save-v2-retention` | 995:984; **02750** | Publisher-owned retained files; H994 reads through GID984. |
| `/run/aukora-prime/owner-save-v2-publisher` | Proposed 995:984; 0710 | Dedicated private publisher IPC parent, pending source profile agreement. |
| `/run/aukora-prime/owner-save-v2-publisher/publisher.sock` | Proposed 995:984; 0660 | Future fixed publisher-only transport; no listener is created here. |

Retained files must be single-link regular files 995:984 **0640**; publisher lock files are **0600**. The retention path must be canonical, absolute, normalized, nonroot and nonsymlink; each ancestor must be root- or publisher-owned and protected against group/other writes. Root-owned sticky ancestors are the source's explicit exception. The publisher and reader must both have GID984; app exclusion and unexpected ACLs require independent metadata/access observations. Do not create a leaf under an ancestor owned by reader994: the retention guard allows only root or publisher995 ancestors.

The proposed new protected configuration roots are `/etc/aukora-prime/owner-save-pilot/v1/h` and `/etc/aukora-prime/owner-save-pilot/v1/publisher`: root-owned, respective verified service-primary group, 0750; immutable configuration/credential files root-owned 0440. Exact filenames and the source guard accepting this layout remain null until the separate entrypoints are reviewed. If an authenticated transport uses a shared channel credential, provision separate protected copies for the two roles rather than placing secret bytes in this repository, template, argv, logs or receipts. Credential issuance/installation is a future approval, not a source-preparation action.

The public prepared PG tuple is private socket directory `/run/aukora-prime/postgres`, port 55434, system account `prime-memory` mapping to DB role `prime_memory`. The actual existing database, new pilot schema, exact grants, durability settings and their current evidence remain unresolved. The operator must approve a distinct empty pilot namespace and exact bounded grants; no historical table/row import or broad DB/schema ownership is implied. Synthetic pools and fixture rows cannot establish real PG acceptance.

## New lineage, registration and bootstrap order gates

1. Freeze the reviewed pilot source, entrypoint/dependency closure, Node executable and external deployment manifest. Pin source/release/manifest bytes externally. The template is incomplete until those literal pins and actual role/path observations are recorded. No candidate-generated qualification marker substitutes for them.
2. Approve creation of a **genuinely new** owner-pilot lineage at the locations above. Verify absence/canonical protected parents before action; an existing or conflicting leaf blocks initialization. Historical C995 state/witness and every existing owner/store lineage remain untouched. Existing-lineage preservation or restore is a different reviewed join and must not enter this fresh path.
3. Obtain the owner's real public identity and an owner-approved registration ceremony bound to an exact RP/origin. C `prepareWebauthnConfig` validates supplied enrolled ES256 records; `verifyWebauthnAssertion` verifies assertions. Neither registers a credential or verifies registration attestation. The separate versioned registration producer/verifier is missing and must be reviewed before accepting a record. Keep private keys and authentication material outside this packet. Require real assertion UP/UV and explicit review of exact save bytes; a real passkey does not provide the missing hardware hash display.
4. Review the C initialization order and invoke only the source-owned **local setup** helper `provisionNewAuthorityStore` after action-time approval and nonempty owner public configuration. It refuses an existing state and returns the actual persisted store ID. Coordinate the expected C/D store pair before constructing runtime C. The helper is never an IPC method; `provisionTrustedState` never appears in H runtime inputs. Do not invent a store ID, copy a fixture, adopt historical state or infer a fresh baseline from a constructor.
5. Review and supply the missing versioned D initializer. Existing `migrate()`, `installWriterClosureGuards` and `migratePrivateV2Guards` are bounded schema/guard primitives, not logical-store or retained-genesis bootstrap. Private-v2 metadata is immutable after its guard is installed; the initializer must establish the genuine new metadata in an explicitly approved transaction/order and then verify the native guards. `readControlV3` must read the actual same owner PoolClient projection. `createControlV3` is a serializer, not database evidence.
6. Supply a reviewed new-lineage retained-genesis publisher. The existing retention module has no bootstrap. Its current pointer requires a matching generation and complete chain to the original empty published genesis; sequence one requires empty heads and all control tables empty. `beginTyped` already requires that current pointer. No operator-written JSON, random digest, canned baseline, candidate status or existing checkpoint adopted as new may satisfy this gate. Keep initializer ownership under publisher995 and preserve fsync/publication/readback semantics before any transition.
7. Supply the separate versioned private publisher server/client profile and entrypoints. The existing local publisher implements exactly `beginTyped`, `retainPrepared`, `publishPrepared`, `clearMatchingPending`; the coordinator requires four own function properties, not the generic client's `request`/`close` interface. Authentication, method allowlist, peer/custody checks, protected configuration and bounded cleanup must be reviewed. Independently reread each actual retained outcome; a successful transport response is insufficient.
8. Agree the separate pilot capability/client/outer-envelope contract with H/Bridge/B. Keep the original qualified public factory closed. A `requiresCapabilities:false` escape, fabricated qualified flag, legacy host record or removal of a current source guard is not this pilot. A narrow real-PG/real-passkey/real-byte run needs separate action-time approval and actual evidence from the agreed pilot path.

The optional current WebAuthn `localhost-pilot-v1` profile is exactly RP `localhost` and origin `http://localhost:18731`. It cannot be silently moved to port 18732, an IP origin or another host. Choosing that profile or a supported exact HTTPS origin remains an owner decision; no port conflict resolution, tunnel or network change is authorized here.

## Approval and acceptance record

The current authorization is source preparation of this reduced-guarantee version only. Future approvals must identify the frozen artifacts and bounded action: new protected directories/configuration, channel credentials, owner enrollment, new PG namespace/guards/metadata, new lineage/genesis, selected owned processes/ports, and the real save acceptance run. Use the existing accounts/groups only if read-only observations confirm the tuple; otherwise stop that setup action and present the discrepancy rather than changing memberships silently.

The narrow acceptance must use the actual owner passkey and actual PG, prove exact saved bytes and canonical receipts, and show that unapproved, tampered and declined operations produce no save. A timeout or uncertain outcome stays fenced and cannot be automatically resubmitted. This packet provides no test command and runs no audit, forbidden fixture or effect. Independent witness, second-host anchor and hardware hash display remain absent in every status/receipt; v0.3 conformance remains NOT_CLAIMED.

Before DONE, Grok must review the **actual frozen bytes** intended for this pilot and the scope/evidence limitations. No such review is performed by source preparation. Keep its exact artifact hashes, review reference and unresolved findings in the approval record; exclude secrets/private inputs and obtain the appropriate approval before external submission. The profile stays `PENDING_ACTUAL_BYTES_REVIEW` until that evidence exists. A favorable review does not grant runtime permission or public qualification.

`operator-inputs.template.json` is a review checklist with unresolved values null. `bootstrap-requirements.json` records source helper names and blocking stages. Neither is accepted directly as H/C/D runtime configuration. Runtime, real enrollment, real PG, current identities/custody and installed byte evidence are **UNPERFORMED**.
