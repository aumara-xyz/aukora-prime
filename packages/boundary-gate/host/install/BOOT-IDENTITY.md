# PrimeBootIdentity — source staging and installed disk verification

This change is SOURCE-ONLY. It adds a fixed boot identity interface; it does not
install a manifest, qualify a workspace, enroll an owner, change an approval
floor or establish a running provider's identity.

The installed read-only command is:

```text
/usr/bin/python3 -I -S /usr/local/lib/aukora-boundary/gate-bootstrap check-boot
```

It accepts no options or paths. Success is exactly
`BOOT_VERIFIED PrimeBootIdentity=sha256:<64 lowercase hex>` and exit 0. A missing
profile, missing protected dependency, changed hash, malformed manifest or local
unit override refuses with exit 2 before dispatch. It neither starts Node nor
queries or starts systemd services. Provider readiness and loaded unit readback
are separate checks. `check-runtime` keeps its previous narrower contract.

Recovery uses the separate no-options `gate-bootstrap check-ready` action. After
the same complete installation verification, mandatory boot identity and
owner-key/launcher profiles, it dispatches only the installed fixed
`bin/gate.mjs check-ready` route with the existing clean Node environment. That
gate entry owns the read-only owner readiness API and refuses unavailable
readiness; no ping, owner registry guess, key creation or alternate module is a
fallback. The installed gate/API readiness outcome remains a separate runtime
observation from disk identity.

Ordinary `serve` dispatch also requires this mandatory boot identity and public
carrier pin. Omitting the optional Aura collector profile cannot bypass either
gate-startup or readiness verification. The existing nongate `check-runtime`
interface retains its narrower source-profile contract.

## Manifest and closure

The fixed root-protected manifest remains
`/etc/aukora-boundary-gate/gate-package-manifest.json`. Its closed v2 grammar
permits `profiles.boot`, with exactly `kind`, `files` and `digest` fields. The kind
is `aukora-prime-boot-identity/v1`. Each fixed installed path has exactly a
`source` reference, `source_sha256` and installed `sha256`. The verifier's
`BOOT_SOURCE_FILES` and `BOOT_DATA_FILES` maps enumerate the complete permitted
path/reference set; extra entries and omissions refuse.

The domain-separated canonical JSON digest binds the entire gate package
inventory, public signer epoch map, every configured nonboot source profile and
the boot file references. Changing package source, launcher/owner-key/Aura pins,
source references, public configuration or installed helper/unit bytes changes
this one identity. It is a root operator's reviewed disk identity; it grants no
new owner authority.

The fixed first-party closure covers the bootstrap itself, `selfcheck-with-retry`,
`genesis-recover-probe`, `sbx-exec`, its descriptor closer and preserved shell
body, the OpenShell inventory/provider helpers and source-owned workload pin and
generation schema. It also covers every source-owned boot/recovery service and
timer, the failure-handler template, the local firewall unit/rules and the
restricted sudo rule. The gate package's existing complete inventory covers its
selfcheck, owner-state reader and other imported gate modules.

The five public operator-data references are the strict release environment
document, owner-state registry, OpenShell deployment inventory, workspace
registration and fixed `/etc/aukora-boundary-gate/aura-context.json` carrier.
They are reviewed as data and pinned from a separate staged mirror. Missing
deployment documents block `check-boot`; the verifier does not create them,
derive them from a writable workspace or qualify their runtime claims. Mutable
approval cache/floor and private key material remain in their existing admission
and custody interfaces.

The public carrier's literal source reference is `operator-data:aura-context/v1`.
Its exact expected bytes come from the separately reviewed `--boot-data-root`
input, and the generator requires the proposed installed copy to match those
bytes. The complete BootIdentity contains 27 source references and five data
references, 32 files in total. The carrier remains mandatory when no
`profiles.aura` collector is configured. This pin join reads public bytes only:
it does not require or validate full Nostr claims, load a collector, read a
private signer or learn an expected hash from runtime. D's flat public interface
owns its separate semantic verification; a matching hash alone proves none of
those semantics.

Local full-unit, template-instance, dash-prefix and type-wide drop-in directories
refuse in the fixed systemd search roots. Relevant override/transient/generated
fragments outside `/etc/systemd/system` also refuse. An arbitrary unrelated host
unit is not part of this closure. Disk verification does not prove that systemd
has reloaded these bytes or that its running processes match them.

## Operator staging delta

Keep the existing complete gate, owner-key, six-input launcher and public signer
staging procedure. Prepare three additional disjoint reviewed staging inputs:

1. `--boot-checkout`: reviewed source containing every named source reference.
2. `--boot-data-root`: a mirror containing exactly the five fixed public data
   paths, with each absolute path represented below the mirror without its
   initial `/`. Review the actual existing release/owner/provider selections;
   do not invent documents to make a check pass.
3. `--boot-root`: the complete proposed installed closure using the same path
   mirroring. Copy the reviewed source files to their named installed paths and
   the reviewed public data files byte-for-byte. Materialize only the gate
   unit's `--gid SKGATE_GID` token with the verified existing `skgate` GID.

Add these arguments to the existing v2 generator command:

```text
--boot-root /operator-staging/boot-root
--boot-checkout /operator-staging/reviewed-checkout
--boot-data-root /operator-staging/reviewed-public-data
--skgate-gid <verified-existing-numeric-gid>
```

The generator reads only staging paths, checks complete mirrored inventories,
requires every materialized source file to equal its reviewed source (apart from
the one bounded GID substitution), and compares every staged data file with its
separate reviewed data input. It creates a new deterministic output file outside
all inputs and installed roots. It never installs or starts anything. The
manifest cannot authorize its own staged inputs: the operator must review the
selected source and public data independently.

Install only a coherent reviewed closure and manifest under the existing
quiescent-root-updater procedure. Every installed file and ancestor retains the
existing root-owned, no-group/other-write, no-symlink custody requirement; files
must be regular and single-link. Restart through units that run `check-boot`
before the gate/application/selfcheck helper paths. Keep the updater quiescent
through verification and handoff; trusted root mutation remains outside the
nonroot tamper claim.

## Evidence and remaining boundaries

```sh
/usr/bin/python3 -I -S packages/boundary-gate/host/install/check-boot-identity.py
/usr/bin/python3 -I -S packages/boundary-gate/host/install/check-bootstrap.py
```

The focused boot check creates new retained source fixtures only below
`~/.aukora-h-boot-fixtures`, validates that root's current-user ownership, exact
`0700` directory mode and canonical non-symlink path, and refuses an existing
root with different custody. It does not repair or delete an old root. Each new
fixture uses `mkdtemp` below that private parent and is retained without teardown;
missing/link/extra-entry controls move invented entries to retained names where
possible. The check runs the production verifier and `main()` against actual
invented files and protected fixture modes, with explicitly synthetic UID0
metadata and simulated protected fixture ancestors. It tests every named file
hash; missing, symlinked, hardlinked and writable helpers; extra/missing manifest
entries; removed digests; whole-profile digest binding; local drop-ins; finite
arguments; deterministic actual-source staging; and detecting controls after
individual hash/digest guards are removed in memory. No production override or
mutation selector is added.

The public-carrier controls additionally exercise omission, changed bytes,
missing files, symlinks, hardlinks and writable mode before either ordinary
gate or readiness dispatch. A named single-guard mutation removes only the
carrier hash comparison: the unchanged production verifier refuses the actual
tampered fixture bytes, while the mutant reaches the same fixed Node dispatch
recorder. Invented flat public fixture bytes establish this byte-pin behavior,
not a valid enrolled controller, Nostr approval or installed semantic context.

Actual root ownership, loaded systemd definitions, the existing release's
admission, owner enrollment, provider readiness and installed Linux/OpenShell
containment remain UNPERFORMED. The fixed distro Python/Bash, standard library,
loader, systemd, sudo/runuser, nftables, Podman, SSH, account metadata and kernel
remain external platform anchors. The reviewed Node and OpenShell binaries,
OpenShell gateway configuration/mTLS state, runtime applied policy and guest
image require their separate installed identity and containment evidence. A
BootIdentity fixture does not close those gates or the final qualification gate.
