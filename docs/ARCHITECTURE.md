# Prime NEXT packages: architecture and build

This page covers the Prime NEXT packages (SOURCE). For the live organism that runs on the Linux pilot (Genesis runtime, boundary gate, OpenShell sandbox, desktop owner app), read [the top-level ARCHITECTURE.md](../ARCHITECTURE.md) first.

The source is divided into contracts, authority, memory, execution, inference, runtime bridge, UI, operations and desktop packages. The harness composes the pinned host and selected UI through Prime adapters. Proposing software supplies a candidate operation; separately configured authority decides whether that exact operation may reach an effect.

This document describes source and operator interfaces. The [README](../README.md) is the status account, and the [Golden Boundary paper](AUKORA-GOLDEN-BOUNDARY.md) explains the general design. A build, render or composed release is not installed-system qualification.

## Package map

| Component | Source and interface |
| --- | --- |
| Contract formats | [packages/contracts](../packages/contracts/README.md): frozen operation, proof, route and receipt profiles. |
| Owner authority | [packages/authority](../packages/authority/README.md): owner login, review, approval, reservation, dispatch and settlement. |
| Persistent memory | [packages/memory](../packages/memory/README.md): authorized capture, PostgreSQL persistence, citation, snapshots and retained controls. |
| Private process join | [packages/runtime-bridge](../packages/runtime-bridge/README.md): trusted worker configuration, IPC and owner workflows. |
| Effect execution | [packages/execution](../packages/execution/README.md): owned foreground lifecycle and OpenShell qualification interfaces; actual execution remains disabled. |
| Model route | [packages/inference](../packages/inference/README.md): brokered credentials, scope and budget bounds; live inference is unperformed. |
| Owner UI | [packages/ui/prime-authority](../packages/ui/prime-authority/README.md): exact operation review and authenticator interface; fixtures do not enroll an owner. |
| Release operations | [packages/ops](../packages/ops/README.md): pinned digests and observed gates; package checks do not qualify a deployment. |
| Desktop preview | [packages/desktop](../packages/desktop/README.md): preview launcher; no authority comes from a browser access cookie. |

## Build and operator interface

The following account is retained from the source baseline. Commands that create or start a deployment require its actual trusted configuration; the keyless sharing check does not supply that configuration.

Independent first-party source, frozen Genesis donor `645d3213b8aede3b544269b4224ae09df06b0a42`, DSH `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`, Cordis 4.0.2 and pnpm 11.7.0. Licenses and the original 43-row inventory are retained in `licenses/` and `provenance/`. No other Aumara checkout is required at build or runtime.

With Node 24.11.1, pnpm 11.7.0, Python 3.10+ and an ordinary native compiler available:

```sh
./prime build
./prime compose
./prime boot --deployment-manifest /etc/aukora-prime/preview-deployment.json
```

The build starts from a complete pristine archive extraction. A reused `vendor/dsh` with extra files, generated output, hooks or configuration is refused before pnpm runs; use a fresh task-owned checkout for a new build. A successful full build writes `.dsh-build/pinned-harness-identity.json`, binding the pinned archive, patches, lockfile, compiler inputs and host/client output inventories. Commit and platform provenance stay in the separate build receipt. Older v1 build receipts require a fresh build and are never migrated into new proof.

`boot` requires a separately retained, protected root-owned deployment manifest outside the release. It checks the selected source commit, full release digest and UI snapshot against that anchor before starting the pinned harness in the foreground on `127.0.0.1:18731`. The release and launcher must be protected against writes by the application identity. Manifest creation and host protection belong to the approved operator deployment step; composing a release alone does not authorize or qualify it. Launch access is stored only in the named private `launch-url.json` descriptor; `./prime status --json` exposes the clean origin. `./prime stop` verifies the owned process before stopping it. Process observation denied by a sandbox is reported as unavailable.

Composition verifies the genuine owner UI source/output receipt and pinned build inputs, preserves all nine donor client bundles and assets exactly, and mounts separate Prime adapters. Embedded static Apps retain their selected assets with hash-bound script CSP. The Prime route seam refuses the AumaLive and Lingwa pages and their voice entry modules before those donor scripts are served. Their original artifacts remain hash-bound on release disk; the inactive entry routes return an inert unavailable response. This is necessary because a backend refusal alone does not disable browser speech fallback. Original donor host entries are never mounted. The DSH welcome notice and preview theme preferences live only in the new process-local settings provider.

The actual execution factory is wired with capability `unavailable`: foreground Bash and child launchers refuse before any grant callback or host process spawn. Owner login/approval, PostgreSQL persistence, external inference, messaging and media remain unavailable until their trusted configuration and acceptance are established. The DSH browser cookie grants access to this disposable UI, not owner authority.

Scoped package checks are in each package. `./prime check G1 --ui-launch-access true --evidence-dir /absolute/path/outside/this/repo` records observations and reports missing independent acceptance. It does not turn package checks into a running-system qualification. Memory CLI `./prime export OWNER OUTPUT`, `./prime verify SNAPSHOT OWNER [RETAINED_HEADS_JSON]`, and `./prime restore` delegate to the preserved memory closure; database access and non-synthetic restore require explicit trusted configuration.

Persistent broker/UID/socket/security setup, OpenShell guest activation, real owner enrollment and production deployment remain separate approvals. No private data, provider keys or paid model calls belong in this repository.

## Data residence in the preview

The Mac window is a renderer for the approved Linux pilot. Its loopback connection is forwarded through the existing authenticated SSH connection to the remote HTTP application. This does not make the application or entered content local to the Mac.

| Data or boundary | Current residence and limit |
| --- | --- |
| Shared repository | Source, licenses, synthetic fixtures and sanitized historical evidence. Personal runtime data, access tokens and provider credentials are excluded. The repository does not provision a machine or supply account authorization. |
| Mac preview | Rendered DOM, a disposable Electron profile and an in-memory browser access cookie. Explicitly saved screenshots are local artifacts; the authorized screenshot archive was separately saved to Library. A browser access cookie is not owner authorization. |
| Linux application | The running UI host, runtime workspace and private launch state reside on the pilot. Browser requests terminate there, so future entered content can reach that host. Current public owner, memory and inference effects remain unavailable. |
| Memory evidence | The retained PostgreSQL experiment used synthetic data at its recorded older revision and was cleaned up. It is not a current active private-memory service or permission to import personal records. |
| Credentials and processing | Separate worker and vault mechanisms are source interfaces, not qualified deployment custody. The unmounted inference recorder writes full request bodies to plaintext JSONL, while its application-side SQLite ledger can retain the body-bearing receipt and result/accounting data; a retention or forget policy for those payloads is not qualified. No real provider key or paid model call was used. Voice and vision are unavailable, and their egress has not been measured. |

These observations do not establish local-only storage, hardware custody or a fully contained live agent. Any future sensitive-data use needs an explicit policy for the selected host, storage, provider and retention boundaries. The current preview’s disabled controls and read-only catalog do not enable those uses.
