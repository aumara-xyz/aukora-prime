# AUKORA Prime

Independent first-party source, frozen Genesis donor `645d3213b8aede3b544269b4224ae09df06b0a42`, DSH `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`, Cordis 4.0.2 and pnpm 11.7.0. Licenses and the original 43-row inventory are retained in `licenses/` and `provenance/`. No other Aumara checkout is required at build or runtime.

With Node 24.11.1, pnpm 11.7.0, Python 3.10+ and an ordinary native compiler available:

```sh
./prime build
./prime compose
./prime boot --deployment-manifest /etc/aukora-prime/preview-deployment.json
```

The build starts from a complete pristine archive extraction. A reused `vendor/dsh` with extra files, generated output, hooks or configuration is refused before pnpm runs; use a fresh task-owned checkout for a new build. A successful full build writes `.dsh-build/pinned-harness-identity.json`, binding the pinned archive, patches, lockfile, compiler inputs and host/client output inventories. Commit and platform provenance stay in the separate build receipt. Older v1 build receipts require a fresh build and are never migrated into new proof.

`boot` requires a separately retained, protected root-owned deployment manifest outside the release. It checks the selected source commit, full release digest and UI snapshot against that anchor before starting the pinned harness in the foreground on `127.0.0.1:18731`. The release and launcher must be protected against writes by the application identity. Manifest creation and host protection belong to the approved operator deployment step; composing a release alone does not authorize or qualify it. Launch access is stored only in the named private `launch-url.json` descriptor; `./prime status --json` exposes the clean origin. `./prime stop` verifies the owned process before stopping it. Process observation denied by a sandbox is reported as unavailable.

Composition verifies the genuine owner UI source/output receipt and pinned build inputs, preserves all nine donor client bundles and assets exactly, and mounts separate Prime adapters. Embedded static Apps retain their selected assets with hash-bound script CSP. Original donor host entries are never mounted. The DSH welcome notice and preview theme preferences live only in the new process-local settings provider.

The actual execution factory is wired with capability `unavailable`: foreground Bash and child launchers refuse before any grant callback or host process spawn. Owner login/approval, PostgreSQL persistence, external inference, messaging and media remain unavailable until their trusted configuration and acceptance are established. The DSH browser cookie grants access to this disposable UI, not owner authority.

Scoped package checks are in each package. `./prime check G1 --ui-launch-access true --evidence-dir /absolute/path/outside/this/repo` records observations and reports missing independent acceptance. It does not turn package checks into a running-system qualification. Memory CLI `./prime export`, `./prime verify`, and `./prime restore` delegate to the preserved memory closure; database access and non-synthetic restore require explicit trusted configuration.

Persistent broker/UID/socket/security setup, OpenShell guest activation, real owner enrollment and production deployment remain separate approvals. No private data, provider keys or paid model calls belong in this repository.
