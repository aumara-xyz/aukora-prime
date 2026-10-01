# AUKORA Prime

Independent first-party source, frozen Genesis donor `645d3213b8aede3b544269b4224ae09df06b0a42`, DSH `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`, Cordis 4.0.2 and pnpm 11.7.0. Licenses and the original 43-row inventory are retained in `licenses/` and `provenance/`. No other Aumara checkout is required at build or runtime.

With Node 24.11.1, pnpm 11.7.0, Python 3.10+ and an ordinary native compiler available:

```sh
./prime build
node packages/ui/scripts/build-client.mjs --dsh vendor/dsh --output .runtime/client-dist
./prime compose
./prime boot
```

`boot` runs the pinned harness in the foreground on `127.0.0.1:18731`, using a new isolated state home. The private launch URL is printed once; `./prime status --json` exposes only the clean origin. `./prime stop` verifies the owned process before stopping it. Process observation denied by a sandbox is reported as unavailable.

Composition verifies pinned build receipts and every new client artifact, preserves the exact UI baseline, and mounts separate Prime adapters. Embedded static Apps retain their selected assets. Original donor host entries are never mounted. The original DSH welcome notice persists only in the new Prime state home.

The actual execution factory is wired with capability `unavailable`: foreground Bash and child launchers refuse before any grant callback or host process spawn. Owner login/approval, PostgreSQL persistence, external inference, messaging and media remain unavailable until their trusted configuration and acceptance are established. The DSH browser cookie grants access to this disposable UI, not owner authority.

Scoped package checks are in each package. `./prime check G1 --ui-launch-access true --evidence-dir /absolute/path/outside/this/repo` records observations and reports missing independent acceptance. It does not turn package checks into a running-system qualification. Memory CLI `./prime export`, `./prime verify`, and `./prime restore` delegate to the preserved memory closure; database access and non-synthetic restore require explicit trusted configuration.

Persistent broker/UID/socket/security setup, OpenShell guest activation, real owner enrollment and production deployment remain separate approvals. No private data, provider keys or paid model calls belong in this repository.
