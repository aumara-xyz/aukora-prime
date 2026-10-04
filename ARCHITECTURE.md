# How AUKORA fits together

*Start here if you are reading the repository rather than running it.* Every row below names the code, the test that
covers it, and one status word: **RAN** (ran on the configured path, with the evidence named), **SOURCE** (code and
tests in this repository, not run as an installed system) or **NOT YET** (designed or stubbed, not working).
[docs/CLAIMS.md](docs/CLAIMS.md) is the claim-by-claim account; the [README](README.md) carries the status history.

The repository holds two layers. Keep them apart while reading:

1. **The organism (RAN on one Linux pilot).** A Genesis agent runtime ("Auma") whose plugins are admitted only as an
   owner-approved set, whose hands are inside an NVIDIA OpenShell sandbox, and which cannot change its own system
   except by proposing to a boundary gate that only the owner can approve, from a desktop app on the owner's Mac.
2. **Prime NEXT packages (SOURCE).** `packages/authority`, `memory`, `execution`, `inference`, `runtime-bridge`,
   `contracts`, `ui`, `ops`: a stricter authority path under construction. `./prime verify` runs their 66-job source
   profile. They are not what runs on the pilot. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## The organism on one page

```
 owner's Mac                                   Linux pilot (one host, separate Linux users)
 ───────────                                   ────────────────────────────────────────────────────────────────
 AUKORA desktop app  ── SSH tunnel ──►  Genesis runtime "Auma"  (user aukora-host, loopback :18735)
 (apps/aukora-desktop)                    │  plugins admitted by the composition gate (owner-approved plugin set)
   owner card:                            │  every tool call judged by the action gate
   gate facts first,                      │  bash ──► sbx-exec (root wrapper, one sudo rule) ──► OpenShell sandbox
   model text fenced,                     │                                                    (user auma, /sandbox)
   one-click Approve                      │  proposes changes (cannot approve)
        ▲                                 ▼
        └──── owner.sock ◄──── BOUNDARY GATE (user aukora-gate) ◄──── propose.sock
                               signed hash-chained ledger · owner-only targets · signed receipts
                               signs plugin-set approvals ─► /etc/aukora-approvals (root) ─► launcher
                                                                    release floor ─┘   (systemd ExecStartPre)
```

## Components

| Component | What it does | Code | Covered by | Status |
| --- | --- | --- | --- | --- |
| Genesis runtime | Runs Auma's sessions on the pinned DeepSeek Harness (DSH). A release is materialized in place and launched by `launch-dsh.py --foreground`, which refuses any waiver flag | `scripts/launch-dsh.py`, `scripts/materialize-aukora-release.py`, `upstream-dsh.json` (the pinned DSH archive, extracted to `vendor/dsh` at build) | `tests/aukora-plugin-set-trusted-verifier.test.mjs` (service unit and launcher refusal) | **RAN** (pilot, systemd) |
| Composition gate | Records every AUKORA plugin's file digests as one plugin set; admits the set at import only with an owner approval bound to this release and record; at-rest sweep at boot | `plugins/aukora-composition-gate` | `tests/aukora-plugin-set-gate-signer.test.mjs` | **RAN** |
| Boundary gate | A separate Linux user owns the targets. The agent proposes exact bytes on the propose socket; only the owner socket can approve, through one review-then-decide ceremony. Every event is an Ed25519-signed, hash-chained SQLite ledger entry; applies return signed receipts. Targets: Auma's theme, and the plugin-set approval (operator-raised only) | `packages/boundary-gate` | `packages/boundary-gate/checks/*.mjs` (52), `tests/aukora-owner-card-*.test.mjs` | **RAN** (pilot) |
| Signed-enforcement launch + release floor | The runtime starts only if the exact recorded plugin set is owner-approved and bound to this release and record, and that approval is not older than the newest one ever installed (rollback = a fresh owner card labelled ROLLBACK). Root tools read a candidate release as data and never import it | `packages/boundary-gate/src/plugin-set-canon.mjs`, `src/release-floor.mjs`, `bin/plugin-set-approval.mjs`, `bin/release-floor.mjs`, `host/systemd/aukora-genesis.service` | `tests/aukora-plugin-set-trusted-verifier.test.mjs` | **RAN** (pilot; a downgrade was refused live) |
| Boundary self-check | Before every runtime start and every 15 minutes: every forbidden action must be refused and the sandbox egress probe must pass, recorded in the gate ledger, or the runtime stays down | `packages/boundary-gate/bin/selfcheck.mjs`, `host/systemd/` | `packages/boundary-gate/checks/selfcheck-bin.mjs` | **RAN** |
| Action gate | Judges every tool call by every session with the vendored seed guard; authority actions go to the owner route; a guard can deny, never force-allow | `plugins/aukora-action-gate`, `vendor/seed`, `vendor/authority` | `plugins/aukora-action-gate/check.mjs` | **RAN** (mounted) |
| OpenShell confinement | Auma's one-shot bash runs inside the NVIDIA OpenShell sandbox (`/sandbox`, host user `auma` under rootless Podman) through the root-owned `sbx-exec` wrapper | `plugins/aukora-openshell-confinement`, `packages/boundary-gate/host/` | `tests/aukora-openshell-confinement.test.mjs` | **RAN** one-shot bash; background bash, `run_code` and terminals **NOT YET** (refused) |
| Desktop owner app | Electron app on the owner's Mac. Shows the gate's own facts first and the model's words last inside a MODEL-AUTHORED fence; one click approves. The bridge refuses an approve the gate review did not make available | `apps/aukora-desktop` (`aumlok-approval.html`, `aumlok-bridge.mjs`, `aumlok-signer-airlock.mjs`) | `tests/aukora-owner-card-model-fence.test.mjs`, `tests/aukora-owner-card-no-friction.test.mjs` | **RAN** (owner's Mac) |
| Aumlok | Identity and control: which AUKORA subject this is and whether it is still the pinned one; owner approval signing through the Airlock account on the Mac | `plugins/aukora-aumlok`, `plugins/aukora-owner-daemon` | `tests/aukora-airlock.test.mjs`, `tests/aukora-aumlok-verify.test.mjs` | **RAN** partly; the root key resists an offline guess: **NOT YET** |
| Kira | Memory: Remembered notes (labelled unreviewed) and Signed proposals; recall and forget | `plugins/aukora-kira` | `tests/kira-*.test.mjs` | **RAN** (mounted) |
| Aura observation lane | Makes the composition gate's transition log judgeable by the pinned append-only court, with countersigned witness envelopes | `scripts/aura/` (`adapter.py`, `witness.py`, `verify-append-only.mjs`), `vendor/append-only` | `tests/aukora-witness-commits.test.mjs` | **SOURCE**, with recorded runs |
| Aura gate collector → Nostr records | Reads the boundary gate's signed ledger, verifies every entry against the pinned gate key, and emits NIP-01-signed, Nostr-shaped records (kinds 8930–8934) with NIP-44-encrypted private content; a cold verifier rechecks the whole chain | `scripts/aura/collect-gate.mjs`, `gate-snapshot.mjs`, `verify-collected.mjs`, `plugins/aukora-nostr/lib/records.mjs` | `scripts/aura/checks/collector.mjs`, `plugins/aukora-nostr/checks/records.mjs` | **SOURCE** (synthetic keys); installed collector and Kira recall of these records **NOT YET** |
| PQ hybrid signatures | The membrane's ML-DSA-65 + Ed25519 receipt signature (both must verify) and an experimental ML-KEM hybrid key wrap, on the vendored Noble libraries; grants no authority | `labs/pq-hybrid` | `labs/pq-hybrid/checks/hybrid.mjs` | **SOURCE** |

## Three flows, end to end

1. **Auma changes something she may only propose (her theme).** Auma calls `aukora_gate_propose` → the gate validates
   the exact bytes against the target schema and base hash and records `propose` → the owner's app receives the
   pending question over `owner.sock` → the card shows the gate-computed from→to, then the model's note fenced →
   one click → `review` + `decide_review` → the gate writes the bytes from its own version store, signs a receipt,
   appends `decide` and `apply`. Auma's own socket has no approve operation (`packages/boundary-gate/src/gate.mjs`).
2. **A new release goes live.** Materialize → `plugin-set-approval.mjs raise` (owner channel only; agents cannot raise
   it) → the card states whether the plugin set is unchanged since the previous approval → one click → `install`
   writes the gate-signed approval into a root-owned approval root and moves the release floor → `release.env` →
   restart: self-check, floor check, launcher, composition gate admits the set. Procedure:
   [`packages/boundary-gate/host/systemd/README.md`](packages/boundary-gate/host/systemd/README.md).
3. **Auma runs a command.** The action gate judges the call → the OpenShell adapter accepts only one-shot
   `workspace-write` bash in `/sandbox` → `sbx-exec` runs it in the sandbox as `auma` → output returns. Paths under
   the gate's and approvals' directories are refused before bash runs.

## Not mounted, fixtures, history

Present in the tree but not part of the live organism: `plugins/aukora-gate-demo` (a one-file fixture for the
composition gate's governed-grant lane), `plugins/aukora-box`, `plugins/aukora-organism`,
`plugins/aukora-subscription-hands`, `plugins/aukora-nostr` (a library, used by the collector),
`labs/deepseek-harness-boundary` (the lab the boundary gate was distilled from), `labs/laya-screen`.
Historical reports live in `docs/` with their dates; [ARCHIVE.md](ARCHIVE.md) lists retired material.

## What this does not claim

Not containment of a hostile agent on the Mac, not independent verification (all verifiers are this project's code),
not that only approved code runs (bare dependencies, the gate bootstrap and workers are outside the plugin set), and
not human attendance or comprehension at an approval. [docs/CLAIMS.md](docs/CLAIMS.md#not-claimed) names each.
