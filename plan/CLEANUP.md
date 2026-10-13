# Repository cleanup inventory

Inventory date: 2026-10-13. Baseline: 42 root entries, 4,427 tracked files and
1,279,039 lines by `wc -l` over the tracked tree. The checkout was clean. Literal
reference counts below exclude the entry itself and its descendants; zero does not
mean unused, so release copy lists, pin inventories and indirect callers were checked
separately.

## A. Root surface

Risk is `low`, `medium` or `high`. Dependency says whether a release or check relies
on the entry. The action for every directory without a root-level README is to add a
short orientation file; it does not rename or reorganize the directory.

| Path | What it is; reference evidence | Proposed action | Risk | Release or test dependency |
| --- | --- | --- | --- | --- |
| `.github/` | CI workflows and templates; 21 external literal references | add README | low | CI |
| `.gitignore` | local/build exclusion policy; 18 references | leave | high | fresh-clone and materialization checks |
| `.gitleaksignore` | secret-scanner exceptions; no literal reference | leave: conventional tool input | high | security tooling |
| `AGENTS.md` | repository operating rules; 42 references | leave; owner-protected | high | contributor workflow |
| `ARCHITECTURE.md` | root architecture map; 28 references | leave; owner-protected | high | documentation links |
| `ARCHIVE.md` | archive/removal record; 14 references | leave at root: it explains missing former trees | medium | documentation and ignore policy |
| `CHANGELOG.md` | public change history; 2 references | leave | low | documentation |
| `CLAUDE.md` | agent rules and release-carried instructions; 6 references | leave; owner-protected | high | release strip/baseline checks |
| `CONTRIBUTING.md` | canonical repository rules; 4 references | leave | high | contributor workflow |
| `LICENSE` | AGPL license; 199 references | leave | high | licensing |
| `NOTICE` | attribution notices; 69 references | leave | high | licensing and releases |
| `PROVENANCE.md` | donor/source provenance index; 42 references | leave | high | provenance checks |
| `README.md` | owner-designed front door; 137 references | leave; owner-protected | high | public reading flow |
| `SECURITY-BOUNDARY.md` | concise boundary statement; 7 references | leave | high | security documentation |
| `SECURITY.md` | vulnerability-reporting policy; 11 references | leave | high | public security process |
| `SHARE.md` | owner-designed sharing routes; 8 references | leave; owner-protected | high | public reading flow |
| `apps/` | desktop application source; 254 references | add README | low | release/desktop tests |
| `docs/` | current documentation, evidence records and history; 161 references | add README | low | claims/evidence links |
| `evidence/` | generated current evidence and containment records; 96 references | leave: README exists | high | evidence pins |
| `harness/` | retained NEXT host and preview source; 67 references | add README | low | harness checks |
| `host/` | host installers, units and retained host components; 164 references | add README | low | installed-host paths |
| `labs/` | bounded experiments; 16 references | leave: README exists | medium | selected lab checks |
| `licenses/` | dependency notices and inventory; 63 references | leave: README exists | high | license checks |
| `ops/` | node and pilot operator procedures; 89 references | add README | low | operator checks |
| `overlays/` | composition patch declarations; 16 references | add README | low | release composition |
| `package.json` | Node engine and command registry; 227 references | leave | high | all Node checks |
| `packages/` | boundary, contracts, runtime and UI packages; 340 references | add README | low | releases and tests |
| `patches/` | pinned upstream harness patches; 21 references | leave: README exists and deletion forbidden | high | harness build |
| `plan/` | current plan, ADRs and historical plan archive; 21 references | add README | low | contributor workflow |
| `plugins/` | application plugins; 495 references | add README | low | releases and plugin tests |
| `presets/` | composed agent preset; 11 references | add README | low | release materializer |
| `prime` | top-level CLI; 686 references | leave at root: executable front door | high | build/boot/verify |
| `provenance/` | machine-readable donor and share-asset records; 25 references | add README | low | provenance checks |
| `research/` | retained research corpus; 36 references | leave: README exists | medium | source-only references |
| `runtime-dependencies/` | locked runtime-only dependency closures; 3 references | add README | low | PG materialization/license inventory |
| `scripts/` | build, audit, release and operator commands; 415 references | leave: README exists | high | releases and checks |
| `security-review` | security review runner; 22 references | leave at root: documented command | high | security checks |
| `security-review-containment` | containment review runner; 7 references | leave at root: documented command | high | containment checks |
| `tests/` | repository integration and regression tests; 196 references | add README | low | test runner |
| `tools/` | narrowly scoped operator tools; 27 references | add README | low | pilot/operator paths |
| `upstream-dsh.json` | pinned harness source and patch manifest; 78 references | leave | high | build, bootstrap and release checks |
| `vendor/` | pinned third-party and donor source; 384 references | add README; never delete contents | low | releases, pins and tests |

## B. Dated reports and session history

Use one location: `docs/archive/`. Each moved item gets one line in its index. History
linked by current claims, evidence, pin files or owner-protected reading pages stays put.

| Path | Evidence | Proposed action | Risk | Release or test dependency |
| --- | --- | --- | --- | --- |
| `docs/NEBIUS-WINDOW-REPORT-20260921.md` | closed 2026-09-21 compute-window report; only match is a historical URL in `plan/archive/MASTER-PLAN-v4.md`, not a local link | move to `docs/archive/` | low | none found |
| `docs/RECURSION-FULL-REPORT-20260921.md` | dated closed-session report; no inbound path or basename reference | move to `docs/archive/` | low | none found |
| `docs/labs/2026-10-03-skunkworks-boundary-lab-status.md` | dated lab status superseded by current claims; no inbound reference | move to `docs/archive/` | low | none found |
| `plan/MORNING-2026-10-13.md` | session note whose own opening says later portions are out of date; cited by `evidence/status.json` | leave in place | low | none found |
| `plan/HANDOFF-2026-10-12.md` | current working handoff linked by `AGENTS.md` | leave | high | contributor workflow |
| `docs/development/INTEGRATION-CHECKPOINT-2026-10-02.md` | linked by current README, claims, changelog, evidence and package docs | leave | high | evidence/current.json and public claims |
| `docs/development/NEXT-PREVIEW-HANDOFF.md` | linked by changelog, Golden Boundary, checkpoint and archived README | leave | high | current evidence narrative |

## C. Scripts with no literal full-path caller

The audit searched each path, basename and import-style spelling across all tracked
files, then checked `scripts/materialize-aukora-release.py`,
`scripts/artifacts-coverage.json`, `packages/ui/baseline-manifest.json`, `evidence/*.json`
and the gate bootstrap inventory. None is safe to delete in this pass.

| Path(s) | Evidence and dependency | Proposed action | Risk |
| --- | --- | --- | --- |
| `scripts/aura/approval-request-preview.mjs`, `settle-approved.mjs`, `settle-preflight.mjs`, `wire-binding.mjs` | no full-path caller; operator entries, with `wire-binding.mjs` reached by basename; all of `scripts/aura/` is copied into releases | leave: release-copied | high |
| `scripts/composition/grant-binding.mjs`, `hexutil.py`, `jcs.py`, `mediator.py`, `refusals.py` | imported or invoked by basename inside the composition package; all of `scripts/composition/` is copied into releases | leave: indirect consumers and release copy | high |
| `scripts/kira/backfill-memory.mjs`, `memory-pressure.mjs`, `secret-scan.mjs` | operator/migration commands; `memory-pressure.mjs` has a basename caller; all of `scripts/kira/` is copied into releases | leave: release-copied | high |
| `scripts/lib/goal-resume.mjs`, `machine-guard.sh`, `platform-tools.sh`, `verdict-grammar.mjs` | no full-path callers for these spellings, but the materializer copies all of `scripts/lib/` | leave: explicitly off limits | high |
| `scripts/aukora/guest-start.mjs` | future fail-closed guest entry and self-test; basename appears in `become.mjs` | leave pending guest migration decision | medium |
| `scripts/aukora/install-hooks.mjs` | manual idempotent hook installer; basename appears in shell policy | leave as operator command | medium |
| `scripts/aumlok/write-source-pins.py` | one-off reproducibility generator, no caller; header still names an obsolete `.scratch/x2/` invocation | leave until owner decides whether regeneration is supported | medium |
| `scripts/materialize-pg.mjs` | manual locked PG closure materializer; runtime dependency and license inventory rely on the closure | leave | medium |
| `scripts/owner/after-install.mjs` | documented post-install acceptance entry point; direct manual invocation | leave | high |
| `scripts/stage-cd-pg-fixture.py`, `scripts/stage-pg-acceptance.py` | paired check scripts and `check.sh` registration reach them by basename/convention | leave | high |

## D. Directories without orientation

Add 5–10 line `README.md` files to `.github/`, `apps/`, `docs/`, `harness/`,
`host/`, `ops/`, `overlays/`, `packages/`, `plan/`, `plugins/`, `presets/`,
`provenance/`, `runtime-dependencies/`, `tests/`, `tools/` and `vendor/`. Each says
what is present, what consumes it and how to check it. Risk is low because no existing
path moves; release dependency varies as recorded in section A.

## E. Naming, stale comments and duplicate concepts

| Path | Evidence | Proposed action | Risk / dependency |
| --- | --- | --- | --- |
| `scripts/genesis-check.mjs` and `/opt/aukora-genesis` strings | active launcher, gate bootstrap digest, checks and installed service paths use the old name | leave until a reviewed live-node migration moves every pin and installed path | high; bootstrap/release/live node |
| `packages/memory/genesis/` and `licenses/Genesis-NOTICE` | donor snapshot and its notice, not current branding | leave as history/provenance | high; pins and license record |
| `apps/aukora-desktop/` vs `packages/desktop/` | application runtime and packaging/native package are distinct and both referenced | leave; explain at directory roots | high; desktop build |
| `evidence/`, `docs/evidence/`, `research/evidence/` | current machine-readable evidence, dated documentation evidence and research evidence have different scopes | leave; explain through READMEs | medium; evidence links |
| `scripts/aumlok/write-source-pins.py` header | run line points at removed `.scratch/x2/` path and requires `/tmp/eff_pub.txt` | owner decision: repair supported regeneration or archive/delete generator | medium; generated safety pins |
| first-party TODO/XXX scan | apparent hits were `mktemp` templates, test fixtures or vendored Noble TODOs; no actionable first-party stale TODO found | leave vendored/pinned copies unchanged | high if altered |
| commented-out code scan | executable-looking blocks are in vendored Noble code or frozen face source | leave; they are upstream or pin-controlled | high; provenance/baselines |
| `.gitignore` | repeated `node_modules`, `dist`, `.DS_Store` rules are untidy but equivalent | leave this pass; cosmetic consolidation has no visitor value | low |

## F. Tracked files over 1 MiB

| Path | Evidence | Proposed action | Risk / dependency |
| --- | --- | --- | --- |
| `docs/assets/aukora-human-first.png` | 1,842,262 bytes; used by root README and pinned by `provenance/share-assets.json` | leave; optimization would move a provenance pin and owner-designed front-door asset | high |

## G. Generated-looking tracked files and ignore coverage

| Path(s) | Evidence | Proposed action | Risk / dependency |
| --- | --- | --- | --- |
| four `package-lock.json` files | deterministic dependency locks; desktop and PG locks are named by provenance/license inventories | leave tracked | high |
| `plugins/aukora-kira/lib/cage/quickjs/pkg/*/dist/*.mjs` | generated upstream distribution bytes, individually pinned in `plugins/aukora-kira/lib/cage/quickjs/PROVENANCE.json` | leave tracked | high; Kira cage |
| `.gitignore` coverage | clean checkout; `git status --ignored` shows only `vendor/dsh-source.tar.gz`, intentionally ignored and pinned by `upstream-dsh.json`; no generated-looking untracked gap | no change | low |

## Pass 2 result

Completed in this pass:

- Files removed: **0**. No script met the no-consumer, no-release-copy and no-pin test.
- Files moved: **4**, all into `docs/archive/`, with one-line index entries.
- Top-level directory READMEs added: **16**.
- `.gitignore` changes: **0**. The checkout exposed no unignored generated artifact.
- Root entries: **42 before, 42 after**.
- Project files intended for version control: **4,427 before, 4,444 after**. The Git
  index remains at 4,427 because this sandbox must leave the work unstaged and uncommitted.
- Repository lines: **1,279,039 before, 1,279,332 after**, counted over the same
  project-file set.

The archive group and README group each passed the required eight-command gate.
On both runs `./security-review` reported 19 PASS, 0 FAIL and 11 UNPERFORMED.
The UNPERFORMED rows are the profile's named runtime and external prerequisites,
not cleanup regressions. The final gate after this update reported the same counts.
The basename-driven test sweep passed three files; the pilot-switch mutation file's
13 socket-backed cases were unperformed because this sandbox refused its disposable
Unix socket binds with `EPERM`, while its two non-socket mutation cases passed.

## Remaining work, ordered by value

1. **Rename active `genesis` runtime and service paths only as a migration.** Not done:
   it needs an owner-approved live-node migration, coordinated launcher and bootstrap
   pin changes, release rebuilding and installed rollback evidence.
2. **Decide whether the source-pin generator remains supported.** Not done:
   `scripts/aumlok/write-source-pins.py` has a stale invocation and external scratch
   input, but deleting it would remove reproducibility while repairing it defines a
   new supported workflow; this needs an owner decision.
3. **Retire zero-literal-reference operator scripts individually.** Not done:
   the Aura, composition, Kira and scripts-lib candidates are copied into releases;
   other candidates are manual entry points, basename-driven helpers or migration
   tools. Each needs a consumer migration or an explicit owner decision, not bulk deletion.
4. **Archive the linked 2026-10-02 checkpoint and preview handoff only with a claims
   migration.** Not done: current README/claims/evidence or owner-protected reading
   pages link to them, so moving them now would require touching another worker's scope.
5. **Unify `apps/aukora-desktop` and `packages/desktop` naming only with a build
   migration.** Not done: they are distinct consumed surfaces and their paths are
   present in provenance, snapshots and tests.
6. **Consider recompressing `docs/assets/aukora-human-first.png`.** Not done: it is
   the only tracked file over 1 MiB, but it is an owner-designed front-door asset and
   its exact bytes are pinned in provenance.
7. **Keep generated-looking lockfiles and QuickJS distribution files.** No action:
   they are required locked or vendored inputs and are named by license/provenance
   inventories.
