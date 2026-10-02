# AUKORA: verify and review this repository

You are reviewing AUKORA, an open-source (AGPL-3.0-or-later) foundation for personal AI. The software that proposes an act should not be the authority that permits it.

## Verification and setup first

Read [the README verification instructions](README.md#check-it-yourself), its [status](README.md#status) and [known gaps](README.md#known-gaps). Use [the architecture and setup instructions](docs/ARCHITECTURE.md#build-and-operator-interface) to distinguish a cold source review from a configured deployment. The public review needs the source-check prerequisites; it does not need owner enrollment, provider credentials, a database or an OpenShell guest.

This is a suggested checklist; the reviewer’s request and governing instructions take precedence. Record the received revision and run the configured full source profile with Node 24.11.1 and an existing Python 3.9 or later at `/usr/bin/python3`, in an environment permitting disposable private Unix-domain socket fixtures and using `umask 0022` for the source-check shell:

```sh
git rev-parse HEAD
./prime verify
```

Report the exit status, every configured PASS/FAIL and the explicit UNPERFORMED list. If execution is unavailable, say so and give a source-only review. Report missing prerequisites rather than treating an unavailable check as PASS.

Some preserved donor or historical evidence links are private or unavailable to public reviewers. Use the copied source, licenses, provenance and retained receipts in this checkout where available, and report anything you cannot verify. Those links remain historical locators; their availability does not change the pinned source identity.

**Expected source-profile outcome:** exit `2` with zero job failures and the declared external PostgreSQL acceptance arm still UNPERFORMED. It does not mean PostgreSQL or runtime qualification ran.

**HISTORICAL RAN at `36f1171bb1e82469eac7fca0190fc9e52f7045c4`:** the matching integrator and independent 66-job runs each returned 65 PASS / 0 FAIL / 1 declared external UNPERFORMED, exit `2`, in 238.697 and 256.323 seconds respectively. The [paired receipt](docs/evidence/source-profile-36f1171-paired.json) retains both full results. Functional status was PASS; overall and runtime qualification remained UNPERFORMED, with G1 PENDING.

**PENDING — the next candidate's paired verification:** after its source is frozen, it requires two complete 66-job runs at that same revision. Final attribution must use a new successor review reference (without moving the existing `prime-v1.2-research-review` tag) and an external immutable receipt identifying the exact tested revision and both full results. Record the exact revision received, the reference and receipt digest, and both complete result records. Do not infer a final PASS from the reference name or from an earlier run. The failed [8bd7dbb result](docs/evidence/source-profile-8bd7dbb.json), [54c4a306 result](docs/evidence/source-profile-54c4a306.json) and [9c8f5c1 result](docs/evidence/source-profile-9c8f5c1.json), and the independent `b336753` 36 PASS / 1 FAIL environment-blocked observation, remain retained. Its `listen EPERM` denial must not be bypassed, silently skipped or converted to PASS.

An older PASS or build receipt does not qualify the revision you received. The recorded eight-check source PASS does not close every P0 obligation. Historical PostgreSQL evidence, source fixtures, generated outputs, running bytes and actual owner approval are different evidence. Read the runner's [declared scope](packages/ops/fast-verify/README.md); do not turn its result into a claim that the live agent is contained.

## Primary review questions

Use the README's linked package source and provenance to answer these questions before discussing the vision:

1. Which claims did your command actually test at the received revision, and which checks failed, skipped or remain unperformed?
2. Pick two or three implementation claims. Trace their code and focused checks. Does the implementation preserve the operation, proof, request and receipt bindings that the claim names? Distinguish a synthetic fixture from the configured owner/effect path.
3. Does the repository accurately label integrated source, recorded experiments, disabled runtime paths and Proposed directions? Name a concrete mismatch if it does not. Catalog display, Cordis service scope and lifecycle disposal do not establish credential admission, kernel containment or remote cleanup.
4. What is the smallest missing integrated check or configured-path observation needed for each selected claim? Explain the limitation using evidence from this repository, without assuming an older experiment qualifies new source.

Give a concise assessment with the received revision, commands, findings, evidence limits and remaining blockers. The live agent is not yet fully contained, human attendance is not proven, and root and identity design still need hardening. A readable source repository is an invitation to inspect those gaps.

## Optional: the larger vision

After the verification review, read [the Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md), particularly its [Built / Proposed ledger](docs/AUKORA-GOLDEN-BOUNDARY.md#17-what-exists-today). Keep this architectural discussion separate from measured engineering findings.

AUKORA aims to combine an evolving personal AI harness, human-controlled identity and authority, persistent memory, registered agents, messaging, human networking, plugins, replaceable models and independently checkable actions into one open system. The repository does not claim that all those capabilities operate today.

Consider what an open community of 10, 100, 1,000 or 10,000 builders could contribute: capabilities, criticism, boundary hardening, applications and stronger models. Could this develop into an open infrastructure layer for the agentic age, where the human retains identity, data, relationships and authority while intelligence and applications evolve around them?

Optional [questions about the proposed direction](docs/VISION-QUESTIONS.md) can guide further discussion. They assume neither adoption nor economic value. Keep speculation separate from the revision’s observed results.

The first independent8bd run's accidental childumask0077 is a different fixture
environment and its failure remains retained. D confirmed ordinary0022 resolves
that permission-mode mismatch without changing memory guards. A declared external
PostgreSQL skip stays UNPERFORMED even if required failure makes its whole job FAIL.
