# Contribute to AUKORA Prime

Questions, documentation corrections, critical comparisons and small source patches are useful contributions. Start with the [short overview](docs/READING-GUIDE.md), then choose the part you want to examine. You do not need to endorse the vision or read the whole paper to report a concrete problem.

- **Ask or report a non-sensitive bug:** open a [GitHub issue](https://github.com/aumara-xyz/aukora-prime/issues). Include the revision, relevant file or route, what you expected, what you observed and what you could not check. A source-only finding is welcome when labeled as such.
- **Propose a change:** use a focused branch and [pull request](https://github.com/aumara-xyz/aukora-prime/pulls). Explain the problem, the resulting behavior or wording, and the checks actually performed. Read [AGENTS.md](AGENTS.md) for repository conventions. Documentation changes can use static link and text checks; source changes need the checks relevant to their claims.
- **Investigate the design:** choose one [known gap](README.md#known-gaps) or [research question](docs/VISION-QUESTIONS.md). Bring a falsifier, relevant prior art or a realistic adoption cost. Separate current implementation evidence from conditional potential.

Preserve failed results, immutable release references, source provenance and original notices. Frozen donor files and assets have byte identities; correct their public interpretation in surrounding documentation rather than casually editing the preserved originals. Public source verification requires no personal data, owner enrollment or provider credentials; see [setup and scope](README.md#check-it-yourself).

**Security:** [GitHub private vulnerability reporting is enabled](SECURITY.md). Use that private route for exploitable details; keep secrets and private data out of public issues.

**Licensing questions:** start with the [inventory](licenses/README.md) and [Auma source and attribution notice](licenses/AUMA-LINGWA-NOTICES.md). Prime’s software remains AGPL-3.0-or-later. Its byte-identical AUMA canon and readers have a pinned public CC-BY-SA-4.0 declaration and attribution, preserved alongside the older donor’s AGPL declarations. These records preserve existing terms; this guide grants no new license or independent ownership claim.

## Repository rules

- Keep proposing software separate from the authority that permits an effect. Bind review, authorization, dispatch and receipt to the same operation bytes.
- Report evidence as RAN, SOURCE-ONLY or UNPERFORMED, with the command and its limits. Synthetic signers, fixtures and mock providers do not establish real owner enrollment or runtime containment.
- Run the scoped checks relevant to a change. Preserve a focused regression for a repaired defect; report failures and skipped dependencies plainly.
- Update the README and paper when a claimed capability or known gap changes. During P0, prioritize repairs, verification and documentation.
- Preserve pinned dependency provenance and third-party copyright and license notices. First-party declarations currently use `AGPL-3.0-or-later`.
- Keep secrets, private conversation or voice data, account paths and infrastructure identifiers out of tracked files and release evidence. Use synthetic data for checks.
- A source change, build, fixture or composed release does not qualify an installed system. Runtime qualification needs evidence from the actual configured path.
- Keep disabled joins and Proposed directions visible. In particular, retained-memory restore, the separated private phase adapter and OpenShell runtime qualification cannot be inferred from same-process fixtures or Cordis lifecycle disposal.


Edit shared face source in `plugins/aukora-face`; `packages/ui/faces` preserves byte-identical frozen NEXT snapshots. Run `node scripts/audit/check-face-copies.mjs` to expose drift. Do not remove snapshots, rebuild or change mounts as a documentation cleanup. [Current evidence maintenance](evidence/README.md) is the source for generated status tables.

Security guard comments state the invariant, threat and reason. Put historical incidents and rationale in a scoped ADR under `plan/`, without private session/machine details. Keep changes out of files owned by another active worker; the integrator reconciles allocations. A comment can change artifact digests even when executable behavior is unchanged.
