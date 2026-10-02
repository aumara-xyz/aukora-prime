# Working in AUKORA Prime

For repository reviews, [SHARE.md](SHARE.md) offers a suggested checklist. Follow the reviewer’s request and your governing instructions. Record the received revision and report the configured `./prime verify` result and exclusions. A prior checkpoint’s PASS is not a current runtime claim.

Read [the status table and known gaps](README.md) and [the Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) before changing an implementation claim.

- Keep proposing software separate from the authority that permits an effect. Bind review, authorization, dispatch and receipt to the same operation bytes.
- Report evidence as RAN, SOURCE-ONLY or UNPERFORMED, with the command and its limits. Synthetic signers, fixtures and mock providers do not establish real owner enrollment or runtime containment.
- Run the scoped checks relevant to a change. Preserve a focused regression for a repaired defect; report failures and skipped dependencies plainly.
- Update the README and paper when a claimed capability or known gap changes. During P0, prioritize repairs, verification and documentation.
- Preserve pinned dependency provenance and third-party copyright and license notices. First-party declarations currently use `AGPL-3.0-or-later`.
- Keep secrets, private conversation or voice data, account paths and infrastructure identifiers out of tracked files and release evidence. Use synthetic data for checks.
- A source change, build, fixture or composed release does not qualify an installed system. Runtime qualification needs evidence from the actual configured path.
- Keep disabled joins and Proposed directions visible. In particular, retained-memory restore, the separated private phase adapter and OpenShell runtime qualification cannot be inferred from same-process fixtures or Cordis lifecycle disposal.

[Architecture and build instructions](docs/ARCHITECTURE.md) · [Licenses](licenses/README.md) · [Vulnerability reporting](SECURITY.md)
