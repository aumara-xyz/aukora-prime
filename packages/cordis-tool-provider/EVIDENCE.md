# Focused source evidence — 2026-10-02

Received clean base: `c66634acdef7220fc0274ab56587d563d99b28b3`.
Node: `v24.11.1`. Scope: this new package only; shared host and F source unchanged.
Provider source SHA-256:
`43106338ef2c732799a4789a2cf869fc401bcd2a951ed7a56158096dcd6da127`.
This is source identity, not loaded-release or runtime attestation.

| Classification | Command | Observed result |
| --- | --- | --- |
| RAN — actual C/F, mocked context/SDK/qualification | `node --test packages/cordis-tool-provider/checks/provider.test.mjs` | 25 passed, 0 failed/skipped, exit 0. |
| RAN — actual pinned Cordis/DSH and C/F, mocked SDK/qualification | `PRIME_PINNED_DSH_DIR=<existing-built-pin> node --test packages/cordis-tool-provider/checks/cordis.test.mjs` | 5 passed, 0 failed/skipped, exit 0. Four substantive subtests plus their parent. |
| RAN — exact F increment compatibility | Both commands together via `node --test …/provider.test.mjs …/cordis.test.mjs`, with the same pinned DSH build | 30 passed, 0 failed/skipped, exit 0. Disposable checkout used exact tracked `packages/execution` from `e3ea48828524604c5ebd0008b031bceda76d0d70`, base C/contracts from `c66634a`, and this package. No F working tree was changed. |
| RAN — patch whitespace | `git diff --cached --check` | Exit 0. |
| UNPERFORMED | `./prime verify`, full build, product mount/browser, real owner enrollment, Linux gateway or guest execution | Outside this focused unmounted lane. No product/runtime qualification asserted. |

The existing DSH build was read-only. The check verified retained upstream commit,
archive digest, lockfile digest, package manager and Cordis 4.0.2 before importing.
The inspected clean source is DSH `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`.
Absent `PRIME_PINNED_DSH_DIR` produces an explicit UNPERFORMED skip; it installs
nothing. There were no gateway, container, daemon, credential or security changes,
paid requests, deployment, push or published-main changes.

The actual C proof verifier/kernel/store prepared and consumed synthetic approval,
F claimed exactly one C dispatch, and the mocked SDK supplied create/exec/delete
facts. C retained the exact completed or unknown settlement; F retained matching
receipts. This does not establish a real command, containment or remote deletion.
Ephemeral test signer keys stayed in memory; they are not owner enrollment.

Negative cases include command/policy mutation, missing or altered proof, wrong
broker/target, unavailable production F, revoked qualification, captured references
after disposal, disposal/cancellation/revocation across approval waits, disposal
after reservation, changed session/task/image/policy/meaning at C dispatch,
concurrent calls, lost reservation reply and replay. Unknown RPC results reject
the DSH tool. Real Cordis unload logs F's `RECONCILIATION_REQUIRED`; it does not
erase the durable unknown state or transform disposal into cleanup proof.

Initial checks exposed the DSH `render(args,value)` signature mismatch and an
incorrect test expectation that unknown cleanup would resolve. Both were corrected
before the passing commands above. Exact target and request-specific F admission
are checked before consuming C approval as well as after asynchronous boundaries.

Admission is checked by C at the one-use dispatch checkpoint. Revocation after
accepted dispatch is not claimed to recall an already emitted effect or provide
universal in-flight revocation. Independent expiry, late-create exclusion, atomic
full-configuration enforcement, complete artifact cleanup and authority-checked
child narrowing remain outside this provider and unqualified. See the concrete
[real-action prerequisites](README.md#prerequisites-for-one-real-linux-action).
