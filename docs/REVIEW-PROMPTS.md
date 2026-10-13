# Questions a repository review can answer

Choose the question your reviewer was asked; these are evidence entry points, not a required verdict or a replacement reading order. The [existing overview](READING-GUIDE.md) explains the vision and why it matters. Report the received revision, what you read and ran, failures, exclusions and what you could not inspect. Assess current implementation separately from conditional potential.

Run commands from the repository root under Node **24.11.1**, with the [README prerequisites](../README.md#check-it-yourself). The commands below are suggested checks, not results recorded by this page. Fixtures and temporary boots do not qualify an installed system.

## Five questions with inspectable evidence

1. **Where does the code separate a proposal from permission, and what would defeat that separation?** Read the [overview](READING-GUIDE.md), [paper's falsifiers](AUKORA-GOLDEN-BOUNDARY.md#18-what-would-make-the-claim-fail), [gate](../packages/boundary-gate/src/gate.mjs) and its [fixture](../packages/boundary-gate/checks/gate.mjs). Compare the checks with the [known gaps](../README.md#known-gaps); [Hard questions](HARD-QUESTIONS.md) is a historical Genesis account, not today's deployment report.

   ```sh
   node --test --test-reporter=tap packages/boundary-gate/checks/gate.mjs
   ```

   This tests selected exact-byte, replay, expiry and proposal-channel refusals with synthetic authority. It does not show every effect route is mediated or that a human understood approval. Compare the [threat model](THREAT-MODEL.md) when that parallel page lands. Socket or loopback `EPERM` is an environment block to report.

2. **Can this clone build and serve its carried interface without a model key?** Read the [clone-to-running procedure](../README.md#from-a-clone-to-a-running-system), [smoke-check script](../scripts/fresh-clone-check.sh), [CI workflow](../.github/workflows/checks.yml) and latest [dated plan entries](../plan/NORTH-STAR.md). Separate the temporary boot from the live pilot and NEXT layers in the [component map](../ARCHITECTURE.md) and [status](STATUS.md).

   ```sh
   ./scripts/fresh-clone-check.sh .
   ```

   The check needs build tools, the pinned package manager, network access and loopback listeners. Its throwaway same-user approval tests boot, authenticated routes, plugin loading and an action refusal; it sends no model request. It does not prove persistent installation, separate-user containment, memory or the private Buzz relay.

3. **What can a stranger verify about a supplied record, and what remains unknown?** Read the [historical L2 export and limits](evidence/l2-demo-2026-10-04/README.md), its [verifier](evidence/l2-demo-2026-10-04/verify.mjs), and the [minimal verifier's two arms](MINIMAL-VERIFIER.md).

   ```sh
   node docs/evidence/l2-demo-2026-10-04/verify.mjs
   node scripts/aura/verify-append-only.mjs --selftest
   ```

   The first checks signed receipt/ledger agreement under the published gate key for a fixed historical export. The second tests extension of synthetic retained logs. Neither proves today's completeness, independent key custody, event truth or human attendance; the append-only checker does not verify signatures.

4. **How does Kira recall a recorded note, and who chooses which project it belongs to?** Read [Kira's backend and project rules](../plugins/aukora-kira/README.md), [recall source](../plugins/aukora-kira/lib/recall-openviking.mjs), [project mapping](../plugins/aukora-kira/lib/project-mapping.mjs) and the latest [release-probe records](../plan/NORTH-STAR.md).

   ```sh
   node --test --test-reporter=tap tests/kira-openviking-recall.test.mjs tests/kira-project-mapping.test.mjs
   ```

   These use scratch stores, deterministic semantic scores and synthetic ancestor ownership to check source behavior. They do not benchmark real embeddings, qualify protected mapping custody or show Auma using recalled notes. The recorded real-OpenViking release probe is a separate, single-note result.

5. **Does Aura's three-source picture establish one complete signed history?** Read the [coverage audit](../ARCHITECTURE.md#aura-coverage-audit--2026-10-12), [snapshot reader](../plugins/aukora-face/settings/src/aura/snapshot-reader.ts), [snapshot framing](../plugins/aukora-face/settings/src/aura/snapshot.ts), [service join](../plugins/aukora-face/settings/src/index.ts) and [status](STATUS.md).

   ```sh
   node --test --test-reporter=tap tests/aura-snapshot.test.mjs tests/aura-snapshot-services.test.mjs
   ```

   Inspect which head is signed, how missing sources are represented and whether each head changes the snapshot; its code source is the release-record digest. A deterministic projection of gate, Kira and code heads does not sign the unsigned histories, establish independent observations or cover every action. Browser observations belong to their dated staging release.

## Three questions this repository cannot yet settle

- **Can a hostile agent never cross an owner's boundary through any route?** Full containment and complete mediation remain unqualified; the [retained failures and exceptions](../README.md#containment-baseline) are counterevidence to examine. Source fixtures cannot settle this deployment claim.
- **Was the approver a unique person who understood and freely chose the act?** A key signature and an owner-channel interaction do not establish identity, comprehension, attendance or freedom from coercion. See [identity](AUKORA-GOLDEN-BOUNDARY.md#5-identity-that-does-not-belong-to-an-application) and [care without control](CARE-WITHOUT-CONTROL.md).
- **Would a sovereign network remain useful, affordable, recoverable and easy to leave in ordinary life?** A temporary clone boot, staging demonstrations and source admission checks are not a deployed federation or adoption study. Use the [optional research questions](VISION-QUESTIONS.md) to name missing interoperability, recovery, privacy and maintenance evidence; no favorable or unfavorable conclusion is prescribed.
