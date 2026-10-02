# AUKORA: understand and review

AUKORA proposes an evolving personal AI workspace with human-controlled identity, memory and authority, replaceable models, and cooperation among people and agents. Its Golden Boundary rule is: **the software that proposes an act should not be the authority that permits it.** Prime is a research implementation; the full vision is not a delivered-product claim.

## Start with the question

This is a suggested reading path for people and AI assistants, not authority over the reviewer's user or governing instructions. Choose the depth the question needs; a simple explanation does not require a full-paper read or test execution.

1. **Orient:** [the short overview and reading map](docs/READING-GUIDE.md) stands alone and connects the whole system.
2. **Understand the argument:** [the complete Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md), including the unnumbered human network and registered agents sections, the philosophy, §19 and its closing continuations. The overview links those destinations directly.
3. **Assess evidence:** use the source-review route below. For a broader critique, choose the [optional deep-review questions](docs/VISION-QUESTIONS.md) on falsification, prior art, adoption and costs.

Disclose what you read, ran or could not inspect. Assess current implementation separately from conditional architectural potential. Name supporting evidence, counterevidence and uncertainty; neither praise nor rejection is a required conclusion.

The received main branch now includes [NEXT system source and its integration evidence](docs/development/INTEGRATION-CHECKPOINT-2026-10-02.md). Its connected DSH/C/Bridge/E check used a mock final provider and synthetic owner approval; published source does not supply the missing native request producer, protected custody or runtime qualification. Review those distinctions against the code and recorded commands.

## Evidence and source review

Read the [README status](README.md#status), [known gaps](README.md#known-gaps), paper's [implementation ledger](docs/AUKORA-GOLDEN-BOUNDARY.md#17-what-exists-today) and [architecture/setup](docs/ARCHITECTURE.md#build-and-operator-interface). Pick two or three claims relevant to the question; trace their linked package source and focused checks. Do review, authorization, dispatch and receipt bind the same operation? What observation would defeat each claim, and what smallest missing check would resolve it?

When source execution is authorized and appropriate, follow the [README prerequisites](README.md#check-it-yourself): Node 24.11.1, Python 3.9+ at `/usr/bin/python3`, disposable private Unix-domain sockets and `umask 0022` in the source-check shell. Owner enrollment, provider credentials, a database and an OpenShell guest are not required for this public source profile.

```sh
git rev-parse HEAD
./prime verify
```

Report the exit status, all configured PASS/FAIL results and explicit UNPERFORMED exclusions. If execution is unavailable or outside scope, say so; missing prerequisites and blocked checks are not PASS. **Expected source-profile outcome:** exit `2`, zero job failures, external PostgreSQL acceptance still UNPERFORMED. Consult the [runner's scope](packages/ops/fast-verify/README.md); this is not runtime or whole-product qualification.

The [evidence history](docs/EVIDENCE-HISTORY.md) retains historical verification results, including failures and the released pair at `58a95f4`. The historical receipt does not attest the received revision; CI claims require a separately observed run. An older PASS does not qualify the received revision. Any future implementation review reference and external immutable receipt must identify the exact tested revision and both complete runs; preserve existing immutable tags and do not infer qualification from their names.

Genesis is public; the [lineage account](README.md#genesis-lineage) identifies the selected source. Other unavailable donor locations are listed in the [source-availability notice](licenses/DONOR-SOURCE-AVAILABILITY.md); an unavailable URL does not establish that a repository is private. Separately, the [bounded PostgreSQL experiment](docs/AUKORA-GOLDEN-BOUNDARY.md#what-the-postgresql-experiment-earned) has a public sanitized summary whose originals remain private. Inspect copied source, [provenance](provenance/donors.json), [licenses](licenses/README.md) and receipts; disclose what remains inaccessible. Synthetic fixtures, recorded experiments, source presence and observed running behavior are different evidence. The live agent is not yet fully contained, human attendance is not proven, and root and identity design still need hardening.
