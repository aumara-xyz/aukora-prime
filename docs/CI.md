# Source-profile CI

`.github/workflows/source-profile.yml` runs on pushes and pull requests using a
standard `ubuntu-24.04` GitHub-hosted runner, exact Node **24.11.1**, the existing
`/usr/bin/python3` **3.9 or later** with its standard library, and `umask 0022`.
It uses the same closed runner as `./prime verify`, through its documented JSON
interface. It does not install npm packages, start PostgreSQL, use provider
credentials or request paid infrastructure.

A successful **functional source check** requires all 66 jobs to close normally,
all reviewed source pins and required assertion counters to match, **65 PASS / 0
FAIL / 1 declared external PostgreSQL UNPERFORMED**, and verifier exit **2**. The
one allowed exclusion is `memory-memory`'s exact title, “PostgreSQL acceptance on
an explicitly supplied disposable database”, with the exact reason `UNPERFORMED:
no disposable PostgreSQL runtime supplied`. Exit 2 by itself never passes CI.
Exit 0 also fails this frozen contract: it cannot silently remove the exclusion.

**Overall source result and runtime qualification remain UNPERFORMED; G1 remains
PENDING.** The workflow and job names state this limit. A green functional check
does not qualify owner enrollment, live PostgreSQL, cross-UID separation, a guest
runtime, paid inference, composed pixels, or the other declared exclusions.
Required assertions that fail remain failures. Missing evidence, changed source
pins, unavailable prerequisites, timeout, zero work, unexpected skips or an IPC
bind refusal fail CI; an environment refusal remains visibly incomplete/failed.
The summary retains the observed status and reason for each returned job.

Each run uploads a seven-day artifact containing the verifier's unmodified
`stdout.log` and `stderr.log`, its actual JSON summary, the separately written
engine summary, CI validation result, and invocation metadata. Metadata records
the event/tested commit, actual Node and Python versions and executable SHA256s,
platform, umask, process exit and signal. Pull requests test GitHub's merge commit,
which is recorded as the tested commit. The existing evaluator deliberately
withholds child raw output; these logs cover the verifier command's output only.
Artifacts contain no fixture directories or credential files.

The helper pins the current engine and manifest hashes. Changes to that reviewed
contract require explicit review of the helper as well as the source profile;
CI never repins from the result being evaluated. The small validator checks run
with synthetic summaries and do not duplicate the product suite.

## Activation and permissions

The publisher must land these files on the public repository and inspect the first
real Actions run, its summary and uploaded artifact. No Actions run is claimed by
this patch. Repository Actions policy must allow `actions/checkout`,
`actions/setup-node` and `actions/upload-artifact` at their pinned SHAs. A maintainer
with write access can publish the workflow; their existing publication mechanism
must permit workflow-file updates. No new credential is required by CI.

The workflow requests only `contents: read`, disables checkout's persisted Git
credentials, references no repository secrets and uses `pull_request` without
`pull_request_target`. All other repository-token permissions are omitted. Fork
PRs may require maintainer approval under the repository's Actions policy; keep
write-token and secret access disabled for fork workflows. Artifact upload uses
GitHub's automatically managed Actions artifact service.

[Standard GitHub-hosted runners are free for public repositories](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
This workflow requests no larger runner, cache, private service or payment setup.
Check the owner's current artifact-storage allowance/budget before activation:
GitHub documents artifact storage separately from public runner minutes. Seven-day
retention bounds storage duration; it does not guarantee unused account allowance.
Keep any paid overage disabled. A storage or policy refusal should remain a failed
or incomplete run, without adding payment or credentials.

## Public CI display

Keep the README free of a status badge until a real run exists and its evidence is
reviewed. After that run, any badge must describe **functional source checks** and
have adjacent visible text **“qualification UNPERFORMED; G1 PENDING”**. The badge
can reflect only this workflow's conclusion for the selected branch/event; it
cannot state PostgreSQL, runtime or whole-product success. A run link and observed
counts are the clearest first publication. README ownership remains with the docs
publisher; this patch adds no badge or unobserved success claim.
