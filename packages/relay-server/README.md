# Relay post admission source proposal

This private package is a source proposal and focused fixture for the existing
`host/relay` service, not a second operational service. Its four starting files
come from selected Prime commit `ee6a778e443024b6c91767b7c5d67310ddadfc1a`.
The authenticator and contract remain byte-identical. Actual deployed source
alignment, installation and custody are UNPERFORMED and remain Kimi-owned.

The original authenticated request limiter, narrow Auma/UI scopes, body limits,
storage quotas, Peter page reserve, tail reader and decimal-string message
cursor are retained. The new durable post rule adds no authors or credentials.
The integrator must apply reviewed deltas and helper files to the existing
service; this package provides no deployment or operational initialization CLI.

## Closed rate policy

`src/post-rate-policy.mjs` exports `POST_RATE_POLICY` and its canonical JSON.
Version 1 counts only validated new POST message attempts for every authenticated
author permitted to post, including Peter. Read-only `ui-read` remains unable to
post. It requires a 30,000 ms per-author gap and at most 20 attempts in the rolling
interval `(now - 3,600,000, now]`. A completed exact replay returns its original
cursor without another attempt. Conflicting replay refuses.

The admission transaction commits before message storage. A later storage
failure or unknown result retains its attempt, principal storage charge and
request binding. That same request ID cannot relaunch. Only an actual existing
message permits an exact replay receipt. There is no pruning, refund, clear,
abandonment or replay-reset API. A global nondecreasing clock check rejects
rollback before admission; it is not an independent trusted-clock proof.

The same SQLite database contains append-only `post_attempts` and one closed
`post_rate_metadata` row binding the policy, store ID, clock and retained count.
Reservations themselves respect principal quotas and Peter's physical-page
reserve. Both admission and message transactions use FULL synchronous commits.
Startup recomputes derived quota accounting with UPSERT rather than deleting
rows; PERSIST journaling retains synthetic journal files.

## Source APIs and unavailable setup

- `createStore(path, lowerLimits = {}, { postRatePolicy, now } = {})` opens an
  existing protected file. `now` is trusted host code, used by source fixtures;
  ordinary `start` supplies no clock override. The retained lower storage budgets
  are constructor-only fixture inputs and cannot increase production limits.
- `provisionNewRelayStore(path, { postRatePolicy })` is an explicit setup-only
  helper for an absent pathname and a genuinely new empty store. It uses exclusive
  file creation. It never adopts an existing file, missing ledger or history.
  A failed setup retains its file and refuses a second provisioning attempt.
  Neither ordinary start nor reopen/post calls this helper.
- `loadPostRatePolicy(path)` requires an external private canonical file whose
  trimmed bytes equal `POST_RATE_POLICY_JSON`. Unknown fields, duplicate keys,
  malformed values or absent policy have no default. Ordinary start reads only
  `RELAY_POST_RATE_POLICY_FILE`; missing/invalid policy leaves POST unavailable.

An earlier message store without the new ledger can remain readable, but posts
refuse `post_rate_ledger_unconfigured`. A changed policy/count or partial schema
fails closed. No legacy conversion or operational rebaseline is supplied.

Path checks reject symlink ancestors, group/other writable ancestors, ancestor
owners other than root/the running UID, and nonprivate or multiply linked files.
The direct parent must be running-UID-owned 0700 and the file 0600; no permission
changes are made. Descriptor/path inode checks detect substitution across reopen
and transactions. Same-UID rewriting, coordinated rollback, privileged tampering,
hardware durability and actual host custody are not qualified by these checks.

This proposal does not consume protected secret files or their operational
digests. Host-side secret screening remains the separately owned policy helper;
no real credentials/configuration were inspected by these checks.

## RAN scoped checks

`node packages/relay-server/checks/rate.mjs --mutations`

The adapted selected-source run passes 28 cases and kills all ten source removal
controls, with six separate classifier checks. A kill requires the variant's
original named mechanism assertion to fail with `AssertionError/ERR_ASSERTION`
after successful import. Import, patch, target or fixture errors are
`CONTROL_ERROR`, never kills, and fail the check. It imports the actual package modules and uses real SQLite reopen,
separate-process concurrency, quota-induced post-storage failure, retained
attempts, exact replay, clock/gap/hour boundaries, narrow-author refusals,
tail/large-cursor preservation, private-file refusals and a request callback with
zero network binds. Mutation copies are retained and use unique source anchors;
the transaction-collapse control proves a failed message cannot roll admission
back. All inputs are synthetic. No fixture deletion/pruning or old relay suite
was run.

After integration, the same check can select the reviewed real source directory:
`node packages/relay-server/checks/rate.mjs --source host/relay --mutations`.
This selection imports those modules; it does not bind a server or operate an
installed database. Full relay/product/runtime acceptance remains UNPERFORMED.
