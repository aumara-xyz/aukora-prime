# Host relay post policy

`lib/post-policy.mjs` implements a host-only screening closure. It is not an installed policy or a relay-server rate counter. A trusted host composition must supply the explicit protected-file inventory and bind the closure to `relay_post` before gate intent, rate reservation and send. No operational configuration, protected contents or operational digests are included here. Missing or malformed configuration refuses; it never means a passing screen.

Peter's delegated source implementation permits the explicit profile below. These source choices are not evidence that actual file custody, configuration or the production join has been accepted.

## Closed configuration

The configuration is a plain object, or a null-prototype object, with exactly the following data properties. Proxies, accessors, symbols and unknown fields refuse. Proxy objects and arrays are rejected before reflective property access invokes a trap. Dense arrays must have exactly `Array.prototype`; custom prototypes and subclasses refuse before inherited mapping/getter/species callbacks can execute.

| Field | Required value |
| --- | --- |
| `version` | `1` |
| `kind` | `aukora-relay-post-policy/v1` |
| `algorithm` | `sha256` |
| `domain` | `aukora-relay:protected-secret:v1` |
| `encoding` | `strict-utf8-no-bom/v1` |
| `normalization` | `literal-and-ecmascript-trim/v1` |
| `matching_unit` | `contiguous-utf8-byte-window/v1` |
| `refresh` | `per-post-stable-read/v1` |
| `reader_uid` | Positive safe integer equal to the current host process UID |
| `files` | Dense array of 1–16 explicit file descriptors |

Every file descriptor has exactly `category`, `path`, `owner_uid` and `selectors`:

- `category` is one of `credentials`, `auma-key`, `nostr-identity`, `launch-token`. All four categories must be present. Additional explicitly inventoried files may repeat a category.
- `path` is a distinct absolute normalized host-approved path containing well-formed Unicode and no NUL. No search, discovery, environment fallback or guest-provided path is performed.
- `owner_uid` is the approved file owner's nonnegative safe integer UID. It must match the actual file owner. This does not grant the reader access.
- `selectors` is a dense array of 1–8 distinct selectors. Each selector has exactly `kind` and `pointer`.

Selectors have two forms:

| `kind` | `pointer` | Selected input |
| --- | --- | --- |
| `whole-utf8` | Empty string | Entire decoded file text |
| `json-pointer` | At most 512 code units, begins with `/`, well-formed Unicode, only `~0`/`~1` escapes | Exact existing JSON member resolved by the pointer; it must be a well-formed string |

For JSON selectors, strict parsing rejects duplicate keys and enforces a 64 KiB input bound and depth 32. Missing members and nonstring selections refuse. Unselected JSON fields are not implicitly protected. The empty JSON-root pointer is not supported.

A schematic configuration uses `POST_POLICY_PROFILE` plus `reader_uid` and four descriptors. Values such as **HOST_APPROVED_PATH**, **APPROVED_FILE_OWNER_UID** and **EXPLICIT_SELECTOR** are placeholders to be supplied by the trusted host. They are not defaults, operational paths, usable configuration or approval to read a file. The model/tool argument contains only the post text; it cannot choose the policy, inventory, selector or UID.

## Decision and custody

`createProtectedPostPolicy(trustedInput)` snapshots the configuration and returns a frozen object containing only synchronous `assertAllowed(text)` and `forbiddenDigestCheck(text)`. Configuration mutations after construction cannot retarget the captured inventory. No contents, path list or digest exporter is returned.

Posts must be well-formed Unicode, nonblank and at most 2,000 UTF-8 bytes. C0 controls other than LF/TAB, and DEL, refuse. The pinned evidence secret catalogue is used directly. Additional refusal shapes cover long hexadecimal runs of at least 32 characters, private-key PEM headers and credential assignment/Bearer contexts. These shape checks may reject benign text with the same shape; they are not proof that every possible secret encoding is recognized.

For a post reaching digest screening, every explicit file is read afresh. Each selected string produces two projections: the literal text and its ECMAScript `trim()` result, deduplicated when equal. Each projection must be 1–2,000 UTF-8 bytes. The internal digest is SHA-256 over UTF-8 bytes of the fixed domain, one NUL byte, then the projected secret bytes. Every contiguous byte window in the original post with a protected projection's length is hashed under the same domain. Equality refuses, including a protected opaque value embedded in longer prose. No post normalization or rewriting is performed.

Files must be regular, non-symlink, single-link, match `owner_uid`, have no group/other permissions, and have no executable or set-ID/sticky bits. Files contain 1–65,536 bytes of strict UTF-8 without a BOM. Every ancestor must be a real directory owned by root or the reader UID with no group/other write bits. The reader is nonroot. Opening requires `O_NOFOLLOW`; identity and metadata are checked before open, against the opened descriptor, after reading, and again across all files and captured ancestors before the decision. Missing, unreadable, malformed, changed or unsupported inputs produce `UNAVAILABLE` rather than approval.

Temporary raw buffers are cleared on success and failure. JavaScript strings and internal hashes are not guaranteed to be physically erased. Neither the supplied files nor their permissions are created or changed by this helper. Error messages are closed generic strings: `relay post refused` (`REFUSED`) or `relay post policy unavailable` (`UNAVAILABLE`). Logs, tool results and evidence must not add matched values, operational digests or private file paths.

The final metadata pass detects changes observed during the read sequence; it does not make filesystem reads atomic or protect against a process with the same UID rewriting state after the decision. Host configuration and code must remain inaccessible to guests. Rotation, inventory authorization and installed custody are host/operator responsibilities. Arbitrarily encoded, transformed, split-across-post or unselected values are outside this digest profile. Catalogue transformations do not extend the digest normalization profile.

## Entry and counter joins

The entry source preserves D's gate-sequence return change and binds the actual helper to one captured post text value. It rejects Proxy, accessor, symbol and unknown argument fields before capture. The same immutable string is screened, hashed and sent; screening precedes the post's key access, limiter, gate intent and send. Policy failure returns directly with a generic reason and `error_code`, without invoking the key-reading scrubber. This source join does not establish an installed policy or accepted file custody.

The trusted plugin configuration slot is `postPolicy`. Its value must be exactly the factory configuration above: the fixed profile fields plus `reader_uid` and `files`, with their closed descriptor/selector grammar. It is not a tool argument, environment setting, default or discovery input. Factory construction validates and captures configuration without reading a protected file; only the per-post closure reads the explicit files. Missing `postPolicy` refuses `relay_post` before that post's key read, refusal scrub, limiter, gate or send, while preserving `relay_read`. This source configuration slot grants no provisioning, permission change or protected-file read authorization. H completed the authorized continuation in an isolated source branch; no operational configuration was supplied.

The relay server's authenticated per-author durable counter is separate. This package's helper does not select the server's limits, counted routes, replay semantics, persistent ledger or custody. Server author identity must be derived from authentication rather than a post field. Source screening checks do not qualify the server counter or live relay behavior.

## Scoped checks

Run with Node 24.11.1 or the separately approved compatible pinned Node:

```sh
node plugins/aukora-relay-auma/checks/post-policy.mjs --mutations
```

The check imports the actual helper. Protected inputs are wholly invented, created in a private fixture directory beneath the check's canonical source directory, and retained. No cleanup, permission modification, operational-file read, digest output or network call is performed. Creation-time modes exercise private, public, executable and unreadable fixtures without changing existing permissions.

The current focused result is 30 cases passed, zero failed, with 14 unique in-memory guard-removal controls killed. Controls change only the imported module source through Node's load hook; the original assertion remains unchanged. Only the check's dedicated mechanism-assertion class counts as a kill. Other errors, including syntax/import failures and unrelated fixture errors, are control errors. Coverage includes all categories, ordinary and embedded opaque values, JSON selection/trim, shapes, malformed policy, zero-trap proxy refusal, zero-callback custom-array refusal, configured-path grammar, caller mutation, per-post refresh, UTF-8 byte windows and bounds, missing/unreadable files, ownership/modes/links, closed errors and final ancestor revalidation. The final-ancestor case substitutes stale invented `lstat` metadata after the four real fixture reads/rechecks; it performs no filesystem race or directory replacement.

These are synthetic source checks. Actual inventory, protected-file custody, production entry binding, relay server counter and installed/runtime acceptance remain **UNPERFORMED**.

The combined entry check is `node plugins/aukora-relay-auma/checks/post-policy-join.mjs --mutations`: 15 groups pass and eight intended source-removal controls are detected by original assertions. `node --test tests/relay-post-gate-return.test.mjs` passes all 16 existing receipt cases against the actual signed gate/SQLite core, with the explicit invented policy supplied to the actual joined entry. The signed-gate fixture uses fresh retained state and creation-time modes; it binds no listener and touches no installed input. D's receipt assertions remain unchanged. The older network/chmod/cleanup relay suite is not run; only its fixture composition supplies the newly mandatory synthetic policy.
