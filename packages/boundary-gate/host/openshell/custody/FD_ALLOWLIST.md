# Launcher descriptor boundary

SPDX-License-Identifier: AGPL-3.0-or-later

The host entry `host/sbx-exec` uses Bash `-p` to ignore caller startup hooks and
exported functions, then starts the fixed descriptor helper with Python `-I -S`.
The preserved body also enters Bash with `-p`, including its existing direct
policy recheck invocation. The helper physically closes
every descriptor above 2 before executing
the preserved `sbx_exec_body.sh`. Caller arguments cannot select an executable,
add an allowed descriptor or skip closure. The preserved body also uses the
helper before ordinary and cancellation OpenShell dispatch. Query subprocesses
and streaming SSH explicitly use `close_fds=True, pass_fds=()`.

| Boundary | Allowed descriptors and reason |
| --- | --- |
| Host entry to preserved shell body | 0, 1, 2: deliberately wired input, output and diagnostics. |
| Host admission supervisor | The supervisor creates lock FD9 after entry closure and retains it until admission ends. It is not forwarded to OpenShell or SSH. |
| Host body to OpenShell or SSH | 0, 1, 2 only. The JSONL stream carries `run_code` control bytes; no host FD7 is required. |
| OpenShell runtime to workload image | 0, 1, 2: configured pipes or PTY slave. Inherited descriptors above 2 receive no exception. |
| Guest carrier to an admitted control workload | 0, 1, 2, plus FD7 only when the carrier creates a fresh duplex socketpair for that launch. Its existing startup-error writer is CLOEXEC and never reaches the executed workload. |

On Linux the host helper uses `close_range(3, UINT_MAX, 0)`, with no fallback
after a syscall failure. This includes descriptors beyond a lowered resource
limit. An unavailable libc entry or kernel syscall refuses execution. The
Darwin implementation exists for disposable local source fixtures and closes
enumerated descriptors in a fresh process. It does not qualify Linux behavior.

The upstream handoff patch targets NVIDIA OpenShell commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. It marks all descriptors above 2
CLOEXEC in the existing guest child hooks. A final barrier after policy setup
covers any newly created setup descriptors. These descriptors close at successful
exec, before workload instructions execute. They remain available for trusted
setup and factual error reporting if setup or exec fails. Physically closing
Rust's private startup-error channel inside `pre_exec` would incorrectly let its
parent interpret EOF as successful launch. This patch retains that channel and
the existing Landlock, child self-protection and workload filter order.

Install the host entry, helper and preserved body together at their fixed paths.
H owns the trusted installation/manifest join. The upstream patch is source
handoff pending the selected installed provenance or pinned rebuild; a version
string alone does not establish that join. Grok owns live containment acceptance,
including a closed route with confinement and a detecting control without it.
Disposable local descriptor fixtures are source regression evidence only.

The genuine placement, independent lease and durable recovery joins remain
open. Descriptor hygiene does not qualify cgroup custody, `/proc` disclosure or
same-UID terminal isolation. FILE routing remains queued behind the functional
launcher and its separate non-overlap agreement.
