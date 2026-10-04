# Linux execution routing handoff

SOURCE-ONLY. This is the L1 source map, not installed execution evidence or
completion of Peter's requested Bash, `run_code` and terminal support.
Selected Prime source: `f946c1c0431c2bf7da0d1d1b4c0490e03cd1df25`.
Branch base: `b6005268bd080cd3f804351048e2e4ed09aa2938`, whose delta adds only
the L4 host source. DSH pin: `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`, with
the selected `patches/mandatory-agent-confinement.patch.json` applied.
Paths below are relative to DSH unless explicitly identified as Prime/plugin.
Post-patch source was read; built modules, installed profile/session config and
actual subprocesses were not inspected or run in this lane.

| Route or alias | Source selection | Exact consumer and launch seam | L1 result | Runtime |
| --- | --- | --- | --- | --- |
| One-shot `bash` | Base POSIX row; web disables the host tool row, then standard/cordis/PTC restores `tool-bash` per preset on POSIX. CORE disables it. | `packages/shell/tool-bash/src/index.ts:375` calls `ctx.shell.run(ctx.shell.resolve(...))`; `packages/shell/bash-sandbox/src/index.ts:184` requires `aukoraConfinement` and confines `['bash','-c',command]`; local managed spawn is `packages/shell/bash-local/src/index.ts:252`. | Supported source candidate: plugin `lib/index.mjs` subclasses the existing executor, validates guest cwd/policy `/sandbox`, changes host transport cwd to `/`, and receives full file-policy argv through the actual boundary `sandboxArgv()`. Missing real applied-policy INFO refuses. Dispatch argv uses sudo as `auma`, never host Bash. | NOT RUN |
| Background one-shot `bash` | Tool default permits background; proposed L1 row sets `enableRunInBackground:false`. | `packages/shell/tool-bash/src/index.ts:369` calls `ctx.shell.start`; plugin `GuestBashExecutor.start()` refuses independently of tool config. | REFUSED. No background capability inferred from foreground support. | NOT RUN |
| Minimal preset's `bash` | Linux-enabled `terminal-bash` and `persistent-bash` rows at `packages/preset/agent-presets/presets/minimal/agent.cordis.yml:30,36`; `persistent-bash` loads `dsh-tool-bash-persistent`. | `packages/shell/tool-bash-persistent/src/index.ts:405` registers the same `bash` alias; line 256 calls `ctx.terminals.spawn`; `packages/terminal/terminal-bash/src/index.ts:101` requires confinement, then line 204 launches a PTY. Default argv is `/bin/bash --noprofile --norc -i`, from `src/config.ts:54`. | Unsupported argv refuses in this provider. Proposed shared Linux consumer guard also refuses custom shell argv before launch. Grok must disable these exact row IDs and preserve the consumer guard. | NOT RUN |
| `terminal_open`, `terminal_send`, `terminal_read`, `terminal_signal`, `terminal_close`, `terminal_list` | `packages/terminal/tool-terminal/src/index.ts` defines all six; this row is not selected by base/standard/minimal in the inspected default source. An approved overlay could select it. | `terminal_open` calls the terminal registry; the `shell` backend is `terminal-bash`; subsequent tools act on the registered terminal handle. | Shell-backend launch is unsupported/refused. Never infer these aliases are disabled from their absence in an action-gate allow list. Other custom terminal backends are not selected or qualified here. | NOT RUN |
| Browser terminal RPC `terminal.*` | Web `terminal-controller` at `packages/bundle/web-app/cordis.patch.yml:107` and `ui-sidebar-terminal` at line 234 are enabled independently of agent tool presets. | `packages/api/terminal-controller/src/index.ts:316` discovers a shell; lines 324–327 require confinement then call `subprocess.spawnTerminal` with host cwd and PTY/env fields. | Unsupported argv refuses in this provider. Proposed shared Linux controller guard covers even custom argv that looks like foreground Bash. Disable controller and UI affordance until a real guest terminal handle is joined. | NOT RUN |
| `run_code` | Base `ptc-runtime` at `packages/bundle/base/cordis.patch.yml:369` is enabled. Tool is visible in ptc/both presentation scopes; standard defaults native. PTC preset `tool-presentation` at `packages/preset/agent-presets/presets/ptc/agent.cordis.yml:277` selects `mode:ptc`. | Fixed reserved name in `packages/core/tools/src/ptc.ts:23,326`; presentation invokes `ctx.ptcRuntime.resolve/run`; `packages/ptc-runtime/ptc-runtime-node/src/index.ts:110` requires policy/provider, lines 217–237 build Node/bootstrap argv, confine it, and spawn with `control:'pipe'`. `packages/subprocess/subprocess/src/control.ts:7` defines FD7. | REFUSED: not Bash argv, no guest bootstrap/control mapping. Proposed Linux guards cover normal resolve and direct run reaching launch. No Node host fallback. | NOT RUN |
| PTC workflow | Base `workflow-ptc` exists; web disables that host row at `packages/bundle/web-app/cordis.patch.yml:460`. Standard and CORE mount enabled preset-local workflow rows; PTC disables both `workflow-ptc` and `tool-workflow` at `presets/ptc/agent.cordis.yml:229–241`. | `packages/workflow/workflow-ptc/src/runtime.ts` invokes the same Node PTC runtime; it can await nested tools including Bash. | Same unsupported/refused Node path. Disabling only `run_code` presentation does not cover standard/CORE workflow invocation. | NOT RUN |
| `pwsh` and persistent `pwsh` | Base/standard and minimal PowerShell rows are win32-only. | `packages/shell/pwsh-sandbox/src/index.ts` requires confinement; minimal `persistent-pwsh` uses terminal-bash with the pwsh dialect. | Unsupported by this Linux plugin; positive Bash allowlist refuses the argv. | NOT RUN |
| Native SDK subagents | CORE disables Codex/Claude tool rows; shared providers may remain registered. | Mandatory patch makes both SDK start closures throw `AUKORA_NATIVE_CONFINEMENT_UNWIRED`. | Remain refused; registration does not establish a launch capability. | NOT RUN |
| `aukora_workspace_patch` | Prime materializer selects `aukora-caged-worker` at `scripts/materialize-aukora-release.py:1504`; Prime `plugins/aukora-caged-worker/lib/index.mjs:17` registers this fixed tool. | Separate box path, outside `ctx.subprocess` and `requiredConfinement`. Prime `plugins/aukora-caged-worker/lib/run.mjs:179` spawns the host issuer before `plugins/aukora-box/aukora/supervisor/guest-confinement.mjs:40–48` refuses non-macOS worker startup. | Unsupported Linux route. Proposed `linux-caged-worker-refusal.patch` moves explicit refusal before adapter mkdir and before direct run preflight, state/key setup or issuer spawn. This is a Grok-owned first-party consumer diff, not a DSH patch. | NOT RUN |
| Legacy Prime harness shell | Prime `harness/shell-unavailable.mjs`, separate from the Genesis zipper runtime. | Resolution/execution throws unavailable. | Refused. It does not describe the actual Genesis Bash/PTC/terminal profile. | NOT RUN |

The exact installed profile and session cwd remain UNINSPECTED. Source-enabled
means the named selected row has no Linux-disable condition in that profile; it
does not prove the running app uses that profile or that the row mounted.
Prime's materializer writes `aukora-composition.patch.yml` and separately carries
the Seatbelt overlay. Its action-gate rows also disable stock `sandbox` and mount
`aukora-seatbelt`; that provider refuses Linux. Web selects the standard preset
by default at `packages/bundle/web-app/cordis.patch.yml:489`.
It does not yet carry/mount this new L1 plugin on the
selected base. Grok owns its materializer/composition join and the Linux session
cwd. CORE and preset-local realms must not be conflated with host base rows.

## Exact shared-consumer refusal handoff

`linux-unsupported-consumers.patch.json` uses the existing pinned patch format.
Grok must integrate it after `mandatory-agent-confinement`, bind its actual hash
and reason in Prime `upstream-dsh.json`, and preserve normal patch/build checks.
This lane does not edit those shared files or run a build. Each `find` string
was independently observed exactly once in the post-mandatory source.

The four guards are after `requiredConfinement`: persistent terminal, browser
terminal, PTC resolve and direct PTC launch. They refuse Linux startup regardless
of custom shell argv, configured executable spelling or a direct runtime caller.
PTC resolve throws `SandboxUnavailableError`; the launch guard is caught by the
runtime and returns `error.kind:'sandbox-unavailable'`. Terminal guards throw
`code:'SANDBOX_UNAVAILABLE'`. None supplies partial enforcement or a synthetic
qualification flag. These proposed guards are unjoined source, not current main
or installed behavior.

`linux-caged-worker-refusal.patch` is a separate exact Git diff for the selected
Prime caged-worker consumer. Its Linux guard returns a fixed REFUSED result with
zero worker spawns at both the model tool entry and direct `runPatch()` entry.
It is a zero-context diff: use `git apply --unidiff-zero` against the selected
unchanged consumer files, then review the two entry guards.
It preserves the existing macOS route and avoids issuer startup or filesystem
preparation on unsupported Linux. Grok must also hide/disable that row in the
selected Linux composition. No box developer launcher is mounted by the inspected
closure, and the box library registers no separate tool alias there.

## Smallest substantive transport join

The current `sbx-exec` closes stdin, buffers stdout/stderr, sets `--no-tty`, and
serializes/cleans the whole shared sandbox. These contracts cannot be preserved
merely by widening argv or wrapping a local PTY around the CLI.

- PTC needs genuine preinstalled guest Node/bootstrap mapping, a bidirectional
  FD7 channel for ready/program/tool-call/completion frames, and streaming output.
  Preserve existing tool admission and file policy; no provider or host
  credential environment is transferred.
- Terminal needs a genuine guest PTY handle with input/output, resize, bounded
  teardown and guest foreground inspection/signals. Local sudo/OpenShell waiting
  must not become guest `stdin_read`; unsupported observations remain unknown.
- Both need explicit guest cwd/environment separated from host transport cwd,
  and per-execution ownership/cleanup. A terminal holding the shared lock blocks
  later calls; releasing it allows the next cleanup to kill it. A PTC worker
  holding that lock while awaiting `tools.bash()` blocks its own nested call.
  Distinguish simultaneously live executions or use explicitly approved isolated
  sandbox instances; do not add a new architecture silently.
- Retain `requiredConfinement` at every current launch and validate the genuine
  applied full file policy. Startup policy and per-launch checks remain Grok's
  existing wrapper ownership. No older durable-ledger architecture is required.

Grok owns the shared subprocess/terminal/PTC transport, consumer patch registration,
wrapper, materializer and deployment. L1 owns only this plugin and its handoff
files. Fence-r2 owns action-gate policy/index/checks; these are untouched here.
At the selected gate, `bash`, `terminal_open`, `terminal_send` and `run_code` are
switch-known aliases; absence from `allowTools` is not an execution disable.
Browser RPCs are a separate controller surface. Source refusal is the interim;
working all-three execution support remains BLOCKED pending the substantive join.

Experimental Python PTC contains a raw spawn and explicitly lacks file
confinement. It is dormant source, not an enabled row in the inspected shipped
profiles, and is outside the existing mandatory patch. Do not enable that
backend or a custom terminal backend under this L1 profile. `job_output`,
`job_list` and `job_kill` act on existing managed jobs; they are not new launch
aliases. Arbitrary operator-added overlays remain uninspected configuration.

No new tests, module imports, build, UI/guest/runtime probes, host setup,
credentials, permissions, network changes or activation were performed by L1.
