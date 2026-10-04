# Linux host lifecycle templates

Source proposal only. No unit, user, key, socket, directory, service, tunnel or runtime is created or activated by this change. The sole deployment integrator owns rendering, installation and observed acceptance. The privileged transition unit is a proposed operator role requiring separately reviewed installation authority; the application gets no sudo fallback.

The backend runs as `aukora-host`. Its durable support/state tree survives replacement of root-protected source, runtime and release directories. `aukora-host.service.in` retains the launcher in the service cgroup (`Type=simple`, `KillMode=control-group`). Linux foreground launch returns the backend exit status, forwards TERM/INT/HUP to its owned process group, bounds startup, keeps draining/redacting output, and publishes exactly `{url,pid}` to private `launch-url.json`. The existing detached desktop path remains the default. Foreground services refuse both approval waivers.

## Required rendered inputs

`host.json.in` is a closed root-owned configuration. Render actual canonical existing paths, a full approved machinery Git commit and the exact Node executable hash. Source and runtime trees, their ancestors and contained dependency targets must be root-owned with no group/other writes; escaping links and special files refuse. The Git checkout and reference inputs are part of that protection. Source HEAD must equal `source_commit`; both that commit and the selected release commit require the existing code Aura `MATCH` and local `origin/main` ancestry checks. No fetch, upgrade, build or approval is performed here.

Keep the host-owned support root separate from `/var/lib/aukora-host-control`. The control root and its ancestors are root-owned and non-writable to the host. Give only the already approved host primary group directory traversal/read access (proposed mode0750); do not expand memberships. Root configuration and `deployment.json` must be host-readable but host-unwritable (proposed root:host0440). Transition journal/lease remain root-private. No host-owned ancestor may contain an authoritative file.

The v2 deployment identifies exact artifact-record, plugin-set, approval and public approver-pin hashes. Its approval cache is exactly `CONTROL/approvals/COMMIT/state/gate-state/{plugin-set-approval.json,plugin-set-approver.json}`, root-protected and host-readable. Installation of public proofs is a separate owner-approved operator action. This code never mints, replaces or copies a signing key. Every service start verifies existing owner protocol, machinery approval, signed plugin-set admission and the actual release/runtime binding; the loader reads the protected approval cache. A missing proof is a refusal.

**Current L2 blocker:** the retained Genesis owner-protocol check actively requests a signature over its configured channel. The host must not gain access to the gate OWNER socket. Until L2 supplies an independently reviewed non-OWNER protocol/approval-verification seam, host boot will refuse. Do not widen OWNER access, install a signer, waive admission or claim the proposed service usable to make this check pass. The launch wrapper intentionally forwards no signer socket or credential to the backend. Existing Linux gate admission tooling also requires its reviewed L2 owner-pin/grant join.

## Operator commands and rollback

After separately authorized materialization and public-proof installation, the external operator may validate without a live write:

```
NODE SOURCE/scripts/aukora/become-linux.mjs --config /etc/aukora-host/host.json \
  --commit FULL_SHA --release /opt/aukora/releases/FULL_SHA \
  --approval-state /var/lib/aukora-host-control/approvals/FULL_SHA/state --plan
```

The same command without `--plan` uses `/usr/bin/flock -n -F` and verifies its inherited kernel lease. The OS releases it on process death; no expiry-based lock stealing occurs. Execution must be outside the backend service cgroup. It verifies the current approved predecessor before recording it, records stop intent before calling systemd, rechecks approved bytes, changes only the protected deployment selector, starts exactly `aukora-host.service`, and checks the actual Node executable/argv/UID/service cgroup plus the private manual303→cookie→clean200 exchange. A failed or interrupted forward transition attempts the retained predecessor and records `ROLLED_BACK` only after readiness. An uncertain recovery remains `OUTCOME_UNKNOWN` and blocks fresh transitions.

```
NODE SOURCE/scripts/aukora/become-linux.mjs --config /etc/aukora-host/host.json --rollback
```

Rollback consumes the retained predecessor and its unchanged protected approval cache, with proof rechecks; it does not produce a fresh signature or clear uncertainty automatically. A SIGKILL can prevent cleanup, but leaves a journal and an OS-released lease so the external operator can run this explicit recovery. Preserve both release directories, runtime closure and both public approval caches. Current waived previews cannot be represented as approved predecessors: initial migration needs a separately reviewed deployment/rollback plan before this controller can be used. Source does not stop an unrelated unit or preview.

`aukora-become@.service.in` is a separate root controller cgroup with only the operator control root writable. Its1800-second outer bound accommodates proof/startup and a recovery attempt. This is a template, not an installed privilege grant. Runtime timing, signals, lease inheritance, cookie exchange, restart and rollback remain UNPERFORMED pending coordinated Linux acceptance.

## Existing Mac Electron handoff

The private descriptor carries no redundant token field. Keep the existing authorized SSH tunnel and host-key checking. The existing Prime desktop pilot launcher can map its fixed local18731 origin to the deployed backend18735 remote port and project a private descriptor; the Genesis desktop attach mode can use the existing18735 loopback origin directly. Grok must choose the existing approved path. The Prime desktop policy rejects direct18735 attach, so do not change its guard or expose the token to Room/journal. The L4 code performs no tunnel or Electron operation. Actual desktop/cookie and browser acceptance remain unperformed by this lane.

## L3 memory template

`aukora-openviking.service.in` follows L3's foreground source contract: `sh SOURCE/scripts/openviking-setup.sh serve /var/lib/aukora-host/openviking`, OpenViking1933, embedder1934, CPU only. It gives a 64-task bound, memory MemoryHigh=2048M / MemoryMax=2304M (throttled above 2048M, killed only above 2304M; not a 2GiB hard limit) and a one-CPU cgroup bound and stops the whole owned cgroup. Source supervisors own two-thread/context bounds. Existing private `root.key`, Python3.11, the selected GGUF and an independently pinned/qualified llama-server are prerequisites; no credentials/models are installed here. The authenticated door8766 template uses L3's exact `node SOURCE/scripts/kira/viking-door.mjs --installed --support-root SUPPORT` contract and a path-only `AUKORA_VIKING_DOOR_KEY_FILE` to an existing private credential; no credential value enters the unit. It has a384MiB hard memory bound. These rows require L3 commit `a07807c30154df689c9cbf6d8319081834733841` or its reviewed integrated postimages; no L3 source is copied by this lane. These limits are proposed, not observed enforcement. Integration rows/manifests and every installation remain Grok-owned.

## Checks and provenance

All changes are first-party lifecycle adapters over the unchanged selected Genesis/DSH/Cordis source. No upstream upgrade, dependency install, build copy, test forest or donor host effect is added. Static syntax/CLI checks and an independent read-only source review are the available evidence. They do not establish current Linux runtime, owner attendance, OpenShell cleanup, memory persistence or a successful deployment. The code Aura observation retains its documented same-UID limitation.
