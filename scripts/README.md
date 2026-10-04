# Script index

Source checks, build tools and operator tools share this directory. Presence is not permission to install, start a service or use private state. Read each command's arguments and status scope; use [current claims](../docs/CLAIMS.md) to distinguish the pilot from NEXT.

| Area | Entry points and purpose |
| --- | --- |
| Audit surface | `audit/render-evidence.mjs --write` generates current tables; `--check` checks drift. `audit/check-face-copies.mjs` checks shared source equality. Root `./security-review` runs the fixed existing offline profile. |
| NEXT source profile | `ci/source-profile.mjs` and root `./prime verify`; [CI scope](../docs/CI.md). The complete profile has a retained failure and external exclusions. |
| Retained Genesis checks | `check.sh`, `genesis-check.mjs`, `face-parse-check.mjs`. Their profiles/results are distinct from NEXT and from installed-system acceptance. |
| Build/composition | `build-dsh.py`, `compose.py`, `materialize-aukora-release.py`, `launch-dsh.py`; [NEXT build account](../docs/PRIME-NEXT-ARCHITECTURE.md) and [pilot units](../packages/boundary-gate/host/systemd/README.md). Builds and launches require their declared inputs and operator scope. |
| Identity | [aumlok/](aumlok/README.md): bind, approval verification, signing and provenance. Keyless synthetic checks do not enroll the owner. |
| Owner records | [owner/records/](owner/records/README.md): governed record tooling; not an installed custody claim. |
| Memory | `kira/`: recall, evidence export/verification and checks. Source tools do not authorize importing personal memory or starting a live signer. |
| Observation | [aura/](aura/README.md): signed record collection, court adapters and cold verification; collector deployment is separate evidence. |
| Composition court | [composition/](composition/README.md): record/receipt closure and synthetic process checks. |
| Linux/operator tooling | `linux/` and `aukora/`: sandbox/install/cutover helpers. Do not confuse preview configuration with signed service enforcement. |
| Frozen earlier work | [phase0/](phase0/README.md) and `phase0-check-pins.py`: retained phase evidence and pin checks. |
| Shared helpers | `lib/`: support code for explicit callers; no independent command or runtime qualification. |

No command was executed just to create this index. Historical results remain in [evidence history](../docs/EVIDENCE-HISTORY.md).
