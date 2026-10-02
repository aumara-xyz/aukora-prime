# Evidence class: SYNTHETIC proposed row-index schedule; no model evaluation or training.
import collections
import hashlib
import json
from pathlib import Path
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent


def main():
    started = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    quota = [50, 50, 8, 8, 8, 8, 8]
    used = [0] * 7
    total = sum(quota)
    schedule = []
    for step in range(1, total + 1):
        choices = [row for row in range(7) if used[row] < quota[row]]
        row = max(choices, key=lambda row: (quota[row] * step - used[row] * total, -row))
        schedule.append(row)
        used[row] += 1
    assert used == quota
    assert sum(collections.Counter(schedule).values()) == 140
    data = {"evidence_class": "synthetic", "reference_only": True,
            "kind": "proposed_deficit_balanced_engraving_row_schedule_not_model_inputs",
            "status": "DRAFT_NOT_REGISTERED", "quota": quota, "row_indices": schedule,
            "rule": "At one-based step s choose eligible row maximizing quota[row]*s-used[row]*140; tie selects lower row ID",
            "bound_actual_row_content_hashes": False}
    output = HERE / "row-schedule-DRAFT.json"
    output.write_text(json.dumps(data, indent=2) + "\n")
    ledger = {"evidence_class": "measured", "reference_only": True,
              "kind": "local_synthetic_schedule_calculation_telemetry",
              "command": "python3 build_schedule.py > schedule.stdout.txt",
              "started_at_utc": started, "wall_seconds": time.perf_counter() - clock,
              "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "model_calls": 0, "provider_actions": 0, "cloud_compute_seconds": 0,
              "new_storage_resources": 0, "new_paid_experiment_spend_usd": 0,
              "standing_storage_cost": "UNVERIFIED; no provider call",
              "spend_scope_excludes": ["standing storage", "host energy", "subscription/agent usage"]}
    (HERE / "schedule-run-ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    print("Evidence class: SYNTHETIC proposed row-index schedule; not model results.")
    print(json.dumps({"quota": used, "total": len(schedule), "target_share": "5/7", "output_sha256": ledger["output_sha256"]}))


if __name__ == "__main__":
    main()
