# Evidence class: MEASURED offline byte-hash verification, no archived source execution.
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent


def main():
    started = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    spec = json.loads((HERE / "source-inventory.json").read_text())
    source_root = os.environ["GENESIS_SOURCE_ROOT"]
    rows = []
    for row in spec["files"]:
        target = spec["source_revision"] + ":" + spec["path_prefix"] + row["path"]
        command = ["git", "show", target]
        one = time.perf_counter()
        result = subprocess.run(command, cwd=source_root, capture_output=True, timeout=5)
        raw = result.stdout
        actual = hashlib.sha256(raw).hexdigest() if result.returncode == 0 else None
        rows.append({"path": spec["path_prefix"] + row["path"], "command": command,
                     "exit_code": result.returncode, "bytes": len(raw),
                     "sha256": actual, "matches_inventory": actual == row["sha256"],
                     "wall_seconds": time.perf_counter() - one,
                     "raw_source_exported": False})
    report = {"evidence_class": "measured", "reference_only": True,
              "kind": "offline_named_Git_blob_hash_check",
              "command": "python3 verify_sources.py > source-verification.stdout.txt",
              "source_root_binding": "Operator-supplied GENESIS_SOURCE_ROOT; private absolute path intentionally omitted",
              "source_revision": spec["source_revision"], "started_at_utc": started,
              "wall_seconds": time.perf_counter() - clock, "files": rows,
              "passed": all(row["matches_inventory"] for row in rows),
              "archived_source_execution": False, "model_calls": 0, "provider_actions": 0,
              "cloud_compute_seconds": 0, "new_storage_resources": 0,
              "new_paid_experiment_spend_usd": 0,
              "standing_storage_cost": "UNVERIFIED; no provider call",
              "spend_scope_excludes": ["standing storage", "host energy", "subscription/agent usage"]}
    (HERE / "source-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Evidence class: MEASURED offline named-source hashes; raw blobs not exported or executed.")
    print(json.dumps({"passed": report["passed"], "files": len(rows), "wall_seconds": report["wall_seconds"],
                      "new_paid_experiment_spend_usd": 0}))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
