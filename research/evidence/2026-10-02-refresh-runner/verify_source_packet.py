# Evidence class: SYNTHETIC static source-packet checks, not model qualification.
import ast
import hashlib
import json
from pathlib import Path
import re
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent


def main():
    started, timer = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    files = sorted(p for p in HERE.iterdir() if p.is_file() and p.name != "source-packet-checks.json")
    failures = []
    inventory = []
    for path in files:
        raw = path.read_bytes()
        text = raw.decode()
        if not re.search(r'evidence.class|Evidence class', "\n".join(text.splitlines()[:3])):
            failures.append(path.name + ": classification missing in first three lines")
        if path.suffix == ".py":
            ast.parse(text, filename=path.name)
        if path.suffix == ".json":
            json.loads(text)
        if re.search(r'/Users/[A-Za-z0-9_.-]+/', text) or re.search(r'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----', text):
            failures.append(path.name + ": private absolute path/key marker")
        inventory.append({"path": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    report = {"evidence_class": "synthetic", "reference_only": True,
              "command": "python3 verify_source_packet.py", "started_at_utc": started,
              "wall_seconds": time.perf_counter() - timer, "failures": failures,
              "files_checked": len(files), "inventory": inventory,
              "check_scope": "Immediate source/evidence files only; cache directories excluded; no input/model/provider reads",
              "private_content_review": "Limited path/key-marker scan only, not an exhaustive privacy or secrecy guarantee",
              "new_paid_experiment_spend_usd": 0, "provider_actions": 0, "model_stack_imports": 0}
    report_bytes = (json.dumps(report, indent=2) + "\n").encode()
    number = 1
    while (HERE / ("source-packet-checks-run" + str(number) + ".json")).exists():
        number += 1
    (HERE / ("source-packet-checks-run" + str(number) + ".json")).write_bytes(report_bytes)
    (HERE / "source-packet-checks.json").write_bytes(report_bytes)
    print("Evidence class: SYNTHETIC static source-packet check only.")
    print(json.dumps({"files_checked": len(files), "failure_count": len(failures), "wall_seconds": report["wall_seconds"]}))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
