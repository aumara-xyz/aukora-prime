# Evidence class: SYNTHETIC control-fixture capture only; no model/provider execution.
"""Keep each test attempt, including failures, with source hashes and bounded execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent


def main():
    number = 2
    while (HERE / ("synthetic-checks-run" + str(number) + ".receipt.json")).exists():
        number += 1
    prefix = HERE / ("synthetic-checks-run" + str(number))
    command = [sys.executable, "synthetic_control_checks.py"]
    sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
               for p in [HERE / name for name in ("runner_core.py", "refresh_runner.py", "synthetic_control_checks.py",
                                                 "capture_synthetic_checks.py", "manifest-template.json")]}
    started = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    timed_out = False
    try:
        result = subprocess.run(command, cwd=HERE, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        def as_text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        result = subprocess.CompletedProcess(command, 124, as_text(error.stdout), as_text(error.stderr))
    wall = time.perf_counter() - clock
    # Generated CPU fixture roots are the only path information in expected failure tracebacks.
    # Keep stdout raw after a label; sanitize host paths from stderr and state that transformation.
    stderr = result.stderr.replace(str(HERE), "<RUNNER_DIRECTORY>")
    Path(str(prefix) + ".stdout.txt").write_text(
        "Evidence class: SYNTHETIC captured CPU-check stdout; label added before captured bytes.\n" + result.stdout)
    Path(str(prefix) + ".stderr.txt").write_text(
        "Evidence class: SYNTHETIC CPU-check stderr; runner-directory path sanitized; may be empty.\n" + stderr)
    receipt = {"evidence_class": "synthetic", "reference_only": True, "command": command,
               "source_sha256": sources, "started_at_utc": started, "wall_seconds": wall,
               "exit_code": result.returncode, "stdout_raw_bytes": len(result.stdout.encode()),
               "timed_out": timed_out,
               "stderr_raw_bytes": len(result.stderr.encode()), "stderr_sanitized": True,
               "real_model_calls": 0, "provider_actions": 0, "new_paid_experiment_spend_usd": 0,
               "spend_scope_excludes": ["standing storage", "host energy", "subscription/agent usage"]}
    latest_results = HERE / "synthetic-check-results.json"
    if result.returncode == 0 and latest_results.is_file():
        report = json.loads(latest_results.read_text())
        if datetime.fromisoformat(report["started_at_utc"]) >= datetime.fromisoformat(started):
            Path(str(prefix) + ".results.json").write_bytes(latest_results.read_bytes())
            receipt["pass_count"] = report["pass_count"]
            receipt["failure_count"] = report["failure_count"]
    Path(str(prefix) + ".receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Evidence class: SYNTHETIC CPU-check capture only.")
    print(json.dumps({"run": number, "exit_code": result.returncode, "wall_seconds": wall}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
