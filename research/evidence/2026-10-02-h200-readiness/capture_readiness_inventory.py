# Evidence class: SYNTHETIC metadata-extraction source; execution emits separately classified observations.
"""Read selected allowed audit files and named input metadata only; never load a model."""
import argparse
import hashlib
import json
from pathlib import Path
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent


def fingerprint(path):
    return {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    timer, started = time.perf_counter(), datetime.now(timezone.utc).isoformat()
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator-root", required=True)
    args = parser.parse_args()
    root = Path(args.operator_root).resolve()
    sources = ["local-source-audit/local-source-manifest.json", "local-source-audit/gen16-continuation-checkpoint.json",
               "private-provider/resume-final-h200-get.receipt.json", "private-provider/resume-final-h200-get.stdout",
               "private-provider/resume-h200-quote.stdout", "private-provider/resume-boot200-quote.stdout",
               "private-provider/resume-data186-quote.stdout"]
    data = {name: json.loads((root / name).read_text()) for name in sources}
    local = data[sources[0]]
    selected = []
    for alias in ["pairs-burn-13.json", "pairs-burn-16.json", "train_burn18-hybrid.py"]:
        matches = [r for r in local["source_records"] if Path(r.get("path", "")).name == alias]
        for row in matches:
            path = Path(row["path"])
            observed = fingerprint(path) if path.is_file() and not path.is_symlink() else {"present_regular_file": False}
            selected.append({"artifact_alias": alias, "historical_operator_metadata": {
                "evidence_class": "historical_measured", **{k:row[k] for k in ["bytes", "sha256", "row_count", "row_key_union"] if k in row}},
                "current_local_metadata": {"evidence_class": "measured", **observed},
                "content_not_parsed_or_printed": True})
    checkpoint = data[sources[1]]
    weight = Path(checkpoint["weight_path"])
    cp_observation = {"present_regular_file": weight.is_file() and not weight.is_symlink()}
    if cp_observation["present_regular_file"]:
        cp_observation["current_bytes"] = weight.stat().st_size
    provider = data[sources[3]]
    rates = {}
    for name, alias in [(sources[4], "h200_compute"), (sources[5], "boot200_storage"), (sources[6], "data186_storage")]:
        rates[alias] = data[name]["hourly_cost"]["general"]["total"]["cost"]
    output = {"evidence_class": "measured", "reference_only": True,
        "kind": "new_read_only_local_metadata_extraction_with_explicit_historical_operator_sections",
        "started_at_utc": started, "command": "python3 capture_readiness_inventory.py --operator-root " + args.operator_root,
        "source_audit_captured_at_utc": local.get("captured_at_utc"), "selected_inputs": selected,
        "checkpoint_historical": {"evidence_class": "historical_measured", **{k:checkpoint[k] for k in ["started_at_utc", "bytes", "sha256", "config_sha256", "header_extent_valid", "stable_during_read", "tensor_values_loaded", "base_revision_in_adapter_config", "local_base_backup_directory_present", "base_and_tokenizer_hashes"]}},
        "checkpoint_current_metadata": {"evidence_class": "measured", **cp_observation, "checkpoint_hash_not_repeated": True},
        "provider_historical": {"evidence_class": "historical_measured", "state": provider["status"]["state"],
            "platform": provider["spec"]["resources"]["platform"], "preset": provider["spec"]["resources"]["preset"],
            "captured_at_utc": data[sources[2]]["finished_at"], "output_sha256": data[sources[2]]["stdout_sha256"],
            "currency_in_quote_json": "UNSPECIFIED; USD corroboration reported separately by operator",
            "quoted_hourly_amounts": rates, "fresh_capacity_or_current_state_established": False},
        "source_files": [{"alias": name, **fingerprint(root / name)} for name in sources],
        "wall_seconds": time.perf_counter() - timer, "new_paid_experiment_spend_usd": 0,
        "model_imports": 0, "model_calls": 0, "tests_run": 0, "provider_calls": 0, "resources_mutated": 0,
        "cost_excludes": ["standing storage", "host electricity", "agent/subscription usage"],
        "privacy": "No private text, raw provider IDs, journal, key or raw operator manifest is exported",
        "limits": "Local metadata and saved provider observations only; no tensor load, remote inspection, compatibility, disk or stop/export qualification"}
    (HERE / "readiness-inventory.json").write_text(json.dumps(output, indent=2) + "\n")
    print("Evidence class: MEASURED bounded local metadata extraction; provider/model facts remain historical or unproven.")
    print(json.dumps({"selected_input_count": len(selected), "wall_seconds": output["wall_seconds"], "tests_run": 0,
                      "provider_calls": 0, "model_calls": 0, "new_paid_experiment_spend_usd": 0}))


if __name__ == "__main__":
    main()
