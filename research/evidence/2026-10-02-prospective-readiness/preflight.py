# Evidence class: MEASURED local inventory telemetry; no model or provider execution.
"""Bounded, offline metadata/header/hash preflight of explicitly named inputs only."""
import ast
import hashlib
import importlib.metadata as metadata
import json
import math
import os
from pathlib import Path
import platform
import shutil
import struct
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
REVISION = "1c5edc17a7acd8701df6fc341c0d179f1c62c982"
MODEL = "convaiinnovations/laya"
MAX_HASH_BYTES = 900_000_000
HASH_WALL_CAP_SECONDS = 15


def digest_bounded(path):
    size = path.stat().st_size
    if size > MAX_HASH_BYTES:
        return {"status": "HELD_SIZE_CAP", "bytes": size}
    start = time.perf_counter()
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while True:
            if time.perf_counter() - start > HASH_WALL_CAP_SECONDS:
                return {"status": "HELD_WALL_CAP", "bytes_read": count, "bytes": size}
            block = stream.read(1024 * 1024)
            if not block:
                break
            count += len(block)
            digest.update(block)
    return {"status": "HASHED", "bytes": size, "sha256": digest.hexdigest(),
            "hash_wall_seconds": time.perf_counter() - start}


def inspect_snapshot(root):
    report = {"present": root.is_dir(), "revision": root.name, "files": {}}
    if not root.is_dir():
        return report
    for name in ["rl_agent_config.json", "encoder/config.json", "tokenizer/tokenizer.json",
                 "tokenizer/tokenizer_config.json", "model.safetensors"]:
        path = root / name
        report["files"][name] = digest_bounded(path) if path.is_file() else {"status": "ABSENT"}
    weight = root / "model.safetensors"
    if weight.is_file():
        with weight.open("rb") as stream:
            length_raw = stream.read(8)
            if len(length_raw) != 8:
                report["header_status"] = "INVALID_LENGTH_PREFIX"
                return report
            length = struct.unpack("<Q", length_raw)[0]
            if length > 1024 * 1024:
                report["header_status"] = "HELD_HEADER_SIZE_CAP"
                return report
            raw = stream.read(length)
        header = json.loads(raw)
        tensors = [v for k, v in header.items() if k != "__metadata__"]
        report["safetensors"] = {
            "header_bytes": length, "header_sha256": hashlib.sha256(raw).hexdigest(),
            "tensor_count": len(tensors),
            "parameter_count": sum(math.prod(v["shape"]) for v in tensors),
            "dtypes": sorted({v["dtype"] for v in tensors}),
            "data_bytes": max(v["data_offsets"][1] for v in tensors),
            "declared_extent_matches_file": 8 + length + max(v["data_offsets"][1] for v in tensors) == weight.stat().st_size,
            "tensor_values_or_model_loaded": False,
            "architecture_or_quality_verified": False,
        }
    return report


def main():
    started = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    try:
        os.nice(10)
        priority = "lowered_by_10"
    except OSError:
        priority = "UNCHANGED"
    packages = {}
    for name in ["torch", "transformers", "peft", "accelerate", "laya", "safetensors", "huggingface-hub"]:
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = None
    cache = Path.home() / ".cache/huggingface/hub"
    snapshot = cache / "models--convaiinnovations--laya/snapshots" / REVISION
    named_presence = {
        name: (cache / ("models--" + name.replace("/", "--"))).is_dir()
        for name in ["convaiinnovations/laya-typed-decisions", "Qwen/Qwen2.5-1.5B-Instruct"]
    }
    loader = {}
    try:
        package = metadata.distribution("laya")
        loader["requires_python"] = package.metadata.get("Requires-Python")
        for name in ["laya/agent.py", "laya/common.py"]:
            source = package.locate_file(name)
            raw = source.read_bytes()
            if len(raw) > 262144:
                loader[name] = {"status": "HELD_SOURCE_SIZE_CAP"}
                continue
            tree = ast.parse(raw)
            calls = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    target = ast.unparse(node.func)
                    if any(key in target for key in ["from_pretrained", "from_config", "snapshot_download", "load_file", "_fix_tokenizer_config"]):
                        calls.append({"call": target, "line": node.lineno})
            loader[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "calls": calls}
    except metadata.PackageNotFoundError:
        loader["status"] = "PACKAGE_ABSENT"
    report = {
        "evidence_class": "measured", "reference_only": True,
        "kind": "bounded_offline_local_availability_not_model_results",
        "captured_at_utc": started, "python": platform.python_version(),
        "packages": packages, "named_other_cache_directory_presence": named_presence,
        "laya": inspect_snapshot(snapshot), "installed_loader": loader,
        "disk_available_gib": shutil.disk_usage(HERE).free / 2 ** 30,
        "ram_and_gpu_headroom": "UNQUALIFIED; no alternative access attempted after prior OS denial",
        "cuda_and_model_compatibility": "UNTESTED; metadata presence is not a load test",
        "hashing_caps": {"file_bytes": MAX_HASH_BYTES, "per_file_wall_seconds": HASH_WALL_CAP_SECONDS,
                         "read_buffer_bytes": 1024 * 1024, "process_priority": priority},
    }
    (HERE / "local-preflight.json").write_text(json.dumps(report, indent=2) + "\n")
    ledger = {
        "evidence_class": "measured", "reference_only": True,
        "command": "python3 preflight.py > preflight.stdout.txt",
        "started_at_utc": started, "wall_seconds": time.perf_counter() - clock,
        "source_execution": False, "weight_loading": False,
        "model_calls": 0, "provider_actions": 0, "cloud_compute_seconds": 0,
        "downloads_or_installs": 0, "new_storage_resources": 0,
        "new_paid_experiment_spend_usd": 0,
        "standing_storage_cost": "UNVERIFIED; no provider call",
        "spend_scope_excludes": ["standing storage", "host energy", "subscription/agent usage"],
    }
    (HERE / "run-ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    print("Evidence class: MEASURED offline metadata, header and checksum preflight; no model run.")
    print(json.dumps({"local_files_checked": len(report["laya"].get("files", {})),
                      "wall_seconds": ledger["wall_seconds"], "new_paid_experiment_spend_usd": 0,
                      "gpu_readiness": "HELD; compatibility/headroom/data/controls/budget unqualified"}))


if __name__ == "__main__":
    main()
