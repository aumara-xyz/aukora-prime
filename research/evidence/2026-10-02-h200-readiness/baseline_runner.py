# Evidence class: SYNTHETIC unexecuted research baseline source; no model results or qualification.
"""Separate Gen16 inference-only prerequisite. No optimizer, updates or provider control."""
import argparse
import importlib.metadata as metadata
import json
import math
import os
from pathlib import Path
import platform
import signal
import sys
import time

CORE_DIR = Path(__file__).resolve().parent.parent / "2026-10-02-refresh-runner"
sys.path.insert(0, str(CORE_DIR))
from runner_core import (Guard, Interrupted, Refused, METRICS, PARENT_SHA, PARENT_CONFIG_SHA,
                         require, utc, no_symlink, inside, input_file, row_sha,
                         write_json, export_manifest)

PROTOCOL = {"question": "gen16_seven_row_prefix_baseline_v1", "max_tokens": 16384,
            "max_window_seconds": 3600, "runner_wall_seconds": 1800,
            "teardown_reserve_seconds": 1200, "minimum_output_free_bytes": 1073741824}


def binding(inputs):
    return {"parent_sha256": inputs["parent_weights"]["sha256"],
            "parent_config_sha256": inputs["parent_config"]["sha256"],
            "base_file_sha256s": sorted(s["sha256"] for s in inputs["base_files"]),
            "tokenizer_file_sha256s": sorted(s["sha256"] for s in inputs["tokenizer_files"]),
            "engraving_sha256": inputs["engraving"]["sha256"]}


def read_receipt(path):
    require(path.stat().st_size <= 4 * 1024 * 1024, "Receipt exceeds bound")
    receipt = json.loads(path.read_text())
    require(receipt.get("evidence_class") == "measured", "Actual operator receipt required")
    return receipt


def disk_check(context):
    stat = os.statvfs(context["roots"]["output_parent"])
    available = stat.f_bavail * stat.f_frsize
    require(available >= context["disk_required_bytes"] and stat.f_favail >= 100,
            "Output filesystem free-space/inode reserve not met; no pruning authorized")
    return {"available_bytes": available, "available_inodes": stat.f_favail,
            "required_free_bytes": context["disk_required_bytes"]}


def validate(raw, expected_sha, guard, execute=False):
    import hashlib
    require(hashlib.sha256(raw).hexdigest() == expected_sha, "Fixed baseline manifest hash differs")
    m = json.loads(raw)
    require(m.get("schema_version") == 1 and m.get("status") == "REGISTERED", "Baseline manifest remains unregistered")
    require(m.get("reference_only") is True and m.get("execution_mode") == "baseline_inference_only", "Inference-only registration required")
    require(m.get("protocol") == PROTOCOL and m.get("metrics") == METRICS, "Baseline protocol differs")
    require(m.get("baseline_not_yet_run_ack") is True and utc(m.get("frozen_at_utc")) <= guard.now(), "Pre-baseline freeze missing")
    import re
    require(isinstance(m.get("run_id"), str) and re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", m["run_id"]), "Unique baseline run ID missing")
    roots = {}
    for name in ["base_model", "tokenizer", "parent_adapter", "output_parent"]:
        value = m["roots"].get(name)
        require(isinstance(value, str) and value, "Root missing: " + name)
        roots[name] = no_symlink(value).resolve(strict=True)
        require(roots[name].is_dir(), "Existing directory required: " + name)
    out = roots["output_parent"] / m["run_id"]
    parts = roots["output_parent"].parts
    require(any(parts[i:i+2] == ("research", "evidence") for i in range(len(parts)-1)), "Research evidence output required")
    require(not out.exists() and not out.is_symlink(), "Existing output refused")
    require(all(not inside(out, roots[n]) and not inside(roots[n], out)
                for n in ["base_model", "tokenizer", "parent_adapter"]), "Output overlaps model input")
    a = m["approval"]
    require(0 < a["ceiling_usd"] <= 30 and a["max_window_seconds"] == PROTOCOL["max_window_seconds"] and
            a["runner_wall_seconds"] == PROTOCOL["runner_wall_seconds"] and
            a["teardown_reserve_seconds"] == PROTOCOL["teardown_reserve_seconds"], "Baseline subwindow exceeds registered limits")
    if execute:
        require(a.get("explicit_go") is True and a.get("scope") == "baseline_only_no_training",
                "Exact baseline approval/readiness has not been recorded")
    guard.configure(m)
    inputs, paths = m["inputs"], {}
    sources = inputs.get("runner_files")
    require(isinstance(sources, list) and len(sources) == 2, "Two exact source bindings required")
    require({input_file(s, guard) for s in sources} == {Path(__file__).resolve(), CORE_DIR / "runner_core.py"},
            "Actual baseline/core source files must be bound")
    require(inputs["parent_weights"]["sha256"] == PARENT_SHA and inputs["parent_config"]["sha256"] == PARENT_CONFIG_SHA,
            "Only pinned Gen16 parent allowed; no substitute model")
    for name in ["parent_weights", "parent_config", "engraving", "runtime_receipt", "pricing_receipt",
                 "supervisor_receipt", "disk_receipt", "data_eligibility_receipt"]:
        paths[name] = input_file(inputs.get(name), guard)
    require(paths["parent_weights"] == roots["parent_adapter"] / "adapter_model.safetensors" and
            paths["parent_config"] == roots["parent_adapter"] / "adapter_config.json", "Parent paths differ")
    require({p.name for p in roots["parent_adapter"].iterdir()} == {"adapter_model.safetensors", "adapter_config.json"},
            "Parent directory must contain only bound weights/config")
    for key, root_name in [("base_files", "base_model"), ("tokenizer_files", "tokenizer")]:
        require(isinstance(inputs.get(key), list) and inputs[key], "Complete model inventory required")
        files = [input_file(s, guard) for s in inputs[key]]
        require(all(inside(p, roots[root_name]) for p in files), "Inventory escapes root")
        require(not any(p.is_symlink() for p in roots[root_name].rglob("*")), "Symlink model inventory refused")
        require(set(files) == {p.resolve() for p in roots[root_name].rglob("*") if p.is_file()}, "Unbound model files found")
        require(not any(p.suffix in {".py", ".bin", ".pt", ".pth", ".pkl"} for p in files), "Executable/pickle artifacts prohibited")
        paths[key] = files
    require(any(p.name == "config.json" for p in paths["base_files"]) and
            any(p.suffix == ".safetensors" for p in paths["base_files"]), "Safetensors base/config required")
    require(paths["engraving"].stat().st_size <= 4 * 1024 * 1024, "Engraving input exceeds bound")
    rows = json.loads(paths["engraving"].read_text())
    require(isinstance(rows, list) and len(rows) == 7, "Exactly seven source-order engraving rows required")
    require(all(isinstance(r, dict) and isinstance(r.get("prompt"), str) and r["prompt"].strip() and
                isinstance(r.get("chosen", r.get("completion")), str) and r.get("chosen", r.get("completion")).strip()
                for r in rows), "Invalid/empty pair row")
    require(inputs["engraving"].get("row_content_sha256") == [row_sha(r) for r in rows], "Frozen row mapping differs")
    paths["engraving_rows"] = rows
    b = binding(inputs)
    runtime = m["runtime"]
    require(runtime.get("python") == platform.python_version(), "Python binding differs")
    for package in ["torch", "transformers", "peft", "safetensors"]:
        require(isinstance(runtime["packages"].get(package), str) and metadata.version(package) == runtime["packages"][package],
                "Package binding differs: " + package)
    require(runtime.get("device") == "cuda:0" and isinstance(runtime.get("cuda_version"), str) and
            type(runtime.get("qualified_context_tokens")) is int and runtime["qualified_context_tokens"] > 120,
            "CUDA/context envelope binding missing")
    environment = read_receipt(paths["runtime_receipt"])
    require(environment.get("environment_binding_verified") is True and environment.get("runtime") == runtime and
            environment.get("binding") == b, "Environment receipt does not bind this model/tokenizer/adapter/data")
    # This is environment preparation only. Actual model fit is measured by the approved baseline, not assumed.
    price = read_receipt(paths["pricing_receipt"])
    require(price.get("currency") == "USD" and price.get("verified_hourly_rate_usd") == a["verified_hourly_rate_usd"] and
            price.get("unavoidable_costs_upper_usd") == a["unavoidable_costs_upper_usd"], "All-in price receipt differs")
    supervisor = read_receipt(paths["supervisor_receipt"])
    s = m["supervision"]
    require(isinstance(s.get("provider_target_sha256"), str) and re.fullmatch("[0-9a-f]{64}", s["provider_target_sha256"]),
            "Exact existing provider-target identity binding missing")
    require(all(supervisor.get(k) == (m["run_id"] if k == "run_id" else s[k])
                for k in ["run_id", "session_id", "controller_identity", "provider_deadline_utc"]), "Supervisor binding differs")
    require(all(supervisor.get(k) is True for k in ["armed", "provider_stop_responsibility_acknowledged",
            "independent_stop_qualified", "partial_export_qualified", "received_copy_verification_qualified"]),
            "Actual independent stop/export qualification acknowledgment missing")
    proofs = inputs.get("supervisor_qualification_files")
    require(isinstance(proofs, list) and len(proofs) == 3, "Three actual stop/export qualification receipts required")
    require(supervisor.get("qualification_receipt_sha256s") == sorted(p.get("sha256") for p in proofs) and
            supervisor.get("provider_target_sha256") == s["provider_target_sha256"], "Supervisor proof/target binding differs")
    kinds = set()
    for proof in proofs:
        record = read_receipt(input_file(proof, guard))
        require(record.get("status") == "QUALIFIED" and record.get("controller_identity") == s["controller_identity"] and
                record.get("provider_target_sha256") == s["provider_target_sha256"], "Qualification receipt scope/status differs")
        kind = record.get("qualification_kind")
        require(kind in {"independent_stop", "partial_export", "received_copy_verification"} and kind not in kinds,
                "Qualification receipt kind missing/duplicated")
        raw_files = record.get("raw_receipt_files")
        require(isinstance(raw_files, list) and raw_files, "Actual raw qualification artifacts missing")
        for spec in raw_files:
            input_file(spec, guard)
        kinds.add(kind)
    # These verify receipt bytes/scope, not whether the operator actually performed the reported checks.
    eligibility = read_receipt(paths["data_eligibility_receipt"])
    require(eligibility.get("approved_for_this_baseline") is True and eligibility.get("no_private_conversation_ingest") is True and
            eligibility.get("no_safety_refused_replay") is True and eligibility.get("engraving_sha256") == inputs["engraving"]["sha256"],
            "Exact baseline data approval missing")
    disk = read_receipt(paths["disk_receipt"])
    require(disk.get("output_root") == str(roots["output_parent"]) and
            type(disk.get("required_free_bytes")) is int and disk["required_free_bytes"] >= PROTOCOL["minimum_output_free_bytes"] and
            type(disk.get("available_bytes")) is int and disk["available_bytes"] >= disk["required_free_bytes"] and
            type(disk.get("available_inodes")) is int and disk["available_inodes"] >= 100,
            "Measured output disk reserve missing")
    require(0 <= (guard.now() - utc(disk.get("measured_at_utc"))).total_seconds() <= 900, "Disk receipt stale/future")
    context = {"manifest": m, "manifest_bytes": raw, "manifest_sha256": expected_sha, "roots": roots,
               "paths": paths, "output": out, "binding": b, "disk_required_bytes": disk["required_free_bytes"]}
    disk_check(context)
    guard.check()
    return context


class InferenceBackend:
    def __init__(self, context, guard):
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
        self.torch, self.context, self.guard = torch, context, guard
        m = context["manifest"]
        require(torch.cuda.is_available() and torch.version.cuda == m["runtime"]["cuda_version"], "Bound CUDA runtime unavailable/different")
        self.device = torch.device(m["runtime"]["device"])
        torch.manual_seed(20260904)
        torch.cuda.reset_peak_memory_stats(self.device)
        guard.check()
        self.tokenizer = AutoTokenizer.from_pretrained(str(context["roots"]["tokenizer"]), local_files_only=True, trust_remote_code=False)
        guard.check()
        base = AutoModelForCausalLM.from_pretrained(str(context["roots"]["base_model"]), local_files_only=True,
               trust_remote_code=False, use_safetensors=True, torch_dtype=torch.bfloat16, device_map={"": str(self.device)})
        guard.check()
        configured = getattr(base.config, "max_position_embeddings", None)
        if configured is None:
            configured = getattr(getattr(base.config, "text_config", None), "max_position_embeddings", None)
        self.capacity = m["runtime"]["qualified_context_tokens"]
        require(type(configured) is int and 0 < self.capacity <= configured, "Declared context envelope lacks model-config support")
        base.config.use_cache = False
        self.model = PeftModel.from_pretrained(base, str(context["roots"]["parent_adapter"]), is_trainable=False, local_files_only=True)
        self.model.requires_grad_(False)
        self.model.eval()
        require(not any(p.requires_grad for p in self.model.parameters()), "Inference model unexpectedly trainable")
        guard.check()

    def measure(self):
        torch, tok, context, guard = self.torch, self.tokenizer, self.context, self.guard
        prepared, results = [], []
        encoding_start = guard.clock()
        for index, row in enumerate(context["paths"]["engraving_rows"]):
            guard.check()
            chosen = row.get("chosen", row.get("completion"))
            messages = [{"role": "user", "content": row["prompt"]}, {"role": "assistant", "content": chosen}]
            text = tok.apply_chat_template(messages, tokenize=False)
            ids = tok(text, truncation=False, return_tensors="pt").input_ids[0]
            prompt = tok.apply_chat_template(messages[:1], tokenize=False, add_generation_prompt=True)
            prefix_ids = tok(prompt, truncation=False).input_ids
            target = chosen.strip()[:METRICS["prefix_characters"]]
            target_ids = tok(target, add_special_tokens=False).input_ids
            require(len(ids) <= min(PROTOCOL["max_tokens"], self.capacity) and len(prefix_ids) < len(ids), "Supervised context/target invalid")
            require(ids[:len(prefix_ids)].tolist() == prefix_ids, "Prompt/full-token alignment differs")
            require(len(prefix_ids) + METRICS["max_new_tokens"] <= self.capacity, "Generation exceeds context envelope")
            require(target and 0 < len(target_ids) <= METRICS["max_new_tokens"] and
                    tok.decode(target_ids, skip_special_tokens=False, clean_up_tokenization_spaces=False) == target,
                    "Target prefix not reachable/round-trip consistent under fixed budget")
            labels = ids.clone()
            labels[:len(prefix_ids)] = -100
            require((labels[1:] != -100).any().item(), "No shifted assistant loss tokens")
            row_measurement = {"row": index, "row_content_sha256": row_sha(row), "target_prefix_tokens": len(target_ids),
                               "supervised_tokens": len(ids), "prompt_tokens": len(prefix_ids)}
            write_json(context["output"] / ("encoding-row-" + str(index) + ".json"), row_measurement)
            prepared.append((ids, labels, prefix_ids, target, row_measurement))
            guard.check()
        encoding_wall = guard.clock() - encoding_start
        eval_start = guard.clock()
        with torch.inference_mode():
            for ids, labels, prefix_ids, target, meta in prepared:
                guard.check()
                disk_check(context)
                row_start = guard.clock()
                forward = self.model(input_ids=ids[None].to(self.device), labels=labels[None].to(self.device))
                loss = float(forward.loss.detach().item())
                del forward
                require(math.isfinite(loss) and loss >= 0, "Invalid measured loss")
                prompt_ids = torch.tensor(prefix_ids, dtype=torch.long, device=self.device)[None]
                generated = self.model.generate(prompt_ids, max_new_tokens=METRICS["max_new_tokens"], do_sample=False)
                decoded = tok.decode(generated[0][len(prefix_ids):], skip_special_tokens=False, clean_up_tokenization_spaces=False)
                result = {**meta, "loss": loss, "strict_recall": decoded.strip().startswith(target),
                          "legacy_substring_diagnostic": target in decoded, "generated": decoded,
                          "row_wall_seconds": guard.clock() - row_start, "training_updates": 0}
                write_json(context["output"] / ("baseline-row-" + str(meta["row"]) + ".json"), result)
                results.append(result)
                guard.check()
        return {"binding": context["binding"], "metrics": METRICS,
                "strict_recall": [r["strict_recall"] for r in results], "loss": [r["loss"] for r in results],
                "target_prefix_tokens": [r["target_prefix_tokens"] for r in results],
                "row_content_sha256": [r["row_content_sha256"] for r in results],
                "target_deficit_present": not (results[0]["strict_recall"] and results[1]["strict_recall"]),
                "encoding_wall_seconds": encoding_wall, "evaluation_wall_seconds": guard.clock() - eval_start,
                "peak_cuda_allocated_bytes": torch.cuda.max_memory_allocated(self.device),
                "peak_cuda_reserved_bytes": torch.cuda.max_memory_reserved(self.device),
                "runtime": context["manifest"]["runtime"], "training_updates": 0,
                "training_runtime_qualified": False, "checkpoint_save_reload_qualified": False,
                "interpretation": "Repeated training-answer prefix recall baseline, not generalization; deficit does not authorize training"}


def execute(context, guard):
    out = no_symlink(context["output"])
    out.mkdir(mode=0o700, exist_ok=False)
    status, reason, baseline = "FAILED", "not_started", None
    errors = []
    try:
        (out / "fixed-baseline-registration.json").write_bytes(context["manifest_bytes"])
        write_json(out / "run-state.json", {"status": "RUNNING", "phase": "before_load"})
        guard.check()
        disk = disk_check(context)
        load_started = guard.clock()
        backend = InferenceBackend(context, guard)
        load_wall = guard.clock() - load_started
        baseline = backend.measure()
        baseline["model_load_wall_seconds"] = load_wall
        baseline["whole_runner_wall_seconds"] = guard.clock() - guard.started
        baseline["disk_observation"] = disk
        guard.check()
        write_json(out / "baseline-receipt.json", baseline)
        status, reason = "COMPLETE_BASELINE", "seven measured rows; no training performed"
    except Interrupted as error:
        status, reason = "INCOMPLETE", str(error)
    except Refused as error:
        status, reason = "REFUSED", str(error)
    except (KeyboardInterrupt, SystemExit) as error:
        status, reason = "INCOMPLETE", type(error).__name__
    except Exception as error:
        status, reason = "FAILED", type(error).__name__ + ": " + str(error)
    finally:
        supervision = context["manifest"]["supervision"]
        outcome = {"status": status, "status_scope": "BASELINE_PROTOCOL_ONLY", "reason": reason,
                   "command_argv": context["command_argv"], "manifest_sha256": context["manifest_sha256"],
                   "whole_runner_wall_seconds": guard.clock() - guard.started, "training_updates": 0,
                   "training_authorized": False, "target_deficit_present": baseline.get("target_deficit_present") if baseline else None,
                   "actual_all_in_cost": "PENDING_OPERATOR_LEDGER", "provider_STOPPED": "UNVERIFIED"}
        for name, data in [("outcome.json", outcome), ("stop-request.json", {
                "request": "EXPORT_PARTIAL_OR_COMPLETE_BASELINE_AND_STOP_EXISTING_INSTANCE",
                "run_id": context["manifest"]["run_id"], **{k:supervision[k] for k in
                ["session_id", "controller_identity", "provider_deadline_utc"]}, "provider_action_performed": False}),
                ("run-state.json", {"status": status, "phase": "terminal"})]:
            try:
                write_json(out / name, data)
            except Exception as error:
                errors.append({"file": name, "error_type": type(error).__name__})
        try:
            write_json(out / "finalization-status.json", {"baseline_protocol_status": status, "local_finalization_errors": list(errors),
                       "local_export_status": "PENDING_NEXT_BEST_EFFORT_ATTEMPT"})
        except Exception as error:
            errors.append({"file": "finalization-status.json", "error_type": type(error).__name__})
        try:
            with (out / "RESULTS.md").open("x") as stream:
                stream.write("Evidence class: MEASURED research baseline run telemetry; no training.\n\n"
                    + "Protocol status: " + status + ". Reason: " + reason + ".\n\n"
                    + "Exact command argv: " + json.dumps(context["command_argv"]) + ".\n\n"
                    + "Whole runner wall seconds at finalization: " + str(outcome["whole_runner_wall_seconds"]) + ".\n\n"
                    + "Spend: PENDING_OPERATOR_LEDGER; compute seconds × verified rate, storage, transfer and other charges.\n\n"
                    + "UNPROVEN: all-in spend, provider STOPPED, received-copy verification, training runtime/save/reload, generalization and improvement.\n\n"
                    + "Failures/partial row outputs remain in this directory; finalization errors: " + json.dumps(errors) + ".\n\n"
                    + "A complete baseline does not authorize training. Local export is best effort; check supervisor output and export-manifest.\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception as error:
            errors.append({"file": "RESULTS.md", "error_type": type(error).__name__})
        try:
            exported = export_manifest(out, "measured", status, guard.check, errors)
            complete_hashes = exported["complete_hash_manifest"]
        except Exception as error:
            errors.append({"file": "export-manifest.json", "error_type": type(error).__name__})
            complete_hashes = False
        outcome["baseline_protocol_status"] = status
        outcome["local_finalization_errors"] = errors
        outcome["local_export_hashes_complete"] = complete_hashes
        if errors or not complete_hashes:
            outcome["status"] = "INCOMPLETE"
    return outcome


def main():
    guard = Guard(wall_seconds=PROTOCOL["runner_wall_seconds"])
    parser = argparse.ArgumentParser(description="Registered Gen16 seven-row baseline only; no training/provider control")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--execute-baseline", action="store_true")
    args = parser.parse_args()
    print("Evidence class: MEASURED baseline control telemetry; models run only after exact approved registration.", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(Interrupted("SIGTERM from independent controller")))
    try:
        path = no_symlink(args.manifest)
        require(path.is_file() and path.stat().st_size <= 4 * 1024 * 1024, "Bounded regular baseline manifest required")
        context = validate(path.read_bytes(), args.manifest_sha256, guard, args.execute_baseline)
        context["command_argv"] = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
        if args.validate_only:
            print(json.dumps({"status": "INPUT_BINDINGS_ONLY", "model_loaded": False, "output_created": False,
                              "provider_action": False, "stop_or_export_qualified_by_this_command": False}))
            return 0
        outcome = execute(context, guard)
        print(json.dumps(outcome))
        return 0 if outcome["status"] == "COMPLETE_BASELINE" and outcome["local_export_hashes_complete"] else 2
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"status": "INCOMPLETE" if isinstance(error, (Interrupted, KeyboardInterrupt)) else "REFUSED",
                          "error_type": type(error).__name__, "reason": str(error), "model_start_authorized_by_result": False,
                          "failure_export": "Independent operator retains stdout; no existing output modified", "provider_action": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
