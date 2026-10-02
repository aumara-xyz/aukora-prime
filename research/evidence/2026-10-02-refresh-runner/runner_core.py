# Evidence class: SYNTHETIC unexecuted research runner source; no model results.
"""Standard-library controls. No provider API and no model imports."""
import hashlib
import importlib.metadata as metadata
import json
import math
import os
from pathlib import Path
import platform
import re
import time
from datetime import datetime, timezone

PARENT_SHA = "ed8b316728368f73f670485eaf2bac09126585e68f17e50dd48cb4c9b9ee1dac"
PARENT_CONFIG_SHA = "38e08fda482a14a20d1f294b0da71ce1d0b930323fa2db9ba761e84cca18c1be"
QUOTA = [50, 50, 8, 8, 8, 8, 8]
TRAINING = {"seed": 20260904, "lr": 0.0001, "max_tokens": 16384, "repeat": 20,
            "min_epoch": 3, "max_epochs": 6, "quota": QUOTA, "train_wall_seconds": 4800}
METRICS = {"loss_floor": 0.001, "prefix_characters": 240, "max_new_tokens": 120,
           "skip_special_tokens": False, "clean_up_tokenization_spaces": False}


class Refused(Exception):
    pass


class Interrupted(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def utcnow():
    return datetime.now(timezone.utc)


def utc(value):
    require(isinstance(value, str), "UTC timestamp missing")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(stamp.tzinfo is not None, "UTC timestamp requires timezone")
    return stamp.astimezone(timezone.utc)


def sha(path, check=lambda: None):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            check()
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def row_sha(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def no_symlink(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        require(not item.is_symlink(), "Symlink write/input path is not permitted")
    return path


def inside(path, root):
    try:
        Path(path).relative_to(root)
        return True
    except ValueError:
        return False


class Guard:
    """Cooperative checks only; independent supervision must kill a blocked worker."""
    def __init__(self, clock=time.monotonic, now=utcnow, wall_seconds=7200):
        self.clock, self.now = clock, now
        self.started = clock()
        self.deadline = self.started + wall_seconds
        self.supervision = None

    def configure(self, manifest):
        a, s = manifest["approval"], manifest["supervision"]
        for name in ["session_id", "controller_identity", "heartbeat_file"]:
            require(isinstance(s.get(name), str) and s[name].strip(), "Nonempty supervisor identity/path required")
        heartbeat_path = no_symlink(s["heartbeat_file"])
        require(heartbeat_path.is_file() and heartbeat_path.stat().st_size <= 1024 * 1024, "Regular bounded heartbeat file required")
        require(isinstance(s.get("heartbeat_max_age_seconds"), (int, float)) and 0 < s["heartbeat_max_age_seconds"] <= 60, "Heartbeat freshness bound invalid")
        require(a["currency"] == "USD", "Verified USD currency required")
        rate = a["verified_hourly_rate_usd"]
        other = a["unavoidable_costs_upper_usd"]
        require(type(rate) in (int, float) and math.isfinite(rate) and rate > 0, "Verified rate missing")
        require(type(other) in (int, float) and math.isfinite(other) and 0 <= other < a["ceiling_usd"], "Unavoidable cost bound missing")
        require(0 < a["ceiling_usd"] <= 30 and 0 < a["max_window_seconds"] <= 14400, "Conditional ceiling/window exceeded")
        require(0 < a["runner_wall_seconds"] <= 7200 and a["teardown_reserve_seconds"] >= 1200, "Runner cap/teardown reserve invalid")
        paid_start = utc(a["paid_window_started_at_utc"])
        require(paid_start <= self.now(), "Paid start cannot be in the future")
        affordable = (a["ceiling_usd"] - other) / rate * 3600
        end = paid_start.timestamp() + min(a["max_window_seconds"], affordable)
        supervisor_end = utc(s["provider_deadline_utc"]).timestamp()
        require(supervisor_end <= end, "Supervisor deadline exceeds all-in budget/window")
        remaining = supervisor_end - a["teardown_reserve_seconds"] - self.now().timestamp()
        require(remaining > 0, "No run time remains after teardown reserve")
        self.deadline = min(self.started + a["runner_wall_seconds"], self.clock() + remaining)
        self.supervision = {**s, "run_id": manifest["run_id"]}
        self.check()

    def check(self, training_start=None, training_cap=None):
        if self.clock() >= self.deadline:
            raise Interrupted("Whole-run cooperative deadline reached")
        if training_start is not None and self.clock() - training_start >= training_cap:
            raise Interrupted("Training/gate/checkpoint deadline reached")
        if self.supervision:
            s = self.supervision
            heartbeat_path = no_symlink(s["heartbeat_file"])
            require(heartbeat_path.is_file() and heartbeat_path.stat().st_size <= 1024 * 1024, "Heartbeat file changed or missing")
            heartbeat = json.loads(heartbeat_path.read_text())
            if (heartbeat.get("session_id") != s["session_id"] or
                    heartbeat.get("controller_identity") != s["controller_identity"] or
                    heartbeat.get("run_id") != s["run_id"] or
                    heartbeat.get("provider_deadline_utc") != s["provider_deadline_utc"] or
                    heartbeat.get("armed") is not True):
                raise Interrupted("Independent supervisor heartbeat not armed/bound")
            age = (self.now() - utc(heartbeat.get("updated_at_utc"))).total_seconds()
            if age < -5 or age > s["heartbeat_max_age_seconds"]:
                raise Interrupted("Independent supervisor heartbeat stale")
            if heartbeat.get("stop_requested") is True:
                raise Interrupted("Independent supervisor requested interruption")


def input_file(spec, guard):
    require(isinstance(spec, dict), "Input file binding missing")
    require(isinstance(spec.get("path"), str) and spec["path"], "Input path missing")
    require(isinstance(spec.get("sha256"), str) and re.fullmatch("[0-9a-f]{64}", spec["sha256"]), "Input SHA-256 missing")
    path = no_symlink(spec["path"]).resolve(strict=True)
    require(path.is_file(), "Bound input is not a regular file")
    require(sha(path, guard.check) == spec["sha256"], "Input SHA-256 mismatch")
    return path


def validate_manifest(raw, expected_sha, guard, execute=False):
    require(hashlib.sha256(raw).hexdigest() == expected_sha, "Fixed preregistration manifest SHA-256 mismatch")
    m = json.loads(raw)
    require(m.get("schema_version") == 1 and m.get("status") == "REGISTERED", "Manifest remains unregistered")
    require(m.get("reference_only") is True and m.get("execution_mode") == "real", "Real research registration required")
    require(m.get("question") == "gen16_target_restoration_v1", "Different question needs a separately implemented protocol")
    require(m.get("trial_training_not_yet_run_ack") is True and utc(m.get("frozen_at_utc")) <= guard.now(), "Pre-trial freeze acknowledgment missing")
    require(m.get("training") == TRAINING and m.get("metrics") == METRICS, "Fixed training/metric preregistration differs")
    require(isinstance(m.get("run_id"), str) and re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", m["run_id"]), "Unique run ID missing")
    roots = {}
    for name in ["base_model", "tokenizer", "parent_adapter", "output_parent"]:
        value = m["roots"].get(name)
        require(isinstance(value, str) and value, "Explicit root missing: " + name)
        root = no_symlink(value).resolve(strict=True)
        require(root.is_dir(), "Root is not an existing directory: " + name)
        roots[name] = root
    out = roots["output_parent"] / m["run_id"]
    parts = roots["output_parent"].parts
    require(any(parts[i:i+2] == ("research", "evidence") for i in range(len(parts)-1)), "Output parent must be under research/evidence")
    require(not out.exists() and not out.is_symlink(), "Refusing existing output; no overwrite")
    for name in ["base_model", "tokenizer", "parent_adapter"]:
        require(not inside(out, roots[name]) and not inside(roots[name], out), "Output overlaps model inputs")
    if execute:
        require(m["approval"].get("explicit_go") is True, "Conditional execution authorization not recorded as ready")
    guard.configure(m)
    inputs, paths = m["inputs"], {}
    require(isinstance(inputs.get("runner_files"), list) and inputs["runner_files"], "Runner source hashes missing")
    bound_runner = {input_file(item, guard) for item in inputs["runner_files"]}
    expected_runner = {Path(__file__).resolve(), Path(__file__).with_name("refresh_runner.py").resolve()}
    require(bound_runner == expected_runner, "Actual runner/core source files must be hash-bound")
    require(inputs["parent_weights"].get("sha256") == PARENT_SHA and inputs["parent_config"].get("sha256") == PARENT_CONFIG_SHA, "Only pinned Gen16 parent is allowed")
    for name in ["parent_weights", "parent_config", "corpus", "engraving", "baseline", "schedule", "runtime_receipt", "pricing_receipt", "supervisor_receipt", "data_eligibility_receipt"]:
        paths[name] = input_file(inputs.get(name), guard)
    for key, root_name in [("base_files", "base_model"), ("tokenizer_files", "tokenizer")]:
        require(isinstance(inputs.get(key), list) and inputs[key], "Complete directory hash bindings missing")
        paths[key] = [input_file(item, guard) for item in inputs[key]]
        require(all(inside(p, roots[root_name]) for p in paths[key]), "Bound files escape declared model/tokenizer root")
        actual = {p.resolve() for p in roots[root_name].rglob("*") if p.is_file()}
        require(actual == set(paths[key]), "Every model/tokenizer file must be hash-bound; no extra files")
        require(not any(p.is_symlink() for p in roots[root_name].rglob("*")), "No model/tokenizer symlink inputs")
    require(paths["parent_weights"].parent == roots["parent_adapter"] and paths["parent_weights"].name == "adapter_model.safetensors", "Parent weights path/name invalid")
    require(paths["parent_config"].parent == roots["parent_adapter"] and paths["parent_config"].name == "adapter_config.json", "Parent config path/name invalid")
    require({p.name for p in roots["parent_adapter"].iterdir()} == {"adapter_config.json", "adapter_model.safetensors"}, "Parent directory must contain only bound adapter/config")
    base_names = {p.name for p in paths["base_files"]}
    require("config.json" in base_names and any(p.suffix == ".safetensors" for p in paths["base_files"]), "Safetensors base/config required")
    require(not any(p.suffix in {".py", ".bin", ".pt", ".pth", ".pkl"} for p in paths["base_files"] + paths["tokenizer_files"]), "Executable/pickle model artifacts prohibited")
    for name, expected_count in [("corpus", 146), ("engraving", 7)]:
        data = json.loads(paths[name].read_text())
        require(isinstance(data, list) and len(data) == expected_count, "Bound pair-row count differs")
        for row in data:
            require(isinstance(row, dict) and isinstance(row.get("prompt"), str) and row["prompt"].strip(), "Empty/invalid prompt")
            chosen = row.get("chosen", row.get("completion"))
            require(isinstance(chosen, str) and chosen.strip(), "Empty/invalid assistant target")
        paths[name + "_rows"] = data
    baseline = json.loads(paths["baseline"].read_text())
    require(baseline.get("evidence_class") == "measured", "Real baseline receipt required; synthetic control fixtures are not readiness")
    expected_binding = {"parent_sha256": PARENT_SHA, "parent_config_sha256": PARENT_CONFIG_SHA,
                        "base_file_sha256s": sorted(item["sha256"] for item in inputs["base_files"]),
                        "tokenizer_file_sha256s": sorted(item["sha256"] for item in inputs["tokenizer_files"]),
                        "engraving_sha256": inputs["engraving"]["sha256"]}
    require(baseline.get("binding") == expected_binding and baseline.get("metrics") == METRICS, "Baseline not bound to same parent/model/data/decoder")
    recalls = baseline.get("strict_recall")
    require(isinstance(recalls, list) and len(recalls) == 7 and all(type(v) is bool for v in recalls), "Seven measured baseline recalls missing")
    require(not (recalls[0] and recalls[1]), "Targets already pass; restoration question does not justify training")
    lengths = baseline.get("target_prefix_tokens")
    require(isinstance(lengths, list) and len(lengths) == 7 and all(type(n) is int and 0 < n <= 120 for n in lengths), "Prefix reachability unqualified")
    losses = baseline.get("loss")
    require(isinstance(losses, list) and len(losses) == 7 and all(isinstance(v, (int, float)) and math.isfinite(v) and v >= 0 for v in losses), "Seven finite baseline losses missing")
    schedule = json.loads(paths["schedule"].read_text())
    ids = schedule.get("row_indices")
    require(schedule.get("status") == "REGISTERED" and schedule.get("quota") == QUOTA, "Schedule still unregistered or changed")
    require(isinstance(ids, list) and len(ids) == 140 and all(type(i) is int and 0 <= i < 7 for i in ids), "Schedule row IDs invalid")
    require([ids.count(i) for i in range(7)] == QUOTA, "Schedule quotas differ")
    require(schedule.get("row_content_sha256") == [row_sha(r) for r in paths["engraving_rows"]], "Schedule row-content binding missing")
    paths["schedule_rows"] = ids
    runtime = m["runtime"]
    require(runtime["python"] == platform.python_version(), "Python runtime lock differs")
    for package in ["torch", "transformers", "peft", "safetensors"]:
        require(isinstance(runtime["packages"].get(package), str) and metadata.version(package) == runtime["packages"][package], "Package runtime lock differs: " + package)
    require(runtime.get("device") == "cuda:0" and isinstance(runtime.get("cuda_version"), str), "Qualified single CUDA device/runtime required")
    require(type(runtime.get("qualified_context_tokens")) is int and runtime["qualified_context_tokens"] > 120,
            "Qualified model context capacity missing")
    runtime_receipt = json.loads(paths["runtime_receipt"].read_text())
    require(runtime_receipt.get("qualified") is True and runtime_receipt.get("runtime") == runtime, "Runtime smoke receipt missing/different")
    pricing = json.loads(paths["pricing_receipt"].read_text())
    require(pricing.get("currency") == "USD" and pricing.get("verified_hourly_rate_usd") == m["approval"]["verified_hourly_rate_usd"] and pricing.get("unavoidable_costs_upper_usd") == m["approval"]["unavoidable_costs_upper_usd"], "Pricing receipt does not bind verified USD/all-in bounds")
    supervisor = json.loads(paths["supervisor_receipt"].read_text())
    require(supervisor.get("armed") is True and supervisor.get("provider_stop_responsibility_acknowledged") is True and supervisor.get("session_id") == m["supervision"]["session_id"] and supervisor.get("controller_identity") == m["supervision"]["controller_identity"] and supervisor.get("run_id") == m["run_id"] and supervisor.get("provider_deadline_utc") == m["supervision"]["provider_deadline_utc"], "Independent supervisor acknowledgment missing/different")
    require(0 < m["supervision"]["heartbeat_max_age_seconds"] <= 60, "Heartbeat freshness bound invalid")
    eligibility = json.loads(paths["data_eligibility_receipt"].read_text())
    require(eligibility.get("approved_for_this_research_training") is True and eligibility.get("no_private_conversation_ingest") is True and eligibility.get("corpus_sha256") == inputs["corpus"]["sha256"] and eligibility.get("engraving_sha256") == inputs["engraving"]["sha256"], "Data approval does not bind these files")
    guard.check()
    return {"manifest": m, "paths": paths, "roots": roots, "output": out, "manifest_bytes": raw,
            "manifest_sha256": expected_sha, "baseline": baseline}


def write_json(path, data, evidence_class="measured"):
    path = no_symlink(path)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists(), "Refusing an existing temporary output")
    with temporary.open("x") as stream:
        json.dump({"evidence_class": evidence_class, "reference_only": True, **data}, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def export_manifest(out, evidence_class, status, check=lambda: None, finalization_errors=None):
    files, errors = [], []
    for path in sorted(out.rglob("*")):
        if path.is_symlink():
            errors.append("Symlink artifact excluded")
        elif path.is_file() and path.name != "export-manifest.json":
            try:
                files.append({"path": str(path.relative_to(out)), "bytes": path.stat().st_size, "sha256": sha(path, check)})
            except (OSError, Interrupted, Refused) as error:
                errors.append(type(error).__name__)
                files.append({"path": str(path.relative_to(out)), "bytes": path.stat().st_size,
                              "sha256": None, "hash_status": "UNCOMPLETED"})
    data = {"worker_status": status, "worker_status_scope": "MODEL_PROTOCOL_ONLY",
               "artifacts": files,
               "local_finalization_errors": finalization_errors or [],
               "errors": errors, "complete_hash_manifest": not errors,
               "transfer_status": "PENDING_OPERATOR_TRANSFER_AND_MAC_VERIFICATION",
               "provider_STOPPED": "UNVERIFIED", "actual_all_in_cost": "PENDING_OPERATOR_LEDGER",
               "best_effort_only": True, "machine_or_network_failure_guarantee": False}
    write_json(out / "export-manifest.json", data, evidence_class)
    return data


def validate_evaluation(rows, context, name):
    require(isinstance(rows, list) and all(isinstance(r, dict) for r in rows) and
            [r.get("row") for r in rows] == list(range(7)), name + " row coverage invalid")
    require(all(type(r.get("strict_recall")) is bool and type(r.get("loss")) in (int, float) and
                math.isfinite(r["loss"]) and r["loss"] >= 0 for r in rows), name + " contains invalid recall/loss")
    require([r.get("row_content_sha256") for r in rows] ==
            [row_sha(r) for r in context["paths"]["engraving_rows"]], name + " row content binding differs")


def run_session(context, guard, backend_factory, evidence_class="measured"):
    """Only caller can supply a backend; real CLI uses the explicitly lazy CUDA backend."""
    out, m = context["output"], context["manifest"]
    no_symlink(out)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    status, reason, selected, backend = "FAILED", "not_started", None, None
    started = guard.clock()
    updates = 0
    gate_rows = []
    last_checkpoint = None
    events_path = out / "training-events.jsonl"
    try:
        write_json(out / "run-state.json", {"status": "RUNNING", "phase": "before_load"}, evidence_class)
        if context.get("manifest_bytes"):
            (out / "fixed-preregistration.json").write_bytes(context["manifest_bytes"])
        with events_path.open("x") as events:
            events.write(json.dumps({"evidence_class": evidence_class, "kind": "training_event_header"}) + "\n")
        guard.check()
        backend = backend_factory(context, guard)
        guard.check()
        backend.prepare(context, guard)
        guard.check()
        baseline = backend.evaluate(guard)
        write_json(out / "baseline-evaluation.json", baseline, evidence_class)
        rows = baseline.get("rows")
        validate_evaluation(rows, context, "Fresh baseline")
        actual_recalls = [r["strict_recall"] for r in baseline["rows"]]
        require(actual_recalls == context["baseline"]["strict_recall"], "Fresh baseline differs from preregistration; no training")
        require(not (actual_recalls[0] and actual_recalls[1]), "Targets already pass; no training")
        training_start = guard.clock()
        tick = lambda: guard.check(training_start, m["training"]["train_wall_seconds"])
        for epoch in range(1, m["training"]["max_epochs"] + 1):
            online = []
            order = [("corpus", i) for i in range(146)] + [("engraving", i) for i in context["paths"]["schedule_rows"]]
            for kind, row in order:
                tick()
                loss = backend.train_one(kind, row)
                if not math.isfinite(loss):
                    raise ValueError("Nonfinite training loss")
                updates += 1
                with events_path.open("a") as events:
                    events.write(json.dumps({"evidence_class": evidence_class, "update": updates,
                                            "epoch": epoch, "kind": kind, "row": row, "loss": loss}) + "\n")
                    events.flush()
                    os.fsync(events.fileno())
                online.append({"kind": kind, "row": row, "loss": loss})
                tick()
            backend.complete_epoch()
            gate = backend.evaluate(tick)
            tick()
            rows = gate.get("rows")
            write_json(out / ("gate-epoch-" + str(epoch) + "-evaluation.json"),
                       {**gate, "epoch": epoch, "checkpoint_binding": "UNBOUND_UNTIL_SAVE_COMPLETES"}, evidence_class)
            validate_evaluation(rows, context, "Gate")
            checkpoint = out / ("checkpoint-epoch-" + str(epoch))
            backend.save(checkpoint, tick)
            tick()
            write_json(checkpoint / "artifact-label.json", {"kind": "adapter-only checkpoint; not resumable training state",
                       "binary_label_sidecar": True, "epoch": epoch}, evidence_class)
            for name in ["adapter_model.safetensors", "adapter_config.json"]:
                artifact = no_symlink(checkpoint / name)
                if not artifact.is_file() or artifact.stat().st_size <= 0:
                    raise OSError("Checkpoint expected nonempty weights/config missing")
            checkpoint_files = [{"path": str(p.relative_to(out)), "sha256": sha(p, tick), "bytes": p.stat().st_size}
                                for p in sorted(checkpoint.rglob("*")) if p.is_file()]
            require(checkpoint_files, "Checkpoint contains no files")
            gate.update({"epoch": epoch, "checkpoint_files": checkpoint_files,
                         "online_losses": online, "criterion": "all-seven post-epoch loss plus strict character-prefix recall"})
            write_json(out / ("gate-epoch-" + str(epoch) + ".json"), gate, evidence_class)
            gate_rows.append(gate)
            last_checkpoint = str(checkpoint.relative_to(out))
            passed = max(r["loss"] for r in rows) <= m["metrics"]["loss_floor"] and all(r["strict_recall"] for r in rows)
            no_regression = all(not prior or rows[i]["strict_recall"] for i, prior in enumerate(actual_recalls))
            if epoch >= m["training"]["min_epoch"] and passed and no_regression:
                status, reason, selected = "PASS", "first_complete_passing_gate", str(checkpoint.relative_to(out))
                break
        else:
            status, reason = "FAIL", "complete_epoch_budget_without_passing_gate"
    except Interrupted as error:
        status, reason = "INCOMPLETE", str(error)
    except Refused as error:
        status, reason = "REFUSED", str(error)
    except (KeyboardInterrupt, SystemExit) as error:
        status, reason = "INCOMPLETE", type(error).__name__
    except Exception as error:
        status, reason = "FAILED", type(error).__name__ + ": " + str(error)
    finally:
        # A killed process/host can prevent this block. The independent supervisor owns that path.
        outcome = {"status": status, "reason": reason, "selected_checkpoint": selected,
                   "status_scope": "MODEL_PROTOCOL_ONLY; export/provider/cost completion is separate",
                   "last_completed_checkpoint": last_checkpoint,
                   "completed_gates": len(gate_rows), "worker_wall_seconds": guard.clock() - started,
                   "whole_runner_wall_seconds": guard.clock() - guard.started,
                   "completed_training_updates": updates,
                   "manifest_sha256": context.get("manifest_sha256"),
                   "command_argv": context.get("command_argv"),
                   "prospective_case_study_only": True, "no_machine_prediction_graded": True,
                   "provider_STOPPED": "UNVERIFIED", "actual_cost": "PENDING_OPERATOR_LEDGER",
                   "resume_authorized": False}
        final_errors = []
        supervision = m.get("supervision", {})
        outputs = [("outcome.json", outcome), ("stop-request.json", {
            "request": "EXPORT_AVAILABLE_ARTIFACTS_AND_STOP_EXISTING_INSTANCE",
            "run_id": m.get("run_id"), "session_id": supervision.get("session_id"),
            "controller_identity": supervision.get("controller_identity"),
            "provider_deadline_utc": supervision.get("provider_deadline_utc"),
            "worker_status": status, "provider_action_performed": False, "best_effort_only": True}),
            ("run-state.json", {"status": status, "phase": "terminal"})]
        for name, content in outputs:
            try:
                write_json(out / name, content, evidence_class)
            except Exception as error:
                final_errors.append({"file": name, "error_type": type(error).__name__})
        try:
            write_json(out / "finalization-status.json", {"model_protocol_status": status,
                       "local_finalization_errors": list(final_errors),
                       "local_export_status": "PENDING_NEXT_BEST_EFFORT_ATTEMPT",
                       "provider_STOPPED": "UNVERIFIED", "transfer_status": "UNVERIFIED"}, evidence_class)
        except Exception as error:
            final_errors.append({"file": "finalization-status.json", "error_type": type(error).__name__})
        try:
            # Native checkpoint files use the artifact-label sidecar; do not alter model formats.
            result_text = ("Evidence class: " + evidence_class.upper() + "; research-only run receipt.\n\n"
                + "# Runner outcome\n\nModel protocol status: " + status + ". Reason: " + reason + ".\n\n"
                + "Exact command argv: " + json.dumps(context.get("command_argv")) + ". Null means injected control fixture; see its outer capture receipt.\n\n"
                + "Whole runner wall seconds at terminal protocol state: " + str(outcome["whole_runner_wall_seconds"]) + ".\n\n"
                + "Completed updates: " + str(updates) + "; completed gates: " + str(len(gate_rows)) + ".\n\n"
                + "Local terminal write errors so far: " + json.dumps(final_errors) + ". See export-manifest and supervisor stdout for final export status.\n\n"
                + "Spend: PENDING_OPERATOR_LEDGER. Compute seconds × verified rate, storage, transfer/API and other charges require the operator's final ledger.\n\n"
                + "UNPROVEN: actual all-in cost, provider STOPPED, transferred-copy integrity, generalization, causal improvement and any historical prediction grade.\n\n"
                + "A model-protocol PASS does not establish export, shutdown or cost completion. Checkpoints are adapter-only; resume is not authorized.\n")
            target = no_symlink(out / "RESULTS.md")
            with target.open("x") as result_stream:
                result_stream.write(result_text)
                result_stream.flush()
                os.fsync(result_stream.fileno())
        except Exception as error:
            final_errors.append({"file": "RESULTS.md", "error_type": type(error).__name__})
        try:
            export = export_manifest(out, evidence_class, status, guard.check, final_errors)
        except Exception as error:
            final_errors.append({"file": "export-manifest.json", "error_type": type(error).__name__})
            outcome["local_export_manifest_confirmed"] = False
            outcome["local_export_hashes_complete"] = False
        else:
            outcome["local_export_manifest_confirmed"] = True
            outcome["local_export_hashes_complete"] = export["complete_hash_manifest"]
        outcome["local_finalization_errors"] = final_errors
        outcome["model_protocol_status"] = status
        if final_errors or not outcome.get("local_export_hashes_complete"):
            outcome["status"] = "INCOMPLETE"
            outcome["reason"] = "Model protocol=" + status + "; local evidence finalization incomplete"
    return outcome
