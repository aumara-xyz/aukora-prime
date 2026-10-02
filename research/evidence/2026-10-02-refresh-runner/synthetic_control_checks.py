# Evidence class: SYNTHETIC injected control-flow fixtures; no real models/training/providers.
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
from datetime import timedelta

import runner_core as core
import refresh_runner

HERE = Path(__file__).resolve().parent


class Clock:
    def __init__(self):
        self.value = 0.0
    def __call__(self):
        return self.value
    def advance(self, seconds):
        self.value += seconds


class StubBackend:
    """No tensors, optimizer, tokenizer or model library; fixed synthetic replies."""
    def __init__(self, context, guard, load_delay=0, fail_load=False, step_delay=0, fail_save=False):
        self.context, self.guard = context, guard
        self.evaluations, self.updates = 0, 0
        self.step_delay, self.fail_save = step_delay, fail_save
        guard.clock.advance(load_delay)
        if fail_load:
            raise RuntimeError("synthetic injected loader failure")
    def prepare(self, context, guard):
        pass
    def train_one(self, kind, row):
        self.updates += 1
        self.guard.clock.advance(self.step_delay)
        return 0.01
    def complete_epoch(self):
        pass
    def evaluate(self, check):
        self.evaluations += 1
        recalls = [False, False, True, True, True, True, True] if self.evaluations == 1 else [True] * 7
        return {"rows": [{"row": i, "loss": 0.0001, "strict_recall": recalls[i],
                           "generated": "SYNTHETIC stub text",
                           "row_content_sha256": core.row_sha(self.context["paths"]["engraving_rows"][i])}
                          for i in range(7)]}
    def save(self, checkpoint, tick):
        checkpoint.mkdir()
        core.write_json(checkpoint / "artifact-label.json", {"binary_fixture": True}, "synthetic")
        (checkpoint / "adapter_model.safetensors").write_bytes(b"SYNTHETIC opaque fixture, not valid model weights")
        core.write_json(checkpoint / "adapter_config.json", {"fixture": "not a model configuration"}, "synthetic")
        if self.fail_save:
            raise OSError("synthetic injected checkpoint write failure")


def context(root, name):
    return {"output": root / name, "manifest": {
        "training": {"min_epoch": 1, "max_epochs": 1, "train_wall_seconds": 100},
        "metrics": {"loss_floor": 0.001}, "supervision": {"session_id": "synthetic"}},
        "paths": {"schedule_rows": [i for i, n in enumerate(core.QUOTA) for _ in range(n)],
                  "engraving_rows": [{"prompt": "SYNTHETIC prompt " + str(i),
                                      "chosen": "SYNTHETIC target " + str(i)} for i in range(7)]},
        "baseline": {"strict_recall": [False, False, True, True, True, True, True]},
        "manifest_sha256": None}


def main():
    print("Evidence class: SYNTHETIC injected CPU fixtures only; no real model/provider execution.", flush=True)
    started, clock_start = core.utcnow().isoformat(), time.perf_counter()
    checks = []
    def passed(name, details=None):
        checks.append({"name": name, "pass": True, "evidence_class": "synthetic", "details": details})
    require_absent = ["torch", "transformers", "peft", "safetensors"]
    assert all(name not in sys.modules for name in require_absent)
    template = (HERE / "manifest-template.json").read_bytes()
    for label, expected_sha in [("unregistered_manifest", hashlib.sha256(template).hexdigest()),
                                 ("manifest_hash_mismatch", "0" * 64)]:
        try:
            core.validate_manifest(template, expected_sha, core.Guard(), execute=True)
        except core.Refused:
            passed(label)
        else:
            raise AssertionError(label + " was not refused")
    with tempfile.TemporaryDirectory(prefix="prime-synthetic-control-") as temp:
        # Canonicalize our newly created fixture directory; do not weaken real input-path guards.
        root = Path(temp).resolve() / "research/evidence"
        root.mkdir(parents=True)
        existing = context(root, "existing")
        existing["output"].mkdir()
        sentinel = existing["output"] / "sentinel.txt"
        sentinel.write_text("Evidence class: SYNTHETIC existing-output sentinel\n")
        original = sentinel.read_bytes()
        calls = []
        try:
            core.run_session(existing, core.Guard(clock=Clock()), lambda *_: calls.append(True), "synthetic")
        except FileExistsError:
            assert not calls and sentinel.read_bytes() == original
            passed("existing_output_refused_without_backend_or_overwrite")
        else:
            raise AssertionError("existing output accepted")
        success_context = context(root, "success")
        success = core.run_session(success_context, core.Guard(clock=Clock()), StubBackend, "synthetic")
        assert success["status"] == "PASS" and success["completed_training_updates"] == 286
        export = json.loads((success_context["output"] / "export-manifest.json").read_text())
        assert export["complete_hash_manifest"] and export["provider_STOPPED"] == "UNVERIFIED"
        assert export["transfer_status"] == "PENDING_OPERATOR_TRANSFER_AND_MAC_VERIFICATION"
        gate = json.loads((success_context["output"] / "gate-epoch-1.json").read_text())
        assert gate["checkpoint_files"] and success["selected_checkpoint"] == "checkpoint-epoch-1"
        passed("synthetic_pass_binds_checkpoint_but_never_claims_transfer_or_STOPPED")
        failed_context = context(root, "loader-failed")
        failed = core.run_session(failed_context, core.Guard(clock=Clock()),
                                  lambda c, g: StubBackend(c, g, fail_load=True), "synthetic")
        assert failed["status"] == "FAILED" and failed["completed_training_updates"] == 0
        assert (failed_context["output"] / "stop-request.json").is_file()
        assert (failed_context["output"] / "export-manifest.json").is_file()
        passed("loader_failure_records_failed_outcome_and_best_effort_manifest")
        late_context = context(root, "late-load")
        late = core.run_session(late_context, core.Guard(clock=Clock(), wall_seconds=3),
                                lambda c, g: StubBackend(c, g, load_delay=4), "synthetic")
        assert late["status"] == "INCOMPLETE" and late["completed_training_updates"] == 0
        assert late["whole_runner_wall_seconds"] == 4
        late_export = json.loads((late_context["output"] / "export-manifest.json").read_text())
        assert not late_export["complete_hash_manifest"]
        passed("whole_timer_counts_loading_and_expired_export_hashes_are_uncompleted")
        partial_context = context(root, "partial-update")
        partial = core.run_session(partial_context, core.Guard(clock=Clock(), wall_seconds=3),
                                   lambda c, g: StubBackend(c, g, step_delay=4), "synthetic")
        assert partial["status"] == "INCOMPLETE" and partial["completed_training_updates"] == 1
        lines = (partial_context["output"] / "training-events.jsonl").read_text().splitlines()
        assert len(lines) == 2 and json.loads(lines[1])["update"] == 1
        passed("interrupted_update_retains_partial_event_and_no_pass")
        save_context = context(root, "save-failed")
        save = core.run_session(save_context, core.Guard(clock=Clock()),
                                lambda c, g: StubBackend(c, g, fail_save=True), "synthetic")
        assert save["status"] == "FAILED" and save["selected_checkpoint"] is None
        assert (save_context["output"] / "gate-epoch-1-evaluation.json").exists()
        save_export = json.loads((save_context["output"] / "export-manifest.json").read_text())
        assert any(r["path"].endswith("adapter_model.safetensors") for r in save_export["artifacts"])
        passed("save_failure_retains_unbound_gate_and_labels_partial_binary_fixture")
        class NonfiniteBaseline(StubBackend):
            def evaluate(self, check):
                value = super().evaluate(check)
                value["rows"][0]["loss"] = float("nan")
                return value
        invalid = core.run_session(context(root, "invalid-baseline"), core.Guard(clock=Clock()),
                                    NonfiniteBaseline, "synthetic")
        assert invalid["status"] == "REFUSED" and invalid["completed_training_updates"] == 0
        passed("nonfinite_fresh_baseline_refuses_before_training")
        original_write = core.write_json
        def fail_first_state(path, data, evidence_class="measured"):
            if Path(path).name == "run-state.json" and data.get("status") == "RUNNING":
                raise OSError("synthetic injected first-state write failure")
            return original_write(path, data, evidence_class)
        core.write_json = fail_first_state
        try:
            initial_context = context(root, "initial-write-failed")
            initial = core.run_session(initial_context, core.Guard(clock=Clock()), StubBackend, "synthetic")
        finally:
            core.write_json = original_write
        assert initial["status"] == "FAILED" and initial["completed_training_updates"] == 0
        assert (initial_context["output"] / "stop-request.json").exists()
        assert (initial_context["output"] / "export-manifest.json").exists()
        passed("initial_write_failure_still_attempts_stop_request_and_export")
        def fail_outcome(path, data, evidence_class="measured"):
            if Path(path).name == "outcome.json":
                raise OSError("synthetic injected outcome write failure")
            return original_write(path, data, evidence_class)
        core.write_json = fail_outcome
        try:
            terminal_context = context(root, "terminal-write-failed")
            terminal = core.run_session(terminal_context, core.Guard(clock=Clock()), StubBackend, "synthetic")
        finally:
            core.write_json = original_write
        assert terminal["status"] == "INCOMPLETE" and terminal["model_protocol_status"] == "PASS"
        assert (terminal_context["output"] / "stop-request.json").exists()
        assert (terminal_context["output"] / "export-manifest.json").exists()
        passed("terminal_outcome_failure_does_not_skip_stop_or_export_and_precludes_complete_PASS")
        durable = json.loads((terminal_context["output"] / "export-manifest.json").read_text())
        assert durable["local_finalization_errors"][0]["file"] == "outcome.json"
        assert (terminal_context["output"] / "RESULTS.md").read_text().startswith("Evidence class: SYNTHETIC")
        passed("terminal_write_failure_and_RESULT_receipt_are_durable")
        for flaw in ["negative_loss", "truthy_recall", "wrong_row_hash"]:
            class InvalidGate(StubBackend):
                def evaluate(self, check):
                    value = super().evaluate(check)
                    if self.evaluations > 1:
                        if flaw == "negative_loss":
                            value["rows"][0]["loss"] = -0.01
                        elif flaw == "truthy_recall":
                            value["rows"][0]["strict_recall"] = "true"
                        else:
                            value["rows"][0]["row_content_sha256"] = "0" * 64
                    return value
            rejected = core.run_session(context(root, flaw), core.Guard(clock=Clock()), InvalidGate, "synthetic")
            assert rejected["status"] == "REFUSED" and rejected["selected_checkpoint"] is None
            passed("invalid_gate_" + flaw + "_refused")
        class MissingWeights(StubBackend):
            def save(self, checkpoint, tick):
                checkpoint.mkdir()
                core.write_json(checkpoint / "artifact-label.json", {"fixture": "weights absent"}, "synthetic")
        missing = core.run_session(context(root, "missing-weights"), core.Guard(clock=Clock()), MissingWeights, "synthetic")
        assert missing["status"] == "FAILED" and missing["selected_checkpoint"] is None
        passed("sidecar_alone_never_counts_as_saved_checkpoint")
        badfile = root / "hash-input.txt"
        badfile.write_text("Evidence class: SYNTHETIC tiny input\n")
        try:
            core.input_file({"path": str(badfile), "sha256": "0" * 64}, core.Guard())
        except core.Refused:
            passed("input_hash_mismatch_refused")
        else:
            raise AssertionError("input hash mismatch accepted")
        heartbeat = root / "heartbeat.json"
        now = core.utcnow()
        deadline = (now + timedelta(seconds=7200)).isoformat()
        heartbeat.write_text(json.dumps({"evidence_class": "synthetic", "session_id": "fixture",
             "controller_identity": "cpu-fixture", "run_id": "fixture", "provider_deadline_utc": deadline,
             "armed": True, "updated_at_utc": (now - timedelta(seconds=61)).isoformat()}))
        supervised = {"run_id": "fixture", "approval": {"currency": "USD", "verified_hourly_rate_usd": 5,
             "unavoidable_costs_upper_usd": 1, "ceiling_usd": 30, "max_window_seconds": 14400,
             "runner_wall_seconds": 7200, "teardown_reserve_seconds": 1200,
             "paid_window_started_at_utc": now.isoformat()}, "supervision": {"session_id": "fixture",
             "controller_identity": "cpu-fixture", "heartbeat_file": str(heartbeat),
             "heartbeat_max_age_seconds": 60, "provider_deadline_utc": deadline}}
        try:
            core.Guard(now=lambda: now).configure(supervised)
        except core.Interrupted:
            passed("stale_independent_heartbeat_interrupts")
        else:
            raise AssertionError("stale heartbeat accepted")
        supervised["supervision"]["session_id"] = None
        try:
            core.Guard(now=lambda: now).configure(supervised)
        except core.Refused:
            passed("null_supervisor_identity_refused")
        else:
            raise AssertionError("null supervisor identity accepted")
    assert all(name not in sys.modules for name in require_absent)
    report = {"evidence_class": "synthetic", "reference_only": True,
              "kind": "injected_CPU_control_flow_checks_not_model_or_provider_qualification",
              "command": "python3 capture_synthetic_checks.py",
              "started_at_utc": started, "wall_seconds": time.perf_counter() - clock_start,
              "checks": checks, "pass_count": len(checks), "failure_count": 0,
              "real_model_calls": 0, "model_stack_imports": 0, "provider_actions": 0,
              "new_paid_experiment_spend_usd": 0, "cloud_compute_seconds": 0,
              "new_storage_resources": 0, "standing_storage_cost": "UNVERIFIED; no provider action",
              "spend_scope_excludes": ["standing storage", "host energy", "subscription/agent usage"],
              "does_not_establish": ["CUDA compatibility", "actual training", "memory/time qualification",
                                      "provider stop", "network transfer", "registered experiment", "improvement"]}
    (HERE / "synthetic-check-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass_count": len(checks), "failure_count": 0, "wall_seconds": report["wall_seconds"],
                      "real_model_calls": 0, "new_paid_experiment_spend_usd": 0}))


if __name__ == "__main__":
    main()
