# Evidence class: SYNTHETIC fresh control fixtures only; no actual models, eligibility or provider qualification.
"""One bounded standard-library suite. Stubbed positive structures are never real approvals."""
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time

import baseline_runner as baseline
import prepare_baseline_registration as preparer
import runner_core as core

HERE = Path(__file__).resolve().parent


@contextmanager
def changed(owner, name, value):
    old = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield
    finally:
        setattr(owner, name, old)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_json(path, value):
    path.write_text(json.dumps({"evidence_class": "synthetic", **value}, indent=2) + "\n")
    return {"path": str(path), "sha256": digest(path)}


def invoke_preparer(source, parent, name):
    capture = io.StringIO()
    with changed(sys, "argv", ["prepare_baseline_registration.py", "--engraving", str(source),
                               "--output-parent", str(parent), "--run-id", name]), redirect_stdout(capture):
        result = preparer.main()
    return result, capture.getvalue()


def make_baseline_fixture(root):
    for name in ["base", "tokenizer", "adapter", "research/evidence"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    m = json.loads((HERE / "baseline-manifest-template.json").read_text())
    now = datetime.now(timezone.utc)
    m.update({"status": "REGISTERED", "run_id": "synthetic-baseline", "frozen_at_utc": now.isoformat()})
    m["roots"] = {"base_model": str(root / "base"), "tokenizer": str(root / "tokenizer"),
                  "parent_adapter": str(root / "adapter"), "output_parent": str(root / "research/evidence")}
    base_config = fixture_json(root / "base/config.json", {"fixture": True})
    for path in [root / "base/model.safetensors", root / "adapter/adapter_model.safetensors"]:
        path.write_bytes(b"SYNTHETIC opaque fixture, not valid tensor weights\n")
    config = fixture_json(root / "adapter/adapter_config.json", {"fixture": True})
    weights = {"path": str(root / "adapter/adapter_model.safetensors"), "sha256": digest(root / "adapter/adapter_model.safetensors")}
    tok = fixture_json(root / "tokenizer/tokenizer.json", {"fixture": True})
    inputs = m["inputs"]
    inputs.update({"parent_weights": weights, "parent_config": config, "base_files": [base_config,
                  {"path": str(root / "base/model.safetensors"), "sha256": digest(root / "base/model.safetensors")}],
                  "tokenizer_files": [tok], "runner_files": [{"path": str(p), "sha256": digest(p)}
                  for p in [HERE / "baseline_runner.py", baseline.CORE_DIR / "runner_core.py"]]})
    rows = [{"prompt": "SYNTHETIC INERT PROMPT " + str(i), "chosen": "SYNTHETIC INERT TARGET " + str(i)} for i in range(7)]
    eng = root / "engraving.json"
    eng.write_text(json.dumps(rows) + "\n")
    inputs["engraving"] = {"path": str(eng), "sha256": digest(eng), "row_content_sha256": [core.row_sha(r) for r in rows]}
    runtime = {"python": baseline.platform.python_version(), "packages": {p: "synthetic-version" for p in
               ["torch", "transformers", "peft", "safetensors"]}, "cuda_version": "synthetic", "device": "cuda:0", "qualified_context_tokens": 16384}
    m["runtime"] = runtime
    m["approval"].update({"explicit_go": True, "currency": "USD", "verified_hourly_rate_usd": 5,
                          "unavoidable_costs_upper_usd": 1, "paid_window_started_at_utc": now.isoformat()})
    deadline = (now + timedelta(seconds=3600)).isoformat()
    supervision = {"session_id": "synthetic-session", "controller_identity": "synthetic-controller",
                   "provider_target_sha256": "1" * 64, "heartbeat_file": str(root / "heartbeat.json"),
                   "heartbeat_max_age_seconds": 60, "provider_deadline_utc": deadline}
    m["supervision"] = supervision
    fixture_json(root / "heartbeat.json", {"run_id": m["run_id"], **supervision, "armed": True, "updated_at_utc": now.isoformat()})
    b = baseline.binding(inputs)
    inputs["runtime_receipt"] = fixture_json(root / "runtime.json", {"environment_binding_verified": True, "runtime": runtime, "binding": b})
    inputs["pricing_receipt"] = fixture_json(root / "price.json", {"currency": "USD", "verified_hourly_rate_usd": 5, "unavoidable_costs_upper_usd": 1})
    proofs = []
    for kind in ["independent_stop", "partial_export", "received_copy_verification"]:
        raw = fixture_json(root / (kind + "-raw.json"), {"fixture_only": True, "kind": kind})
        proofs.append(fixture_json(root / (kind + ".json"), {"status": "QUALIFIED", "qualification_kind": kind,
             "controller_identity": supervision["controller_identity"], "provider_target_sha256": supervision["provider_target_sha256"], "raw_receipt_files": [raw]}))
    inputs["supervisor_qualification_files"] = proofs
    inputs["supervisor_receipt"] = fixture_json(root / "supervisor.json", {"run_id": m["run_id"], **supervision,
        **{k: True for k in ["armed", "provider_stop_responsibility_acknowledged", "independent_stop_qualified", "partial_export_qualified", "received_copy_verification_qualified"]},
        "qualification_receipt_sha256s": sorted(p["sha256"] for p in proofs)})
    inputs["data_eligibility_receipt"] = fixture_json(root / "data.json", {"approved_for_this_baseline": True,
        "no_private_conversation_ingest": True, "no_safety_refused_replay": True, "engraving_sha256": inputs["engraving"]["sha256"]})
    inputs["disk_receipt"] = fixture_json(root / "disk.json", {"output_root": m["roots"]["output_parent"],
        "required_free_bytes": 1073741824, "available_bytes": 2147483648, "available_inodes": 1000, "measured_at_utc": now.isoformat()})
    return m


def main():
    print("Evidence class: SYNTHETIC fresh local fixtures; no model/provider qualification.", flush=True)
    started, timer = datetime.now(timezone.utc).isoformat(), time.perf_counter()
    checks = []
    model_modules = ["torch", "transformers", "peft", "safetensors"]
    assert all(p not in sys.modules for p in model_modules)
    def passed(name):
        checks.append({"name": name, "pass": True, "evidence_class": "synthetic"})
    for p in [HERE / "baseline_runner.py", HERE / "prepare_baseline_registration.py", baseline.CORE_DIR / "runner_core.py"]:
        compile(p.read_text(), p.name, "exec")
    passed("reviewed_python_sources_compile_without_execution")
    raw_template = (HERE / "baseline-manifest-template.json").read_bytes()
    for name, expected in [("unregistered_baseline_refuses", hashlib.sha256(raw_template).hexdigest()), ("manifest_hash_mismatch_refuses", "0" * 64)]:
        try:
            baseline.validate(raw_template, expected, core.Guard(), True)
        except core.Refused:
            passed(name)
        else:
            raise AssertionError(name)
    with tempfile.TemporaryDirectory(prefix="prime-focused-local-") as temp:
        root = Path(temp).resolve()
        parent = root / "preparer/research/evidence"
        parent.mkdir(parents=True)
        source = root / "synthetic-rows.json"
        rows = [{"prompt": "SYNTHETIC_DO_NOT_EXPORT_PROMPT_" + str(i), "chosen": "SYNTHETIC_DO_NOT_EXPORT_TARGET_" + str(i)} for i in range(7)]
        source.write_text(json.dumps(rows))
        with changed(preparer, "PINNED_ENGRAVING_SHA", digest(source)):
            code, _ = invoke_preparer(source, parent, "synthetic-good")
            out = parent / "preparation-synthetic-good"
            assert code == 0
            review = json.loads((out / "eligibility-review-DRAFT.json").read_text())
            draft = json.loads((out / "baseline-registration-DRAFT.json").read_text())
            assert review["review_status"] == "PENDING" and not any(k.startswith("approved_") for k in review)
            assert draft["status"] == "UNREGISTERED" and draft["frozen_at_utc"] is None and draft["approval"]["explicit_go"] is False
            assert draft["inputs"]["data_eligibility_receipt"] == {"path": None, "sha256": None}
            assert draft["inputs"]["engraving"]["row_content_sha256"] == [core.row_sha(r) for r in rows]
            assert all("SYNTHETIC_DO_NOT_EXPORT_" not in p.read_text() for p in out.iterdir() if p.is_file())
            passed("helper_hashes_existing_rows_without_text_or_approval_leak")
            sentinel = out / "sentinel.txt"
            sentinel.write_text("SYNTHETIC sentinel")
            before = {p.name: p.read_bytes() for p in out.iterdir()}
            code, _ = invoke_preparer(source, parent, "synthetic-good")
            assert code == 2 and {p.name:p.read_bytes() for p in out.iterdir()} == before
            passed("helper_existing_output_refused_without_mutation")
            original_write = preparer.write_json
            for name, target, error in [("first-write", "row-fingerprints.json", OSError), ("interrupt", "row-fingerprints.json", KeyboardInterrupt), ("terminal-write", "preparation-receipt.json", OSError)]:
                def injected(path, value, evidence_class, chosen=target, error_kind=error):
                    if Path(path).name == chosen:
                        raise error_kind("synthetic injected write interruption")
                    return original_write(path, value, evidence_class)
                with changed(preparer, "write_json", injected):
                    code, output = invoke_preparer(source, parent, "synthetic-" + name)
                results = parent / ("preparation-synthetic-" + name) / "RESULTS.md"
                assert code == 2 and results.is_file()
                if name == "terminal-write":
                    assert "preparation-receipt.json" in results.read_text() and "INCOMPLETE_PREPARATION" in output
                else:
                    assert (results.parent / "preparation-receipt.json").is_file()
                passed("helper_" + name + "_preserves_durable_failure")
        fixture_root = root / "baseline"
        m = make_baseline_fixture(fixture_root)
        try:
            baseline.read_receipt(Path(m["inputs"]["pricing_receipt"]["path"]))
        except core.Refused:
            passed("synthetic_receipt_refused_by_real_receipt_classifier")
        else:
            raise AssertionError("synthetic receipt accepted as measured")
        def fixture_receipt(path):
            value = json.loads(path.read_text())
            assert value["evidence_class"] == "synthetic"
            return value
        with changed(baseline, "PARENT_SHA", m["inputs"]["parent_weights"]["sha256"]), changed(baseline, "PARENT_CONFIG_SHA", m["inputs"]["parent_config"]["sha256"]), changed(baseline, "read_receipt", fixture_receipt), changed(baseline.metadata, "version", lambda _: "synthetic-version"), changed(baseline, "disk_check", lambda _: {"fixture_only": True}):
            def validate(value):
                raw = json.dumps(value).encode()
                return baseline.validate(raw, hashlib.sha256(raw).hexdigest(), core.Guard(wall_seconds=1800), True)
            context = validate(m)
            context["command_argv"] = ["SYNTHETIC injected baseline control call"]
            passed("synthetic_structural_positive_binding_no_backend")
            denied = json.loads(json.dumps(m))
            denied["approval"]["explicit_go"] = False
            try:
                validate(denied)
            except core.Refused:
                passed("missing_baseline_scope_readiness_refuses")
            else:
                raise AssertionError("scope readiness accepted")
            original_proof = Path(m["inputs"]["supervisor_qualification_files"][0]["path"])
            proof_bytes = original_proof.read_bytes()
            for name, update in [("wrong_target", {"provider_target_sha256":"2"*64}), ("wrong_controller", {"controller_identity":"another-synthetic-controller"}), ("missing_raw", {"raw_receipt_files": []}), ("raw_hash_mismatch", {"raw_receipt_files": [{"path":str(fixture_root/"independent_stop-raw.json"),"sha256":"0"*64}]})]:
                changed_manifest = json.loads(json.dumps(m))
                proof = json.loads(proof_bytes)
                proof.update(update)
                original_proof.write_text(json.dumps(proof))
                changed_manifest["inputs"]["supervisor_qualification_files"][0]["sha256"] = digest(original_proof)
                supervisor_path = fixture_root / "supervisor.json"
                supervisor_original = supervisor_path.read_bytes()
                supervisor = json.loads(supervisor_original)
                supervisor["qualification_receipt_sha256s"] = sorted(p["sha256"] for p in changed_manifest["inputs"]["supervisor_qualification_files"])
                supervisor_path.write_text(json.dumps(supervisor))
                changed_manifest["inputs"]["supervisor_receipt"]["sha256"] = digest(supervisor_path)
                try:
                    validate(changed_manifest)
                except core.Refused:
                    passed("qualification_" + name + "_refuses_before_backend")
                else:
                    raise AssertionError(name)
                finally:
                    original_proof.write_bytes(proof_bytes)
                    supervisor_path.write_bytes(supervisor_original)
            calls = []
            class NoModelBackend:
                def __init__(self, *_):
                    calls.append(True)
                    raise OSError("synthetic injected loader failure; no model loaded")
            existing = dict(context, output=fixture_root / "research/evidence/existing")
            existing["output"].mkdir()
            marker = existing["output"] / "sentinel.txt"
            marker.write_text("SYNTHETIC baseline sentinel")
            with changed(baseline, "InferenceBackend", NoModelBackend):
                try:
                    baseline.execute(existing, core.Guard())
                except FileExistsError:
                    assert calls == [] and marker.read_text() == "SYNTHETIC baseline sentinel"
                    passed("baseline_existing_output_refuses_before_backend")
                else:
                    raise AssertionError("existing baseline output accepted")
                failed = baseline.execute(context, core.Guard())
                assert failed["status"] == "FAILED" and failed["provider_STOPPED"] == "UNVERIFIED"
                assert (context["output"] / "stop-request.json").exists() and (context["output"] / "RESULTS.md").exists()
                passed("baseline_load_failure_preserves_stop_and_results_without_STOPPED_claim")
                context2 = dict(context, output=fixture_root / "research/evidence/export-failed")
                def no_export(*_):
                    raise OSError("synthetic injected export write failure")
                with changed(baseline, "export_manifest", no_export):
                    incomplete = baseline.execute(context2, core.Guard())
                assert incomplete["status"] == "INCOMPLETE" and (context2["output"] / "stop-request.json").exists()
                passed("baseline_export_failure_is_incomplete_and_keeps_independent_stop_request")
    assert all(p not in sys.modules for p in model_modules)
    report = {"evidence_class": "synthetic", "reference_only": True,
        "command": "python3 focused_local_checks.py", "started_at_utc": started, "wall_seconds": time.perf_counter()-timer,
        "checks": checks, "pass_count":len(checks), "failure_count":0, "model_stack_imports":0,"model_calls":0,"provider_calls":0,
        "new_paid_experiment_spend_usd":0,
        "test_only_injections":["synthetic parent pins", "synthetic receipt classification", "package metadata availability", "remote filesystem headroom", "no-model failure backend"],
        "fixture_retention":"Fresh temporary fixtures only; no old refused cases; no fake measured qualification/model artifact retained in reference packet",
        "does_not_establish":["real data eligibility", "original base identity", "GPU/model fit", "actual independent stop/export", "registered trial", "training", "all-in account spend"]}
    (HERE / "focused-local-checks.results.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"pass_count":len(checks),"failure_count":0,"wall_seconds":report["wall_seconds"],"model_calls":0,"provider_calls":0}))


if __name__ == "__main__":
    main()
