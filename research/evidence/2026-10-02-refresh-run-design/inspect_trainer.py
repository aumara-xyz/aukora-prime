# Evidence class: MEASURED static source inspection; archived trainer is not executed.
import ast
import hashlib
import json
import re
from pathlib import Path
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent


def main():
    start = datetime.now(timezone.utc).isoformat()
    clock = time.perf_counter()
    source = Path.home() / "aukora-lab/train_burn18-hybrid.py"
    raw = source.read_bytes()
    if len(raw) > 65536:
        raise ValueError("named trainer exceeds static inspection size bound")
    tree = ast.parse(raw)
    expressions = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [ast.unparse(t) for t in node.targets]
            if any(name in {"BASE", "HERE", "CORPUS", "ENGRAVE", "CARRIER", "OUT", "REPEAT", "EPOCHS_CAP, WALL_CAP_MIN", "(EPOCHS_CAP, WALL_CAP_MIN)", "MIN_EPOCH", "(LR, MAXLEN, SEED, FLOOR)"} for name in names):
                expressions.append({"line": node.lineno, "names": names,
                                    "expression": re.sub(r"/home/[^/]+", "${REMOTE_HOME}", ast.unparse(node.value))})
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func)
            if any(t in name for t in ["AdamW", "backward", "save_pretrained", "from_pretrained", "generate"]):
                calls.append({"line": node.lineno, "call": name})
    report = {
        "evidence_class": "measured", "reference_only": True,
        "kind": "named_recovered_trainer_static_inspection",
        "source_id": "aukora-lab/train_burn18-hybrid.py", "source_bytes": len(raw),
        "source_sha256": hashlib.sha256(raw).hexdigest(), "assignments": expressions,
        "selected_calls": calls,
        "observations": {
            "actual_optimizer_backward_loop": True,
            "default_output_generation": "gen-17; MUST NOT RUN DEFAULT",
            "fixed_receipt_name": "burn-18-receipt.json; explicit OUT does not redirect receipt",
            "corpus_rows_expected": 146, "engraving_rows_expected": 7,
            "repeat_default": 20, "minimum_epoch": 3, "epoch_cap": 6,
            "training_loop_wall_cap_minutes": 80, "max_token_length": 16384,
            "seed": 20260904, "learning_rate": 0.0001, "loss_floor": 0.001,
            "source_order": "146 corpus rows followed by engraving block, unlike comment",
            "loss_gate": "max of last 100 online engraving losses, not post-epoch max across all seven rows",
            "recall_gate": "original.strip()[:240] is a substring of generated decoded text; characters, not byte equality",
            "generation": "greedy; max_new_tokens=120; skip_special_tokens=False",
            "wall_cap_scope": "starts after loading/tokenizing; checked between training steps; not a hard cap on gates, saves or provider lifecycle",
            "per_epoch_checkpoint_save": True,
            "current_share_knob": "none; all seven engraving rows receive equal repeat count"
        },
        "raw_training_texts_exported": False, "archived_source_imported_or_executed": False,
        "model_calls": 0, "provider_actions": 0,
    }
    (HERE / "trainer-inspection.json").write_text(json.dumps(report, indent=2) + "\n")
    ledger = {"evidence_class": "measured", "reference_only": True,
              "command": "python3 inspect_trainer.py > trainer-inspection.stdout.txt",
              "started_at_utc": start, "wall_seconds": time.perf_counter() - clock,
              "model_calls": 0, "provider_actions": 0, "cloud_compute_seconds": 0,
              "new_storage_resources": 0, "new_paid_experiment_spend_usd": 0,
              "standing_storage_cost": "UNVERIFIED; no provider call",
              "spend_scope_excludes": ["standing storage", "host energy", "subscription/agent usage"]}
    (HERE / "run-ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    print("Evidence class: MEASURED static inspection only; no archived source/model execution.")
    print(json.dumps({"source_sha256": report["source_sha256"], "wall_seconds": ledger["wall_seconds"], "new_paid_experiment_spend_usd": 0}))


if __name__ == "__main__":
    main()
