# Evidence class: SYNTHETIC unexecuted registration-preparation source; no eligibility decision or model result.
"""After approved local inspection, hash the existing seven rows and emit private UNREGISTERED drafts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

PINNED_ENGRAVING_SHA = "d465ead722c1fb2bcfd08f30eb82b098539d47b2e6380d9157e6b5981f197beb"
PINNED_TEMPLATE_SHA = "15318a2ae55b3e37a5b28c6fea79215bb1754f9992feb815a5c6003434ef4c3c"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def nonsymlink(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in [path, *path.parents]), "Symlink path refused")
    return path


def row_sha(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def write_json(path, data, evidence_class):
    with nonsymlink(path).open("x") as stream:
        json.dump({"evidence_class": evidence_class, "reference_only": True, **data}, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    timer = time.perf_counter()
    started = datetime.now(timezone.utc).isoformat()
    parser = argparse.ArgumentParser(description="Prepare private row hashes and pending review; cannot register or authorize a run")
    parser.add_argument("--engraving", required=True)
    parser.add_argument("--output-parent", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print("Evidence class: MEASURED local fingerprint telemetry only; eligibility and registration remain pending.", flush=True)
    output = None
    created = False
    errors = []
    try:
        require(re.fullmatch("[a-z0-9][a-z0-9-]{0,48}", args.run_id), "Prospective baseline run ID invalid")
        engraving = nonsymlink(args.engraving).resolve(strict=True)
        parent = nonsymlink(args.output_parent).resolve(strict=True)
        require(parent.is_dir() and engraving.is_file(), "Existing output parent and regular source file required")
        parts = parent.parts
        require(any(parts[i:i+2] == ("research", "evidence") for i in range(len(parts)-1)), "Private research/evidence output required")
        output = parent / ("preparation-" + args.run_id)
        require(not output.exists() and not output.is_symlink(), "Existing preparation directory refused")
        require(output not in engraving.parents, "Preparation overlaps original input")
        require(engraving.stat().st_size <= 4 * 1024 * 1024, "Input exceeds bounded inspection size")
        raw = engraving.read_bytes()
        source_sha = hashlib.sha256(raw).hexdigest()
        require(source_sha == PINNED_ENGRAVING_SHA, "Existing seven-row source differs; do not invent replacements")
        def reject_constant(value):
            raise ValueError("Nonstandard JSON constant: " + value)
        rows = json.loads(raw, parse_constant=reject_constant)
        require(isinstance(rows, list) and len(rows) == 7, "Exact seven-row source required")
        require(all(isinstance(r, dict) and isinstance(r.get("prompt"), str) and r["prompt"].strip() and
                    isinstance(r.get("chosen", r.get("completion")), str) and
                    r.get("chosen", r.get("completion")).strip() for r in rows), "Invalid existing row schema")
        hashes = [row_sha(r) for r in rows]
        template_path = nonsymlink(Path(__file__).with_name("baseline-manifest-template.json"))
        template_raw = template_path.read_bytes()
        require(hashlib.sha256(template_raw).hexdigest() == PINNED_TEMPLATE_SHA, "Reviewed draft template changed")
        draft = json.loads(template_raw)
        require(draft.get("status") == "UNREGISTERED" and draft.get("execution_mode") == "baseline_inference_only" and
                draft.get("approval", {}).get("explicit_go") is False, "Unregistered baseline-only template required")
        output.mkdir(mode=0o700)
        created = True
        write_json(output / "row-fingerprints.json", {
            "kind": "canonical_hashes_of_existing_rows_not_case_labels_or_eligibility",
            "source_sha256": source_sha, "source_bytes": len(raw), "source_row_count": 7,
            "canonicalization": "UTF-8 json.dumps(row,sort_keys=True,ensure_ascii=False,separators=(',',':'))",
            "rows": [{"row": i, "row_content_sha256": h} for i, h in enumerate(hashes)],
            "raw_text_exported": False, "eligibility_inferred": False, "ground_truth_labels_created": False}, "measured")
        eligibility = {
            "status": "PENDING_OWNER_REVIEW", "requested_scope": "existing_weight_baseline_only", "engraving_sha256": source_sha,
            "row_content_sha256": hashes, "derived_measurements": "row-fingerprints.json",
            "review_status": "PENDING", "training_review_status": "NOT_REQUESTED",
            "private_conversation_screening_status": "UNREVIEWED", "stopped_refused_case_screening_status": "UNREVIEWED",
            "reviewer_identity": None, "reviewer_role": None, "reviewed_at_utc": None, "instruction_reference": None,
            "source_rights_and_provenance_verified": None, "review_receipt_sha256s": [],
            "per_row_review": [{"row": i, "row_content_sha256": h, "disposition": "PENDING",
                                "source_provenance": None, "private_conversation_origin_excluded": None,
                                "safety_refused_replay_excluded": None, "decision_receipt_sha256s": []}
                               for i, h in enumerate(hashes)],
            "intended_processing_boundary": "Local-only model loading/inference on the named existing H200; private row transfer/use requires owner review; no optimizer or updates",
            "intended_export_boundary": "Raw texts/paths/results private until reviewed; public reference only sanitized metadata",
            "permitted_use_decision": "PENDING",
            "cannot_authorize": ["model execution", "training", "corpus promotion", "new permissions/resources/model scope"]}
        write_json(output / "eligibility-review-DRAFT.json", eligibility, "synthetic")
        draft["run_id"] = args.run_id
        draft["frozen_at_utc"] = None
        draft["status"] = "UNREGISTERED"
        draft["approval"]["explicit_go"] = False
        draft["inputs"]["engraving"].update({"path": str(engraving), "sha256": source_sha, "row_content_sha256": hashes})
        draft["preparation_provenance"] = {"helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "template_sha256": PINNED_TEMPLATE_SHA, "row_fingerprints_sha256": hashlib.sha256((output / "row-fingerprints.json").read_bytes()).hexdigest(),
            "review_status": "PENDING; source hashing does not register an experiment"}
        # Eligibility path/hash deliberately stays null until a genuine reviewed receipt exists.
        write_json(output / "baseline-registration-DRAFT.json", draft, "synthetic")
        status, reason = "DRAFTS_PREPARED_NOT_REGISTERED", "Seven existing row hashes; owner review and all operational gates still pending"
    except Exception as error:
        status, reason = "REFUSED_OR_FAILED", type(error).__name__ + ": " + str(error)
    except (KeyboardInterrupt, SystemExit) as error:
        status, reason = "INCOMPLETE_PREPARATION", type(error).__name__
    # Finalize ordinary failures too, but never write into a refused pre-existing directory.
    if created:
        try:
            write_json(output / "preparation-receipt.json", {"status": status, "reason": reason,
                "command_argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
                "started_at_utc": started, "wall_seconds": time.perf_counter() - timer,
                "model_calls": 0, "provider_calls": 0, "registered": False, "data_approved": False,
                "training_authorized": False, "raw_text_exported": False}, "measured")
        except Exception as error:
            errors.append({"file": "preparation-receipt.json", "error_type": type(error).__name__})
        try:
            with nonsymlink(output / "RESULTS.md").open("x") as stream:
                stream.write("Evidence class: MEASURED local fingerprint/preparation telemetry; eligibility/registration drafts are SYNTHETIC.\n\n"
                    + "Status: " + status + ". " + reason + ".\n\nExact argv: "
                    + json.dumps([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
                    + ".\n\nWall seconds: " + str(time.perf_counter() - timer)
                    + ".\n\nNo model/provider calls; no data approval, registration or training authorization.\n\n"
                    + "Status scope: draft-preparation protocol only; final completion/errors are reported in retained stdout.\n\n"
                    + "Local finalization errors before this RESULTS write: " + json.dumps(errors) + ".\n\n"
                    + "Cost: no model/API/resource-creation action; host/standing charges require separate ledger if applicable.\n\n"
                    + "UNPROVEN: provenance/eligibility, base/runtime/disk, qualified stop/export, actual model behavior and all-in spend.\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception as error:
            errors.append({"file": "RESULTS.md", "error_type": type(error).__name__})
    if errors:
        status = "INCOMPLETE_PREPARATION"
    print(json.dumps({"status": status, "reason": reason, "local_finalization_errors": errors,
                      "registered": False, "data_approved": False, "training_authorized": False}))
    return 0 if status == "DRAFTS_PREPARED_NOT_REGISTERED" and not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
