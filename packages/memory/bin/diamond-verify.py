#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prime-owned separate-process adapter over the unchanged Diamond consumer."""
from __future__ import annotations
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "genesis/vendor/kira-export"))
from diamond import kira_evidence as ke

try:
    record, receipt, log, anchor = map(Path, sys.argv[1:5])
    report = ke.verify_evidence(record_document=ke.read_json_strict(record),
        receipt_document=ke.read_json_strict(receipt), log_path=log,
        anchor_raw=ke.raw_public_key_bytes(anchor.read_text(encoding="utf8")))
    print(json.dumps(report, separators=(",", ":")))
except ke.Refusal as error:
    print(json.dumps({"verified": False, "status": "REFUSED", "refusal": {"code": error.code}}))
except Exception:
    print(json.dumps({"verified": False, "status": "REFUSED", "refusal": {"code": "memory:diamond-evidence-unreadable"}}))
