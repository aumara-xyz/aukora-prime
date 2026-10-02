# SYNTHETIC: newly authored fail-closed reference tooling; not the archived generator.
"""Inventory corpus eligibility without treating narrative reports as receipts.

No receipt-chain verifier or sanitized source receipts were supplied to this lab.
This implementation therefore has NO acceptance adapter. It exports zero examples
and explicit rejection metadata. It cannot be used to claim a verified corpus.
An independently reviewed adapter bound to actual verifier outputs is required
before accepting any future receipt; corpus_eligible flags do not authorize it.
"""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    raw = args.inventory.read_bytes()
    data = json.loads(raw)
    if data.get('reference_only') is not True:
        raise ValueError('inventory must be reference only')
    sources = data.get('sources', [])
    rejected = [{'source_id': s['source_id'], 'revision': s.get('revision'),
                 'reason': 'NO_REVIEWED_RECEIPT_VERIFIER_ADAPTER: ' + s.get('reason', 'source cannot be accepted')}
                for s in sources]
    result = {'evidence_class': 'measured', 'measurement_kind': 'corpus_inventory_execution',
              'input_class': 'historical_report_and_source_metadata', 'reference_only': True,
              'status': 'NO_VERIFIED_RECEIPTS', 'training_performed': False,
              'example_count': 0, 'accepted_source_revision_count': 0,
              'accepted_source_revisions': [],
              'inventoried_source_revision_count': len({s.get('revision') for s in sources}),
              'inventoried_source_revisions': sorted({s.get('revision') for s in sources}),
              'inventory_sha256': hashlib.sha256(raw).hexdigest(),
              'rejected_source_count': len(rejected), 'rejections': rejected,
              'examples': [], 'paid_spend_usd': 0}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'evidence_class': 'measured', 'status': result['status'],
                      'example_count': 0, 'source_revision_coverage': 0,
                      'rejected_source_count': len(rejected), 'training_performed': False}))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
