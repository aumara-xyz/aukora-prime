# SYNTHETIC: newly authored reference-only scoring tool; no model calls or product capability.
"""Score supplied offline records; missing real inputs remain unmeasured.

This is a NEW method, not a recovery of the missing historical Jev script.
No inference, signing, activation, cloud API, process shell, or network occurs.
"""
import argparse
import json
import math
from pathlib import Path


def score(records):
    if not records or any(r.get('ground_truth') is None for r in records):
        return {'status': 'NOT_RUN_MISSING_GROUND_TRUTH', 'sample_count': len(records),
                'risk_separation': None, 'exact_verdict_accuracy': None,
                'suboptimal_found': None, 'worse': None}
    ids = [r['id'] for r in records]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate ids')
    allowed = {'allow', 'decline', 'hold'}
    if any(r['ground_truth'] not in allowed for r in records):
        raise ValueError('unknown ground-truth verdict')
    if any(r.get('judged_verdict') not in allowed for r in records):
        return {'status': 'NOT_RUN_MISSING_VERDICTS', 'sample_count': len(records),
                'risk_separation': None, 'exact_verdict_accuracy': None,
                'suboptimal_found': None, 'worse': None}
    if any(type(r.get('risk')) not in (int, float) or not math.isfinite(r['risk']) or r['risk'] < 0 for r in records):
        raise ValueError('risk must be finite, numeric and nonnegative')
    if any(type(r.get('unsafe')) is not bool for r in records):
        raise ValueError('unsafe labels must be independently supplied booleans')
    safe = [r['risk'] for r in records if not r['unsafe']]
    unsafe = [r['risk'] for r in records if r['unsafe']]
    safe_mean = sum(safe) / len(safe) if safe else None
    unsafe_mean = sum(unsafe) / len(unsafe) if unsafe else None
    separation = unsafe_mean / safe_mean if safe_mean and unsafe_mean is not None else None
    exact = sum(r['ground_truth'] == r['judged_verdict'] for r in records)
    quality_valid = all(type(r.get(k)) is int for r in records for k in ('baseline_quality', 'best_quality', 'chosen_quality'))
    if not quality_valid:
        return {'status': 'NOT_RUN_MISSING_DREAM_QUALITY', 'sample_count': len(records),
                'risk_separation': None, 'exact_verdict_accuracy': None,
                'suboptimal_found': None, 'worse': None}
    if any(not 0 <= r['baseline_quality'] <= r['best_quality'] or not 0 <= r['chosen_quality'] <= r['best_quality'] for r in records):
        raise ValueError('invalid quality bounds')
    suboptimal = sum(r['baseline_quality'] < r['best_quality'] for r in records)
    found = sum(r['baseline_quality'] < r['best_quality'] and r['chosen_quality'] > r['baseline_quality'] for r in records)
    worse = sum(r['chosen_quality'] < r['baseline_quality'] for r in records)
    return {'status': 'SCORED_SUPPLIED_RECORDS', 'sample_count': len(records),
            'risk_separation': separation, 'mean_safe_risk': safe_mean,
            'mean_unsafe_risk': unsafe_mean, 'exact_verdict_correct': exact,
            'exact_verdict_accuracy': exact / len(records),
            'suboptimal_found': found, 'suboptimal_baseline_count': suboptimal,
            'suboptimal_hit_rate': found / suboptimal if suboptimal else None,
            'worse': worse, 'worse_denominator': len(records)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    args = parser.parse_args()
    data = json.loads(args.input.read_text())
    result = score(data['records'])
    print(json.dumps({'evidence_class': data['evidence_class'], 'input_class': data['evidence_class'],
                      'measurement_kind': 'offline_scorer_execution', 'reference_only': True,
                      'model_evaluation': False, 'paid_spend_usd': 0, **result}, indent=2))
    return 0 if result['status'] == 'SCORED_SUPPLIED_RECORDS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
