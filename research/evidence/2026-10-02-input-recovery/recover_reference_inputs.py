# SYNTHETIC: newly authored offline reference tool; no model/provider call, training or activation.
"""Read exact archived source/artifacts; export only bounded sanitized metadata.

Original scripts are parsed, never imported or executed. Source-file SHA checks
prove byte consistency, not the truth of producer-reported model outcomes.
"""
import argparse
import ast
from collections import Counter
import datetime
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path
import subprocess
import time

ALLOW_ACTIONS = {'keep', 'reject-no-improvement', 'tombstone'}
ALLOW_LABELS = {'KEEP', 'SAFE', 'HOSTILE', 'REJECT', 'TOMBSTONE'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--genesis-repo', type=Path, required=True)
    p.add_argument('--revision', required=True)
    args = p.parse_args()
    if len(args.revision) != 40 or any(c not in '0123456789abcdef' for c in args.revision):
        raise ValueError('full pinned revision required')
    root = Path(__file__).resolve().parent
    started = time.monotonic()
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    source_manifest = []

    def source(rel):
        raw = subprocess.check_output(['git', '-C', str(args.genesis_repo), 'show', args.revision + ':' + rel], timeout=10)
        source_manifest.append({'path': rel, 'git_revision': args.revision, 'bytes': len(raw),
                                'sha256': sha(raw),
                                'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()})
        return raw

    def write(name, value):
        (root / name).write_text(json.dumps(value, indent=2) + '\n')

    dream_tree = ast.parse(source('experiments/dream-rsi-phase-a-v2.py'))
    literals = {}
    for node in dream_tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            try:
                literals[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    pool = literals['POOL_V1_HISTORICAL']
    assert len(pool) == 5
    dream = [{'id': 'dream-' + str(i + 1).zfill(2), 'source_row': i,
              'option_count': len(row['options']), 'baseline_option': row['chosen'],
              'author_ground_truth_option': row['ground_truth_best']}
             for i, row in enumerate(pool)]
    write('recovered-dream-metadata.json', {
        'evidence_class': 'synthetic', 'reference_only': True,
        'input_kind': 'archived hand-authored scenario encodings of historical decisions',
        'original_five_scenarios_recovered': 5, 'author_labels_recovered': 5,
        'independent_ground_truth_verified': False,
        'baseline_suboptimal_by_author_labels': sum(r['baseline_option'] != r['author_ground_truth_option'] for r in dream),
        'judge_outputs_recovered': 0, 'dream_hit_rate': None, 'worse_rate': None,
        'forward_scenario_count': len(literals['POOL_FORWARD']),
        'original_locked_forward_prediction_recovered': False,
        'prompt_and_proposal_text_omitted': True, 'rows': dream})

    original = json.loads(source('experiments/jev-calibration-v01.json'))
    data = original['results']
    assert len(data) == 12 and len({r['id'] for r in data}) == 12
    rows = []
    for i, r in enumerate(data):
        assert r['gt'] in ALLOW_LABELS and r['jev_verdict'] in ALLOW_LABELS
        assert type(r['risk']) in (int, float) and math.isfinite(r['risk'])
        hit = r['gt'] == r['jev_verdict']
        assert bool(r['hit']) == hit
        rows.append({'id': 'calibration-' + str(i + 1).zfill(2), 'source_row': i,
                     'author_ground_truth': r['gt'], 'recorded_verdict': r['jev_verdict'],
                     'exact_hit': hit, 'recorded_risk': r['risk']})
    hostile = [r['recorded_risk'] for r in rows if r['author_ground_truth'] == 'HOSTILE']
    keep_safe = [r['recorded_risk'] for r in rows if r['author_ground_truth'] in ('KEEP', 'SAFE')]
    all_other = [r['recorded_risk'] for r in rows if r['author_ground_truth'] != 'HOSTILE']
    mean = lambda v: sum(v) / len(v)
    exact = sum(r['exact_hit'] for r in rows)
    stats = {'exact_correct': exact, 'exact_total': len(rows),
             'exact_verdict_accuracy': exact / len(rows),
             'historical_ratio_hostile_over_keep_safe': mean(hostile) / mean(keep_safe),
             'historical_ratio_denominators': {'hostile': len(hostile), 'keep_safe': len(keep_safe),
                                              'excluded_reject_tombstone': len(all_other) - len(keep_safe)},
             'ratio_hostile_over_all_other': mean(hostile) / mean(all_other),
             'all_other_ratio_denominators': {'hostile': len(hostile), 'all_other': len(all_other)},
             'mean_hostile_risk': mean(hostile), 'mean_keep_safe_risk': mean(keep_safe),
             'mean_all_other_risk': mean(all_other)}
    write('historical-calibration-recomputation.json', {
        'evidence_class': 'synthetic', 'reference_only': True,
        'measurement_kind': 'new offline arithmetic over a historical cached benchmark table',
        'original_prompt_provenance': 'UNVERIFIED; prompts and full API responses absent',
        'fresh_model_evaluation': False, 'independent_ground_truth_verified': False,
        'recorded_model': 'typesafe/jev-1.13-20260917', 'recorded_date': '2026-09-20',
        'risk_is_probability': False, 'rows': rows, 'recomputed_statistics': stats})

    generator = ast.parse(source('experiments/governed-learning/generate_governance_corpus.py'))
    archived_corpus = json.loads(source('experiments/governed-learning/governance-corpus-v01.json'))
    loop_dirs = {}
    for node in generator.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ('D28_DEFAULT', 'D32_DEFAULT'):
            loop_dirs[node.targets[0].id] = Path(ast.literal_eval(node.value))
    refs, loop_sources, historical_cost = [], [], Decimal('0')
    for name, directory in loop_dirs.items():
        label = name.removesuffix('_DEFAULT')
        raw = (directory / 'loop-receipts.jsonl').read_bytes()
        digest = sha(raw)
        assert any(s['sha256'] == digest for s in archived_corpus['sources'].values())
        results_raw = (directory / 'RESULTS.md').read_bytes()
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        assert len({r['iter'] for r in records}) == len(records)
        candidates = {sha(f.read_bytes()) for f in directory.glob('*.py') if f.is_file()}
        for r in records:
            assert r['action'] in ALLOW_ACTIONS
            assert all(k in r for k in ('iter', 'model', 'action', 'usage'))
            if r['action'] != 'tombstone':
                assert 'proposal_sha256' in r and 'cases' in r
            cost = Decimal(str(r['usage']['cost']))
            assert cost.is_finite() and cost >= 0
            historical_cost += cost
            refs.append({'source_label': label, 'iteration': r['iter'], 'recorded_action': r['action'],
                         'proposal_digest_present': 'proposal_sha256' in r,
                         'proposal_bytes_match_in_bounded_snapshot_search': r.get('proposal_sha256') in candidates,
                         'recorded_case_count': len(r.get('cases', {})),
                         'historical_reported_api_cost_usd': str(cost),
                         'source_receipt_sha256': digest,
                         'outcome_independently_reverified': False})
        loop_sources.append({'source_label': label, 'receipt_basename': 'loop-receipts.jsonl',
                             'receipt_sha256': digest, 'receipt_bytes': len(raw),
                             'results_sha256': sha(results_raw), 'row_count': len(records),
                             'archived_corpus_source_hash_match': True,
                             'actions': dict(Counter(r['action'] for r in records)),
                             'verification_class': 'local source-file integrity only; producer-recorded outcomes'})
    write('recovered-reference-records.json', {
        'evidence_class': 'measured', 'reference_only': True,
        'measurement_kind': 'sanitized metadata extracted from existing historical experiment records',
        'new_model_run': False, 'record_count': len(refs), 'sources': loop_sources,
        'records': refs, 'historical_reported_api_cost_usd': str(historical_cost),
        'historical_invoice_verified': False, 'new_paid_experiment_spend_usd': 0,
        'raw_receipts_prompts_code_and_private_paths_omitted': True})
    write('verified-corpus-manifest.json', {
        'evidence_class': 'measured', 'reference_only': True,
        'status': 'REFERENCE_METADATA_RECOVERED; VERIFIED_GOVERNANCE_CORPUS_BLOCKED',
        'reference_record_count': len(refs), 'source_file_integrity_verified_count': len(loop_sources),
        'source_git_revision_coverage': [args.revision],
        'proposal_binding_matches': sum(r['proposal_bytes_match_in_bounded_snapshot_search'] for r in refs),
        'non_tombstone_proposals': sum(r['recorded_action'] != 'tombstone' for r in refs),
        'verified_governance_example_count': 0,
        'cryptographic_chain_verification_performed': False, 'court_reexecution_performed': False,
        'hand_authored_examples_excluded': len(archived_corpus['hand_authored']),
        'original_corpus_complete': archived_corpus['complete'], 'training_performed': False,
        'examples': [], 'new_paid_experiment_spend_usd': 0})
    write('recovery-source-manifest.json', {'evidence_class': 'measured', 'reference_only': True,
                                          'measurement_kind': 'bounded local Git byte inventory',
                                          'source_revision': args.revision, 'files': source_manifest})
    elapsed = time.monotonic() - started
    write('recovery-run-ledger.json', {
        'evidence_class': 'measured', 'reference_only': True,
        'measurement_kind': 'offline local recovery execution telemetry',
        'started_at_utc': started_utc, 'wall_seconds': elapsed,
        'command': 'python3 recover_reference_inputs.py --genesis-repo "$GENESIS_ROOT" --revision ' + args.revision,
        'cloud_compute_seconds': 0, 'model_api_calls': 0, 'new_storage_resources': 0,
        'new_paid_experiment_spend_usd': 0,
        'standing_storage_cost': 'UNVERIFIED; no provider call',
        'spend_scope_excludes': ['standing storage', 'host energy', 'subscription/agent usage']})
    print('MEASURED: local recovery telemetry; cached benchmark data remains labeled synthetic/unknown provenance.')
    print(json.dumps({'source_files_read': len(source_manifest), 'dream_scenarios_recovered': len(pool),
                      'cached_calibration_rows_recovered': len(rows), 'reference_records_recovered': len(refs),
                      'verified_governance_examples': 0, 'wall_seconds': elapsed,
                      'new_paid_experiment_spend_usd': 0, 'statistics': stats}, indent=2))


if __name__ == '__main__':
    main()
