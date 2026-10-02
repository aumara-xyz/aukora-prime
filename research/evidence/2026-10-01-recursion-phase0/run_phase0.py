# SYNTHETIC: bounded reference-only runner for the NEW offline tools; no real model evaluation.
import datetime
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    previous = json.loads((ROOT / 'run-ledger.json').read_text()) if (ROOT / 'run-ledger.json').exists() else None
    run_number = (previous.get('run_number', 3) + 1) if previous else 1
    prefix = 'run' + str(run_number) + '.'
    locked_files = ['source-inventory.json', 'metric-fixture.json', 'dream-pool-registry.json',
                    'preregistration.json', 'evaluate_offline.py', 'generate_governance_corpus.py',
                    'run_phase0.py', 'model-source-audit.json']
    lock = {'evidence_class': 'measured', 'measurement_kind': 'local_pre_execution_hash_record',
            'reference_only': True, 'independent_timestamp_or_lock': False,
            'captured_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'files_sha256': {name: digest(ROOT / name) for name in locked_files}}
    (ROOT / (prefix + 'input-lock.json')).write_text(json.dumps(lock, indent=2) + '\n')
    jobs = [
        ('metric-fixture', ['evaluate_offline.py', 'metric-fixture.json'], 0, 'synthetic'),
        ('missing-dream-inputs', ['evaluate_offline.py', 'dream-pool-registry.json'], 2, 'synthetic_missing_input_registry'),
        ('corpus-inventory', ['generate_governance_corpus.py', '--inventory', 'source-inventory.json', '--output', prefix + 'corpus-manifest.json'], 2, 'historical_source_metadata')
    ]
    runs = []
    for name, args, expected, input_class in jobs:
        begin_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start = time.monotonic()
        exception = None
        try:
            result = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True,
                                    text=True, timeout=10, stdin=subprocess.DEVNULL)
            stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ''
            stderr = exc.stderr or ''
            stdout = stdout.decode(errors='replace') if isinstance(stdout, bytes) else stdout
            stderr = stderr.decode(errors='replace') if isinstance(stderr, bytes) else stderr
            exit_code, exception = None, 'TIMEOUT'
        except OSError as exc:
            stdout, stderr, exit_code, exception = '', str(exc), None, 'LAUNCH_FAILED'
        wall = time.monotonic() - start
        classification = 'SYNTHETIC' if input_class.startswith('synthetic') else 'MEASURED'
        header = classification + ': offline command output; input=' + input_class + '; no model inference; reference only.\n'
        out_name, err_name = prefix + name + '.stdout.txt', prefix + name + '.stderr.txt'
        (ROOT / out_name).write_text(header + stdout)
        (ROOT / err_name).write_text(header + stderr)
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed, exception = {}, exception or 'OUTPUT_NOT_JSON'
        if not isinstance(parsed, dict):
            parsed, exception = {}, exception or 'OUTPUT_WRONG_SHAPE'
        assertions = exit_code == expected and exception is None
        if name == 'metric-fixture':
            expected_metrics = json.loads((ROOT / 'preregistration.json').read_text())['synthetic_fixture_expected']
            assertions = assertions and all(parsed.get(k) == value for k, value in expected_metrics.items())
        elif name == 'missing-dream-inputs':
            assertions = assertions and parsed.get('risk_separation') is None and parsed.get('exact_verdict_accuracy') is None
        else:
            manifest_path = ROOT / (prefix + 'corpus-manifest.json')
            try:
                manifest = json.loads(manifest_path.read_text())
                if not isinstance(manifest, dict):
                    raise ValueError('manifest must be an object')
                assertions = assertions and manifest.get('example_count') == 0 and manifest.get('training_performed') is False
            except (OSError, ValueError):
                assertions, exception = False, exception or 'MANIFEST_UNAVAILABLE'
        runs.append({'run_id': name, 'started_at_utc': begin_utc,
                     'command': 'python3 ' + ' '.join(args), 'wall_seconds': wall,
                     'input_class': input_class, 'exit_code': exit_code,
                     'failure_kind': exception, 'stdout_file': out_name, 'stderr_file': err_name,
                     'expected_exit_code': expected, 'validation_passed': assertions,
                     'model_evaluation': False, 'cloud_compute_seconds': 0,
                     'cloud_compute_rate_usd_per_second': 0, 'cloud_compute_usd': 0,
                     'api_model_calls': 0, 'api_usd': 0, 'new_cloud_storage_usd': 0,
                     'incremental_external_experiment_spend_usd': 0,
                     'standing_storage_burn': 'UNVERIFIED; provider account not accessed',
                     'output_sha256': digest(ROOT / out_name)})
    for name, expected_hash in lock['files_sha256'].items():
        if digest(ROOT / name) != expected_hash:
            raise ValueError('locked input changed: ' + name)
    summary = {'evidence_class': 'measured', 'measurement_kind': 'offline_tool_execution',
               'reference_only': True, 'real_model_evaluation': False,
               'run_number': run_number, 'input_lock_file': prefix + 'input-lock.json',
               'prior_ledger': previous,
               'runs': runs, 'total_wall_seconds': sum(r['wall_seconds'] for r in runs),
               'total_incremental_external_experiment_spend_usd': 0,
               'scope_excludes': ['standing storage costs', 'host energy', 'Codex subscription/agent usage'],
               'all_expected_results_validated': all(r['validation_passed'] for r in runs)}
    (ROOT / 'run-ledger.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('MEASURED: offline tooling only; synthetic/historical inputs; reference only.')
    print(json.dumps(summary, indent=2))
    return 0 if summary['all_expected_results_validated'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
