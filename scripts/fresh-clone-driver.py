#!/usr/bin/env python3
# Tear down the shared example runtime after every fresh-clone assertion.
import argparse, os, shutil, signal, subprocess, sys, tempfile, time
from pathlib import Path
from fresh_clone import Refused, passed, preflight, prepare, run, runtime_command


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description='Clone, build, approve and probe a disposable release; no model key required.')
    parser.add_argument('source', nargs='?')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--built', type=Path)
    parser.add_argument('--cache', type=Path)
    args = parser.parse_args()
    caller = Path(__file__).resolve().parents[1]
    source = args.source or str(caller)
    if Path(source).exists():
        source = str(Path(source).resolve())
    archive_input = args.archive.resolve() if args.archive else None
    built_input = args.built.resolve() if args.built else None
    cache = args.cache.resolve() if args.cache else None
    def interrupted(signum, frame):
        raise Refused('interrupted')
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    status, work = 1, None
    try:
        preflight()
        work = Path(tempfile.mkdtemp(prefix='aukora-fresh-clone-', dir=os.environ.get('TMPDIR', '/tmp'))).resolve()
        os.chmod(work, 0o700)
        os.umask(0o077)
        spec = prepare(source, work, archive_input, built_input, cache)
        print('MODE | temporary same-user authority (not owner enrollment or containment)', flush=True)
        run(runtime_command(spec), 'runtime', spec['checkout'], spec['env'], timeout=110)
        for line in (work / 'runtime.log').read_text().splitlines():
            if __import__('re').fullmatch(r'PASS \| [a-zA-Z0-9 ()/.-]+', line):
                print(line, flush=True)
        passed('release boot and all runtime assertions')
        status = 0
    except Refused as error:
        status = 2 if error.missing else 1
        print(('UNPERFORMED: ' if error.missing else 'FAIL | ') + error.code, flush=True)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError):
        print('FAIL | fresh-clone-input-invalid', flush=True)
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)
        print('TOTAL %.2fs | %s' % (time.monotonic() - started, 'PASS' if status == 0 else 'UNPERFORMED' if status == 2 else 'FAIL'), flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
