#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Containment probe. Runs as the confined identity (auma, inside the guest or on the host)
# and tries every route in the manifest. Prints one JSON line per attempt:
#   {"route","target","result":"DENIED"|"ALLOWED"|"OK"|"FAIL","detail"}
# DENIED/ALLOWED are for protected targets; OK/FAIL for the allowed workspace operation.
# A canary target is ALLOWED only if its secret bytes were actually read, overwritten or reached.
# Stdlib only, no network beyond the listed loopback/unix targets, no retries.
import json, os, socket, subprocess, sys

def emit(route, target, result, detail=''):
    print(json.dumps({'route': route, 'target': target, 'result': result, 'detail': str(detail)[:160]}), flush=True)

def denied(e):
    return isinstance(e, (PermissionError, FileNotFoundError, NotADirectoryError, IsADirectoryError, ConnectionRefusedError,
                          ProcessLookupError, OSError))

import base64
raw = sys.argv[1]
m = json.loads(raw if raw.startswith('{') else base64.b64decode(raw))
canary = m.get('canary', '')

for t in m.get('read', []):           # file read
    try:
        with open(t, 'rb') as f: b = f.read(1 << 20)
        hit = canary.encode() in b if canary and t in m.get('canary_files', []) else True
        emit('file-read', t, 'ALLOWED' if hit else 'DENIED', f'read {len(b)} bytes' + ('' if hit else ' (no canary)'))
    except Exception as e: emit('file-read', t, 'DENIED' if denied(e) else 'ALLOWED', type(e).__name__)

for t in m.get('write', []):          # file write (append, so a success is observable by the outside observer)
    try:
        with open(t, 'ab') as f: f.write(b'\n# containment-probe-was-here\n')
        emit('file-write', t, 'ALLOWED', 'appended')
    except Exception as e: emit('file-write', t, 'DENIED' if denied(e) else 'ALLOWED', type(e).__name__)

for t in m.get('create', []):         # create a new file in a protected directory
    try:
        fd = os.open(t, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, b'probe'); os.close(fd)
        emit('file-create', t, 'ALLOWED', 'created')
    except Exception as e: emit('file-create', t, 'DENIED' if denied(e) else 'ALLOWED', type(e).__name__)

for pid in m.get('signal', []):       # process: signal 0 (existence+permission only, harmless) and environ read
    try:
        os.kill(int(pid), 0); emit('process-signal', f'pid {pid}', 'ALLOWED', 'kill(0) permitted')
    except Exception as e: emit('process-signal', f'pid {pid}', 'DENIED', type(e).__name__)
    try:
        with open(f'/proc/{int(pid)}/environ', 'rb') as f: b = f.read(4096)
        emit('process-environ', f'pid {pid}', 'ALLOWED' if b else 'DENIED', f'{len(b)} bytes')
    except Exception as e: emit('process-environ', f'pid {pid}', 'DENIED', type(e).__name__)

for t in m.get('unix', []):           # unix sockets
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
    try: s.connect(t); emit('socket-unix', t, 'ALLOWED', 'connected')
    except Exception as e: emit('socket-unix', t, 'DENIED', type(e).__name__)
    finally: s.close()

for hp in m.get('tcp', []):           # loopback tcp
    h, p = hp.rsplit(':', 1); s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
    try: s.connect((h, int(p))); emit('socket-tcp', hp, 'ALLOWED', 'connected')
    except Exception as e: emit('socket-tcp', hp, 'DENIED', type(e).__name__)
    finally: s.close()

# inherited handles: any descriptor beyond 0-2 that reaches a protected path/socket or the canary
prot = tuple(m.get('protected_prefixes', []))
leaks = []
for fd in sorted(int(x) for x in os.listdir('/proc/self/fd')):
    if fd <= 2: continue
    try: target = os.readlink(f'/proc/self/fd/{fd}')
    except OSError: continue
    if target.startswith('/proc/') and target.endswith('/fd'): continue      # the listdir handle itself
    readable = b''
    try: readable = os.pread(fd, 4096, 0)
    except OSError: pass
    if target.startswith(prot) or (canary and canary.encode() in readable) or target.startswith('socket:'):
        leaks.append(f'{fd}->{target}')
emit('inherited-handle', 'fds>2', 'ALLOWED' if leaks else 'DENIED', ','.join(leaks) or 'none reach protected targets')

for argv, needs_canary in m.get('helpers', []):   # privileged helpers: must not run successfully
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        out = r.stdout + r.stderr
        ok = r.returncode == 0 and (not needs_canary or canary.encode() in out)
        emit('privileged-helper', ' '.join(argv), 'ALLOWED' if ok else 'DENIED', f'exit {r.returncode}')
    except Exception as e: emit('privileged-helper', ' '.join(argv), 'DENIED', type(e).__name__)

ws = m.get('workspace')               # the allowed operation must SUCCEED
if ws:
    p = os.path.join(ws, '.containment-allowed-op')
    try:
        with open(p, 'w') as f: f.write('allowed\n')
        with open(p) as f: ok = f.read() == 'allowed\n'
        os.unlink(p); emit('workspace-write', ws, 'OK' if ok else 'FAIL', 'write/read/delete')
    except Exception as e: emit('workspace-write', ws, 'FAIL', type(e).__name__)
