#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Live containment verification (root, on the pilot). See README.md.
#  1. plant random canaries in protected places; outside observer records hashes + gate ledger head
#  2. REAL run A: probe inside the guest through the production route (aukora-host -> sudo -u auma sbx-exec)
#  3. REAL run B: probe on the host as auma (guest-escape depth)
#  4. observer re-checks: canaries/targets unchanged, ledger prefix unchanged, no files created
#  5. CONTROL: disposable user + decoy targets with NO confinement; every route must come back ALLOWED
#     and the observer must see the decoy changes, proving the checks detect a missing protection
# Exit 0 only when every real protected route is DENIED, the workspace op is OK, the observer sees no
# change, and the control detects everything.
import base64, hashlib, json, os, pwd, secrets, shutil, socket, sqlite3, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__)); PROBE = open(os.path.join(HERE, 'probe.py')).read()
if os.geteuid() != 0: sys.exit('run as root')
C = 'AUKORA-CANARY-' + secrets.token_hex(16)
CANARIES = {'/home/aukora-gate/.containment-canary': ('aukora-gate', 0o600),
            '/home/aukora-host/.containment-canary': ('aukora-host', 0o600),
            '/etc/aukora-aura/.containment-canary': ('root', 0o600),
            '/root/.containment-canary': ('root', 0o600)}
STATIC = ['/opt/aukora-boundary-gate/bin/gate.mjs', '/usr/local/lib/aukora-boundary/sbx-exec', '/etc/aukora-genesis/release.env',
          '/etc/sudoers.d/aukora-boundary', '/etc/aukora-aura/author-INTERIM.key', '/etc/systemd/system/aukora-genesis.service']
CREATE = ['/opt/aukora-boundary-gate/bin/.probe-new', '/etc/sudoers.d/zz-probe', '/home/aukora-gate/.probe-new', '/home/aukora-host/.probe-new']
GATE_DB = '/home/aukora-gate/gate.db'

def sh(argv, **kw): return subprocess.run(argv, capture_output=True, text=True, timeout=kw.pop('timeout', 120), **kw)
def sha(p):
    try: return hashlib.sha256(open(p, 'rb').read()).hexdigest()
    except FileNotFoundError: return 'absent'
def mainpid(unit): return sh(['systemctl', 'show', '-p', 'MainPID', '--value', unit]).stdout.strip()
def ledger_row(seq=None):
    db = sqlite3.connect(f'file:{GATE_DB}?mode=ro', uri=True)
    r = db.execute('select seq, hash from ledger order by seq desc limit 1' if seq is None else 'select seq, hash from ledger where seq=?',
                   () if seq is None else (seq,)).fetchone(); db.close(); return r

def observe():
    return {'files': {p: sha(p) for p in list(CANARIES) + STATIC + CREATE}}

def manifest(workspace, pids):
    return {'canary': C, 'canary_files': list(CANARIES),
            'read': list(CANARIES) + [GATE_DB, '/etc/aukora-aura/author-INTERIM.key', '/etc/shadow', '/etc/sudoers.d/aukora-boundary'],
            'write': list(CANARIES) + ['/opt/aukora-boundary-gate/bin/gate.mjs', '/usr/local/lib/aukora-boundary/sbx-exec', '/etc/aukora-genesis/release.env'],
            'create': CREATE, 'signal': pids,
            'unix': ['/run/aukora-gate/owner.sock', '/run/aukora-gate/gate.sock', '/run/podman/podman.sock', '/var/run/docker.sock'],
            'tcp': ['127.0.0.1:18735', '127.0.0.1:18733'],
            'protected_prefixes': ['/home/aukora-gate', '/home/aukora-host', '/run/aukora-gate', '/etc/aukora-aura', '/root', '/opt/aukora-boundary-gate'],
            'helpers': [[['sudo', '-n', 'true'], False],
                        [['sudo', '-n', '-u', 'aukora-gate', 'cat', '/home/aukora-gate/.containment-canary'], True],
                        [['/usr/bin/podman', 'unshare', 'cat', '/home/aukora-gate/.containment-canary'], True]],
            'workspace': workspace}

def parse(out):
    rows = []
    for line in out.splitlines():
        try: rows.append(json.loads(line))
        except ValueError: pass
    return rows

def guest_cmd(m):
    b = base64.b64encode(json.dumps(m).encode()).decode()
    return f"/usr/bin/python3 -I - {b} <<'AUKORA_PROBE'\n{PROBE}\nAUKORA_PROBE\n"

results = {}
for p, (owner, mode) in CANARIES.items():
    with open(p, 'w') as f: f.write(C + '\n')
    u = pwd.getpwnam(owner); os.chown(p, u.pw_uid, u.pw_gid); os.chmod(p, mode)
head0 = ledger_row(); before = observe()
pids = [mainpid('aukora-boundary-gate'), mainpid('aukora-genesis'), mainpid('aukora-relay')]
try:
    # REAL A: guest via production route
    r = sh(['sudo', '-n', '-u', 'aukora-host', 'sudo', '-n', '-u', 'auma', '/usr/local/lib/aukora-boundary/sbx-exec', '90',
            guest_cmd(manifest('/sandbox', pids))], cwd='/tmp', timeout=150)
    results['guest (auma via sbx-exec)'] = parse(r.stdout) or [{'route': 'run', 'target': 'sbx-exec', 'result': 'FAIL', 'detail': f'exit {r.returncode} {r.stderr[:120]}'}]
    # REAL B: host as auma
    tmpws = tempfile.mkdtemp(prefix='containment-ws-', dir='/tmp'); au = pwd.getpwnam('auma'); os.chown(tmpws, au.pw_uid, au.pw_gid)
    probe_path = os.path.join(tmpws, 'probe.py'); open(probe_path, 'w').write(PROBE); os.chmod(probe_path, 0o644)
    r = sh(['sudo', '-n', '-u', 'auma', 'env', '-i', 'PATH=/usr/bin:/bin', f'HOME={au.pw_dir}', f'XDG_RUNTIME_DIR=/run/user/{au.pw_uid}',
            '/usr/bin/python3', '-I', probe_path, json.dumps(manifest(tmpws, pids))], cwd='/tmp')
    results['host (auma, guest-escape depth)'] = parse(r.stdout)
    shutil.rmtree(tmpws, ignore_errors=True)
finally:
    after = observe(); head_row = ledger_row(head0[0]) if head0 else None
    for p in CANARIES:
        try: os.unlink(p)
        except FileNotFoundError: pass
changed = [p for p in before['files'] if before['files'][p] != after['files'][p]]
ledger_ok = head0 is None or head_row == head0

# CONTROL: disposable user, decoys, no confinement
ctl_user = 'aukora-ctl' + secrets.token_hex(3)
sh(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', ctl_user])
cu = pwd.getpwnam(ctl_user); root = tempfile.mkdtemp(prefix='containment-ctl-', dir='/var/tmp'); os.chmod(root, 0o755)
procs = []
try:
    def own(p): os.chown(p, cu.pw_uid, cu.pw_gid)
    own(root)
    decoy = {k: os.path.join(root, k.strip('/').replace('/', '_')) for k in CANARIES}
    for p in decoy.values(): open(p, 'w').write(C + '\n'); own(p)
    extra_read = os.path.join(root, 'gate.db'); open(extra_read, 'w').write('decoy'); own(extra_read)
    writes = [os.path.join(root, n) for n in ('gate.mjs', 'sbx-exec', 'release.env')]
    for p in writes: open(p, 'w').write('decoy\n'); own(p)
    usock = os.path.join(root, 'owner.sock'); port = 20000 + secrets.randbelow(20000)
    listener = ("import socket,sys,os\nu=socket.socket(socket.AF_UNIX);u.bind(sys.argv[1]);u.listen(4)\n"
                "t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(('127.0.0.1',int(sys.argv[2])));t.listen(4)\n"
                "import time\ntime.sleep(60)\n")
    procs.append(subprocess.Popen(['sudo', '-n', '-u', ctl_user, '/usr/bin/python3', '-I', '-c', listener, usock, str(port)]))
    time.sleep(1.5)
    lpid = sh(['pgrep', '-u', ctl_user, '-n', 'python3']).stdout.strip()
    helper = os.path.join(root, 'helper.sh'); open(helper, 'w').write(f'#!/bin/sh\ncat {decoy[next(iter(CANARIES))]}\n'); os.chmod(helper, 0o755)
    probe_path = os.path.join(root, 'probe.py'); open(probe_path, 'w').write(PROBE); os.chmod(probe_path, 0o644)
    ws = os.path.join(root, 'ws'); os.mkdir(ws); own(ws)
    m = {'canary': C, 'canary_files': list(decoy.values()), 'read': list(decoy.values()) + [extra_read],
         'write': list(decoy.values()) + writes, 'create': [os.path.join(root, 'new-' + str(i)) for i in range(2)],
         'signal': [lpid], 'unix': [usock], 'tcp': [f'127.0.0.1:{port}'], 'protected_prefixes': [root],
         'helpers': [[[helper], True]], 'workspace': ws}
    cbefore = {p: sha(p) for p in list(decoy.values()) + writes}
    r = sh(['sudo', '-n', '-u', ctl_user, '/bin/bash', '-c', f'exec 7<{decoy[next(iter(CANARIES))]}; exec /usr/bin/python3 -I {probe_path} "$1"', '_', json.dumps(m)], cwd='/tmp')
    crow = parse(r.stdout)
    cchanged = [p for p in cbefore if cbefore[p] != sha(p)]
finally:
    for p in procs: p.kill()
    sh(['pkill', '-u', ctl_user]); time.sleep(0.5); sh(['userdel', ctl_user]); shutil.rmtree(root, ignore_errors=True)

# verdict
print('CONTAINMENT VERIFICATION', time.strftime('%Y-%m-%d %H:%M:%S %Z'))
fail = False
for name, rows in results.items():
    print(f'\n== REAL: {name}\nroute | target | result | detail')
    for x in rows: print(f"{x['route']} | {x['target']} | {x['result']} | {x['detail']}")
    bad = [x for x in rows if x['result'] in ('ALLOWED', 'FAIL')]
    ws_ok = any(x['route'] == 'workspace-write' and x['result'] == 'OK' for x in rows)
    print(f"-> {len([x for x in rows if x['result']=='DENIED'])} DENIED, {len([x for x in rows if x['result']=='ALLOWED'])} ALLOWED, workspace {'OK' if ws_ok else 'FAIL'}")
    fail |= bool(bad) or not ws_ok
print(f"\n== OUTSIDE OBSERVER (root): protected targets changed: {changed or 'none'}; gate ledger prefix through seq {head0[0] if head0 else 0} unchanged: {ledger_ok}")
fail |= bool(changed) or not ledger_ok
print('\n== CONTROL (disposable user, decoys, confinement DISABLED)\nroute | result | detail')
for x in crow: print(f"{x['route']} | {x['result']} | {x['detail']}")
blind = [x for x in crow if x['result'] not in ('ALLOWED', 'OK')]
print(f"-> control detected {len([x for x in crow if x['result']=='ALLOWED'])} ALLOWED; blind spots: {[x['route'] for x in blind] or 'none'}; observer saw decoy changes: {len(cchanged)}/{len(cbefore)}")
cfail = bool(blind) or len(cchanged) != len(cbefore)
print('\nVERDICT:', 'PASS' if not fail and not cfail else 'FAIL', '(real routes denied + workspace ok + observer clean)' if not fail else '(real containment gap, see ALLOWED/FAIL rows)', '| control', 'PROVES DETECTION' if not cfail else 'DID NOT DETECT EVERYTHING')
sys.exit(0 if not fail and not cfail else 1)
