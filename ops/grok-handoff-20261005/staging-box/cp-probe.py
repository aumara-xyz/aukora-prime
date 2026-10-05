#!/usr/bin/python3
# Staging-only supplemental control-plane probe (Grok, item 1). Prints: route | target | result | detail
# ALLOWED = the route worked from this context. Never reads secret bytes; /proc/pid/mem is open-only (no read).
import os, sys, socket, errno, ctypes, json
args = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
rows = []
def row(route, target, ok, detail):
    rows.append((route, target, ('ALLOWED' if ok else 'DENIED') if ok in (True, False) else ok, detail))
def err(e): return type(e).__name__ + (('/' + errno.errorcode.get(e.errno, '')) if getattr(e, 'errno', None) else '')
# 1 rootless podman sockets (auma 1001) + rootful
for p in args.get('unix', ['/run/user/1001/podman/podman.sock', '/run/podman/podman.sock', '/run/user/1001/bus', '/run/user/1001/systemd/private']):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(0.5)
    try: s.connect(p); row('socket-unix', p, True, 'connected')
    except Exception as e: row('socket-unix', p, False, err(e))
    finally: s.close()
# 2 TCP loopback incl. OpenShell gateway 17690
for hp in args.get('tcp', ['127.0.0.1:17690', '[::1]:17690', '127.0.0.1:18735', '127.0.0.1:18733', '127.0.0.1:1933', '127.0.0.1:1934', '127.0.0.1:22', '169.254.169.254:80']):
    h, port = hp.rsplit(':', 1); h = h.strip('[]'); fam = socket.AF_INET6 if ':' in h else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(0.5)
    try: s.connect((h, int(port))); row('socket-tcp', hp, True, 'connected')
    except Exception as e: row('socket-tcp', hp, False, err(e))
    finally: s.close()
# 3 abstract unix sockets (names gathered outside by root; '@' prefix)
for name in args.get('abstract', []):
    ok = False; d = ''
    for typ in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        s = socket.socket(socket.AF_UNIX, typ); s.settimeout(0.3)
        try: s.connect('\0' + name[1:]); ok = True; d = 'connected type %d' % typ; break
        except Exception as e: d = err(e)
        finally: s.close()
    row('socket-abstract', name, ok, d)
# also: abstract names visible from here
try:
    vis = [l.split()[-1] for l in open('/proc/net/unix').read().splitlines()[1:] if l.split()[-1].startswith('@')]
    row('abstract-visible', '/proc/net/unix', 'INFO', '%d abstract names visible' % len(vis))
except Exception as e: row('abstract-visible', '/proc/net/unix', False, err(e))
# 4 /proc/<pid>/mem open (no read) for every visible pid except self, plus supplied host pids
me = os.getpid(); pids = sorted({int(p) for p in os.listdir('/proc') if p.isdigit()} | set(args.get('pids', [])))
for pid in pids:
    if pid == me: continue
    try:
        with open('/proc/%d/comm' % pid) as f: comm = f.read().strip()
    except Exception: comm = '?'
    try: uid = os.stat('/proc/%d' % pid).st_uid
    except Exception: uid = -1
    own = uid == os.getuid()
    try: fd = os.open('/proc/%d/mem' % pid, os.O_RDONLY | os.O_CLOEXEC); os.close(fd); row('proc-mem', 'pid %d (%s) uid %d' % (pid, comm, uid), 'INFO' if own else True, 'opened (same uid, own process)' if own else 'opened')
    except Exception as e: row('proc-mem', 'pid %d (%s) uid %d' % (pid, comm, uid), False, err(e))
# 4b positive control for the mem route: own forked child (descendant), open only
cpid = os.fork()
if cpid == 0:
    import time; time.sleep(5); os._exit(0)
try: fd = os.open('/proc/%d/mem' % cpid, os.O_RDONLY | os.O_CLOEXEC); os.close(fd); row('decoy-mem', 'own child pid %d' % cpid, 'CONTROL-OK', 'opened (route detectable)')
except Exception as e: row('decoy-mem', 'own child pid %d' % cpid, 'CONTROL-FAIL', err(e))
os.kill(cpid, 9); os.waitpid(cpid, 0)
# 5 mount audit: mountinfo inventory + mount/unshare attempts
libc = ctypes.CDLL(None, use_errno=True)
try:
    mi = open('/proc/self/mountinfo').read().splitlines()
    for l in mi:
        f = l.split(); sep = f.index('-')
        print('MOUNT | %s | root=%s | %s | %s | src=%s' % (f[4], f[3], f[5], f[sep+1], f[sep+2]))
    row('mount-inventory', '/proc/self/mountinfo', 'INFO', '%d rows (listed above)' % len(mi))
except Exception as e: row('mount-inventory', '/proc/self/mountinfo', False, err(e))
os.makedirs('/tmp/.cp-mnt', exist_ok=True)
r = libc.mount(b'none', b'/tmp/.cp-mnt', b'tmpfs', 0, None); e = ctypes.get_errno()
row('mount-syscall', 'tmpfs on /tmp/.cp-mnt', r == 0, 'mounted' if r == 0 else errno.errorcode.get(e, str(e)))
if r == 0: libc.umount2(b'/tmp/.cp-mnt', 2)
pid = os.fork()
if pid == 0:
    r = libc.unshare(0x10000000 | 0x00020000)  # CLONE_NEWUSER|CLONE_NEWNS
    os._exit(0 if r == 0 else 100 + min(ctypes.get_errno(), 99))
_, st = os.waitpid(pid, 0); c = os.waitstatus_to_exitcode(st)
row('unshare-userns', 'CLONE_NEWUSER|CLONE_NEWNS', c == 0, 'unshared' if c == 0 else errno.errorcode.get(c - 100, str(c)))
try: os.rmdir('/tmp/.cp-mnt')
except Exception: pass
print('route | target | result | detail')
for r_ in rows: print(' | '.join(r_))
print('-> %d DENIED, %d ALLOWED, %d INFO' % (sum(r[2] == 'DENIED' for r in rows), sum(r[2] == 'ALLOWED' for r in rows), sum(r[2] == 'INFO' for r in rows)))
