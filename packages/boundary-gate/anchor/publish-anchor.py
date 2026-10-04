#!/usr/bin/env python3
# Ledger tail anchor publisher. Runs OFF the pilot (the owner's Mac), so the anchor lives outside the gate's box.
#   python3 publish-anchor.py            one round: read the gate head, publish it if it moved
#   python3 publish-anchor.py --plan     pure decision: stdin {"remote": "<jsonl text>", "gate": <log reply>, "now": "..."}
# Source of the head: the gate's READ-ONLY `log` op (limit 200), reached through the owner bridge socket.
# Destination: anchors/gate-ledger.jsonl on branch `ledger-anchor` of the public repo, one JSON line per head
#   {"seq":N,"head":"<64 hex>","gate_fp":"<16 hex>","entry_at":"...","anchored_at":"...Z"}
# Refuses (exit 3, publishes nothing) when the gate's chain does not verify, when the gate key changed, when the head
# went BACKWARDS (seq below the last anchor = truncation), or when the entry at the last anchored seq no longer has
# the anchored hash (rewrite). A refusal is the alarm; it is logged and never papered over by a new anchor.
import json, os, re, socket, subprocess, sys, time, base64
HEX64 = re.compile(r'^[0-9a-f]{64}$'); HEX16 = re.compile(r'^[0-9a-f]{16}$')
REPO = os.environ.get('ANCHOR_REPO', 'aumara-xyz/aukora-prime'); BRANCH = os.environ.get('ANCHOR_BRANCH', 'ledger-anchor')
PATH = 'anchors/gate-ledger.jsonl'
BRIDGE = os.path.expanduser(os.environ.get('ANCHOR_BRIDGE', '~/.aukora-nebius/gate/owner.sock'))
GH = os.environ.get('ANCHOR_GH', '/opt/homebrew/bin/gh')

class Refuse(Exception): pass

def parse_remote(text):
    lines = []
    for i, raw in enumerate(text.splitlines(), 1):
        if not raw.strip(): continue
        a = json.loads(raw)
        if not (isinstance(a.get('seq'), int) and a['seq'] >= 1 and HEX64.match(str(a.get('head'))) and HEX16.match(str(a.get('gate_fp')))):
            raise Refuse(f'remote anchor line {i} malformed')
        if lines and (a['seq'] <= lines[-1]['seq']): raise Refuse(f'remote anchor line {i} not increasing')
        if lines and a['gate_fp'] != lines[-1]['gate_fp']: raise Refuse(f'remote anchor line {i} changes gate key')
        lines.append(a)
    return lines

def plan(remote_text, gate, now):
    v = gate.get('verify') or {}
    if v.get('ok') is not True: raise Refuse('gate chain does not verify: ' + '; '.join(map(str, v.get('errors', [])))[:300])
    seq, head, fp = v.get('entries'), v.get('head'), gate.get('pubkey_fp')
    if not (isinstance(seq, int) and seq >= 1 and HEX64.match(str(head)) and HEX16.match(str(fp))): raise Refuse('gate reply malformed')
    ents = {e['seq']: e for e in gate.get('entries') or []}
    top = ents.get(seq)
    if not top or top.get('hash') != head: raise Refuse('gate log top entry does not match its verified head')
    anchors = parse_remote(remote_text)
    if anchors:
        last = anchors[-1]
        if last['gate_fp'] != fp: raise Refuse(f'gate key changed ({last["gate_fp"]} -> {fp})')
        if seq < last['seq']: raise Refuse(f'TRUNCATION: gate ledger has {seq} entries, anchor #{last["seq"]} is published')
        if seq == last['seq']:
            if head != last['head']: raise Refuse(f'REWRITE: entry #{seq} hash {head[:12]} != anchored {last["head"][:12]}')
            return None
        old = ents.get(last['seq'])
        if old is None: raise Refuse(f'cannot see anchored entry #{last["seq"]} in the gate log window; publish by hand after checking')
        if old.get('hash') != last['head']: raise Refuse(f'REWRITE: entry #{last["seq"]} hash {str(old.get("hash"))[:12]} != anchored {last["head"][:12]}')
    return {'seq': seq, 'head': head, 'gate_fp': fp, 'entry_at': top.get('at'), 'anchored_at': now}

def gate_log():
    s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(BRIDGE)
    s.sendall(b'{"op":"log","args":{"limit":200}}\n'); buf = b''
    while True:
        d = s.recv(1 << 20)
        if not d: break
        buf += d
    r = json.loads(buf)
    if not r.get('ok'): raise Refuse('gate log refused: ' + str(r.get('error')))
    return r['result']

def gh(*args, input=None):
    p = subprocess.run([GH, *args], input=input, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr

def main():
    if '--plan' in sys.argv:
        a = json.load(sys.stdin)
        try: print(json.dumps({'publish': plan(a['remote'], a['gate'], a['now'])}))
        except Refuse as e: print(json.dumps({'refuse': str(e)})); sys.exit(3)
        return
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    try:
        gate = gate_log()
        rc, out, err = gh('api', f'repos/{REPO}/contents/{PATH}?ref={BRANCH}')
        if rc == 0: cur = json.loads(out); text, sha = base64.b64decode(cur['content']).decode(), cur['sha']
        elif 'Not Found' in out + err: text, sha = '', None
        else: raise Refuse('cannot read remote anchor: ' + (err or out)[:200])
        line = plan(text, gate, now)
        if line is None: return
        body = text + json.dumps(line, separators=(',', ':')) + '\n'
        req = {'message': f'ledger anchor #{line["seq"]} head {line["head"][:12]} (gate {line["gate_fp"]})', 'branch': BRANCH,
               'content': base64.b64encode(body.encode()).decode()}
        if sha: req['sha'] = sha
        rc, out, err = gh('api', '-X', 'PUT', f'repos/{REPO}/contents/{PATH}', '--input', '-', input=json.dumps(req))
        if rc != 0: raise Refuse('publish failed: ' + (err or out)[:200])
        print(now, 'anchored', line['seq'], line['head'][:12], flush=True)
    except Refuse as e:
        print(now, 'ANCHOR REFUSED:', e, flush=True); sys.exit(3)

if __name__ == '__main__': main()
