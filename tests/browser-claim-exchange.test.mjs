// SPDX-License-Identifier: AGPL-3.0-or-later
// claim.py retries one changed launch token and syncs spent claims before exchange.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const claimPath = join(root, 'ops/node-spawn/ingress/claim.py')
const court = String.raw`
import base64, importlib.util, json, os, pathlib, stat, sys, tempfile
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('claim_exchange', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
origin, authority, owner, now = 'https://node.example.test', 'node.example.test', 'owner.example.test', 1000
headers = {'host':authority, 'origin':origin, 'sec-fetch-site':'same-origin', 'content-type':'text/plain'}
unauthorized = b'dsh web authentication required; reopen the URL printed by dsh web.\n'
payload = {'version':1, 'authority':authority, 'issuedAt':now*1000, 'expiresAt':(now+86400)*1000}
encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
cookie = m.cookie_name(authority) + '=v1.' + encoded + '.fixture; Max-Age=86400; Path=/; Secure; HttpOnly; SameSite=Strict'

def refused(call, code):
    try: call()
    except m.ClaimRefusal as error:
        assert error.code == code, (error.code, code)
        return
    raise AssertionError('accepted ' + code)

with tempfile.TemporaryDirectory(dir=pathlib.Path.cwd()) as temporary:
    base = pathlib.Path(temporary).resolve()
    descriptor = base / 'launch-url.json'
    def launch(token):
        descriptor.write_text(json.dumps({'url':'http://127.0.0.1:18735/?token=' + token}))
        descriptor.chmod(0o600)

    class Response:
        def __init__(self, status, body=b'', cookie=None, location=None):
            self.status, self.body, self.cookie, self.location = status, body, cookie, location
        def read(self, maximum):
            assert maximum == 1024
            return self.body
        def getheader(self, name): return self.cookie if name == 'Set-Cookie' else self.location

    successful = Response(303, cookie=cookie, location='/')
    token_refusal = Response(401, unauthorized)

    def attempt(name, responses, changed=True, unavailable=False):
        directory = base / name
        directory.mkdir(mode=0o700)
        store = m.ClaimStore(directory / 'claims.json', require_root=False)
        code = store.mint(authority, now, 60)
        launch('old-fixture-token')
        requests, reads, closed = [], [], []
        pending = list(responses)
        real_open = m._protected_file
        def opened(path, **kwargs):
            reads.append(path)
            assert len(reads) <= 2, 'descriptor read more than once after initial read'
            return real_open(path, **kwargs)
        class Connection:
            def __init__(self, host, port, timeout):
                assert (host, port, timeout) == ('127.0.0.1', 18735, 5)
            def request(self, method, target, headers):
                assert (method, headers) == ('GET', {'Host':authority, 'Origin':origin, 'Sec-Fetch-Site':'same-origin'})
                assert store._read()['claims'][0]['spent_at'] == now, 'exchange preceded durable spend'
                requests.append(target)
                assert len(requests) <= 2, 'exchange retried more than once'
                if unavailable: raise OSError('fixture unavailable')
            def getresponse(self):
                assert pending, 'unexpected exchange retry'
                response = pending.pop(0)
                if len(requests) == 1 and changed: launch('new-fixture-token')
                return response
            def close(self): closed.append(True)
        exchange = m.HarnessCookieExchange(descriptor, origin, authority, 18735)
        app = m.ClaimApplication(store, origin, authority, owner, exchange, lambda *_args:None, clock=lambda:now)
        with patch.object(m.http.client, 'HTTPConnection', Connection), patch.object(m, '_protected_file', opened), patch.object(m.time, 'time', lambda:now):
            if responses[-1] is successful and not unavailable:
                try: status, response_headers, body = app.handle('POST', m.CLAIM_PATH, headers, code.encode())
                except m.ClaimRefusal as error: raise AssertionError('expected successful cookie exchange') from error
                assert status == 204 and body == b'' and ('Set-Cookie',cookie) in response_headers
            else:
                refused(lambda:app.handle('POST',m.CLAIM_PATH,headers,code.encode()),
                        'HARNESS_EXCHANGE_UNAVAILABLE' if unavailable else 'HARNESS_COOKIE_INVALID')
        refused(lambda:m.ClaimStore(store.path, require_root=False).consume(code,authority,now+1), 'CLAIM_SPENT')
        assert len(closed) == len(requests), 'exchange connection not closed'
        return requests, reads

    requests, reads = attempt('restart', [token_refusal, successful])
    assert requests == ['/?token=old-fixture-token','/?token=new-fixture-token'] and len(reads) == 2
    requests, reads = attempt('no-restart', [successful])
    assert len(requests) == len(reads) == 1
    requests, reads = attempt('unchanged', [token_refusal], changed=False)
    assert len(requests) == 1 and len(reads) == 2, 'unchanged token retried'
    requests, reads = attempt('two-restarts', [token_refusal, token_refusal])
    assert len(requests) == len(reads) == 2, 'second refusal caused another descriptor read'
    for name, response in [('forbidden',Response(403,unauthorized)), ('generic',Response(401,b'other refusal')),
            ('cookie',Response(401,unauthorized,cookie='unexpected')), ('redirect',Response(401,unauthorized,location='/elsewhere'))]:
        requests, reads = attempt(name,[response])
        assert len(requests) == len(reads) == 1, 'non-token refusal retried'
    requests, reads = attempt('unavailable',[token_refusal],unavailable=True)
    assert len(requests) == len(reads) == 1, 'transport error retried'

    store = m.ClaimStore(base / 'durable.json', require_root=False)
    original_fsync, original_replace = os.fsync, os.replace
    events = []
    def synced(fd):
        kind = 'directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file'
        events.append(kind)
        if kind == 'directory':
            assert store.path.exists(), 'directory sync preceded replacement'
        original_fsync(fd)
    def replaced(source, destination):
        original_replace(source,destination)
        events.append('replace')
    with patch.object(m.os,'fsync',synced), patch.object(m.os,'replace',replaced):
        code = store.mint(authority,now,60)
        assert events == ['file','replace','directory'], 'mint directory was not synced after replace'
        events.clear()
        store.consume(code,authority,now+1)
        assert events == ['file','replace','directory'], 'spent directory was not synced after replace'
    refused(lambda:m.ClaimStore(store.path,require_root=False).consume(code,authority,now+2),'CLAIM_SPENT')
    code = store.mint(authority,now,60)
    exchanges = []
    def sync_failure(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('fixture directory sync failure')
        original_fsync(fd)
    app = m.ClaimApplication(store,origin,authority,owner,lambda:exchanges.append(True),lambda *_args:None,clock=lambda:now)
    with patch.object(m.os,'fsync',sync_failure):
        try: app.handle('POST',m.CLAIM_PATH,headers,code.encode())
        except OSError: pass
        else: raise AssertionError('directory sync failure allowed exchange')
    assert not exchanges, 'cookie exchange happened after directory sync failure'
print('PASS browser claim exchange: changed-token retry once; spend-before-exchange; refusals stay spent; file/replace/directory fsync order')
`

const run = source => spawnSync('/usr/bin/python3', ['-I', '-S', '-B', '-c', court, source],
  { cwd: root, encoding: 'utf8', timeout: 10000 })

test('claim exchange recovers one restart and durably spends before exchange', t => {
  const baseline = run(claimPath)
  assert.equal(baseline.status, 0, baseline.stderr)
  t.diagnostic(baseline.stdout.trim())
  const source = readFileSync(claimPath, 'utf8')
  const mutations = [
    ['restart retry', 'if current_token != token:', 'if False:'],
    ['refusal status', 'status == 401 and body ==', 'status in (401, 403) and body =='],
    ['refusal body', 'body == b"dsh web authentication required; reopen the URL printed by dsh web.\\n"', 'True'],
    ['refusal cookie', 'and cookie is None and location is None', 'and location is None'],
    ['refusal redirect', 'and cookie is None and location is None', 'and cookie is None'],
    ['changed token only', 'if current_token != token:', 'if True:'],
    ['single descriptor reread', 'current_token = self._launch_token()', 'current_token = self._launch_token()\n            self._launch_token()'],
    ['single retry', 'status, body, cookie, location = self._exchange(current_token)', 'status, body, cookie, location = self._exchange(current_token)\n                self._exchange(current_token)'],
    ['spend before exchange', 'self.store.consume(code, self.public_authority, int(self.clock()))\n        cookie = self.exchange_cookie()', 'cookie = self.exchange_cookie()\n        self.store.consume(code, self.public_authority, int(self.clock()))'],
    ['directory fsync', 'os.fsync(directory)', 'pass'],
  ]
  const scratch = mkdtempSync(join(root, '.claim-exchange-mutants-'))
  try {
    for (const [name, before, after] of mutations) {
      assert.equal(source.split(before).length, 2, `mutation anchor: ${name}`)
      const path = join(scratch, name.replaceAll(' ', '-') + '.py')
      writeFileSync(path, source.replace(before, after))
      const result = run(path)
      assert.notEqual(result.status, 0, `surviving mutant: ${name}`)
      assert.match(result.stderr, /AssertionError/u, `mutation did not fail an assertion: ${name}`)
    }
  } finally { rmSync(scratch, { recursive: true, force: true }) }
  t.diagnostic(`MUTATION browser claim exchange: ${mutations.length}/${mutations.length} killed`)
})
