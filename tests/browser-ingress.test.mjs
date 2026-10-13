// SPDX-License-Identifier: AGPL-3.0-or-later
// Source fixtures exercise launch-dsh.py, claim.py, render.py and Caddyfile.template without a listener.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const claimPath = join(root, 'ops/node-spawn/ingress/claim.py')
const renderPath = join(root, 'ops/node-spawn/ingress/render.py')
const templatePath = join(root, 'ops/node-spawn/ingress/Caddyfile.template')
const launcherPath = join(root, 'scripts/launch-dsh.py')
const python = '/usr/bin/python3'

const claimCourt = String.raw`
import contextlib, importlib.util, io, json, os, pathlib, sys, tempfile
source = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('claim_under_test', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def refused(call, code):
    try:
        call()
    except module.ClaimRefusal as error:
        assert error.code == code, (error.code, code)
        return
    raise AssertionError('expected ' + code)

def fresh(base, name):
    directory = base / name
    directory.mkdir(mode=0o700)
    return module.ClaimStore(directory / 'claims.json', require_root=False)

with tempfile.TemporaryDirectory() as temporary:
    base = pathlib.Path(temporary).resolve()
    authority = 'node.example.test'
    origin = 'https://' + authority
    now = 1000

    store = fresh(base, 'reuse')
    code = store.mint(authority, now, 60)
    state = (base / 'reuse/claims.json').read_text()
    assert code not in state and 'sha256:' in state
    store.consume(code, authority, now + 1)
    refused(lambda: store.consume(code, authority, now + 2), 'CLAIM_SPENT')
    restarted = module.ClaimStore(base / 'reuse/claims.json', require_root=False)
    refused(lambda: restarted.consume(code, authority, now + 3), 'CLAIM_SPENT')

    expired = fresh(base, 'expired')
    old = expired.mint(authority, now, 30)
    refused(lambda: expired.consume(old, authority, now + 30), 'CLAIM_EXPIRED')

    calls = []
    cookie = 'dsh-auth-fixture=v1.fixture; Path=/; HttpOnly; SameSite=Strict; Secure'
    wrong = fresh(base, 'wrong-host')
    claim = wrong.mint(authority, now, 60)
    app = module.ClaimApplication(wrong, origin, authority, 'owner.example.test',
      lambda: calls.append('exchange') or cookie, lambda *_args: (_ for _ in ()).throw(AssertionError('owner proxy')),
      clock=lambda: now + 1)
    headers = {'host': authority, 'origin': origin, 'sec-fetch-site': 'same-origin', 'content-type': 'text/plain'}
    refused(lambda: app.handle('POST', module.CLAIM_PATH, {**headers, 'host': 'wrong.example.test'}, claim.encode()), 'CLAIM_HOST_REFUSED')
    refused(lambda: app.handle('POST', module.CLAIM_PATH, {**headers, 'origin': 'https://wrong.example.test'}, claim.encode()), 'CLAIM_ORIGIN_REFUSED')
    status, response_headers, body = app.handle('POST', module.CLAIM_PATH, headers, claim.encode())
    assert status == 204 and body == b'' and ('Set-Cookie', cookie) in response_headers and calls == ['exchange']

    burned = fresh(base, 'burned')
    burn_code = burned.mint(authority, now, 60)
    failed = module.ClaimApplication(burned, origin, authority, 'owner.example.test',
      lambda: (_ for _ in ()).throw(module.ClaimRefusal('HARNESS_EXCHANGE_UNAVAILABLE', 502)), lambda *_args: None,
      clock=lambda: now + 1)
    refused(lambda: failed.handle('POST', module.CLAIM_PATH, headers, burn_code.encode()), 'HARNESS_EXCHANGE_UNAVAILABLE')
    refused(lambda: module.ClaimStore(base / 'burned/claims.json', require_root=False).consume(burn_code, authority, now + 2), 'CLAIM_SPENT')

    too_large = fresh(base, 'large')
    large_code = too_large.mint(authority, now, 60)
    refused(lambda: module.ClaimApplication(too_large, origin, authority, 'owner.example.test', lambda: cookie, lambda *_args: None,
      clock=lambda: now + 1).handle('POST', module.CLAIM_PATH, headers, large_code.encode() + b'x' * 100), 'CLAIM_REQUEST_TOO_LARGE')

    ticks = iter([0.0, 0.1])
    limiter = module.RateLimiter(maximum=1, window_seconds=60, clock=lambda: next(ticks))
    assert limiter.allow() is True and limiter.allow() is False

    handler = module.handler_for(app)
    instance = object.__new__(handler)
    instance.client_address = ('127.0.0.1', 1)
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        instance.log_message('request %s', claim)
    assert claim not in captured.getvalue()
    assert claim.encode() not in module.CLAIM_PAGE and claim.encode() not in module.CLAIM_SCRIPT
    assert module.parse_origin(origin + '\n') == (origin, authority)
    public_file = base / 'public-origin'
    public_file.write_text(origin + '\n')
    public_file.chmod(0o644)
    assert module.read_origin_file(public_file, require_root=None) == (origin, authority)
    public_file.chmod(0o666)
    refused(lambda: module.read_origin_file(public_file, require_root=None), 'PROTECTED_FILE_INVALID')
    private_file = base / 'launch-url.json'
    private_file.write_text('{"url":"redacted"}\n')
    private_file.chmod(0o644)
    refused(lambda: module._protected_file(private_file, require_root=None), 'PROTECTED_FILE_INVALID')
    for invalid in ['http://' + authority, 'https://*.example.test', origin + '/path', 'https://localhost', 'https://127.0.0.1', 'https://UPPER.example.test']:
        refused(lambda invalid=invalid: module.parse_origin(invalid), 'PUBLIC_ORIGIN_INVALID')

print('PASS claim: reuse, expiry, host/origin, restart spending, bounds, rate and log secrecy')
`

function runClaim(source) {
  const result = spawnSync(python, ['-I', '-S', '-c', claimCourt, source], { encoding: 'utf8', timeout: 10_000 })
  assert.equal(result.signal, null)
  return result
}

test('one-time claim protections and focused guard-removal mutations', t => {
  const source = readFileSync(claimPath, 'utf8')
  const baseline = runClaim(claimPath)
  assert.equal(baseline.status, 0, baseline.stderr)
  assert.match(baseline.stdout, /^PASS claim:/mu)
  const mutations = [
    ['reuse refused', 'if selected.get("spent_at") is not None:', 'if False:'],
    ['expired refused', 'if not isinstance(expires_at, int) or expires_at <= now:', 'if False:'],
    ['wrong host refused', 'if host != self.public_authority:', 'if False:'],
    ['spent survives restart', 'selected["spent_at"] = now\n            self._write(state)', 'selected["spent_at"] = now\n            pass'],
    ['code stored hashed', '"digest": f"sha256:{digest}"', '"digest": code'],
    ['code never logged', 'def log_message(self, _format, *_arguments):\n            return', 'def log_message(self, _format, *_arguments):\n            return super().log_message(_format, *_arguments)'],
    ['rate limited', 'if len(self.attempts) >= self.maximum:', 'if False:'],
    ['request bounded', 'if len(body) > MAX_CLAIM_BODY:', 'if False:'],
    ['origin refused', 'if headers.get("origin") != self.public_origin or headers.get("sec-fetch-site") == "cross-site":', 'if False:'],
    ['public file non-writable', 'or (not private and info.st_mode & 0o022)):', 'or False):'],
    ['launch descriptor private', 'or (private and info.st_mode & 0o077)', 'or False'],
    ['public DNS hostname', 'or re.search(r"[a-z]", labels[-1]) is None', 'or False'],
  ]
  const scratch = mkdtempSync(join(tmpdir(), 'aukora-claim-mutants-'))
  for (const [name, before, after] of mutations) {
    assert.equal(source.split(before).length, 2, `mutation anchor: ${name}`)
    const file = join(scratch, `${name.replaceAll(' ', '-')}.py`)
    writeFileSync(file, source.replace(before, after), { mode: 0o600 })
    const result = runClaim(file)
    assert.notEqual(result.status, 0, `surviving mutant: ${name}`)
    assert.match(result.stderr, /AssertionError/u, `mutation must fail an assertion: ${name}`)
    t.diagnostic(`MUTATION CAUGHT ${name}`)
  }
  t.diagnostic(`MUTATION claim protections: ${mutations.length}/${mutations.length} killed`)
})

const launcherCourt = String.raw`
import ast, pathlib, re, sys, urllib.parse
source = pathlib.Path(sys.argv[1]).read_text()
tree = ast.parse(source)
function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'parse_public_origin')
namespace = {'re': re, 'urllib': urllib}
exec(compile(ast.Module(body=[function], type_ignores=[]), 'launch-dsh.py:function', 'exec'), namespace)
parse = namespace['parse_public_origin']
assert parse('https://node.example.test\n') == 'node.example.test'
for invalid in ['http://node.example.test', 'https://*.example.test', 'https://node.example.test/path', 'https://node.example.test:443', 'https://UPPER.example.test', 'https://localhost', 'https://127.0.0.1']:
    try: parse(invalid)
    except ValueError as error: assert str(error).startswith('PUBLIC_ORIGIN_INVALID')
    else: raise AssertionError('accepted ' + invalid)
assert "origin_file=_root_protected(a.public_origin_file)" in source
assert "command += ['--trusted-host', public_authority]" in source
print('PASS launcher public-origin validation and trusted-host passthrough')
`

function runLauncher(source) {
  return spawnSync(python, ['-I', '-S', '-c', launcherCourt, source], { encoding: 'utf8' })
}

test('launcher accepts only the exact root-file HTTPS hostname and passes only its authority', t => {
  const source = readFileSync(launcherPath, 'utf8')
  const baseline = runLauncher(launcherPath)
  assert.equal(baseline.status, 0, baseline.stderr)
  const mutations = [
    ['scheme', [["parsed.scheme != 'https'", 'False'], ["value != f'https://{hostname}'", "value != f'{parsed.scheme}://{hostname}'"]]],
    ['wildcard hostname', [["or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)\n                   for label in labels)", '']]],
    ['path', [['or parsed.path or parsed.query or parsed.fragment', 'or parsed.query or parsed.fragment'],
      ["value != f'https://{hostname}'", "value != f'https://{hostname}{parsed.path}'"]]],
    ['root protection', [['origin_file=_root_protected(a.public_origin_file)', 'origin_file=a.public_origin_file']]],
    ['trusted host passthrough', [["if public_authority is not None: command += ['--trusted-host', public_authority]", '']]],
    ['DNS not IP', [["or not re.search(r'[a-z]', labels[-1])", '']]],
  ]
  const scratch = mkdtempSync(join(tmpdir(), 'aukora-launch-origin-mutants-'))
  for (const [name, replacements] of mutations) {
    let changed = source
    for (const [before, after] of replacements) {
      assert.equal(changed.split(before).length, 2, `mutation anchor: ${name}`)
      changed = changed.replace(before, after)
    }
    const file = join(scratch, `${name.replaceAll(' ', '-')}.py`)
    writeFileSync(file, changed, { mode: 0o600 })
    const result = runLauncher(file)
    assert.notEqual(result.status, 0, `surviving mutant: ${name}`)
    assert.match(result.stderr, /AssertionError/u)
    t.diagnostic(`MUTATION CAUGHT launcher ${name}`)
  }
})

function render(args = []) {
  return spawnSync(python, ['-I', '-S', renderPath, '--app-host', 'node.example.test',
    '--owner-host', 'owner.example.test', '--harness-port', '28735', '--owner-port', '28736', ...args],
  { encoding: 'utf8' })
}

function assertCaddy(text) {
  const escaped = value => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
  assert.match(text, /^https:\/\/node\.example\.test \{/mu)
  assert.match(text, /^https:\/\/owner\.example\.test \{/mu)
  assert.match(text, /^http:\/\/node\.example\.test \{/mu)
  assert.match(text, /^http:\/\/owner\.example\.test \{/mu)
  assert.match(text, /^:80, :443 \{/mu)
  assert.match(text, /Strict-Transport-Security "max-age=31536000"/u)
  assert.match(text, /request_body \{\s+max_size 8MB/u)
  assert.equal(text.match(/reverse_proxy 127\.0\.0\.1:/gu)?.length, 3)
  assert.equal(text.match(/flush_interval -1/gu)?.length, 3)
  assert.equal(text.match(/header_up -X-Forwarded-\*/gu)?.length, 3)
  for (const [header, value] of Object.entries({ Host: '{http.request.host}', Origin: '{http.request.header.Origin}',
    Cookie: '{http.request.header.Cookie}', 'Sec-Fetch-Dest': '{http.request.header.Sec-Fetch-Dest}',
    'Sec-Fetch-Mode': '{http.request.header.Sec-Fetch-Mode}', 'Sec-Fetch-Site': '{http.request.header.Sec-Fetch-Site}',
    'Sec-Fetch-User': '{http.request.header.Sec-Fetch-User}' })) {
    assert.equal(text.match(new RegExp(`header_up ${escaped(header)} ${escaped(value)}`, 'gu'))?.length, 3, header)
  }
  for (const header of ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto']) {
    assert.equal(text.match(new RegExp(`header_up ${header} `, 'gu'))?.length, 3, header)
  }
  assert.match(text, /@claim path \/__aukora\/claim \/__aukora\/claim\.js \/__aukora\/signin \/__aukora\/signin\.js \/__aukora\/signout/u)
  assert.match(text, /@launch_token query token=\*/u)
  assert.match(text, /respond @launch_token 404/u)
  assert.doesNotMatch(text, /header Content-Security-Policy/u)
  assert.match(text, /X-Frame-Options "DENY"/u)
  assert.doesNotMatch(text, /^\s*log(?:\s|\{)/mu)
  assert.doesNotMatch(text, /tls internal|cert_file|key_file/iu)
  assert.doesNotMatch(text, /__\w+__/u)
}

test('rendered Caddy text has the two-host TLS, proxy and privacy contract', t => {
  const result = render()
  assert.equal(result.status, 0, result.stderr)
  assertCaddy(result.stdout)
  for (const invalid of [
    ['--app-host', '*.example.test'], ['--app-host', 'https://node.example.test'],
    ['--owner-host', 'node.example.test'], ['--harness-port', '28736'],
  ]) {
    const attempted = render(invalid)
    assert.notEqual(attempted.status, 0, invalid.join('='))
  }
  const mutations = [
    ['automatic HTTPS host', 'https://node.example.test {', 'http://node.example.test {'],
    ['HSTS', 'Strict-Transport-Security "max-age=31536000"', 'X-Removed-HSTS "0"'],
    ['body ceiling', 'max_size 8MB', 'max_size 0'],
    ['SSE flushing', 'flush_interval -1', 'flush_interval 1s'],
    ['forwarded stripping', 'header_up -X-Forwarded-*', 'header_up X-Forwarded-Client {http.request.header.X-Forwarded-For}'],
    ['Host preservation', 'header_up Host {http.request.host}', 'header_up Host 127.0.0.1'],
    ['owner frame refusal', 'header X-Frame-Options "DENY"', 'header X-Removed-Frame "ALLOW"'],
    ['closed unknown hosts', ':80, :443 {', ':80 {'],
    ['public launch token refused', 'respond @launch_token 404', 'respond @launch_token 200'],
    ['returning signin route', '/__aukora/signin /__aukora/signin.js', '/removed/signin /removed/signin.js'],
    ['signout route', '/__aukora/signout', '/removed/signout'],
  ]
  for (const [name, before, after] of mutations) {
    assert.ok(result.stdout.includes(before), name)
    assert.throws(() => assertCaddy(result.stdout.replaceAll(before, after)), assert.AssertionError, name)
    t.diagnostic(`MUTATION CAUGHT Caddy ${name}`)
  }
  assert.throws(() => assertCaddy(result.stdout + '\nlog { output stdout }\n'), assert.AssertionError,
    'access logging mutation must fail')
  assert.throws(() => assertCaddy(result.stdout + '\nheader Content-Security-Policy "default-src none"\n'), assert.AssertionError,
    'owner CSP overwrite must fail')
  t.diagnostic(`MUTATION Caddy protections: ${mutations.length + 2}/${mutations.length + 2} killed`)
})
