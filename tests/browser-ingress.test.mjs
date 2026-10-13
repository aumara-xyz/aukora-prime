// SPDX-License-Identifier: AGPL-3.0-or-later
// Source fixtures exercise launch-dsh.py, claim.py, render.py and Caddyfile.template without a listener.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const claimPath = join(root, 'ops/node-spawn/ingress/claim.py')
const renderPath = join(root, 'ops/node-spawn/ingress/render.py')
const templatePath = join(root, 'ops/node-spawn/ingress/Caddyfile.template')
const ingressReadmePath = join(root, 'ops/node-spawn/ingress/README.md')
const browserReadmePath = join(root, 'ops/node-spawn/browser/README.md')
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
    cookie = module.cookie_name(authority) + '=v1.fixture; Path=/; HttpOnly; SameSite=Strict; Secure'
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
    for target, streaming in [('/api/remote.mux', {'connection': 'Upgrade', 'upgrade': 'websocket'}),
                              ('/plugins/events', {'accept': 'text/event-stream'})]:
        refused(lambda: app.handle('GET', target, {**headers, **streaming}, b''), 'CLAIM_ROUTE_REFUSED')

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
    ['broker refuses harness streaming routes', 'if method != "POST" or target not in (CLAIM_PATH, SIGNIN_PATH, SIGNOUT_PATH):', 'if False:'],
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

function render(args = [], source = renderPath) {
  return spawnSync(python, ['-I', '-S', source, '--app-host', 'node.example.test',
    '--owner-host', 'owner.example.test', '--harness-port', '28735', '--owner-port', '28736',
    '--claim-port', '28737', ...args],
  { encoding: 'utf8' })
}

function assertHttpCaddy(text, host) {
  const start = text.indexOf(`http://${host} {\n`)
  assert.notEqual(start, -1, host)
  const block = text.slice(start, text.indexOf('\n}', start) + 2)
  assert.match(block, /@launch_token query token=\*/u, `${host}: HTTP token query matcher`)
  assert.match(block, /handle @launch_token \{\n\t\trespond 404\n\t\}/u, `${host}: HTTP token refusal`)
  assert.ok(block.includes(`handle {\n\t\tredir https://${host}{path} permanent\n\t}`), `${host}: path-only redirect`)
  assert.doesNotMatch(block, /\{uri\}|\{query\}|http\.request\.uri/u, `${host}: no query in redirect`)
}

function assertCaddy(text) {
  const escaped = value => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')
  assert.match(text, /^https:\/\/node\.example\.test \{/mu)
  assert.match(text, /^https:\/\/owner\.example\.test \{/mu)
  assert.match(text, /^http:\/\/node\.example\.test \{/mu)
  assert.match(text, /^http:\/\/owner\.example\.test \{/mu)
  assert.match(text, /^:80, :443 \{/mu)
  assert.match(text, /Strict-Transport-Security "max-age=31536000"/u)
  assert.doesNotMatch(text, /includeSubDomains/u, 'subdomain HSTS is opt-in')
  assertHttpCaddy(text, 'node.example.test')
  assertHttpCaddy(text, 'owner.example.test')
  assert.match(text, /request_body \{\s+max_size 8MB/u)
  assert.equal(text.match(/reverse_proxy 127\.0\.0\.1:/gu)?.length, 3)
  assert.match(text, /handle @claim \{\s+reverse_proxy 127\.0\.0\.1:28737 \{/u)
  assert.match(text, /\thandle \{\s+reverse_proxy 127\.0\.0\.1:28735 \{/u)
  assert.match(text, /https:\/\/owner\.example\.test \{\s+import aukora_headers\s+header X-Frame-Options "DENY"\s+reverse_proxy 127\.0\.0\.1:28736 \{/u)
  assert.equal(text.match(/flush_interval -1/gu)?.length, 3)
  assert.equal(text.match(/header_up -X-Forwarded-\*/gu)?.length, 3)
  assert.equal(text.match(/header_up Host \{http\.request\.host\}/gu)?.length, 3, 'Host')
  // Origin, Cookie and Fetch Metadata must pass through untouched. Restating one sends an EMPTY header when the
  // browser sent none, and the node refuses an Origin that is not its own (found on the first real node).
  for (const header of ['Origin', 'Cookie', 'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Sec-Fetch-User']) {
    assert.doesNotMatch(text, new RegExp(`header_up -?${escaped(header)}\\b`, 'u'), header)
  }
  for (const header of ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto']) {
    assert.equal(text.match(new RegExp(`header_up ${header} `, 'gu'))?.length, 3, header)
  }
  assert.match(text, /@claim path \/__aukora\/claim \/__aukora\/claim\.js \/__aukora\/signin \/__aukora\/signin\.js \/__aukora\/signout/u)
  assert.match(text, /@launch_token query token=\*/u)
  // The refusal sits in its own handle block: a bare respond is ordered after handle and would never fire.
  assert.match(text, /handle @launch_token \{\n\t\trespond 404\n\t\}/u)
  assert.doesNotMatch(text, /^\trespond @launch_token/mu)
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
    ['--app-host', '127.0.0.1'],
    ['--owner-host', 'node.example.test'], ['--harness-port', '28736'],
    ['--claim-port', '28735'], ['--claim-port', '28736'],
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
    ['Origin untouched', 'header_up Host {http.request.host}', 'header_up Host {http.request.host}\n\t\t\theader_up Origin {http.request.header.Origin}'],
    ['owner frame refusal', 'header X-Frame-Options "DENY"', 'header X-Removed-Frame "ALLOW"'],
    ['closed unknown hosts', ':80, :443 {', ':80 {'],
    ['public launch token refused', 'handle @launch_token {\n\t\trespond 404', 'handle @launch_token {\n\t\trespond 200'],
    ['HTTP app token matcher', 'http://node.example.test {\n\t@launch_token query token=*', 'http://node.example.test {\n\t@launch_token query removed=*'],
    ['HTTP owner token matcher', 'http://owner.example.test {\n\t@launch_token query token=*', 'http://owner.example.test {\n\t@launch_token query removed=*'],
    ['HTTP app token refusal', 'http://node.example.test {\n\t@launch_token query token=*\n\thandle @launch_token {\n\t\trespond 404', 'http://node.example.test {\n\t@launch_token query token=*\n\thandle @launch_token {\n\t\trespond 200'],
    ['HTTP owner token refusal', 'http://owner.example.test {\n\t@launch_token query token=*\n\thandle @launch_token {\n\t\trespond 404', 'http://owner.example.test {\n\t@launch_token query token=*\n\thandle @launch_token {\n\t\trespond 200'],
    ['HTTP app drops query', 'redir https://node.example.test{path} permanent', 'redir https://node.example.test{uri} permanent'],
    ['HTTP owner drops query', 'redir https://owner.example.test{path} permanent', 'redir https://owner.example.test{uri} permanent'],
    ['returning signin route', '/__aukora/signin /__aukora/signin.js', '/removed/signin /removed/signin.js'],
    ['signout route', '/__aukora/signout', '/removed/signout'],
    ['claim upstream separated', 'handle @claim {\n\t\treverse_proxy 127.0.0.1:28737', 'handle @claim {\n\t\treverse_proxy 127.0.0.1:28736'],
    ['harness streaming upstream direct', 'reverse_proxy 127.0.0.1:28735', 'reverse_proxy 127.0.0.1:28737'],
    ['owner upstream direct', 'reverse_proxy 127.0.0.1:28736', 'reverse_proxy 127.0.0.1:28737'],
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

const rendererCourt = String.raw`
import importlib.util, json, os, pathlib, tempfile, sys
source = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('render_under_test', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
template = source.with_name('Caddyfile.template').read_text()
nodes = [{'name':'single','app_host':'node.example.test','owner_host':'owner.example.test','harness_port':28735,'owner_port':28736,'claim_port':28737}]
assert 'Strict-Transport-Security "max-age=31536000"' in module._render_nodes(template, nodes)
assert 'includeSubDomains' not in module._render_nodes(template, nodes)
assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains"' in module._render_nodes(template, nodes, hsts_include_subdomains=True)
assert 'includeSubDomains' not in module.render(template, 'node.example.test', 'owner.example.test', 28735, 28736, 28737)
assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains"' in module.render(template, 'node.example.test', 'owner.example.test', 28735, 28736, 28737, hsts_include_subdomains=True)
for value in ['127.0.0.1', 'node.example.123']:
    try: module.hostname(value)
    except module.argparse.ArgumentTypeError: pass
    else: raise AssertionError('numeric authority accepted')
for ports in [(28735, 28735, 28737), (28735, 28736, 28735), (28735, 28736, 28736)]:
    try: module.render(template, 'node.example.test', 'owner.example.test', *ports)
    except ValueError as error: assert str(error) == 'INGRESS_PORTS_MUST_DIFFER'
    else: raise AssertionError('colliding upstreams accepted')
nodes = [
    {'name':'C1','app_host':'one.example.test','owner_host':'one-owner.example.test','harness_port':28735,'owner_port':28736,'claim_port':28737},
    {'name':'C2','app_host':'two.example.test','owner_host':'two-owner.example.test','harness_port':29735,'owner_port':29736,'claim_port':29737},
]
assert len(module.validate_nodes(nodes)) == 2
invalid_port = [dict(node) for node in nodes]
invalid_port[1]['harness_port'] = 29735.5
try: module.validate_nodes(invalid_port)
except ValueError as error: assert str(error) == 'INGRESS_NODE_VALUE_INVALID'
else: raise AssertionError('non-integer JSON port accepted')
for field, value, code in [('app_host', 'one.example.test', 'INGRESS_HOSTS_MUST_DIFFER'),
                           ('harness_port', 28735, 'INGRESS_PORTS_MUST_DIFFER'),
                           ('name', 'C1', 'INGRESS_NODE_NAME_INVALID')]:
    crossed = [dict(node) for node in nodes]
    crossed[1][field] = value
    try: module.validate_nodes(crossed)
    except ValueError as error: assert str(error) == code
    else: raise AssertionError('cross-node collision accepted: ' + field)
with tempfile.TemporaryDirectory() as temporary:
    path = pathlib.Path(temporary) / 'nodes.json'
    path.write_text(json.dumps(nodes))
    path.chmod(0o600)
    assert len(module.load_nodes(path, required_uid=os.getuid())) == 2
    try: module.load_nodes(path, required_uid=os.getuid() + 1)
    except ValueError as error: assert str(error) == 'INGRESS_NODES_FILE_INVALID'
    else: raise AssertionError('wrong-owner nodes file accepted')
print('PASS renderer: protected list, unique DNS authorities and unique loopback upstreams')
`

test('renderer refuses numeric authorities and colliding broker upstreams', t => {
  const source = readFileSync(renderPath, 'utf8')
  const run = file => spawnSync(python, ['-I', '-S', '-c', rendererCourt, file], { encoding: 'utf8' })
  const baseline = run(renderPath)
  assert.equal(baseline.status, 0, baseline.stderr)
  assert.match(baseline.stdout, /^PASS renderer:/mu)
  const mutations = [
    ['DNS authority', 'or re.search(r"[a-z]", labels[-1]) is None', 'or False'],
    ['globally unique hostnames', 'if len(node_hosts) != 2 or hosts & node_hosts:', 'if len(node_hosts) != 2:'],
    ['globally unique ports', 'if len(node_ports) != 3 or ports & node_ports:', 'if len(node_ports) != 3:'],
    ['unique node names', 'or NODE_NAME.fullmatch(name) is None or name in names):', 'or NODE_NAME.fullmatch(name) is None or False):'],
    ['root-owned nodes file', 'or info.st_uid != required_uid', 'or False'],
    ['subdomain HSTS defaults off', 'def _render_nodes(template, nodes, hsts_include_subdomains=False):', 'def _render_nodes(template, nodes, hsts_include_subdomains=True):'],
    ['subdomain HSTS opt-in render', '"; includeSubDomains" if hsts_include_subdomains else ""', '""'],
    ['subdomain HSTS single-node passthrough', 'hsts_include_subdomains=hsts_include_subdomains)', 'hsts_include_subdomains=False)'],
  ]
  const scratch = mkdtempSync(join(tmpdir(), 'aukora-ingress-render-mutants-'))
  writeFileSync(join(scratch, 'Caddyfile.template'), readFileSync(templatePath))
  for (const [name, before, after] of mutations) {
    assert.equal(source.split(before).length, 2, `mutation anchor: ${name}`)
    const file = join(scratch, `${name.replaceAll(' ', '-')}.py`)
    writeFileSync(file, source.replace(before, after), { mode: 0o600 })
    const result = run(file)
    assert.notEqual(result.status, 0, `surviving mutant: ${name}`)
    assert.match(result.stderr, /AssertionError/u)
    t.diagnostic(`MUTATION CAUGHT renderer ${name}`)
  }
  const args = ['-I', '-S', renderPath, '--app-host', 'node.example.test', '--owner-host',
    'owner.example.test', '--harness-port', '28735', '--owner-port', '28736']
  const missing = spawnSync(python, args, { encoding: 'utf8' })
  assert.notEqual(missing.status, 0)
  assert.match(missing.stderr, /single-node mode requires all five host and port flags/u)
  const required = 'if any(value is None for value in single) or arguments.check is not None:'
  assert.equal(source.split(required).length, 2)
  const missingGuard = join(scratch, 'missing-single-guard.py')
  writeFileSync(missingGuard, source.replace(required, 'if arguments.check is not None:'), { mode: 0o600 })
  const missingMutant = spawnSync(python, args.map(value => value === renderPath ? missingGuard : value), { encoding: 'utf8' })
  assert.doesNotMatch(missingMutant.stderr, /single-node mode requires all five host and port flags/u)
  t.diagnostic('MUTATION CAUGHT renderer required single-node flags')
  t.diagnostic(`MUTATION renderer protections: ${mutations.length + 1}/${mutations.length + 1} killed`)
})

test('subdomain HSTS requires the explicit render flag', t => {
  const optedIn = render(['--hsts-include-subdomains'])
  assert.equal(optedIn.status, 0, optedIn.stderr)
  assert.match(optedIn.stdout, /Strict-Transport-Security "max-age=31536000; includeSubDomains"/u)
  const source = readFileSync(renderPath, 'utf8')
  const scratch = mkdtempSync(join(tmpdir(), 'aukora-ingress-hsts-mutants-'))
  writeFileSync(join(scratch, 'Caddyfile.template'), readFileSync(templatePath))
  const mutations = [
    ['CLI subdomain HSTS passthrough', '_render_nodes(template, nodes, hsts_include_subdomains=arguments.hsts_include_subdomains)',
      '_render_nodes(template, nodes)', ['--hsts-include-subdomains'],
      text => assert.match(text, /Strict-Transport-Security "max-age=31536000; includeSubDomains"/u)],
    ['CLI subdomain HSTS defaults off', 'parser.add_argument("--hsts-include-subdomains", action="store_true")',
      'parser.add_argument("--hsts-include-subdomains", action="store_true", default=True)', [], assertCaddy],
  ]
  for (const [name, before, after, args, court] of mutations) {
    assert.equal(source.split(before).length, 2)
    const file = join(scratch, `${name.replaceAll(' ', '-')}.py`)
    writeFileSync(file, source.replace(before, after), { mode: 0o600 })
    const mutant = render(args, file)
    assert.equal(mutant.status, 0, mutant.stderr)
    assert.throws(() => court(mutant.stdout), assert.AssertionError, `surviving mutant: ${name}`)
    t.diagnostic(`MUTATION CAUGHT renderer ${name}`)
  }
  t.diagnostic(`MUTATION renderer HSTS CLI protections: ${mutations.length}/${mutations.length} killed`)
})

const nodesCliCourt = String.raw`
import importlib.util, os, pathlib, sys
source = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('render_cli_under_test', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
load_nodes = module.load_nodes
module.load_nodes = lambda path: load_nodes(path, required_uid=os.getuid())
sys.argv = [str(source), *sys.argv[2:]]
module.main()
`

function assertNodeCaddy(text, node, sibling) {
  const start = text.indexOf(`# Node ${node.name}:`)
  assert.notEqual(start, -1, node.name)
  const next = text.indexOf('# Node ', start + 1)
  const catchall = text.indexOf(':80, :443 {', start)
  const block = text.slice(start, next === -1 ? catchall : next)
  assert.match(block, new RegExp(`https://${node.app_host.replaceAll('.', '\\.')}`))
  assert.match(block, new RegExp(`https://${node.owner_host.replaceAll('.', '\\.')}`))
  assert.match(block, new RegExp(`http://${node.app_host.replaceAll('.', '\\.')}`))
  assert.match(block, new RegExp(`http://${node.owner_host.replaceAll('.', '\\.')}`))
  assert.equal(block.match(/import aukora_headers/gu)?.length, 2)
  assert.equal(block.match(/header_up -X-Forwarded-\*/gu)?.length, 3)
  assert.equal(block.match(/flush_interval -1/gu)?.length, 3)
  assert.match(block, new RegExp(`handle @claim \\{\\s+reverse_proxy 127\\.0\\.0\\.1:${node.claim_port}`))
  assert.match(block, new RegExp(`\\thandle \\{\\s+reverse_proxy 127\\.0\\.0\\.1:${node.harness_port}`))
  assert.match(block, new RegExp(`header X-Frame-Options "DENY"\\s+reverse_proxy 127\\.0\\.0\\.1:${node.owner_port}`))
  assert.match(block, /handle @launch_token \{\n\t\trespond 404\n\t\}/u)
  assertHttpCaddy(block, node.app_host)
  assertHttpCaddy(block, node.owner_host)
  for (const header of ['Origin', 'Cookie', 'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Sec-Fetch-User']) {
    assert.doesNotMatch(block, new RegExp(`header_up -?${header}\\b`, 'u'), `${node.name}: ${header}`)
  }
  for (const port of [sibling.harness_port, sibling.owner_port, sibling.claim_port]) {
    assert.doesNotMatch(block, new RegExp(`127\\.0\\.0\\.1:${port}\\b`, 'u'), `${node.name}: sibling port ${port}`)
  }
}

test('multi-node render keeps each sibling hostname on its own ports and check catches a crossed port', t => {
  const scratch = mkdtempSync(join(tmpdir(), 'aukora-ingress-nodes-'))
  const nodesPath = join(scratch, 'nodes.json')
  const renderedPath = join(scratch, 'Caddyfile')
  const nodes = [
    { name: 'C1', app_host: 'one.example.test', owner_host: 'one-owner.example.test', harness_port: 28735, owner_port: 28736, claim_port: 28737 },
    { name: 'C2', app_host: 'two.example.test', owner_host: 'two-owner.example.test', harness_port: 29735, owner_port: 29736, claim_port: 29737 },
  ]
  writeFileSync(nodesPath, `${JSON.stringify(nodes)}\n`, { mode: 0o600 })
  const run = args => spawnSync(python, ['-I', '-S', '-c', nodesCliCourt, renderPath, ...args], { encoding: 'utf8' })
  const rendered = run(['--nodes', nodesPath, '--output', renderedPath])
  assert.equal(rendered.status, 0, rendered.stderr)
  const text = readFileSync(renderedPath, 'utf8')
  assertNodeCaddy(text, nodes[0], nodes[1])
  assertNodeCaddy(text, nodes[1], nodes[0])
  assert.equal(text.match(/^:80, :443 \{/gmu)?.length, 1)
  assert.match(text, /Strict-Transport-Security "max-age=31536000"/u)
  assert.doesNotMatch(text, /includeSubDomains/u)
  assert.match(text, /request_body \{\s+max_size 8MB/u)

  const checked = run(['--check', renderedPath, '--nodes', nodesPath])
  assert.equal(checked.status, 0, checked.stderr)
  assert.match(checked.stdout, /^PASS ingress: rendered file matches 2 nodes$/mu)

  const optedIn = run(['--nodes', nodesPath, '--hsts-include-subdomains'])
  assert.equal(optedIn.status, 0, optedIn.stderr)
  assert.match(optedIn.stdout, /Strict-Transport-Security "max-age=31536000; includeSubDomains"/u)
  const mismatchedHsts = run(['--check', renderedPath, '--nodes', nodesPath, '--hsts-include-subdomains'])
  assert.notEqual(mismatchedHsts.status, 0, 'default-off rendering must not pass an opt-in check')
  assert.match(mismatchedHsts.stderr, /INGRESS_RENDERED_MISMATCH/u)

  writeFileSync(renderedPath, text.replace('127.0.0.1:29735', '127.0.0.1:28735'))
  const crossed = run(['--check', renderedPath, '--nodes', nodesPath])
  assert.notEqual(crossed.status, 0, 'cross-node port mutation survived --check')
  assert.match(crossed.stderr, /INGRESS_RENDERED_MISMATCH/u)
  t.diagnostic('MUTATION CAUGHT rendered C2 harness crossing to C1 harness port')

  chmodSync(nodesPath, 0o622)
  const writable = run(['--nodes', nodesPath])
  assert.notEqual(writable.status, 0)
  assert.match(writable.stderr, /INGRESS_NODES_FILE_INVALID/u)
})

test('operator runbooks state sibling isolation and ordered add/remove steps', () => {
  const ingress = readFileSync(ingressReadmePath, 'utf8')
  const browser = readFileSync(browserReadmePath, 'utf8')
  for (const text of [ingress, browser]) {
    assert.match(text, /Each hostname can reach only its node's ports|no rule may let one node's hostname reach a\s+sibling node's/u)
    assert.match(text, /`__Host-`[\s\S]{0,100}host-only/u)
  }
  assert.match(ingress, /### Add a second node[\s\S]+create\.sh[\s\S]+JSON[\s\S]+render[\s\S]+validate[\s\S]+reload/u)
  assert.match(ingress, /### Remove one node[\s\S]+Remove only that node's object[\s\S]+render[\s\S]+validate[\s\S]+reload Caddy/u)
  assert.match(ingress, /render\.py --check \/etc\/caddy\/Caddyfile[\s\S]+--nodes \/etc\/caddy\/aukora-nodes\.json/u)
})
