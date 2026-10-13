// SPDX-License-Identifier: AGPL-3.0-or-later
// claim.py bounds real-handler socket reads and concurrent connection admission.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const claimPath = join(root, 'ops/node-spawn/ingress/claim.py')
const court = String.raw`
import argparse, importlib.util, io, sys, threading
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('claim_read_limits', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Clock:
    now = 0
    def __call__(self): return self.now

class Connection:
    def __init__(self, clock, chunks):
        self.clock, self.chunks = clock, list(chunks)
        self.timeout, self.output = None, bytearray()
    def settimeout(self, timeout):
        assert timeout > 0, 'socket timeout must be positive'
        self.timeout = timeout
    def makefile(self, *_args): return io.BytesIO()
    def recv_into(self, buffer):
        if not self.chunks: return 0
        delay, data = self.chunks.pop(0)
        if self.timeout is not None and delay > self.timeout:
            self.clock.now += self.timeout
            raise TimeoutError('fixture deadline')
        self.clock.now += delay
        count = min(len(data), len(buffer))
        buffer[:count] = data[:count]
        if count < len(data): self.chunks.insert(0, (0, data[count:]))
        return count
    def sendall(self, data): self.output.extend(data)

class Application:
    public_authority = 'node.example.test'
    def __init__(self): self.calls = []
    def handle(self, method, path, headers, body):
        self.calls.append((method, path, body))
        return 204, [], b''

def handler(chunks, keepalive=False):
    clock, app = Clock(), Application()
    connection = Connection(clock, chunks)
    with patch.object(m.time, 'monotonic', clock):
        Handler = m.handler_for(app)
        if keepalive: Handler.protocol_version = 'HTTP/1.1'
        try: Handler(connection, ('127.0.0.1', 1000), object())
        except Exception as error: raise AssertionError('handler raised instead of a bounded refusal') from error
    return clock.now, app.calls, bytes(connection.output)

head = b'POST /__aukora/claim HTTP/1.1\r\nHost: node.example.test\r\nContent-Length: 5\r\n\r\n'
elapsed, calls, response = handler([(0, head), (1, b'hello')])
assert elapsed == 1 and calls == [('POST', '/__aukora/claim', b'hello')] and b' 204 ' in response

# Every byte arrives inside the idle timeout, but the complete header misses its absolute deadline.
elapsed, calls, response = handler([(0, b'GET /__aukora/claim HTTP/1.1\r\n'),
    (1.5, b'Host: '), (1.5, b'node.'), (1.5, b'example.'), (1.5, b'test\r\n\r\n')])
assert not calls and b' 408 ' in response and b'HEADER_READ_DEADLINE' in response, 'slow headers reached application'
assert elapsed <= m.HEADER_READ_SECONDS, 'header deadline renewed by a drip'

elapsed, calls, response = handler([(0, b'GET /__aukora/claim HTTP/1.1\r\n'),
    (m.HEADER_READ_SECONDS, b'Host: node.example.test\r\n\r\n')])
assert not calls and b'HEADER_READ_DEADLINE' in response, 'header completing at expiry reached application'

elapsed, calls, response = handler([(0, head), (2.5, b'h'), (2.5, b'e'), (2.5, b'l'), (2.5, b'l'), (2.5, b'o')])
assert not calls and b' 408 ' in response and b'BODY_READ_DEADLINE' in response, 'slow body reached application'
assert elapsed <= m.BODY_READ_SECONDS, 'body deadline renewed by a drip'

elapsed, calls, response = handler([(0, head.replace(b'Length: 5', b'Length: 4')),
    (2.5, b'h'), (2.5, b'e'), (2.5, b'l'), (2.5, b'p')])
assert not calls and b'BODY_READ_DEADLINE' in response, 'body completing at expiry reached application'

elapsed, calls, response = handler([(0, head), (100, b'hello')])
assert not calls and b' 408 ' in response and b'BODY_READ_DEADLINE' in response, 'idle body did not refuse'
assert elapsed <= m.BODY_READ_SECONDS, 'idle body exceeded deadline'

# Header time is not charged to a new body deadline; fully prefetched bodies still dispatch once.
elapsed, calls, response = handler([(4, head), (9, b'hello')])
assert elapsed == 13 and len(calls) == 1 and b' 204 ' in response, 'body did not get its own bounded phase'
elapsed, calls, response = handler([(0, head + b'hello' + head + b'hello')], keepalive=True)
assert len(calls) == 1, 'one connection dispatched another request'

# Check expiry after buffered read completion as well as after each socket receive.
clock, app = Clock(), Application()
connection = Connection(clock, [(0, head), (0, b'hello')])
ticks = iter([0, 0, 0, 0, 0, 0, m.BODY_READ_SECONDS])
with patch.object(m.time, 'monotonic', lambda: next(ticks)):
    m.handler_for(app)(connection, ('127.0.0.1', 1000), object())
assert not app.calls and b'BODY_READ_DEADLINE' in connection.output, 'dispatch ignored expiry after buffered read'

# No bind or thread is needed: exercise the actual admission and worker-finally methods.
server = object.__new__(m.ClaimHTTPServer)
closed, started = [], []
with patch.object(m.ThreadingHTTPServer, '__init__', lambda *_args: None):
    m.ClaimHTTPServer.__init__(server, ('127.0.0.1', 18736), object)
server.shutdown_request = closed.append
with patch.object(m.ThreadingHTTPServer, 'process_request', lambda _server, request, _peer: started.append(request)):
    for index in range(m.MAX_CONNECTIONS + 1): server.process_request(index, ('127.0.0.1', index))
    assert len(started) == m.MAX_CONNECTIONS and closed == [m.MAX_CONNECTIONS], 'connection cap exceeded'
    with patch.object(m.ThreadingHTTPServer, 'process_request_thread', lambda *_args: None):
        server.process_request_thread(0, ('127.0.0.1', 0))
    server.process_request(100, ('127.0.0.1', 100))
    assert started[-1] == 100, 'completed worker retained capacity'
    with patch.object(m.ThreadingHTTPServer, 'process_request_thread', side_effect=OSError('fixture worker')):
        try: server.process_request_thread(100, ('127.0.0.1', 100))
        except OSError: pass
    server.process_request(101, ('127.0.0.1', 101))
    assert started[-1] == 101, 'failed worker retained capacity'
    with patch.object(m.ThreadingHTTPServer, 'process_request_thread', lambda *_args: None):
        server.process_request_thread(101, ('127.0.0.1', 101))
    with patch.object(m.ThreadingHTTPServer, 'process_request', side_effect=RuntimeError('fixture start')):
        try: server.process_request(102, ('127.0.0.1', 102))
        except RuntimeError: pass
    server.process_request(103, ('127.0.0.1', 103))
    assert started[-1] == 103, 'thread-start failure retained capacity'

# CLI serve must select the bounded server rather than its unbounded base class.
options = argparse.Namespace(command='serve', public_origin_file='app', owner_origin_file='owner',
    state_file='claims', launch_url_file='launch', harness_port=18735, owner_page_port=17792, listen_port=18736)
constructed = []
class Served:
    def __init__(self, address, _handler): constructed.append(address)
    def serve_forever(self): constructed.append('served')
with patch.object(m.argparse.ArgumentParser, 'parse_args', lambda *_args: options), \
     patch.object(m, 'require_root', lambda: None), \
     patch.object(m, 'read_origin_file', lambda file: ('https://' + file + '.example.test', file + '.example.test')), \
     patch.object(m, 'ClaimHTTPServer', Served), \
     patch.object(m, 'ThreadingHTTPServer', side_effect=AssertionError('unbounded server selected')):
    m.main()
assert constructed == [('127.0.0.1', 18736), 'served'], 'bounded server not activated by CLI'
print('PASS browser claim limits: absolute header/body deadlines; one request per connection; 32 connections; all exit paths release capacity; bounded CLI server')
`

function runPython(source) {
  return spawnSync('/usr/bin/python3', ['-I', '-S', '-c', court, source], { cwd: root, encoding: 'utf8', timeout: 10000 })
}

test('claim broker read deadlines and connection cap refuse drips without a listener', t => {
  const baseline = runPython(claimPath)
  assert.equal(baseline.status, 0, baseline.stderr)
  t.diagnostic(baseline.stdout.trim())
  const source = readFileSync(claimPath, 'utf8')
  const mutants = [
    ['header deadline', 'self.deadline_reader.start(HEADER_READ_SECONDS, "HEADER_READ_DEADLINE")', 'self.deadline_reader.start(1000, "HEADER_READ_DEADLINE")'],
    ['body deadline', 'self.deadline_reader.start(BODY_READ_SECONDS, "BODY_READ_DEADLINE")', 'self.deadline_reader.start(1000, "BODY_READ_DEADLINE")'],
    ['remaining socket timeout', 'self.connection.settimeout(self.remaining())', 'self.remaining()'],
    ['absolute deadline', 'if remaining <= 0:', 'if remaining <= -1000:'],
    ['read completion deadline', 'raise ClaimRefusal(self.code, 408) from error\n        self.remaining()', 'raise ClaimRefusal(self.code, 408) from error'],
    ['body completion deadline', 'body = self.rfile.read(length)\n                self.deadline_reader.remaining()', 'body = self.rfile.read(length)'],
    ['timeout refusal', 'except (TimeoutError, socket.timeout) as error:\n            raise ClaimRefusal(self.code, 408)', 'except EOFError as error:\n            raise ClaimRefusal(self.code, 408)'],
    ['close after request', 'self.close_connection = True\n                self.deadline_reader.start(BODY_READ_SECONDS', 'self.deadline_reader.start(BODY_READ_SECONDS'],
    ['connection cap', 'if not self.connections.acquire(blocking=False):', 'if self.connections.acquire(blocking=False) and False:'],
    ['worker release', 'finally:\n            self.connections.release()\n\n\ndef handler_for', 'finally:\n            pass\n\n\ndef handler_for'],
    ['thread-start release', 'except BaseException:\n            self.connections.release()', 'except BaseException:\n            pass'],
    ['bounded CLI', 'server = ClaimHTTPServer(("127.0.0.1", arguments.listen_port)', 'server = ThreadingHTTPServer(("127.0.0.1", arguments.listen_port)'],
  ]
  const scratch = mkdtempSync(join(root, '.claim-read-mutants-'))
  try {
    for (const [name, before, after] of mutants) {
      assert.equal(source.split(before).length, 2, name)
      const file = join(scratch, name.replaceAll(' ', '-') + '.py')
      writeFileSync(file, source.replace(before, after))
      const result = runPython(file)
      assert.notEqual(result.status, 0, `surviving mutant ${name}`)
      assert.match(result.stderr, /AssertionError/u, name)
    }
  } finally { rmSync(scratch, { recursive: true, force: true }) }
  t.diagnostic(`MUTATION browser claim read limits: ${mutants.length}/${mutants.length} killed`)
})
