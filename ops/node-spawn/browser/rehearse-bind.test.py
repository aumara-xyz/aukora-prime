# Exercise rehearsal binding against a fake node without services or sockets.
import ast
import base64
import contextlib
import http.client
import io
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('rehearse-bind.py')
TEXT = SOURCE.read_text()
ROOT = SOURCE.resolve().parents[3]


def load(text=TEXT):
    module = types.ModuleType('browser_rehearsal_fixture')
    module.__file__ = str(SOURCE)
    module.__source__ = text
    exec(compile(text, str(SOURCE), 'exec'), module.__dict__)
    return module


M = load()
claim = types.ModuleType('claim_fixture')
claim.__file__ = str(ROOT / 'ops/node-spawn/ingress/claim.py')
exec(compile(Path(claim.__file__).read_text(), claim.__file__, 'exec'), claim.__dict__)
ORIGIN = 'https://app.example.test'
AUTHORITY = 'app.example.test'
CODE = 'C' * 43
WORDS = ['abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb']
SUBJECT = 'aukora:1:' + 'a' * 64
PASSES = ['rehearsal marker', 'claim mint', 'claim exchange', 'unbound status',
          'prepare seven words', 'wrong phrase refused', 'prepare after refusal',
          'correct phrase verified', 'second prepare refused']


class World:
    def __init__(self):
        now = int(time.time() * 1000)
        payload = {'version': 1, 'authority': AUTHORITY, 'issuedAt': now, 'expiresAt': now + 86400000}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        self.cookie = claim.cookie_name(AUTHORITY) + '=v1.' + encoded + '.private-cookie-signature'
        self.responses = [
            (204, [('Set-Cookie', self.cookie + '; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=Strict')], b''),
            (200, [], {'ok': True, 'bound': False}),
            (200, [], {'ok': True, 'draw': {'ceremonyId': 'a' * 64, 'words': WORDS}}),
            (200, [], {'ok': False, 'reason': 'aumlok:phrase-shape', 'drawSpent': True}),
            (200, [], {'ok': True, 'draw': {'ceremonyId': 'b' * 64, 'words': WORDS[::-1]}}),
            (200, [], {'ok': True, 'reason': 'aumlok:ceremony-verified', 'binding': {'subject': SUBJECT}}),
            (200, [], {'ok': False, 'reason': 'aumlok:bind-already-bound'}),
        ]
        self.calls, self.events = [], []
        self.refuse_marker, self.refuse_root = False, False
        self.link = ORIGIN + claim.CLAIM_PATH + '#' + CODE + '\n'
        self.node = types.SimpleNamespace(root_check=self.root_check, installed=lambda: self.events.append('installed'),
            check_rehearsal_marker=self.marker, CHECKOUT=Path('/opt/aukora-genesis/src'),
            STATE=Path('/var/lib/aukora-browser'), run=self.run,
            module=lambda path: types.SimpleNamespace(CLAIM_PATH=claim.CLAIM_PATH,
                read_origin_file=lambda path: (ORIGIN, AUTHORITY), bounded_cookie=claim.bounded_cookie))

    def root_check(self):
        self.events.append('root')
        if self.refuse_root:
            raise ValueError('BROWSER_ROOT_REQUIRED')

    def marker(self):
        self.events.append('marker')
        if self.refuse_marker:
            raise ValueError('BROWSER_REHEARSAL_MARKER_REQUIRED')

    def run(self, command, refusal):
        self.events.append('mint')
        self.mint_command = command
        return self.link

    def connect(self, host, port, timeout):
        world = self
        class Connection:
            def request(self, method, target, body, headers):
                world.calls.append((host, port, timeout, method, target, body, headers))

            def getresponse(self):
                status, headers, payload = world.responses[len(world.calls) - 1]
                data = json.dumps(payload).encode() if isinstance(payload, (dict, list)) else payload
                return types.SimpleNamespace(status=status, getheaders=lambda: headers,
                    read=lambda limit: data[:limit])

            def close(self):
                world.events.append('close')
        return Connection()

    def execute(self):
        output = io.StringIO()
        with patch.object(M, 'load_node', return_value=self.node), \
                patch.object(http.client, 'HTTPConnection', side_effect=self.connect), \
                contextlib.redirect_stdout(output):
            status = M.rehearse()
        return status, output.getvalue()


class Rehearsal(unittest.TestCase):
    def fail(self, world, step, code):
        status, output = world.execute()
        self.assertEqual(status, 1)
        self.assertEqual(output.splitlines()[-1], 'FAIL | ' + step + ' | ' + code)
        for secret in [CODE, world.cookie, ' '.join(WORDS), ' '.join(WORDS[::-1]), 'a' * 64, 'b' * 64]:
            self.assertNotIn(secret, output)

    def test_complete_fake_node_uses_public_authority_and_new_draw(self):
        world = World()
        status, output = world.execute()
        self.assertEqual(status, 0)
        self.assertEqual(output, ''.join('PASS | ' + step + '\n' for step in PASSES))
        self.assertEqual(world.events[:4], ['root', 'installed', 'marker', 'mint'])
        self.assertEqual(world.mint_command, ['/usr/bin/python3', '-I', '-S', '-B',
            '/opt/aukora-genesis/src/ops/node-spawn/ingress/claim.py', 'mint', '--public-origin-file',
            '/etc/aukora/public-origin', '--state-file', '/var/lib/aukora-browser/claims.json'])
        self.assertEqual(len(world.calls), 7)
        for index, (host, port, timeout, method, target, body, headers) in enumerate(world.calls):
            self.assertEqual((host, port, method), ('127.0.0.1', 18736 if index == 0 else 18735, 'POST'))
            self.assertEqual(headers['Host'], AUTHORITY)
            self.assertEqual(headers['Origin'], ORIGIN)
            self.assertEqual(headers['Sec-Fetch-Site'], 'same-origin')
            self.assertEqual(headers['Content-Type'], 'text/plain' if index == 0 else 'application/json')
            self.assertEqual(target, ['/__aukora/claim', M.PREFIX + 'status', M.PREFIX + 'prepare',
                M.PREFIX + 'bind', M.PREFIX + 'prepare', M.PREFIX + 'bind', M.PREFIX + 'prepare'][index])
            if index:
                self.assertEqual(headers['Cookie'], world.cookie)
        self.assertEqual(world.calls[0][5], CODE.encode())
        wrong, correct = (json.loads(world.calls[index][5]) for index in (3, 5))
        self.assertEqual(wrong, {'ceremonyId': 'a' * 64, 'typedPhrase': 'deliberately wrong', 'acknowledged': True})
        self.assertEqual(correct, {'ceremonyId': 'b' * 64, 'typedPhrase': ' '.join(WORDS[::-1]), 'acknowledged': True})
        self.assertEqual(world.events.count('close'), 7)

    def test_root_and_marker_refuse_before_any_claim(self):
        for field, code in [('refuse_root', 'BROWSER_ROOT_REQUIRED'),
                            ('refuse_marker', 'BROWSER_REHEARSAL_MARKER_REQUIRED')]:
            world = World()
            setattr(world, field, True)
            self.fail(world, 'rehearsal marker', code)
            self.assertNotIn('mint', world.events)
            self.assertFalse(world.calls)

    def test_claim_guards(self):
        world = World()
        world.link = 'https://wrong.example.test/__aukora/claim#' + CODE + '\n'
        self.fail(world, 'claim mint', 'REHEARSAL_CLAIM_LINK_INVALID')
        for response, code in [((200, [], b''), 'REHEARSAL_CLAIM_EXCHANGE_REFUSED'),
                               ((204, [], b'private body'), 'REHEARSAL_CLAIM_EXCHANGE_REFUSED'),
                               ((204, [], b''), 'REHEARSAL_CLAIM_COOKIE_INVALID'),
                               ((204, [('Set-Cookie', 'private-cookie')], b''), 'REHEARSAL_OPERATION_REFUSED')]:
            world = World()
            world.responses[0] = response
            self.fail(world, 'claim exchange', code)

    def test_status_refuses_an_owner_node(self):
        for value in [{'ok': True, 'bound': True}, {'ok': False, 'bound': False}]:
            world = World()
            world.responses[1] = (200, [], value)
            self.fail(world, 'unbound status', 'REHEARSAL_ALREADY_BOUND')
            self.assertEqual(len(world.calls), 2)

    def test_prepare_requires_exact_draw(self):
        for value, code in [({'ok': False}, 'REHEARSAL_PREPARE_REFUSED'),
                            ({'ok': True, 'draw': []}, 'REHEARSAL_PREPARE_REFUSED'),
                            ({'ok': True, 'draw': {'words': WORDS[:6], 'ceremonyId': 'a' * 64}}, 'REHEARSAL_DRAW_INVALID'),
                            ({'ok': True, 'draw': {'words': WORDS + ['extra'], 'ceremonyId': 'a' * 64}}, 'REHEARSAL_DRAW_INVALID'),
                            ({'ok': True, 'draw': {'words': ['not a word'] * 7, 'ceremonyId': 'a' * 64}}, 'REHEARSAL_DRAW_INVALID'),
                            ({'ok': True, 'draw': {'words': WORDS, 'ceremonyId': CODE}}, 'REHEARSAL_DRAW_INVALID')]:
            world = World()
            world.responses[2] = (200, [], value)
            self.fail(world, 'prepare seven words', code)

    def test_wrong_bind_must_refuse_and_spend_draw(self):
        for value in [{'ok': True, 'reason': 'aumlok:phrase-shape', 'drawSpent': True},
                      {'ok': False, 'reason': 'aumlok:phrase-mismatch', 'drawSpent': True},
                      {'ok': False, 'reason': 'aumlok:phrase-shape', 'drawSpent': False}]:
            world = World()
            world.responses[3] = (200, [], value)
            self.fail(world, 'wrong phrase refused', 'REHEARSAL_WRONG_BIND_ACCEPTED')

    def test_correct_bind_requires_verified_subject(self):
        for value in [{'ok': False}, {'ok': True, 'reason': 'wrong', 'binding': {'subject': SUBJECT}},
                      {'ok': True, 'reason': 'aumlok:ceremony-verified', 'binding': {}},
                      {'ok': True, 'reason': 'aumlok:ceremony-verified', 'binding': {'subject': 'private-subject'}}]:
            world = World()
            world.responses[5] = (200, [], value)
            self.fail(world, 'correct phrase verified', 'REHEARSAL_CORRECT_BIND_REFUSED')

    def test_second_prepare_must_refuse_bound(self):
        for value in [{'ok': True, 'reason': 'aumlok:bind-already-bound'}, {'ok': False, 'reason': 'different'}]:
            world = World()
            world.responses[6] = (200, [], value)
            self.fail(world, 'second prepare refused', 'REHEARSAL_SECOND_PREPARE_ACCEPTED')

    def test_bounded_response_http_and_json_refusals(self):
        for response, code in [((403, [], b'cookie secret'), 'REHEARSAL_BINDING_HTTP_REFUSED'),
                               ((200, [], b'not json'), 'REHEARSAL_RESPONSE_INVALID'),
                               ((200, [], []), 'REHEARSAL_RESPONSE_INVALID'),
                               ((200, [], b'x' * (M.BODY_LIMIT + 1)), 'REHEARSAL_RESPONSE_LIMIT')]:
            world = World()
            world.responses[1] = response
            self.fail(world, 'unbound status', code)
            self.assertEqual(world.events.count('close'), 2)

    def test_unnamed_exception_never_prints_secret(self):
        for secret in ['secret ' + CODE, 'REHEARSAL_' + CODE, 'BROWSER_' + CODE]:
            world = World()
            world.node.run = lambda *args: (_ for _ in ()).throw(ValueError(secret + world.cookie))
            self.fail(world, 'claim mint', 'REHEARSAL_OPERATION_REFUSED')
            world.node.run = lambda *args: (_ for _ in ()).throw(ValueError(secret))
            self.fail(world, 'claim mint', 'REHEARSAL_OPERATION_REFUSED')

    def test_cli_refuses_arguments_without_echo(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', [str(SOURCE), CODE]), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as caught:
                exec(compile(M.__source__, str(SOURCE), 'exec'), {'__name__': '__main__', '__file__': str(SOURCE)})
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(output.getvalue(), 'FAIL | usage | REHEARSAL_USAGE\n')


def mutations():
    global M
    original = M
    offsets = [0]
    for line in TEXT.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    controls = []
    for call in ast.walk(ast.parse(TEXT)):
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'need':
            arg = call.args[0]
            if isinstance(arg, ast.Constant) and arg.value is False:
                continue
            start = offsets[arg.lineno - 1] + arg.col_offset
            end = offsets[arg.end_lineno - 1] + arg.end_col_offset
            controls.append(('named guard at ' + str(call.lineno), TEXT[:start] + 'True' + TEXT[end:]))
    for before, after in [
            ('        node.root_check()\n', ''), ('        node.installed()\n', ''), ('        node.check_rehearsal_marker()\n', ''),
            ("http.client.HTTPConnection('127.0.0.1', port, timeout=30)", "http.client.HTTPConnection(authority, port, timeout=30)"),
            ("'Host': authority", "'Host': '127.0.0.1'"), ("'Origin': origin", "'Origin': 'http://127.0.0.1'"),
            ("cookie = claim.bounded_cookie(cookies[0], authority, time.time()).split(';', 1)[0]", "cookie = cookies[0].split(';', 1)[0]"),
            ("        step = 'prepare after refusal'\n        offered = draw(origin, authority, cookie)\n", "        step = 'prepare after refusal'\n"),
            ('        if code not in PUBLIC_REFUSALS:', '        if False:'),
            ('    if len(sys.argv) != 1:', '    if False:'),
            ("        print('PASS | ' + step)\n        step = 'claim exchange'", "        print(link)\n        print('PASS | ' + step)\n        step = 'claim exchange'")]:
        assert TEXT.count(before) == 1, before
        controls.append((before, TEXT.replace(before, after)))
    for label, mutated in controls:
        M = load(mutated)
        result = unittest.TestResult()
        with contextlib.redirect_stdout(io.StringIO()):
            unittest.defaultTestLoader.loadTestsFromTestCase(Rehearsal).run(result)
        assert result.failures or result.errors, 'rehearsal mutation survived: ' + label
    M = original
    print('SOURCE-ONLY browser rehearsal mutations: %d/%d killed; fake node only' % (len(controls), len(controls)))


if __name__ == '__main__':
    if '--mutations' in sys.argv:
        mutations()
    else:
        unittest.main()
