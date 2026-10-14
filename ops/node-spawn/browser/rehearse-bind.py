#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Drive a throwaway first binding only on a root-marked rehearsal node.
import http.client
import importlib.util
import json
from pathlib import Path
import re
import sys
import time

PREFIX = '/api/aukora/aumlok-binding/'
BODY_LIMIT = 1024 * 1024
PUBLIC_REFUSALS = frozenset('REHEARSAL_' + code for code in (
    'RESPONSE_LIMIT', 'BINDING_HTTP_REFUSED', 'RESPONSE_INVALID', 'PREPARE_REFUSED',
    'DRAW_INVALID', 'CLAIM_LINK_INVALID', 'CLAIM_EXCHANGE_REFUSED', 'CLAIM_COOKIE_INVALID',
    'ALREADY_BOUND', 'WRONG_BIND_ACCEPTED', 'CORRECT_BIND_REFUSED', 'SECOND_PREPARE_ACCEPTED',
)) | frozenset('BROWSER_' + code for code in (
    'ROOT_REQUIRED', 'PRELOAD_FORBIDDEN', 'LINUX_REQUIRED', 'UBUNTU_24_04_REQUIRED',
    'CUSTODY_INVALID', 'REHEARSAL_MARKER_REQUIRED', 'REHEARSAL_MARKER_INVALID',
    'REHEARSAL_CLAIM_MINT_REFUSED',
))


def need(condition, code):
    if not condition:
        raise ValueError('REHEARSAL_' + code)


def load_node():
    file = Path(__file__).with_name('node.py')
    spec = importlib.util.spec_from_file_location('browser_rehearsal_node', file)
    node = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(node)
    return node


def request(port, origin, authority, target, body, cookie=None, plain=False):
    headers = {'Host': authority, 'Origin': origin, 'Sec-Fetch-Site': 'same-origin',
               'Content-Type': 'text/plain' if plain else 'application/json'}
    if cookie is not None:
        headers['Cookie'] = cookie
    payload = body if plain else json.dumps(body, separators=(',', ':')).encode('utf-8')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
    try:
        connection.request('POST', target, body=payload, headers=headers)
        response = connection.getresponse()
        data = response.read(BODY_LIMIT + 1)
        need(len(data) <= BODY_LIMIT, 'RESPONSE_LIMIT')
        return response.status, response.getheaders(), data
    finally:
        connection.close()


def action(origin, authority, cookie, verb, body):
    status, _, payload = request(18735, origin, authority, PREFIX + verb, body, cookie)
    need(status == 200, 'BINDING_HTTP_REFUSED')
    try:
        value = json.loads(payload)
    except (UnicodeError, ValueError):
        need(False, 'RESPONSE_INVALID')
    need(isinstance(value, dict), 'RESPONSE_INVALID')
    return value


def draw(origin, authority, cookie):
    value = action(origin, authority, cookie, 'prepare', {'handle': 'rehearsal-only', 'language': 'en'})
    offered = value.get('draw')
    need(value.get('ok') is True and isinstance(offered, dict), 'PREPARE_REFUSED')
    words = offered.get('words')
    need(isinstance(words, list) and len(words) == 7
         and all(isinstance(word, str) and re.fullmatch(r'[a-z]+', word) for word in words)
         and re.fullmatch(r'[0-9a-f]{64}', str(offered.get('ceremonyId', ''))) is not None,
         'DRAW_INVALID')
    return {'ceremonyId': offered['ceremonyId'], 'typedPhrase': ' '.join(words), 'acknowledged': True}


def rehearse():
    step = 'rehearsal marker'
    try:
        node = load_node()
        node.root_check()
        node.installed()
        node.check_rehearsal_marker()
        print('PASS | ' + step)
        step = 'claim mint'
        claim = node.module(node.CHECKOUT / 'ops/node-spawn/ingress/claim.py')
        origin, authority = claim.read_origin_file(Path('/etc/aukora/public-origin'))
        link = node.run(['/usr/bin/python3', '-I', '-S', '-B',
                         str(node.CHECKOUT / 'ops/node-spawn/ingress/claim.py'), 'mint',
                         '--public-origin-file', '/etc/aukora/public-origin',
                         '--state-file', str(node.STATE / 'claims.json')], 'REHEARSAL_CLAIM_MINT_REFUSED')
        match = re.fullmatch(re.escape(origin + claim.CLAIM_PATH) + r'#([A-Za-z0-9_-]{43})\n', link)
        need(match is not None, 'CLAIM_LINK_INVALID')
        print('PASS | ' + step)
        step = 'claim exchange'
        status, headers, payload = request(18736, origin, authority, claim.CLAIM_PATH,
                                           match[1].encode('ascii'), plain=True)
        need(status == 204 and not payload, 'CLAIM_EXCHANGE_REFUSED')
        cookies = [value for name, value in headers if name.lower() == 'set-cookie']
        need(len(cookies) == 1, 'CLAIM_COOKIE_INVALID')
        cookie = claim.bounded_cookie(cookies[0], authority, time.time()).split(';', 1)[0]
        print('PASS | ' + step)
        step = 'unbound status'
        value = action(origin, authority, cookie, 'status', {})
        need(value.get('ok') is True and value.get('bound') is False, 'ALREADY_BOUND')
        print('PASS | ' + step)
        step = 'prepare seven words'
        offered = draw(origin, authority, cookie)
        print('PASS | ' + step)
        step = 'wrong phrase refused'
        wrong = {**offered, 'typedPhrase': 'deliberately wrong'}
        value = action(origin, authority, cookie, 'bind', wrong)
        need(value.get('ok') is False and value.get('reason') == 'aumlok:phrase-shape'
             and value.get('drawSpent') is True, 'WRONG_BIND_ACCEPTED')
        print('PASS | ' + step)
        step = 'prepare after refusal'
        offered = draw(origin, authority, cookie)
        print('PASS | ' + step)
        step = 'correct phrase verified'
        value = action(origin, authority, cookie, 'bind', offered)
        binding = value.get('binding')
        need(value.get('ok') is True and value.get('reason') == 'aumlok:ceremony-verified'
             and isinstance(binding, dict)
             and re.fullmatch(r'aukora:1:[0-9a-f]{64}', str(binding.get('subject', ''))) is not None,
             'CORRECT_BIND_REFUSED')
        print('PASS | ' + step)
        step = 'second prepare refused'
        value = action(origin, authority, cookie, 'prepare', {'handle': 'rehearsal-only', 'language': 'en'})
        need(value.get('ok') is False and value.get('reason') == 'aumlok:bind-already-bound',
             'SECOND_PREPARE_ACCEPTED')
        print('PASS | ' + step)
        return 0
    except Exception as error:
        code = str(error)
        if code not in PUBLIC_REFUSALS:
            code = 'REHEARSAL_OPERATION_REFUSED'
        print('FAIL | ' + step + ' | ' + code)
        return 1


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('FAIL | usage | REHEARSAL_USAGE')
        sys.exit(1)
    sys.exit(rehearse())
