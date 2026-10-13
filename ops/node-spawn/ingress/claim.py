#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Issue and spend bounded browser claims without exposing the harness launch token."""

import argparse
import fcntl
import hashlib
import http.client
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
import urllib.parse
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CLAIM_PATH = "/__aukora/claim"
CLAIM_SCRIPT_PATH = "/__aukora/claim.js"
CODE_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MAX_CLAIMS = 64
MAX_CLAIM_BODY = 128
MAX_OWNER_BODY = 64 * 1024
MAX_TARGET = 2048
MAX_HEADERS = 8192

CLAIM_PAGE = b"""<!doctype html>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claim AUKORA node</title>
<p id="status">Claiming this node...</p>
<script src="/__aukora/claim.js" defer></script>
"""

CLAIM_SCRIPT = b"""'use strict';
const statusNode = document.getElementById('status');
const code = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
if (!/^[A-Za-z0-9_-]{43}$/.test(code)) {
  statusNode.textContent = 'This claim link is invalid.';
} else {
  fetch('/__aukora/claim', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: code,
    credentials: 'same-origin', cache: 'no-store', redirect: 'error' })
    .then(response => { if (!response.ok) throw new Error('refused'); location.replace('/'); })
    .catch(() => { statusNode.textContent = 'This claim was refused or has expired.'; });
}
"""


class ClaimRefusal(Exception):
    def __init__(self, code, status_code=403):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def parse_origin(value):
    """Return a canonical HTTPS DNS hostname or a named refusal."""
    if value.endswith("\n"):
        value = value[:-1]
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ClaimRefusal("PUBLIC_ORIGIN_INVALID") from error
    labels = hostname.split(".") if hostname is not None else []
    if (parsed.scheme != "https" or parsed.netloc != hostname or port is not None
            or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
            or value != f"https://{hostname}" or hostname == "localhost"
            or len(hostname) > 253 or len(labels) < 2
            or re.search(r"[a-z]", labels[-1]) is None
            or any(DNS_LABEL.fullmatch(label) is None for label in labels)):
        raise ClaimRefusal("PUBLIC_ORIGIN_INVALID")
    return value, hostname


def _protected_file(path, require_root=True, private=True):
    """Open a non-symlink private file under protected canonical ancestry."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ClaimRefusal("PROTECTED_PATH_INVALID", 500)
    expected_uid = 0 if require_root is True else os.getuid() if require_root is False else None
    if expected_uid is not None:
        for item in (path.parent, *path.parent.parents):
            info = item.lstat()
            if item.is_symlink() or info.st_uid != expected_uid or info.st_mode & 0o022:
                raise ClaimRefusal("PROTECTED_PATH_INVALID", 500)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or (expected_uid is not None and info.st_uid != expected_uid)
            or (private and info.st_mode & 0o077)
            or (not private and info.st_mode & 0o022)):
        os.close(descriptor)
        raise ClaimRefusal("PROTECTED_FILE_INVALID", 500)
    return descriptor


def read_origin_file(path, require_root=True):
    descriptor = _protected_file(path, require_root, private=False)
    try:
        value = os.read(descriptor, 1025)
    finally:
        os.close(descriptor)
    if len(value) > 1024:
        raise ClaimRefusal("PUBLIC_ORIGIN_INVALID")
    try:
        return parse_origin(value.decode("utf-8"))
    except UnicodeError as error:
        raise ClaimRefusal("PUBLIC_ORIGIN_INVALID") from error


class ClaimStore:
    """Durably consume hashed claims under an exclusive file lock."""

    def __init__(self, path, require_root=True):
        self.path = Path(path)
        self.require_root = require_root
        self.expected_uid = 0 if require_root else os.getuid()

    def _check_parent(self):
        if not self.path.is_absolute() or self.path.parent.resolve() != self.path.parent:
            raise ClaimRefusal("CLAIM_STORE_PATH_INVALID", 500)
        if self.require_root:
            for item in (self.path.parent, *self.path.parent.parents):
                info = item.lstat()
                if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ClaimRefusal("CLAIM_STORE_PATH_INVALID", 500)

    def _with_lock(self, operation):
        self._check_parent()
        lock_path = self.path.with_name(self.path.name + ".lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != self.expected_uid or info.st_mode & 0o077:
                raise ClaimRefusal("CLAIM_STORE_LOCK_INVALID", 500)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return operation()
        finally:
            os.close(descriptor)

    def _read(self):
        if not self.path.exists():
            return {"version": 1, "claims": []}
        descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or info.st_mode & 0o077 or info.st_size > 64 * 1024):
                raise ClaimRefusal("CLAIM_STORE_INVALID", 500)
            payload = os.read(descriptor, 64 * 1024 + 1)
        finally:
            os.close(descriptor)
        try:
            state = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ClaimRefusal("CLAIM_STORE_INVALID", 500) from error
        if (not isinstance(state, dict) or state.get("version") != 1
                or not isinstance(state.get("claims"), list)):
            raise ClaimRefusal("CLAIM_STORE_INVALID", 500)
        return state

    def _write(self, state):
        payload = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.path.name}-", dir=self.path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def mint(self, authority, now, ttl_seconds):
        code = secrets.token_urlsafe(32)
        if CODE_PATTERN.fullmatch(code) is None:
            raise ClaimRefusal("CLAIM_RANDOM_INVALID", 500)
        digest = hashlib.sha256(code.encode()).hexdigest()

        def operation():
            state = self._read()
            retained = [row for row in state["claims"]
                        if isinstance(row, dict) and row.get("expires_at", 0) >= now - 86400]
            if len(retained) >= MAX_CLAIMS:
                raise ClaimRefusal("CLAIM_STORE_FULL", 503)
            retained.append({"digest": f"sha256:{digest}", "authority": authority,
                             "expires_at": now + ttl_seconds, "spent_at": None})
            self._write({"version": 1, "claims": retained})

        self._with_lock(operation)
        return code

    def consume(self, code, authority, now):
        digest = f"sha256:{hashlib.sha256(code.encode()).hexdigest()}"

        def operation():
            state = self._read()
            selected = next((row for row in state["claims"]
                             if isinstance(row, dict) and isinstance(row.get("digest"), str)
                             and secrets.compare_digest(row["digest"], digest)), None)
            if selected is None:
                raise ClaimRefusal("CLAIM_INVALID")
            if selected.get("authority") != authority:
                raise ClaimRefusal("CLAIM_AUTHORITY_MISMATCH")
            if selected.get("spent_at") is not None:
                raise ClaimRefusal("CLAIM_SPENT")
            expires_at = selected.get("expires_at")
            if not isinstance(expires_at, int) or expires_at <= now:
                raise ClaimRefusal("CLAIM_EXPIRED")
            selected["spent_at"] = now
            self._write(state)

        self._with_lock(operation)


class RateLimiter:
    """Bound aggregate claim attempts arriving through the loopback proxy."""

    def __init__(self, maximum=20, window_seconds=60, clock=time.monotonic):
        self.maximum = maximum
        self.window_seconds = window_seconds
        self.clock = clock
        self.attempts = deque()
        self.lock = threading.Lock()

    def allow(self):
        now = self.clock()
        with self.lock:
            while self.attempts and self.attempts[0] <= now - self.window_seconds:
                self.attempts.popleft()
            if len(self.attempts) >= self.maximum:
                return False
            self.attempts.append(now)
            return True


class HarnessCookieExchange:
    """Exchange the private loopback launch URL for one public-authority cookie."""

    def __init__(self, launch_file, public_origin, authority, harness_port):
        self.launch_file = Path(launch_file)
        self.public_origin = public_origin
        self.authority = authority
        self.harness_port = harness_port

    def __call__(self):
        descriptor = _protected_file(self.launch_file, require_root=None)
        try:
            payload = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        if len(payload) > 4096:
            raise ClaimRefusal("HARNESS_DESCRIPTOR_INVALID", 502)
        try:
            launch = json.loads(payload)
            url = urllib.parse.urlsplit(launch["url"])
            query = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ClaimRefusal("HARNESS_DESCRIPTOR_INVALID", 502) from error
        if (url.scheme != "http" or url.hostname != "127.0.0.1" or url.port != self.harness_port
                or url.path != "/" or url.fragment or len(query) != 1
                or query[0][0] != "token" or not query[0][1]):
            raise ClaimRefusal("HARNESS_DESCRIPTOR_INVALID", 502)
        connection = http.client.HTTPConnection("127.0.0.1", self.harness_port, timeout=5)
        try:
            connection.request("GET", f"/?token={urllib.parse.quote(query[0][1])}", headers={
                "Host": self.authority,
                "Origin": self.public_origin,
                "Sec-Fetch-Site": "same-origin",
            })
            response = connection.getresponse()
            response.read(1024)
            cookie = response.getheader("Set-Cookie")
            location = response.getheader("Location")
        except OSError as error:
            raise ClaimRefusal("HARNESS_EXCHANGE_UNAVAILABLE", 502) from error
        finally:
            connection.close()
        if (response.status != 303 or location != "/" or not isinstance(cookie, str)
                or not cookie.startswith("dsh-auth-") or "\r" in cookie or "\n" in cookie
                or "; Secure" not in cookie or "; HttpOnly" not in cookie
                or "; SameSite=Strict" not in cookie):
            raise ClaimRefusal("HARNESS_COOKIE_INVALID", 502)
        return cookie


class OwnerProxy:
    """Forward only bounded owner-page requests to its loopback server."""

    REQUEST_HEADERS = {"accept", "content-type", "cookie", "origin", "referer", "user-agent",
                       "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user"}
    RESPONSE_HEADERS = {"cache-control", "content-type", "content-security-policy", "expires",
                        "location", "pragma", "referrer-policy", "set-cookie", "x-content-type-options",
                        "x-frame-options"}

    def __init__(self, port, authority):
        self.port = port
        self.authority = authority

    def __call__(self, method, target, headers, body):
        forwarded = {name: value for name, value in headers.items() if name in self.REQUEST_HEADERS}
        forwarded["Host"] = self.authority
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, target, body=body or None, headers=forwarded)
            response = connection.getresponse()
            payload = response.read(MAX_OWNER_BODY + 1)
            response_headers = [(name, value) for name, value in response.getheaders()
                                if name.lower() in self.RESPONSE_HEADERS]
        except OSError as error:
            raise ClaimRefusal("OWNER_PAGE_UNAVAILABLE", 502) from error
        finally:
            connection.close()
        if len(payload) > MAX_OWNER_BODY:
            raise ClaimRefusal("OWNER_RESPONSE_TOO_LARGE", 502)
        return response.status, response_headers, payload


class ClaimApplication:
    """Serve static fragment exchange and host-isolated owner-page forwarding."""

    def __init__(self, store, public_origin, public_authority, owner_authority,
                 exchange_cookie, owner_proxy, limiter=None, clock=time.time):
        self.store = store
        self.public_origin = public_origin
        self.public_authority = public_authority
        self.owner_authority = owner_authority
        self.exchange_cookie = exchange_cookie
        self.owner_proxy = owner_proxy
        self.limiter = limiter or RateLimiter()
        self.clock = clock

    @staticmethod
    def _headers(extra=None):
        headers = [("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
                   ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                   ("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")]
        return headers + (extra or [])

    def handle(self, method, target, headers, body):
        host = headers.get("host")
        if len(target) > MAX_TARGET or len(body) > MAX_OWNER_BODY:
            raise ClaimRefusal("REQUEST_TOO_LARGE", 413)
        if host == self.owner_authority:
            if method not in ("GET", "HEAD", "POST"):
                raise ClaimRefusal("OWNER_METHOD_REFUSED", 405)
            return self.owner_proxy(method, target, headers, body)
        if host != self.public_authority:
            raise ClaimRefusal("CLAIM_HOST_REFUSED", 421)
        if method == "GET" and target == CLAIM_PATH:
            return 200, self._headers([("Content-Type", "text/html; charset=utf-8")]), CLAIM_PAGE
        if method == "GET" and target == CLAIM_SCRIPT_PATH:
            return 200, self._headers([("Content-Type", "text/javascript; charset=utf-8")]), CLAIM_SCRIPT
        if method != "POST" or target != CLAIM_PATH:
            raise ClaimRefusal("CLAIM_ROUTE_REFUSED", 404)
        if headers.get("origin") != self.public_origin or headers.get("sec-fetch-site") == "cross-site":
            raise ClaimRefusal("CLAIM_ORIGIN_REFUSED")
        if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "text/plain":
            raise ClaimRefusal("CLAIM_CONTENT_TYPE_REFUSED", 415)
        if len(body) > MAX_CLAIM_BODY:
            raise ClaimRefusal("CLAIM_REQUEST_TOO_LARGE", 413)
        try:
            code = body.decode("ascii")
        except UnicodeError as error:
            raise ClaimRefusal("CLAIM_INVALID") from error
        if CODE_PATTERN.fullmatch(code) is None:
            raise ClaimRefusal("CLAIM_INVALID")
        if not self.limiter.allow():
            raise ClaimRefusal("CLAIM_RATE_LIMITED", 429)
        self.store.consume(code, self.public_authority, int(self.clock()))
        cookie = self.exchange_cookie()
        return 204, self._headers([("Set-Cookie", cookie)]), b""


def handler_for(application):
    class Handler(BaseHTTPRequestHandler):
        server_version = "aukora-claim"
        sys_version = ""

        def log_message(self, _format, *_arguments):
            return

        def do_GET(self):
            self._dispatch()

        def do_HEAD(self):
            self._dispatch()

        def do_POST(self):
            self._dispatch()

        def _dispatch(self):
            try:
                if len(self.path) > MAX_TARGET:
                    raise ClaimRefusal("REQUEST_TOO_LARGE", 413)
                header_bytes = sum(len(name) + len(value) + 4 for name, value in self.headers.items())
                if header_bytes > MAX_HEADERS or self.headers.get("Transfer-Encoding") is not None:
                    raise ClaimRefusal("REQUEST_TOO_LARGE", 413)
                raw_length = self.headers.get("Content-Length", "0")
                if not raw_length.isdecimal():
                    raise ClaimRefusal("REQUEST_LENGTH_INVALID", 400)
                length = int(raw_length)
                limit = MAX_CLAIM_BODY if self.headers.get("Host") == application.public_authority else MAX_OWNER_BODY
                if length > limit:
                    raise ClaimRefusal("REQUEST_TOO_LARGE", 413)
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ClaimRefusal("REQUEST_TRUNCATED", 400)
                headers = {name.lower(): value for name, value in self.headers.items()}
                status_code, response_headers, payload = application.handle(self.command, self.path, headers, body)
            except ClaimRefusal as refusal:
                status_code, response_headers = refusal.status_code, ClaimApplication._headers([
                    ("Content-Type", "text/plain; charset=utf-8")])
                payload = (refusal.code + "\n").encode()
            if self.command == "HEAD":
                payload = b""
            self.send_response(status_code)
            for name, value in response_headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)

    return Handler


def require_root():
    if os.geteuid() != 0:
        raise SystemExit("CLAIM_ROOT_REQUIRED")


def valid_port(value):
    port = int(value)
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be in 1024..65535")
    return port


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    mint = commands.add_parser("mint")
    mint.add_argument("--public-origin-file", type=Path, required=True)
    mint.add_argument("--state-file", type=Path, required=True)
    mint.add_argument("--ttl-seconds", type=int, default=300)
    serve = commands.add_parser("serve")
    serve.add_argument("--public-origin-file", type=Path, required=True)
    serve.add_argument("--owner-origin-file", type=Path, required=True)
    serve.add_argument("--state-file", type=Path, required=True)
    serve.add_argument("--launch-url-file", type=Path, required=True)
    serve.add_argument("--harness-port", type=valid_port, required=True)
    serve.add_argument("--owner-page-port", type=valid_port, required=True)
    serve.add_argument("--listen-port", type=valid_port, required=True)
    arguments = parser.parse_args()
    require_root()
    public_origin, public_authority = read_origin_file(arguments.public_origin_file)
    store = ClaimStore(arguments.state_file)
    if arguments.command == "mint":
        if not 30 <= arguments.ttl_seconds <= 900:
            raise SystemExit("CLAIM_TTL_INVALID")
        code = store.mint(public_authority, int(time.time()), arguments.ttl_seconds)
        print(f"{public_origin}{CLAIM_PATH}#{code}")
        return
    owner_origin, owner_authority = read_origin_file(arguments.owner_origin_file)
    if public_authority == owner_authority:
        raise SystemExit("CLAIM_HOSTS_MUST_DIFFER")
    if len({arguments.harness_port, arguments.owner_page_port, arguments.listen_port}) != 3:
        raise SystemExit("CLAIM_PORTS_MUST_DIFFER")
    exchange = HarnessCookieExchange(arguments.launch_url_file, public_origin,
                                     public_authority, arguments.harness_port)
    application = ClaimApplication(store, public_origin, public_authority, owner_authority,
                                   exchange, OwnerProxy(arguments.owner_page_port, owner_authority))
    server = ThreadingHTTPServer(("127.0.0.1", arguments.listen_port), handler_for(application))
    server.handle_error = lambda *_args: None
    server.serve_forever()


if __name__ == "__main__":
    main()
