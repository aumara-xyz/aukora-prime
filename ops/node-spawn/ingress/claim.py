#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Issue and spend bounded browser claims without exposing the harness launch token."""

import argparse
import base64
import fcntl
import hashlib
import http.client
import io
import json
import os
import re
import secrets
import socket
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
SIGNIN_PATH = "/__aukora/signin"
SIGNOUT_PATH = "/__aukora/signout"
SESSION_SECONDS = 86400
CODE_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MAX_CLAIMS = 64
MAX_CLAIM_BODY = 128
MAX_OWNER_BODY = 64 * 1024
MAX_TARGET = 2048
MAX_HEADERS = 8192
MAX_CONNECTIONS = 32
HEADER_READ_SECONDS = 5
BODY_READ_SECONDS = 10

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

SIGNIN_PAGE = CLAIM_PAGE.replace(b"Claim AUKORA node", b"Sign in to AUKORA node").replace(
    b"Claiming this node...", b"Signing in to this node...")
SIGNIN_SCRIPT = CLAIM_SCRIPT.replace(b"/__aukora/claim'", b"/__aukora/signin'")


def cookie_name(authority):
    digest = base64.urlsafe_b64encode(hashlib.sha256(authority.encode()).digest()).decode().rstrip("=")
    hostname = urllib.parse.urlsplit("http://" + authority).hostname
    parts = hostname.split(".") if hostname else []
    loopback = (hostname in ("localhost", "::1") or (len(parts) == 4 and parts[0] == "127"
                and all(part.isdecimal() and int(part) <= 255 for part in parts)))
    return ("" if loopback else "__Host-") + "dsh-auth-" + digest


def bounded_cookie(cookie, authority, now):
    """Accept only the exact harness audience cookie with a signed lifetime of at most one day."""
    try:
        parts = cookie.split(";")
        name, value = parts[0].split("=", 1)
        version, encoded, signature = value.split(".")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        attributes = {piece.strip().split("=", 1)[0].lower(): piece.strip().split("=", 1)[-1]
                      for piece in parts[1:]}
        issued, expires = payload["issuedAt"], payload["expiresAt"]
        lifetime = expires - issued
        max_age = int(attributes["max-age"])
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ClaimRefusal("HARNESS_COOKIE_INVALID", 502) from error
    if (name != cookie_name(authority) or version != "v1" or not signature
            or payload.get("version") != 1 or payload.get("authority") != authority
            or type(issued) is not int or type(expires) is not int
            or not 0 < lifetime <= SESSION_SECONDS * 1000
            or not 0 < max_age <= SESSION_SECONDS or max_age * 1000 != lifetime
            or issued > int(now * 1000) + 5000 or expires <= int(now * 1000)
            or attributes.get("path") != "/" or "domain" in attributes
            or "secure" not in attributes or "httponly" not in attributes
            or attributes.get("samesite") != "Strict" or "\r" in cookie or "\n" in cookie):
        raise ClaimRefusal("HARNESS_COOKIE_INVALID", 502)
    return cookie


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

    def mint(self, authority, now, ttl_seconds, code=None):
        code = secrets.token_urlsafe(32) if code is None else code
        if CODE_PATTERN.fullmatch(code) is None:
            raise ClaimRefusal("CLAIM_RANDOM_INVALID", 500)
        digest = hashlib.sha256(code.encode()).hexdigest()

        def operation():
            state = self._read()
            retained = [row for row in state["claims"]
                        if isinstance(row, dict) and row.get("expires_at", 0) >= now - 86400]
            if any(row.get("digest") == f"sha256:{digest}" for row in retained):
                raise ClaimRefusal("CLAIM_SPENT")
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

    def _launch_token(self):
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
        return query[0][1]

    def _exchange(self, token):
        connection = http.client.HTTPConnection("127.0.0.1", self.harness_port, timeout=5)
        try:
            connection.request("GET", f"/?token={urllib.parse.quote(token)}", headers={
                "Host": self.authority,
                "Origin": self.public_origin,
                "Sec-Fetch-Site": "same-origin",
            })
            response = connection.getresponse()
            body = response.read(1024)
            cookie = response.getheader("Set-Cookie")
            location = response.getheader("Location")
        except OSError as error:
            raise ClaimRefusal("HARNESS_EXCHANGE_UNAVAILABLE", 502) from error
        finally:
            connection.close()
        return response.status, body, cookie, location

    def __call__(self):
        token = self._launch_token()
        status, body, cookie, location = self._exchange(token)
        # Retry one changed launch token inside the already-spent claim.
        if (status == 401 and body == b"dsh web authentication required; reopen the URL printed by dsh web.\n"
                and cookie is None and location is None):
            current_token = self._launch_token()
            if current_token != token:
                status, body, cookie, location = self._exchange(current_token)
        if (status != 303 or location != "/" or not isinstance(cookie, str)
                or not cookie.startswith(cookie_name(self.authority) + "=") or "\r" in cookie or "\n" in cookie
                or "; Secure" not in cookie or "; HttpOnly" not in cookie
                or "; SameSite=Strict" not in cookie):
            raise ClaimRefusal("HARNESS_COOKIE_INVALID", 502)
        return bounded_cookie(cookie, self.authority, time.time())


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
        if method == "GET" and target == SIGNIN_PATH:
            page = SIGNIN_PAGE.replace(b"/__aukora/claim.js", b"/__aukora/signin.js")
            return 200, self._headers([("Content-Type", "text/html; charset=utf-8")]), page
        if method == "GET" and target == SIGNIN_PATH + ".js":
            script = SIGNIN_SCRIPT.replace(
                b"statusNode.textContent = 'This claim link is invalid.';",
                ("location.replace(" + json.dumps("https://" + self.owner_authority + "/owner/signin") + ");").encode())
            return 200, self._headers([("Content-Type", "text/javascript; charset=utf-8")]), script
        if method != "POST" or target not in (CLAIM_PATH, SIGNIN_PATH, SIGNOUT_PATH):
            raise ClaimRefusal("CLAIM_ROUTE_REFUSED", 404)
        if headers.get("origin") != self.public_origin or headers.get("sec-fetch-site") == "cross-site":
            raise ClaimRefusal("CLAIM_ORIGIN_REFUSED")
        if target == SIGNOUT_PATH:
            if body:
                raise ClaimRefusal("SIGNOUT_BODY_REFUSED", 400)
            cleared = cookie_name(self.public_authority) + "=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict"
            return 204, self._headers([("Set-Cookie", cleared)]), b""
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
        if target == SIGNIN_PATH:
            status_code, _, payload = self.owner_proxy("POST", "/owner/signin/redeem", {
                "origin": "https://" + self.owner_authority, "content-type": "application/json",
                "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty",
            }, json.dumps({"code": code, "app_origin": self.public_origin}, separators=(",", ":")).encode())
            if status_code != 200:
                raise ClaimRefusal("SIGNIN_REDEEM_REFUSED")
            try:
                result = json.loads(payload)
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ClaimRefusal("SIGNIN_REDEEM_INVALID", 502) from error
            redeemed = result.get("result", {}) if isinstance(result, dict) else {}
            now_ms = int(self.clock() * 1000)
            if (not isinstance(result, dict) or result.get("ok") is not True
                    or not isinstance(result.get("result"), dict)
                    or redeemed.get("app_origin") != self.public_origin
                    or not isinstance(redeemed.get("node"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", redeemed.get("node", "")) is None
                    or type(redeemed.get("expires_at_ms")) is not int
                    or not now_ms + 1000 <= redeemed.get("expires_at_ms", 0) <= now_ms + 60000):
                raise ClaimRefusal("SIGNIN_REDEEM_INVALID", 502)
            self.store.mint(self.public_authority, int(self.clock()),
                            redeemed["expires_at_ms"] // 1000 - int(self.clock()), code=code)
        self.store.consume(code, self.public_authority, int(self.clock()))
        cookie = self.exchange_cookie()
        return 204, self._headers([("Set-Cookie", cookie)]), b""


class DeadlineReader(io.RawIOBase):
    """Bound socket reads by one absolute deadline per request phase."""

    def __init__(self, connection):
        super().__init__()
        self.connection = connection

    def start(self, seconds, code):
        self.deadline = time.monotonic() + seconds
        self.code = code
        self.connection.settimeout(seconds)

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ClaimRefusal(self.code, 408)
        return remaining

    def readable(self):
        return True

    def readinto(self, buffer):
        self.connection.settimeout(self.remaining())
        try:
            count = self.connection.recv_into(buffer)
        except (TimeoutError, socket.timeout) as error:
            raise ClaimRefusal(self.code, 408) from error
        self.remaining()
        return count


class ClaimHTTPServer(ThreadingHTTPServer):
    """Admit at most a fixed number of simultaneous connection threads."""

    def __init__(self, address, handler):
        self.connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


def handler_for(application):
    class Handler(BaseHTTPRequestHandler):
        server_version = "aukora-claim"
        sys_version = ""

        def setup(self):
            super().setup()
            self.rfile.close()
            self.deadline_reader = DeadlineReader(self.connection)
            self.rfile = io.BufferedReader(self.deadline_reader)

        def handle_one_request(self):
            self.requestline = ""
            self.request_version = self.default_request_version
            self.command = None
            self.deadline_reader.start(HEADER_READ_SECONDS, "HEADER_READ_DEADLINE")
            try:
                super().handle_one_request()
            except ClaimRefusal as refusal:
                self.close_connection = True
                self.send_error(refusal.status_code, refusal.code)

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
                self.close_connection = True
                self.deadline_reader.start(BODY_READ_SECONDS, "BODY_READ_DEADLINE")
                body = self.rfile.read(length)
                self.deadline_reader.remaining()
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
    server = ClaimHTTPServer(("127.0.0.1", arguments.listen_port), handler_for(application))
    server.handle_error = lambda *_args: None
    server.serve_forever()


if __name__ == "__main__":
    main()
