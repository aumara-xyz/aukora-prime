#!/usr/bin/env python3
"""Foreground owner of OpenViking and its memory-bounded embedder."""

import ctypes
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit


class SetupError(Exception):
    """A safe diagnostic containing no configuration contents or key material."""


def say(message):
    print(f"openviking-setup: {message}", file=sys.stderr, flush=True)


def positive_integer(value, name):
    if isinstance(value, bool) or not re.fullmatch(r"[1-9][0-9]*", str(value)):
        raise SetupError(f"{name} must be a positive integer")
    return int(value)


def command(name):
    found = shutil.which(name, path=os.environ.get("PATH", os.defpath) + ":/usr/sbin")
    if not found:
        raise SetupError(f"{name} is required")
    return found


def capture(args):
    # run() kills and reaps its short-lived child on timeout, including during shutdown.
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, timeout=2, check=False)


def stop_child(child, immediate=False, memory=None):
    if child is None or child.returncode is not None:
        return
    memory = memory or memory_monitor()

    def send(sig):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            # Darwin returns EPERM for a group containing only zombies. They
            # still reserve its ID, but need reaping, not another signal.
            if memory.group_alive(child.pid):
                raise

    # Keep the leader unreaped until the entire group has been signalled. This
    # reaches surviving workers without risking a recycled PID/process group.
    if not immediate:
        send(signal.SIGTERM)
        # Observe the whole group: the leader can exit before a worker flushes.
        deadline = time.monotonic() + 5
        while memory.group_alive(child.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
    send(signal.SIGKILL)
    child.wait(timeout=5)


class MacMemory:
    # Darwin sys/resource.h, rusage_info_v0. Unlike RSS, physical footprint
    # includes compressed/swapped dirty allocations. The old 8 GiB prompt
    # cache could therefore exhaust this Mac while ps reported only 1.2 GiB.
    class Usage(ctypes.Structure):
        _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
            (name, ctypes.c_uint64) for name in (
                "user_time", "system_time", "idle_wakeups", "interrupt_wakeups",
                "pageins", "wired_size", "resident_size", "phys_footprint",
                "start_abstime", "exit_abstime")]

    def __init__(self):
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        self.lib.proc_pid_rusage.restype = ctypes.c_int
        self.lib.proc_listpgrppids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listpgrppids.restype = ctypes.c_int

    def group_alive(self, pgid):
        pids = (ctypes.c_int * 4096)()
        count = self.lib.proc_listpgrppids(pgid, pids, ctypes.sizeof(pids))
        if count < 0 or count >= len(pids):
            raise OSError("could not enumerate child process group")
        for pid in pids[:count]:
            try:
                if self.usage(pid).exit_abstime == 0:
                    return True
            except OSError as error:
                if error.errno != errno.ESRCH:
                    raise
        return False

    def usage(self, pid):
        usage = self.Usage()
        if self.lib.proc_pid_rusage(pid, 0, ctypes.byref(usage)) != 0:
            raise OSError(ctypes.get_errno(), "could not sample child memory")
        return usage

    def exited(self, child):
        # poll()/wait() would reap the leader before group cleanup. Darwin keeps
        # this exit timestamp available for our unreaped child instead.
        if child.returncode is not None:
            return True
        try:
            return self.usage(child.pid).exit_abstime != 0
        except OSError as error:
            if error.errno == errno.ESRCH:
                return True
            raise

    def sample(self, pid):
        usage = self.usage(pid)
        return usage.resident_size // 1024, usage.phys_footprint // 1024

    def listener_owned(self, pid, port):
        owner = capture([command("lsof"), "-nP", "-a", "-p", str(pid),
                         f"-iTCP@127.0.0.1:{port}", "-sTCP:LISTEN", "-t"])
        return owner.returncode == 0 and owner.stdout.strip() == str(pid)


class LinuxMemory:
    """Read our unreaped process group from procfs; never adopt another server."""

    @staticmethod
    def process(pid):
        # comm may contain spaces and parentheses. Fields after its final ')' start
        # with state, ppid and pgrp. A zombie leader keeps our group ID reserved.
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rindex(")") + 2:].split()
        return fields[0], int(fields[2])

    def members(self, pgid):
        members = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                state, group = self.process(int(entry.name))
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if group == pgid and state != "Z":
                members.append(int(entry.name))
                if len(members) > 4096:
                    raise OSError("child process group exceeds sampling bound")
        return members

    def group_alive(self, pgid):
        return bool(self.members(pgid))

    def exited(self, child):
        if child.returncode is not None:
            return True
        try:
            return self.process(child.pid)[0] == "Z"
        except (FileNotFoundError, ProcessLookupError):
            return True

    def sample(self, pid):
        rss, swap = 0, 0
        for member in self.members(pid):
            try:
                fields = {}
                for line in Path(f"/proc/{member}/status").read_text().splitlines():
                    name, _, value = line.partition(":")
                    if name in ("VmRSS", "VmSwap"):
                        parts = value.split()
                        if len(parts) != 2 or parts[1] != "kB":
                            raise OSError("unexpected procfs memory units")
                        fields[name] = int(parts[0])
                # Fail closed for a live process whose memory cannot be measured.
                rss += fields["VmRSS"]
                swap += fields["VmSwap"]
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (KeyError, ValueError):
                raise OSError("could not sample child memory") from None
        return rss, rss + swap

    @staticmethod
    def listener_owned(pid, port):
        inodes = set()
        for entry in Path(f"/proc/{pid}/fd").iterdir():
            try:
                link = os.readlink(entry)
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[([0-9]+)\]", link)
            if match:
                inodes.add(match.group(1))
        endpoint = f"0100007F:{port:04X}"
        for line in Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 10 and fields[1] == endpoint and fields[3] == "0A" and fields[9] in inodes:
                return True
        return False


def load_mode_args(help_text):
    """The memory-mapped load flag this llama-server accepts.

    llama.cpp replaced `--mmap` with `--load-mode MODE` (measured: b11381 refuses `--mmap` with
    "invalid argument", so the embedder exited on every start). Both keep the model memory-mapped;
    an unrecognised help text refuses rather than guessing.
    """
    if "--load-mode" in help_text:
        return ["--load-mode", "mmap"]
    if "--mmap" in help_text:
        return ["--mmap"]
    raise SetupError("llama-server offers neither --load-mode nor --mmap; cannot keep the model memory-mapped")


def memory_monitor():
    if sys.platform == "darwin":
        return MacMemory()
    if sys.platform == "linux":
        return LinuxMemory()
    raise SetupError("only macOS and Linux supervisors are supported")


class Supervisor:
    def __init__(self, home):
        self.home = Path(home)
        if not self.home.is_absolute():
            raise SetupError("HOME must be an absolute path")
        with (self.home / "aukora-bridge.json").open() as source:
            embedding = json.load(source)["embedding"]
        self.port = positive_integer(embedding["port"], "embedding.port")
        if self.port > 65535:
            raise SetupError("embedding.port must be at most 65535")
        self.context = positive_integer(embedding["context"], "embedding.context")
        self.model = embedding["model"]
        if not isinstance(self.model, str) or not self.model or not Path(self.model).is_file():
            raise SetupError("embedding.model must name an existing model file")
        # An operator may point at the existing shared model instead of copying it.
        # Preserve the exact Genesis model pin at serve time too, not just install.
        digest = hashlib.sha256()
        with Path(self.model).open("rb") as model:
            for block in iter(lambda: model.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439":
            raise SetupError("embedding.model differs from the pinned Qwen3-Embedding-0.6B-Q8_0.gguf")
        self.limit = positive_integer(os.environ.get("AUKORA_OPENVIKING_EMBED_RSS_MIB", "1536"),
                                      "AUKORA_OPENVIKING_EMBED_RSS_MIB") * 1024
        self.llama = command("llama-server")
        probe = capture([self.llama, "--help"])
        self.load_mode = load_mode_args((probe.stdout or "") + (probe.stderr or ""))
        self.memory = memory_monitor()
        if sys.platform == "darwin":
            command("lsof")
        self.threads = positive_integer(os.environ.get("AUKORA_OPENVIKING_EMBED_THREADS", "2"),
                                        "AUKORA_OPENVIKING_EMBED_THREADS")
        if self.threads > 4:
            raise SetupError("AUKORA_OPENVIKING_EMBED_THREADS must be at most 4")
        if self.context > 2048:
            raise SetupError("embedding.context must be at most 2048")
        self.validate_server()
        self.embed = self.ov = None
        self.readiness = threading.Event()
        self.ready_cancel = threading.Event()
        self.ready_thread = None
        self.stopping = threading.Event()
        self.exit_signal = 0
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, self.on_signal)

    def validate_server(self):
        key_path = self.home / "root.key"
        key_stat = key_path.lstat()
        if (not stat.S_ISREG(key_stat.st_mode) or key_stat.st_mode & 0o077 or
                key_stat.st_uid != os.getuid() or not 1 <= key_stat.st_size <= 4096):
            raise SetupError("root.key must be an existing private regular file owned by the service user")
        key = key_path.read_text().strip()
        if not key or "\n" in key or "\r" in key:
            raise SetupError("root.key must contain the existing single-line credential")
        with (self.home / "ov.conf").open() as source:
            config = json.load(source)
        server = config["server"]
        if server.get("host") != "127.0.0.1" or server.get("auth_mode") != "trusted":
            raise SetupError("ov.conf server must bind 127.0.0.1 with trusted authentication")
        if server.get("root_api_key") != "${AUKORA_OPENVIKING_ROOT_KEY}":
            raise SetupError("ov.conf server.root_api_key must use the existing runtime credential")
        if server.get("cors_origins") != []:
            raise SetupError("ov.conf server.cors_origins must be empty")
        server_port = positive_integer(server["port"], "server.port")
        if server_port > 65535 or server_port == self.port:
            raise SetupError("server.port must be distinct from embedding.port and at most 65535")
        with (self.home / "aukora-bridge.json").open() as source:
            bridge = json.load(source)
        if bridge.get("url") != f"http://127.0.0.1:{server_port}":
            raise SetupError("aukora-bridge.json url must match the loopback server.port")
        dense = config["embedding"]["dense"]
        if dense.get("api_base") != f"http://127.0.0.1:{self.port}/v1":
            raise SetupError("ov.conf embedding.dense.api_base must match the loopback embedding.port")
        if (dense.get("provider") != "openai" or dense.get("api_key") != "local" or
                dense.get("model") != "qwen3-embedding-0.6b" or dense.get("dimension") != 1024 or
                dense.get("encoding_format") != "float"):
            raise SetupError("ov.conf embedding.dense must use the pinned local Qwen embedding profile")
        # Match Kira's modelsOffMachine boundary for optional model sections too.
        # Dense-only validation would let an existing optional provider send note
        # text off-machine. Diagnostics name only the field, never its endpoint/key.
        for name, section in (("embedding.sparse", config["embedding"].get("sparse")),
                              ("vlm", config.get("vlm")), ("rerank", config.get("rerank")),
                              ("query_planner", config.get("query_planner"))):
            if section is None:
                continue
            if not isinstance(section, dict):
                raise SetupError(f"ov.conf {name} must be a model configuration object")
            base = section.get("api_base")
            if base is not None and not isinstance(base, str):
                raise SetupError(f"ov.conf {name}.api_base must be a loopback HTTP endpoint")
            if isinstance(base, str) and base != "":
                try:
                    endpoint = urlsplit(base)
                    local = endpoint.scheme in ("http", "https") and endpoint.hostname in (
                        "127.0.0.1", "localhost", "::1")
                except ValueError:
                    local = False
                if not local:
                    raise SetupError(f"ov.conf {name}.api_base must be a loopback HTTP endpoint")
            elif section.get("provider") not in (None, "", "local"):
                raise SetupError(f"ov.conf {name} must not use a provider default endpoint")

    def on_signal(self, sig, _frame):
        # Do not raise between Popen and assignment: every child must reach cleanup.
        self.exit_signal = sig
        self.stopping.set()

    def start_embed(self):
        # Refuse an existing listener on every start. The ownership check below also
        # closes the bind/check race; a different server's health cannot make us ready.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as guard:
            guard.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                guard.bind(("127.0.0.1", self.port))
                guard.listen(1)
            except OSError:
                raise SetupError(f"embedding port {self.port} unavailable; refusing to adopt a server") from None
        batch = str(min(512, self.context))
        # output_reserve retains vocab * batch float logits even for pooled embeddings;
        # large batches also retain Metal buffers. LAST pooling supports splitting
        # a full-context input into these smaller batches without truncating it.
        # cache-ram 0 disables the default 8192 MiB heap prompt cache; a single
        # slot's prefix KV stays context-bounded. Keep mmap and f16 KV quality.
        args = [self.llama, "-m", self.model, "--embedding", "--pooling", "last",
                "--host", "127.0.0.1", "--port", str(self.port), "-c", str(self.context),
                "-b", batch, "-ub", batch, "--parallel", "1", "--cache-ram", "0", *self.load_mode,
                "--cache-type-k", "f16", "--cache-type-v", "f16", "--alias", "qwen3-embedding-0.6b"]
        if sys.platform == "linux":
            # The existing CPU release supplies llama-server; never download/build
            # another copy here or inherit generation-server GPU/thread settings.
            args += ["--n-gpu-layers", "0", "--threads", str(self.threads),
                     "--threads-batch", str(self.threads)]
        # Explicit arguments govern the service. Inherited generation-server
        # defaults such as mlock or a different load mode must not undo the bound.
        env = {key: value for key, value in os.environ.items() if not key.startswith("LLAMA_ARG_")}
        env.pop("AUKORA_OPENVIKING_ROOT_KEY", None)
        # A restart truncates the existing log; there are no accumulating archives.
        with (self.home / "embed.log").open("wb") as log:
            self.embed = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                          env=env, start_new_session=True)
        self.readiness = threading.Event()
        self.ready_cancel = threading.Event()
        self.ready_thread = threading.Thread(target=self.wait_ready,
                                             args=(self.embed.pid, self.readiness, self.ready_cancel),
                                             daemon=True)
        self.ready_thread.start()

    def ready(self, pid):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
        try:
            connection.request("GET", "/health")
            if connection.getresponse().status != 200:
                return False
        except (OSError, http.client.HTTPException):
            return False
        finally:
            connection.close()
        try:
            return self.memory.listener_owned(pid, self.port)
        except (OSError, subprocess.TimeoutExpired):
            return False

    def wait_ready(self, pid, ready, cancel):
        # HTTP and lsof can block. Keep them off the memory-sampling loop, and
        # bind readiness to this generation so an old probe cannot ready a new PID.
        while not cancel.is_set():
            if self.ready(pid):
                ready.set()
                return
            cancel.wait(1)

    def stop_embed(self, immediate=False):
        self.ready_cancel.set()
        stop_child(self.embed, immediate=immediate, memory=self.memory)
        if self.ready_thread is not None:
            self.ready_thread.join(timeout=4)
        self.ready_thread = None

    def start_ov(self):
        env = os.environ.copy()
        env["AUKORA_OPENVIKING_HOME"] = str(self.home)
        # Read only at runtime, never into shell arguments or supervisor output.
        env["AUKORA_OPENVIKING_ROOT_KEY"] = (self.home / "root.key").read_text().strip()
        if not env["AUKORA_OPENVIKING_ROOT_KEY"]:
            raise SetupError("root.key is empty")
        self.ov = subprocess.Popen([str(self.home / "venv/bin/openviking-server"),
                                    "--config", str(self.home / "ov.conf")],
                                   env=env, start_new_session=True)

    def run(self):
        failures, start_at, restart = 0, 0, None
        while not self.stopping.is_set():
            if self.ov is not None and self.memory.exited(self.ov):
                stop_child(self.ov, memory=self.memory)
                say(f"OpenViking exited (status {self.ov.returncode})")
                return self.ov.returncode if self.ov.returncode >= 0 else 128 - self.ov.returncode
            now = time.monotonic()
            if self.embed is None:
                if now < start_at:
                    self.stopping.wait(min(0.2, start_at - now))
                    continue
                self.start_embed()
                if restart:
                    say(f"embedding restart {restart} new_pid={self.embed.pid}")
                else:
                    say(f"embedding starting pid={self.embed.pid} rss_limit_mib={self.limit // 1024}")
                ready_at, last_rss, last_footprint = None, None, None
                deadline, next_rss = time.monotonic() + 120, 0

            reason = None
            try:
                if self.memory.exited(self.embed):
                    self.stop_embed(immediate=True)
                    reason = f"exit_status={self.embed.returncode}"
                elif time.monotonic() >= next_rss:
                    next_rss = time.monotonic() + 2
                    last_rss, last_footprint = self.memory.sample(self.embed.pid)
                    if max(last_rss, last_footprint) > self.limit:
                        reason = "memory_limit_exceeded"
            except OSError:
                reason = "memory_sample_failed"
            if self.stopping.is_set():
                break
            if reason is None and ready_at is None:
                if self.readiness.is_set():
                    ready_at = time.monotonic()
                    say(f"embedding server up on 127.0.0.1:{self.port} (pid {self.embed.pid})")
                    if self.ov is None and not self.stopping.is_set():
                        self.start_ov()
                elif time.monotonic() >= deadline:
                    reason = "readiness_timeout"
            if reason:
                restart = (f"reason={reason} old_pid={self.embed.pid} "
                           f"last_rss_kib={last_rss if last_rss is not None else 'unavailable'} "
                           f"last_footprint_kib={last_footprint if last_footprint is not None else 'unavailable'}")
                # Sampled protection, not a hard cap: bursts can overshoot and a
                # restart may interrupt a request. Keep OV through normal recycling;
                # repeated failures stop the pair for the outer service manager.
                self.stop_embed(immediate=reason.startswith("memory_"))
                self.embed = None
                if self.stopping.is_set():
                    break
                failures += 1
                if failures > 5:
                    raise SetupError(f"{restart}; embedder restart limit reached")
                delay = min(2 ** failures, 30)
                say(f"embedding stopped {restart}; retry_in_seconds={delay}")
                start_at = time.monotonic() + delay
                continue
            if ready_at is not None and time.monotonic() - ready_at >= 300:
                # A sustained healthy run earns a fresh five-restart allowance.
                failures = 0
            self.stopping.wait(0.2)
        return 128 + self.exit_signal

    def close(self):
        failed = False
        for child in (self.ov, self.embed):
            try:
                if child is self.embed:
                    self.stop_embed()
                else:
                    stop_child(child, memory=self.memory)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
                say(f"cleanup failed for pid={child.pid}; no replacement started")
        return failed


def main():
    supervisor = None
    result = 1
    try:
        if len(sys.argv) != 2:
            raise SetupError("usage: openviking-supervisor.py HOME")
        supervisor = Supervisor(sys.argv[1])
        result = supervisor.run()
    except SetupError as error:
        say(str(error))
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        # Do not dump config, child output or exception payloads that might contain a key.
        say(f"supervisor failed ({type(error).__name__}); check configuration and embed.log")
    finally:
        if supervisor is not None and supervisor.close():
            result = 1
    return result


if __name__ == "__main__":
    sys.exit(main())
