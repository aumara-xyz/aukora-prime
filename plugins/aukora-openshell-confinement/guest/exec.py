#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guest-only JSONL carrier. The root-owned OpenShell entrypoint owns admission.

This file must be entered through the authenticated guest SSH path, after the
wrapper's full applied-policy check. It never starts a host command. Protocol
bytes, the process stdio and the optional duplex fd 7 are separate channels.
Each carrier owns one subreaper tree; it never cleans another execution.
"""

import base64
import collections
import ctypes
import errno
import fcntl
import json
import os
import selectors
import signal
import socket
import stat
import struct
import sys
import termios
import time


MAX_LINE = 1024 * 1024
MAX_QUEUE = 1024 * 1024
HIGH_WATER = MAX_QUEUE // 2
INPUT_STALL_SECONDS = 2
CHUNK = 16384
MAX_PROCESSES = 4096
MAX_THREADS = 1024
LAUNCH_KEYS = {"type", "version", "kind", "argv", "cwd", "env", "stdin",
               "control", "grace_ms", "rows", "cols", "terminal_type"}
SIGNALS = {name: getattr(signal, name) for name in
           ("SIGINT", "SIGTERM", "SIGKILL", "SIGTSTP", "SIGHUP")}
ENV_NAMES = {"LC_ALL", "LANG", "TERM", "PS1", "PROMPT_COMMAND", "DSH_SESSION_ID",
             "DSH_PTY_SESSION_ID", "DSH_SHELL", "DSH_HOME", "NO_COLOR", "PAGER",
             "GIT_PAGER", "BASH_SILENCE_DEPRECATION_WARNING"}


class Refused(Exception):
    def __init__(self, code):
        self.code = code


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def text(value, limit=8192):
    if not isinstance(value, str) or "\0" in value:
        return False
    try:
        return len(value.encode("utf-8", "strict")) <= limit
    except UnicodeError:
        return False


def exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("PROTOCOL")
        result[key] = value
    return result


def parse(line):
    if not line or len(line) > MAX_LINE:
        raise Refused("PROTOCOL")
    try:
        value = json.loads(line.decode("utf-8", "strict"),
                           object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("PROTOCOL")))
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("PROTOCOL")
    if type(value) is not dict:
        raise Refused("PROTOCOL")
    return value


def launch_spec(value):
    if not exact(value, LAUNCH_KEYS) or value["type"] != "launch" or \
            type(value["version"]) is not int or value["version"] != 1 or \
            value["kind"] not in ("process", "terminal", "lookup"):
        raise Refused("LAUNCH")
    argv = value["argv"]
    if type(argv) is not list or not 1 <= len(argv) <= 256 or \
            any(not text(arg, 256 * 1024) for arg in argv) or not argv[0] or \
            sum(len(arg.encode("utf-8")) for arg in argv) > 256 * 1024:
        raise Refused("ARGV")
    if value["cwd"] != "/sandbox" or os.path.realpath("/sandbox") != "/sandbox" or \
            not os.path.isdir("/sandbox"):
        raise Refused("WORKSPACE")
    if value["stdin"] not in ("ignore", "pipe") or type(value["control"]) is not bool or \
            not integer(value["grace_ms"], 1, 10000):
        raise Refused("LAUNCH")
    if value["kind"] == "terminal":
        if value["control"] or value["stdin"] != "pipe" or \
                not integer(value["rows"], 1, 1000) or not integer(value["cols"], 1, 1000) or \
                not text(value["terminal_type"], 128) or not value["terminal_type"] or \
                any(not (ch.isascii() and (ch.isalnum() or ch in "._+-")) for ch in value["terminal_type"]):
            raise Refused("LAUNCH")
    elif type(value["rows"]) is not int or value["rows"] != 0 or \
            type(value["cols"]) is not int or value["cols"] != 0 or value["terminal_type"] != "":
        raise Refused("LAUNCH")
    if value["kind"] == "lookup" and (len(argv) != 1 or value["control"] or value["stdin"] != "ignore"):
        raise Refused("LAUNCH")
    supplied = value["env"]
    if type(supplied) is not dict or set(supplied) - ENV_NAMES or \
            any(not text(entry) for entry in supplied.values()):
        raise Refused("ENV")
    for name in ("DSH_SESSION_ID", "DSH_PTY_SESSION_ID"):
        if name in supplied and (not supplied[name] or len(supplied[name]) > 256 or
                                  any(not (ch.isascii() and (ch.isalnum() or ch in "._:-"))
                                      for ch in supplied[name])):
            raise Refused("ENV")
    if ("DSH_HOME" in supplied and supplied["DSH_HOME"] != "/sandbox") or \
            ("DSH_SHELL" in supplied and supplied["DSH_SHELL"] != "1"):
        raise Refused("ENV")
    for name, expected in (("PAGER", "cat"), ("GIT_PAGER", "cat"), ("NO_COLOR", "1"),
                           ("BASH_SILENCE_DEPRECATION_WARNING", "1")):
        if name in supplied and supplied[name] != expected:
            raise Refused("ENV")
    if value["kind"] == "terminal" and "TERM" in supplied and supplied["TERM"] != value["terminal_type"]:
        raise Refused("ENV")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/sandbox", "LC_ALL": "C", **supplied}
    if value["kind"] == "terminal":
        env["TERM"] = value["terminal_type"]
    if value["control"]:
        env["DSH_SUBPROCESS_CONTROL"] = "pipe"
    return value, env


def resolve(program):
    if not text(program, 4096) or not program or "\r" in program or "\n" in program:
        raise Refused("EXECUTABLE")
    if program.startswith("/"):
        candidates = [program]
    elif "/" not in program:
        candidates = [os.path.join(directory, program) for directory in ("/usr/bin", "/bin")]
    else:
        raise Refused("EXECUTABLE")
    for candidate in candidates:
        resolved = os.path.realpath(candidate)
        if not text(resolved, 4096) or "\r" in resolved or "\n" in resolved:
            continue
        try:
            mode = os.stat(resolved).st_mode
            if stat.S_ISREG(mode) and os.access(resolved, os.X_OK):
                return resolved
        except OSError:
            pass
    raise Refused("EXECUTABLE")


def proc_stat(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as stream:
            data = stream.read(16384)
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError:
        raise Refused("OWNERSHIP_UNKNOWN")
    end = data.rfind(b")")
    fields = data[end + 2:].split()
    try:
        if end < 1 or len(fields) < 20:
            raise ValueError()
        return {"pid": pid, "state": fields[0], "parent": int(fields[1]),
                "group": int(fields[2]), "session": int(fields[3]),
                "tty": int(fields[4]) & 0xffffffff, "started": int(fields[19])}
    except (ValueError, IndexError):
        raise Refused("OWNERSHIP_UNKNOWN")


def child_pids(pid):
    try:
        threads = os.listdir("/proc/%d/task" % pid)
        if len(threads) > MAX_THREADS:
            raise Refused("OWNERSHIP_LIMIT")
        children = set()
        for thread in threads:
            if not thread.isdigit():
                continue
            try:
                with open("/proc/%d/task/%s/children" % (pid, thread), "rb") as stream:
                    data = stream.read(65537)
                if len(data) > 65536:
                    raise Refused("OWNERSHIP_LIMIT")
                children.update(int(entry) for entry in data.split())
            except (FileNotFoundError, ProcessLookupError):
                if pid == os.getpid() and int(thread) == pid:
                    raise Refused("OWNERSHIP_UNKNOWN")
                continue
        return children
    except (FileNotFoundError, ProcessLookupError):
        if pid == os.getpid():
            raise Refused("OWNERSHIP_UNKNOWN")
        return set()
    except (OSError, ValueError):
        raise Refused("OWNERSHIP_UNKNOWN")


class OwnedTree:
    def __init__(self):
        if sys.platform != "linux" or any(not hasattr(os, name) for name in
                ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID")):
            raise Refused("GUEST_UNAVAILABLE")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                                   ctypes.c_ulong, ctypes.c_ulong]
        self.libc.prctl.restype = ctypes.c_int
        if self.libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise Refused("OWNERSHIP_UNAVAILABLE")
        # Ignored SIGCHLD/SA_NOCLDWAIT could recycle a child pid without a wait.
        # The carrier is single-threaded and installs no other reaping handler.
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        self.pid = os.getpid()
        self.records = {}
        self.root = None
        self.root_status = None
        self.signaling_closed = False
        self.finalized = False

    def wait_child(self, pid):
        """Prove current direct-child custody without freeing its kernel pid."""
        try:
            # __WALL includes clone children with a non-SIGCHLD exit signal;
            # these are still our direct children and must not disappear from
            # the kernel custody check merely because of their clone flags.
            event = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT | 0x40000000)
        except ChildProcessError:
            raise Refused("OWNERSHIP_UNKNOWN")
        except OSError:
            raise Refused("OWNERSHIP_UNAVAILABLE")
        if event is not None:
            if event.si_pid != pid or event.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
                raise Refused("OWNERSHIP_UNKNOWN")
            if pid == self.root:
                status_value = event.si_status << 8 if event.si_code == os.CLD_EXITED else \
                    event.si_status | (0x80 if event.si_code == os.CLD_DUMPED else 0)
                if self.root_status is not None and self.root_status != status_value:
                    raise Refused("OUTCOME_UNKNOWN")
                self.root_status = status_value
        return event

    def retain(self, pid):
        if self.signaling_closed:
            raise Refused("OWNERSHIP_CLOSED")
        event = self.wait_child(pid)
        record = self.records.get(pid)
        if record is None:
            if len(self.records) >= MAX_PROCESSES:
                raise Refused("OWNERSHIP_LIMIT")
            record = {"pid": pid, "started": None, "term_sent": False}
            self.records[pid] = record
        fact = proc_stat(pid)
        if fact is None or fact["parent"] != self.pid:
            raise Refused("OWNERSHIP_UNKNOWN")
        if record["started"] is not None and record["started"] != fact["started"]:
            raise Refused("OWNERSHIP_UNKNOWN")
        record.update(fact)
        return record, event

    def set_root(self, pid):
        # The unreaped direct fork child cannot be recycled. Only kernel
        # wait-child proof may subsequently permit a numeric-pid signal.
        self.root = pid
        self.records[pid] = {"pid": pid, "started": None, "term_sent": False}
        self.retain(pid)

    def reap_final(self):
        """Close signalling permanently, then release only proved-dead children."""
        if self.signaling_closed:
            return self.finalized
        children = child_pids(self.pid)
        if children != set(self.records):
            return False
        for pid in children:
            if self.wait_child(pid) is None:
                return False
        # Descendants are reparented before Linux reports their owner's exit.
        if child_pids(self.pid) != children:
            return False
        self.signaling_closed = True
        reaped = set()
        while True:
            try:
                pid, status_value = os.waitpid(-1, os.WNOHANG | 0x40000000)
            except ChildProcessError:
                if reaped != set(self.records) or child_pids(self.pid):
                    raise Refused("OWNERSHIP_UNKNOWN")
                self.records.clear()
                self.finalized = True
                return True
            except InterruptedError:
                continue
            except OSError:
                raise Refused("OWNERSHIP_UNKNOWN")
            if pid == 0:
                raise Refused("OWNERSHIP_UNKNOWN")
            if pid not in self.records or pid in reaped:
                raise Refused("OWNERSHIP_UNKNOWN")
            if pid == self.root and self.root_status != status_value:
                raise Refused("OUTCOME_UNKNOWN")
            reaped.add(pid)

    def census(self):
        if self.signaling_closed:
            return [], self.finalized
        # No early reap or descendant signal from a stat/start-time snapshot.
        # Descendants become retained direct children as their owners die.
        children = child_pids(self.pid)
        live = []
        for pid in children | set(self.records):
            record, event = self.retain(pid)
            if event is None:
                live.append(record)
        if live:
            return live, False
        return [], self.reap_final()

    def observations(self):
        """Read-only descendant facts; these never grant numeric-pid signalling."""
        live, _ = self.census()
        pending = collections.deque(record["pid"] for record in live)
        facts = {record["pid"]: dict(record) for record in live}
        seen = set()
        while pending:
            pid = pending.popleft()
            if pid in seen:
                continue
            seen.add(pid)
            for child in child_pids(pid):
                before = proc_stat(child)
                if before is None or before["parent"] != pid:
                    continue
                after = proc_stat(child)
                if after is None or after["started"] != before["started"] or after["parent"] != pid:
                    continue
                if len(facts) >= MAX_PROCESSES and child not in facts:
                    raise Refused("OWNERSHIP_LIMIT")
                facts[child] = after
                if child not in seen:
                    pending.append(child)
        return [fact for fact in facts.values() if fact["state"] not in (b"Z", b"X", b"x")]

    def deliver(self, record, number):
        pid = record["pid"]
        if self.signaling_closed or self.records.get(pid) is not record or pid == self.pid:
            raise Refused("OWNERSHIP_CLOSED")
        # WNOWAIT also retains exited identities. If this child exits after
        # proof, no reap can recycle it before this signal attempt finishes.
        if self.wait_child(pid) is not None:
            return
        try:
            os.kill(pid, number)
        except ProcessLookupError:
            if self.wait_child(pid) is None:
                raise Refused("SIGNAL_UNAVAILABLE")
        except OSError:
            raise Refused("SIGNAL_UNAVAILABLE")

    def close(self):
        # Unknown cleanup never releases identities before a possible signal.
        self.signaling_closed = True
        self.records.clear()


def tty_signal_ioctl():
    if hasattr(termios, "TIOCSIG"):
        return termios.TIOCSIG
    if os.uname().machine in ("x86_64", "aarch64", "arm64"):
        return 0x40045436  # Linux asm-generic _IOW('T', 0x36, int)
    raise Refused("SIGNAL_UNAVAILABLE")


def copy_fd(descriptor):
    return fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 16)


class Carrier:
    def __init__(self, launch, env, initial):
        self.spec = launch
        self.env = env
        self.input_buffer = bytearray(initial)
        self.selector = selectors.DefaultSelector()
        self.tree = OwnedTree()
        self.channels = {}
        self.output = collections.deque()
        self.output_bytes = 0
        self.host_live = True
        self.host_input = True
        self.ready = False
        self.startup = bytearray()
        self.pre_ready = []
        self.pre_ready_bytes = 0
        self.cleanup_at = None
        self.cleanup_limit = None
        self.cleanup_unknown = False
        self.quiet = False
        self.fatal_code = None
        self.terminate_ids = []
        self.request_ids = set()
        self.outcome_sent = False
        self.quiescent_sent = False
        self.stop_requested = False
        self.terminal_device = None
        os.set_blocking(0, False)
        os.set_blocking(1, False)

    def emit(self, frame):
        if not self.host_live:
            return
        data = (json.dumps(frame, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        if len(data) > MAX_LINE or self.output_bytes + len(data) > MAX_QUEUE:
            raise Refused("OUTPUT_LIMIT")
        self.output.append(memoryview(data))
        self.output_bytes += len(data)

    def add_channel(self, descriptor, read_kind=None, sink=None):
        os.set_blocking(descriptor, False)
        self.channels[descriptor] = {"kind": read_kind, "sink": sink, "queue": collections.deque(),
                                     "bytes": 0, "read": read_kind is not None, "end": False,
                                     "write_closed": sink is None, "progress_at": None}

    def launch(self):
        self.startup_limit = time.monotonic() + 5
        program = resolve(self.spec["argv"][0])
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        control_parent = control_child = None
        if self.spec["control"]:
            control_parent, control_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        master = slave = None
        if self.spec["kind"] == "terminal":
            try:
                master, slave = os.openpty()
                fcntl.ioctl(slave, termios.TIOCSWINSZ,
                            struct.pack("HHHH", self.spec["rows"], self.spec["cols"], 0, 0))
                self.terminal_device = os.fstat(slave).st_rdev & 0xffffffff
            except OSError:
                for descriptor in (master, slave, status_read, status_write):
                    if descriptor is not None:
                        os.close(descriptor)
                raise Refused("PTY_UNAVAILABLE")
            child_in = child_out = child_err = slave
            parent_in = parent_out = master
            parent_err = None
        else:
            parent_out, child_out = os.pipe2(os.O_CLOEXEC)
            parent_err, child_err = os.pipe2(os.O_CLOEXEC)
            if self.spec["stdin"] == "pipe":
                child_in, parent_in = os.pipe2(os.O_CLOEXEC)
            else:
                child_in = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                parent_in = None
        try:
            pid = os.fork()
        except OSError:
            for descriptor in set((status_read, status_write, child_in, child_out, child_err,
                                   parent_in, parent_out, parent_err)) - {None}:
                os.close(descriptor)
            if control_parent is not None:
                control_parent.close()
                control_child.close()
            raise Refused("STARTUP_UNAVAILABLE")
        if pid == 0:
            error_fd = None
            try:
                error_fd = copy_fd(status_write)
                copies = [copy_fd(child_in), copy_fd(child_out), copy_fd(child_err)]
                control_copy = copy_fd(control_child.fileno()) if control_child is not None else None
                os.setsid()
                # A killed carrier cannot leave its direct command running. This
                # is an extra fence, not a claim about escaped descendants.
                if self.tree.libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != self.tree.pid:
                    raise Refused("STARTUP_UNAVAILABLE")
                for destination, source in enumerate(copies):
                    os.dup2(source, destination, inheritable=True)
                if slave is not None:
                    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                    os.tcsetpgrp(0, os.getpgrp())
                if control_copy is not None:
                    os.dup2(control_copy, 7, inheritable=True)
                keep = {0, 1, 2, error_fd} | ({7} if control_copy is not None else set())
                for entry in os.listdir("/proc/self/fd"):
                    if entry.isdigit() and int(entry) not in keep:
                        try:
                            os.close(int(entry))
                        except OSError:
                            pass
                os.chdir("/sandbox")
                os.umask(0o077)
                for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ", "SIGINT", "SIGTERM", "SIGHUP"):
                    if hasattr(signal, name):
                        signal.signal(getattr(signal, name), signal.SIG_DFL)
                if hasattr(signal, "pthread_sigmask"):
                    signal.pthread_sigmask(signal.SIG_SETMASK, [])
                os.execve(program, [program, *self.spec["argv"][1:]], self.env)
            except BaseException:
                try:
                    os.write(error_fd if error_fd is not None else status_write, b"STARTUP_UNAVAILABLE")
                except OSError:
                    pass
                os._exit(127)
        root_refused = None
        try:
            self.tree.set_root(pid)
        except Refused as error:
            root_refused = error
        for descriptor in set((status_write, child_in, child_out, child_err)):
            os.close(descriptor)
        if control_child is not None:
            control_child.close()
            control_fd = control_parent.detach()
            self.add_channel(control_fd, "control", "control")
        if master is not None:
            self.add_channel(master, "output", "stdin")
        else:
            self.add_channel(parent_out, "stdout")
            self.add_channel(parent_err, "stderr")
            if parent_in is not None:
                self.add_channel(parent_in, sink="stdin")
        self.add_channel(status_read, "status")
        if root_refused is not None:
            raise root_refused

    def fail(self, code):
        if self.fatal_code is None:
            self.fatal_code = code
            try:
                self.emit({"type": "error", "error": code})
            except Refused:
                self.host_live = False
                self.output.clear()
                self.output_bytes = 0
        self.begin_cleanup()

    def begin_cleanup(self):
        if self.cleanup_at is None:
            self.cleanup_at = time.monotonic()
            self.cleanup_limit = self.cleanup_at + self.spec["grace_ms"] / 1000 + 5
        for channel in self.channels.values():
            if channel["sink"] is not None:
                channel["queue"].clear()
                channel["bytes"] = 0
                channel["end"] = True
                channel["progress_at"] = None

    def close_channel(self, descriptor):
        try:
            self.selector.unregister(descriptor)
        except KeyError:
            pass
        self.channels.pop(descriptor, None)
        os.close(descriptor)

    def end_sink(self, descriptor, channel):
        if not channel["end"] or channel["queue"] or channel["write_closed"]:
            return
        if channel["sink"] == "control":
            endpoint = socket.socket(fileno=descriptor)
            try:
                endpoint.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            finally:
                endpoint.detach()
            channel["write_closed"] = True
        elif channel["kind"] is None:
            self.close_channel(descriptor)
        else:
            # PTY has no independent write EOF. Closing it also stops output;
            # stdin-end is therefore refused for terminals in frame().
            channel["write_closed"] = True

    def enqueue(self, kind, data):
        selected = [(fd, channel) for fd, channel in self.channels.items() if channel["sink"] == kind]
        if len(selected) != 1 or self.cleanup_at is not None:
            raise Refused("CHANNEL_CLOSED")
        _, channel = selected[0]
        if channel["end"] or channel["write_closed"]:
            raise Refused("CHANNEL_CLOSED")
        if channel["bytes"] + len(data) > MAX_QUEUE:
            raise Refused("INPUT_LIMIT")
        if data:
            if not channel["bytes"]:
                channel["progress_at"] = time.monotonic()
            channel["queue"].append(memoryview(data))
            channel["bytes"] += len(data)

    def foreground(self):
        if self.spec["kind"] != "terminal" or self.cleanup_at is not None:
            return None
        master = next((fd for fd, channel in self.channels.items() if channel["kind"] == "output"), None)
        if master is None:
            return None
        try:
            group = os.tcgetpgrp(master)
            if group <= 0:
                return None
        except OSError:
            return None
        facts = self.tree.observations()
        if self.tree.root_status is not None:
            return None
        members = [record for record in facts if record["group"] == group and
                   record["session"] == self.tree.root]
        if not members:
            return None
        waiting = any(self.stdin_waiting(record) for record in members)
        return {"processGroupId": group, "inputWaiting": waiting}

    def signal_foreground(self, name):
        foreground = self.foreground()
        if foreground is None:
            raise Refused("FOREGROUND_UNAVAILABLE")
        group = foreground["processGroupId"]
        descriptor = next((fd for fd, channel in self.channels.items() if channel["kind"] == "output"), None)
        if descriptor is None or os.tcgetpgrp(descriptor) != group:
            raise Refused("FOREGROUND_CHANGED")
        if name in ("SIGINT", "SIGTSTP"):
            # Linux pty_signal selects the slave's current foreground group
            # using its kernel pid reference, never a reusable numeric PGID.
            # The returned group is the preceding driver observation, not an
            # atomic certificate of which group the ioctl selected.
            fcntl.ioctl(descriptor, tty_signal_ioctl(), SIGNALS[name])
            return group
        facts = [fact for fact in self.tree.observations() if fact["group"] == group and
                 fact["session"] == self.tree.root]
        if not facts:
            raise Refused("FOREGROUND_UNAVAILABLE")
        selected = []
        for fact in facts:
            record = self.tree.records.get(fact["pid"])
            if record is None or fact["parent"] != self.tree.pid or \
                    record["started"] != fact["started"] or self.tree.wait_child(record["pid"]) is not None:
                raise Refused("FOREGROUND_SIGNAL_UNAVAILABLE")
            selected.append(record)
        if os.tcgetpgrp(descriptor) != group:
            raise Refused("FOREGROUND_CHANGED")
        for record in selected:
            self.tree.deliver(record, SIGNALS[name])
        return group

    def stdin_waiting(self, record):
        # Prove a blocked read/readv on this PTY. Denied syscall inspection,
        # poll/select or an unsupported architecture supplies no positive fact.
        machine = os.uname().machine
        reads = {"x86_64": {0, 19}, "aarch64": {63, 65}, "arm64": {63, 65}}.get(machine, set())
        if not reads:
            return False
        pid = record["pid"]
        try:
            threads = os.listdir("/proc/%d/task" % pid)
            if len(threads) > MAX_THREADS:
                return False
            for thread in threads:
                if not thread.isdigit():
                    continue
                prefix = "/proc/%d/task/%s" % (pid, thread)
                try:
                    fd_stat = os.stat(prefix + "/fd/0")
                    if not stat.S_ISCHR(fd_stat.st_mode) or fd_stat.st_rdev & 0xffffffff != self.terminal_device:
                        continue
                    with open(prefix + "/syscall", "rb") as stream:
                        fields = stream.read(512).split()
                    if len(fields) >= 2 and int(fields[0]) in reads and int(fields[1], 16) == 0:
                        return True
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
        return False

    def request(self, frame):
        if not exact(frame, {"type", "id", "op", "args"}) or \
                not integer(frame["id"], 1, 2**53 - 1) or frame["id"] in self.request_ids or \
                frame["op"] not in ("resize", "foreground", "signal", "terminate") or \
                type(frame["args"]) is not dict:
            raise Refused("PROTOCOL")
        request_id = frame["id"]
        if len(self.request_ids) >= 65536:
            raise Refused("REQUEST_LIMIT")
        self.request_ids.add(request_id)
        op, args = frame["op"], frame["args"]
        try:
            if op == "terminate":
                if args or len(self.terminate_ids) >= 32:
                    raise Refused("PROTOCOL")
                self.terminate_ids.append(request_id)
                self.begin_cleanup()
                return
            if not self.ready or self.cleanup_at is not None:
                raise Refused("EXECUTION_CLOSED")
            if op == "foreground":
                if args:
                    raise Refused("PROTOCOL")
                result = self.foreground()
            elif op == "resize":
                if not exact(args, {"cols", "rows"}) or not integer(args["cols"], 1, 1000) or \
                        not integer(args["rows"], 1, 1000):
                    raise Refused("PROTOCOL")
                descriptor = next((fd for fd, channel in self.channels.items() if channel["kind"] == "output"), None)
                if descriptor is None:
                    raise Refused("PTY_UNAVAILABLE")
                fcntl.ioctl(descriptor, termios.TIOCSWINSZ,
                            struct.pack("HHHH", args["rows"], args["cols"], 0, 0))
                result = None
            else:
                if not exact(args, {"signal"}) or not isinstance(args["signal"], str) or args["signal"] not in SIGNALS:
                    raise Refused("PROTOCOL")
                result = self.signal_foreground(args["signal"])
            self.emit({"type": "reply", "id": request_id, "result": result})
        except Refused as error:
            self.emit({"type": "reply", "id": request_id, "error": error.code})
        except OSError:
            self.emit({"type": "reply", "id": request_id, "error": "GUEST_OPERATION_UNAVAILABLE"})

    def frame(self, frame):
        kind = frame.get("type")
        if kind in ("stdin", "control"):
            if not exact(frame, {"type", "data"}) or not isinstance(frame["data"], str):
                raise Refused("PROTOCOL")
            try:
                data = base64.b64decode(frame["data"].encode("ascii"), validate=True)
            except (ValueError, UnicodeError):
                raise Refused("PROTOCOL")
            self.enqueue(kind, data)
        elif kind in ("stdin-end", "control-end"):
            if not exact(frame, {"type"}) or (kind == "stdin-end" and self.spec["kind"] == "terminal"):
                raise Refused("PROTOCOL")
            sink = "stdin" if kind == "stdin-end" else "control"
            channels = [channel for channel in self.channels.values() if channel["sink"] == sink]
            if len(channels) != 1 or channels[0]["end"]:
                raise Refused("CHANNEL_CLOSED")
            channels[0]["end"] = True
        elif kind == "request":
            self.request(frame)
        else:
            raise Refused("PROTOCOL")

    def consume_input(self):
        for _ in range(64):
            end = self.input_buffer.find(b"\n")
            if end < 0:
                if len(self.input_buffer) > MAX_LINE:
                    raise Refused("PROTOCOL")
                return
            if end + 1 > MAX_LINE:
                raise Refused("PROTOCOL")
            line = bytes(self.input_buffer[:end])
            del self.input_buffer[:end + 1]
            self.frame(parse(line))

    def read_channel(self, descriptor, channel):
        try:
            data = os.read(descriptor, CHUNK)
        except BlockingIOError:
            return
        except OSError as error:
            if channel["kind"] == "output" and error.errno == errno.EIO:
                data = b""  # A Linux PTY reports EIO after its last slave closes.
            else:
                raise Refused("STREAM_UNAVAILABLE")
        kind = channel["kind"]
        if not data:
            channel["read"] = False
            if kind == "status":
                self.close_channel(descriptor)
                if self.startup:
                    raise Refused("STARTUP_UNAVAILABLE")
                self.ready = True
                self.emit({"type": "ready", "pid": self.tree.root})
                for frame in self.pre_ready:
                    self.emit(frame)
                self.pre_ready.clear()
                self.pre_ready_bytes = 0
            elif kind == "control":
                if self.ready:
                    self.emit({"type": "control-end"})
                else:
                    self.pre_ready.append({"type": "control-end"})
                if channel["write_closed"]:
                    self.close_channel(descriptor)
            else:
                self.close_channel(descriptor)
            return
        if kind == "status":
            self.startup.extend(data)
            if len(self.startup) > 256:
                raise Refused("STARTUP_UNAVAILABLE")
            return
        frame = {"type": kind, "data": base64.b64encode(data).decode("ascii")}
        if self.ready:
            self.emit(frame)
        else:
            self.pre_ready_bytes += len(data)
            if self.pre_ready_bytes > HIGH_WATER:
                raise Refused("OUTPUT_LIMIT")
            self.pre_ready.append(frame)

    def write_channel(self, descriptor, channel):
        if not channel["queue"]:
            return
        try:
            count = os.write(descriptor, channel["queue"][0])
        except BlockingIOError:
            return
        except OSError:
            raise Refused("CHANNEL_CLOSED")
        if count <= 0:
            raise Refused("CHANNEL_CLOSED")
        channel["progress_at"] = time.monotonic()
        chunk = channel["queue"].popleft()
        channel["bytes"] -= count
        if count < len(chunk):
            channel["queue"].appendleft(chunk[count:])

    def check_input_stall(self):
        # Input backpressure can put terminate/EOF behind queued data. An
        # unreading child must not prevent the guest from starting cleanup.
        now = time.monotonic()
        for channel in self.channels.values():
            if channel["sink"] is not None and channel["bytes"] >= HIGH_WATER and \
                    channel["progress_at"] is not None and \
                    now - channel["progress_at"] >= INPUT_STALL_SECONDS:
                raise Refused("INPUT_STALLED")

    def refresh_selector(self):
        wanted = {}
        sinks_ready = all(channel["bytes"] < HIGH_WATER for channel in self.channels.values()
                          if channel["sink"] is not None)
        if self.host_input and sinks_ready and self.fatal_code is None and not self.quiescent_sent:
            wanted[0] = selectors.EVENT_READ
        if self.host_live and self.output:
            wanted[1] = selectors.EVENT_WRITE
        for descriptor, channel in list(self.channels.items()):
            self.end_sink(descriptor, channel)
            if descriptor not in self.channels:
                continue
            flags = 0
            if channel["read"] and (channel["kind"] == "status" or self.output_bytes < HIGH_WATER):
                flags |= selectors.EVENT_READ
            if channel["queue"] and not channel["write_closed"]:
                flags |= selectors.EVENT_WRITE
            if flags:
                wanted[descriptor] = flags
        for descriptor in list(self.selector.get_map()):
            if descriptor not in wanted:
                self.selector.unregister(descriptor)
        for descriptor, flags in wanted.items():
            try:
                self.selector.modify(descriptor, flags)
            except KeyError:
                self.selector.register(descriptor, flags)

    def cleanup_step(self):
        now = time.monotonic()
        try:
            live, quiet = self.tree.census()
            if self.tree.root_status is not None and self.cleanup_at is None:
                self.begin_cleanup()
            if self.cleanup_at is None:
                return
            number = signal.SIGKILL if now >= self.cleanup_at + self.spec["grace_ms"] / 1000 else signal.SIGTERM
            for record in live:
                if number == signal.SIGKILL or not record["term_sent"]:
                    self.tree.deliver(record, number)
                    record["term_sent"] = True
            self.quiet = quiet
        except Refused as error:
            self.cleanup_unknown = True
            self.fail(error.code)
            # Even after observation failure, signal retained exact identities.
            for record in list(self.tree.records.values()):
                try:
                    self.tree.deliver(record, signal.SIGKILL)
                except Refused:
                    pass
        if self.cleanup_limit is not None and now >= self.cleanup_limit and not self.quiet:
            self.cleanup_unknown = True
            self.fail("CLEANUP_UNKNOWN")

    def finish_if_drained(self):
        if not self.quiet or self.cleanup_unknown:
            return False
        # All owned processes are dead. Their stdout/err/PTY must still reach EOF.
        readable = [channel for channel in self.channels.values() if channel["read"]]
        if readable:
            if time.monotonic() >= self.cleanup_limit:
                self.cleanup_unknown = True
                self.fail("DRAIN_UNKNOWN")
            return False
        if not self.quiescent_sent:
            for request_id in self.terminate_ids:
                self.emit({"type": "reply", "id": request_id, "result": None})
            self.terminate_ids.clear()
            status_value = self.tree.root_status
            if self.ready and status_value is not None:
                if os.WIFEXITED(status_value):
                    outcome = {"exitCode": os.WEXITSTATUS(status_value), "signal": None}
                elif os.WIFSIGNALED(status_value):
                    number = os.WTERMSIG(status_value)
                    try:
                        name = signal.Signals(number).name
                    except ValueError:
                        name = None
                    outcome = {"exitCode": None, "signal": name}
                else:
                    raise Refused("OUTCOME_UNKNOWN")
                self.emit({"type": "outcome", **outcome})
            self.emit({"type": "quiescent"})
            self.quiescent_sent = True
        return not self.output

    def run(self):
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, lambda _number, _frame: setattr(self, "stop_requested", True))
        try:
            try:
                self.launch()
            except Refused as error:
                self.fail(error.code)
            except OSError:
                self.fail("STARTUP_UNAVAILABLE")
            while True:
                if self.stop_requested:
                    self.begin_cleanup()
                if self.fatal_code is None:
                    try:
                        self.check_input_stall()
                        self.consume_input()
                        if not self.ready and time.monotonic() >= self.startup_limit:
                            raise Refused("STARTUP_UNAVAILABLE")
                    except Refused as error:
                        self.fail(error.code)
                self.cleanup_step()
                try:
                    if self.finish_if_drained():
                        return 0 if self.fatal_code is None else 1
                except Refused as error:
                    self.fail(error.code)
                if self.cleanup_unknown and self.cleanup_limit is not None and \
                        time.monotonic() >= self.cleanup_limit and not self.output:
                    # No quiescent frame is sent on an unknown range or drain.
                    return 1
                if self.cleanup_limit is not None and time.monotonic() >= self.cleanup_limit and self.output:
                    # The command range may be empty but an unreading host
                    # cannot keep a guest carrier alive without a bound.
                    self.output.clear()
                    self.output_bytes = 0
                    return 1
                self.refresh_selector()
                for key, events in self.selector.select(0.05):
                    descriptor = key.fd
                    try:
                        if descriptor == 0:
                            data = os.read(0, CHUNK)
                            if data:
                                self.input_buffer.extend(data)
                                if len(self.input_buffer) > MAX_LINE + CHUNK:
                                    raise Refused("PROTOCOL")
                            else:
                                self.host_input = False
                                self.begin_cleanup()
                        elif descriptor == 1:
                            try:
                                count = os.write(1, self.output[0])
                                chunk = self.output.popleft()
                                self.output_bytes -= count
                                if count < len(chunk):
                                    self.output.appendleft(chunk[count:])
                            except BlockingIOError:
                                pass
                            except OSError:
                                self.host_live = False
                                self.host_input = False
                                self.output.clear()
                                self.output_bytes = 0
                                self.begin_cleanup()
                        else:
                            channel = self.channels.get(descriptor)
                            if channel is not None and events & selectors.EVENT_READ:
                                self.read_channel(descriptor, channel)
                            channel = self.channels.get(descriptor)
                            if channel is not None and events & selectors.EVENT_WRITE:
                                self.write_channel(descriptor, channel)
                    except BlockingIOError:
                        pass
                    except Refused as error:
                        self.fail(error.code)
        finally:
            for descriptor in list(self.channels):
                self.close_channel(descriptor)
            self.tree.close()
            self.selector.close()


def first_line():
    buffer = bytearray()
    while True:
        end = buffer.find(b"\n")
        if end >= 0:
            if end + 1 > MAX_LINE:
                raise Refused("PROTOCOL")
            return parse(bytes(buffer[:end])), bytes(buffer[end + 1:])
        if len(buffer) > MAX_LINE:
            raise Refused("PROTOCOL")
        data = os.read(0, CHUNK)
        if not data:
            raise Refused("PROTOCOL")
        buffer.extend(data)


def main():
    if sys.platform != "linux":
        raise Refused("GUEST_UNAVAILABLE")
    launch, env = launch_spec(first_line_result[0])
    if launch["kind"] == "lookup":
        if first_line_result[1]:
            raise Refused("PROTOCOL")
        path = resolve(launch["argv"][0])
        os.write(1, (json.dumps({"type": "resolved", "path": path}, separators=(",", ":")) + "\n" +
                     '{"type":"quiescent"}\n').encode("utf-8"))
        return 0
    return Carrier(launch, env, first_line_result[1]).run()


if __name__ == "__main__":
    try:
        if sys.platform != "linux":
            raise Refused("GUEST_UNAVAILABLE")
        first_line_result = first_line()
        status_code = main()
    except Refused as error:
        try:
            os.write(1, (json.dumps({"type": "error", "error": error.code}, separators=(",", ":")) + "\n").encode("ascii"))
        except OSError:
            pass
        status_code = 1
    except BaseException:
        try:
            os.write(1, b'{"type":"error","error":"GUEST_UNAVAILABLE"}\n')
        except OSError:
            pass
        status_code = 1
    sys.exit(status_code)
