#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Close inherited capabilities in a fresh, single-threaded trusted launcher.

Only deliberately connected stdin/stdout/stderr cross this host boundary.
There is no caller-selected descriptor allowlist or skip marker. The host
JSONL transport does not use FD7; its guest carrier constructs a new control
endpoint later, when the admitted workload requests one.

Linux uses a physical close_range, including descriptors above RLIMIT_NOFILE.
The Darwin branch supports disposable local source fixtures; it does not
qualify the installed Linux/OpenShell path. Unsupported closure refuses exec.
"""

import ctypes
import errno
import os
import sys


def _linux_close_nonstdio():
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        close_range = libc.close_range
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "descriptor closure unavailable") from error
    close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
    close_range.restype = ctypes.c_int
    if close_range(3, 0xffffffff, 0) != 0:
        raise OSError(ctypes.get_errno(), "descriptor closure failed")


def _darwin_close_nonstdio():
    # This runs before exec in a fresh process: no concurrent descriptor
    # opener exists. listdir closes its own transient directory descriptor.
    descriptors = os.listdir("/dev/fd")
    for name in descriptors:
        if not name.isdecimal():
            raise OSError(errno.EIO, "descriptor enumeration unavailable")
        descriptor = int(name)
        if descriptor <= 2:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def close_nonstdio():
    """Retain only 0, 1 and 2. A closure failure never authorizes exec."""
    if sys.platform == "linux":
        _linux_close_nonstdio()
    elif sys.platform == "darwin":
        _darwin_close_nonstdio()
    else:
        raise OSError(errno.ENOSYS, "descriptor closure unavailable")


def exec_argv(argv):
    """For a trusted caller's fixed target, preserve PID and factual errors."""
    if type(argv) is not list or not argv or \
            any(type(argument) is not str or "\0" in argument for argument in argv) or \
            not os.path.isabs(argv[0]):
        raise ValueError("invalid trusted exec arguments")
    close_nonstdio()
    os.execve(argv[0], argv, dict(os.environ))


def main():
    try:
        # Trusted entrypoints supply the first token before caller arguments.
        # Both routes always close the same descriptors; neither offers a skip
        # marker, executable selector, or caller-selected extra-FD exception.
        if len(sys.argv) < 2:
            raise ValueError("missing trusted route")
        if sys.argv[1] == "wrapper":
            argv = [
                "/bin/bash",
                "-p",
                "/usr/local/lib/aukora-boundary/openshell/custody/sbx_exec_body.sh",
                *sys.argv[2:],
            ]
        elif sys.argv[1] == "openshell":
            argv = ["/usr/bin/openshell", *sys.argv[2:]]
        else:
            raise ValueError("unsupported trusted route")
        exec_argv(argv)
    except (OSError, ValueError):
        os.write(2, b"aukora-openshell-confinement: descriptor-launch-unavailable\n")
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
