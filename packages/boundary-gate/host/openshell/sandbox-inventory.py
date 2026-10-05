# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exact deployment-profile validation and bounded read-only admission.

Import is effect-free. The fixed host CLI obtains fresh observations; it never
installs a profile or launches a guest command. Explicit generation only emits
an operator proposal from protected invariants. Missing custody/evidence refuses.
"""

import errno
import fcntl
import hashlib
import json
import math
import posixpath
import re
import os
import pwd
import selectors
import stat
import subprocess
import sys
import time
import unicodedata


READ_ONLY = frozenset(("/bin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev/urandom"))
READ_WRITE = frozenset(("/sandbox", "/tmp", "/dev/null", "/dev/pts", "/dev/ptmx"))
UINT32_MAX = (1 << 32) - 1
ADDRESS_SPACE = 1 << 32
SAFE_INTEGER_MAX = (1 << 53) - 1
APPROVED_HOST_RANGE = {"host_id": 165536, "size": 65536}
PROFILE_KEYS = frozenset(("version", "expected_mounts", "expected_supervisor_mounts", "expected_workload_config", "expected_supervisor_config", "workload_binary_digest", "uid_ranges", "gid_ranges", "forbidden_host_ids"))
CONFIG_KEYS = frozenset(("Tmpfs", "Devices", "IpcMode", "PidMode", "ReadonlyRootfs"))
GENERATION_SCHEMA_KEYS = frozenset(("version", "expected_workload_config", "expected_supervisor_config", "workload_mount_constraints", "supervisor_mount_constraints", "uid_ranges", "gid_ranges", "forbidden_host_ids"))
PROCESS_KEYS = frozenset(("pid", "start_time", "uid", "uid_map", "gid_map", "cap_eff", "cap_prm", "cap_bnd", "no_new_privs", "seccomp"))
MOUNT_KEYS = frozenset(("Type", "Name", "Source", "Destination", "Driver", "Mode", "Options", "RW", "Propagation"))
MOUNT_REQUIRED = frozenset(("Type", "Source", "Destination", "RW"))
MOUNT_ROLES = {
    "/sandbox": ("bind", True),
    "/sandbox/.git": ("bind", False),
    "/sandbox/prime-main": ("bind", False),
    "/.openshell/channel": ("volume", True),
    "/opt/openshell/bin/openshell-sandbox": ("bind", False),
}
SUPERVISOR_MOUNT_ROLES = {"/.openshell/channel": ("volume", False)}
MOUNTINFO_KEYS = frozenset(("mount_id", "parent_id", "device", "root", "mountpoint", "options", "optional", "filesystem", "source", "super_options"))
WORKSPACE_BINDING_KEYS = frozenset(("workspace_source", "git_source", "workspace_device", "workspace_inode", "git_device", "git_inode", "mount_namespace"))
# Proposed required infrastructure shapes, not a qualified runtime baseline.
# A new mountpoint/filesystem or unproven origin must refuse qualification.
INFRASTRUCTURE_MOUNTS = {
    "/proc": ("proc", True),
    "/dev": ("tmpfs", False),
    "/dev/pts": ("devpts", True),
    "/dev/shm": ("tmpfs", False),
    "/dev/mqueue": ("mqueue", True),
    "/dev/null": ("devtmpfs", True),
    "/dev/zero": ("devtmpfs", True),
    "/dev/full": ("devtmpfs", True),
    "/dev/tty": ("devtmpfs", True),
    "/dev/random": ("devtmpfs", True),
    "/dev/urandom": ("devtmpfs", True),
    "/sys": ("sysfs", False),
    "/sys/fs/cgroup": ("cgroup2", False),
    "/proc/bus": ("proc", False),
    "/proc/fs": ("proc", False),
    "/proc/irq": ("proc", False),
    "/proc/sys": ("proc", False),
    "/proc/sysrq-trigger": ("proc", False),
    "/proc/acpi": ("tmpfs", False),
    "/proc/scsi": ("tmpfs", False),
    "/proc/kcore": ("devtmpfs", False),
    "/proc/keys": ("devtmpfs", False),
    "/proc/latency_stats": ("devtmpfs", False),
    "/proc/timer_list": ("devtmpfs", False),
    "/proc/sched_debug": ("devtmpfs", False),
    "/sys/firmware": ("tmpfs", False),
    "/sys/devices/virtual/powercap": ("tmpfs", False),
    "/sys/dev/block": ("tmpfs", False),
    "/etc/hostname": ("tmpfs", False),
    "/etc/hosts": ("tmpfs", False),
    "/etc/resolv.conf": ("ext4", False),
    "/run/secrets": ("tmpfs", False),
    "/run/.containerenv": ("tmpfs", False),
}


def _fail(message):
    raise ValueError("sandbox inventory: " + message)


def _object(value, keys=None, required=None):
    if type(value) is not dict or any(type(key) is not str for key in value):
        _fail("object required")
    if keys is not None and not set(value) <= keys:
        _fail("unknown object field")
    if required is not None and not required <= set(value):
        _fail("missing object field")
    return value


def _text(value, nonempty=False):
    if type(value) is not str or "\0" in value or (nonempty and not value):
        _fail("invalid text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError:
        _fail("invalid text encoding")
    return value


def _uint(value, positive=False):
    if type(value) is not int or value < (1 if positive else 0) or value > UINT32_MAX:
        _fail("invalid unsigned integer")
    return value


def _start_time(value):
    if type(value) is not int or value < 1 or value > SAFE_INTEGER_MAX:
        _fail("invalid process start time")
    return value


def _path(value):
    _text(value, True)
    if not value.startswith("/") or value.startswith("//") or posixpath.normpath(value) != value:
        _fail("path must be a normalized absolute path")
    return value


def _digest(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        _fail("SHA256 digest required")
    return value


def _canonical_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8", "strict")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            _fail("duplicate JSON key")
        out[key] = value
    return out


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        _fail("nonfinite JSON number")
    return value


def _constant(_):
    _fail("nonfinite JSON number")


def _json_text(value):
    if type(value) is str:
        _text(value)
    elif type(value) is list:
        for item in value:
            _json_text(item)
    elif type(value) is dict:
        for key, item in value.items():
            _text(key)
            _json_text(item)


def strict_json(text):
    """Parse JSON without duplicate keys, nonfinite numbers or invalid UTF-8 text."""
    _text(text)
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=_float, parse_constant=_constant)
        _json_text(value)
        return value
    except (RecursionError, OverflowError) as error:
        raise ValueError("sandbox inventory: invalid JSON nesting or number") from error


# The explicit API name used by the host producer; the snake-case name is also
# available to ordinary Python callers.
strictJSON = strict_json


def _exact_path_set(value, expected):
    if type(value) is not list or len(value) != len(expected):
        _fail("filesystem inventory length mismatch")
    for path in value:
        _path(path)
    if len(set(value)) != len(value) or set(value) != expected:
        _fail("filesystem inventory mismatch")


def validate_policy(policy):
    """Require the exact supported startup filesystem/network policy."""
    _object(policy,
            frozenset(("version", "filesystem_policy", "landlock", "process", "network_policies", "network_middlewares")),
            frozenset(("version", "filesystem_policy", "landlock", "network_policies")))
    if type(policy["version"]) is not int or policy["version"] != 1:
        _fail("unsupported policy version")
    filesystem = _object(policy["filesystem_policy"],
                         frozenset(("include_workdir", "read_only", "read_write")),
                         frozenset(("include_workdir", "read_only", "read_write")))
    if filesystem["include_workdir"] is not False:
        _fail("implicit workdir grant")
    _exact_path_set(filesystem["read_only"], READ_ONLY)
    _exact_path_set(filesystem["read_write"], READ_WRITE)
    landlock = _object(policy["landlock"], frozenset(("compatibility",)), frozenset(("compatibility",)))
    if landlock["compatibility"] != "hard_requirement":
        _fail("Landlock hard requirement missing")
    if _object(policy["network_policies"]) or _object(policy.get("network_middlewares", {})):
        _fail("network policy must be empty")
    if "process" in policy:
        process = _object(policy["process"], frozenset(("run_as_user", "run_as_group")),
                          frozenset(("run_as_user", "run_as_group")))
        _text(process["run_as_user"], True)
        _text(process["run_as_group"], True)


def _overlaps(intervals):
    ordered = sorted(intervals)
    if any(right[0] < left[1] for left, right in zip(ordered, ordered[1:])):
        _fail("overlapping identity intervals")


def _ranges(value):
    if type(value) is not list or not value or len(value) > 256:
        _fail("subordinate identity ranges required")
    intervals = []
    for row in value:
        _object(row, frozenset(("host_id", "size")), frozenset(("host_id", "size")))
        start, size = _uint(row["host_id"], True), _uint(row["size"], True)
        end = start + size
        if end > ADDRESS_SPACE:
            _fail("identity interval overflow")
        intervals.append((start, end))
    _overlaps(intervals)
    return intervals


def _maps(value, ranges=None, forbidden=(), host_root=False):
    if type(value) is not list or not value or len(value) > 256:
        _fail("identity map required")
    container_intervals, host_intervals, out = [], [], []
    for row in value:
        _object(row, frozenset(("container_id", "host_id", "size")),
                frozenset(("container_id", "host_id", "size")))
        container_id = _uint(row["container_id"])
        host_id, size = _uint(row["host_id"], not host_root), _uint(row["size"], True)
        container_end, host_end = container_id + size, host_id + size
        if container_end > ADDRESS_SPACE or host_end > ADDRESS_SPACE:
            _fail("identity map overflow")
        if ranges is not None and not any(start <= host_id and host_end <= end for start, end in ranges):
            _fail("identity map exceeds declared subordinate range")
        if any(host_id <= identity < host_end for identity in forbidden):
            _fail("identity map includes a forbidden host identity")
        container_intervals.append((container_id, container_end))
        host_intervals.append((host_id, host_end))
        out.append(dict(row))
    _overlaps(container_intervals)
    _overlaps(host_intervals)
    if not any(start == 0 for start, _ in container_intervals):
        _fail("container root identity is not mapped")
    return out, host_intervals


def _mounts(value, roles=MOUNT_ROLES):
    if type(value) is not list or len(value) != len(roles):
        _fail("mount inventory length mismatch")
    out = {}
    for row in value:
        _object(row, MOUNT_KEYS, MOUNT_REQUIRED)
        required_keys = MOUNT_KEYS if row["Type"] == "volume" else MOUNT_KEYS - {"Name"}
        if set(row) != required_keys:
            _fail("mount record key inventory mismatch")
        for key, item in row.items():
            if key == "RW":
                if type(item) is not bool:
                    _fail("mount writable flag must be boolean")
            elif key == "Options":
                if type(item) is not list or len(item) > 256:
                    _fail("mount options must be a bounded list")
                for option in item:
                    _text(option, True)
                if len(set(item)) != len(item):
                    _fail("duplicate mount option")
            else:
                _text(item)
        destination = _path(row["Destination"])
        _path(row["Source"])
        if destination in out or destination not in roles:
            _fail("duplicate or unsupported mount destination")
        kind, writable = roles[destination]
        if row["Type"] != kind or row["RW"] is not writable:
            _fail("mount role mismatch")
        out[destination] = row
    return out


def _profile(profile):
    _object(profile, PROFILE_KEYS, PROFILE_KEYS)
    if type(profile["version"]) is not int or profile["version"] != 1:
        _fail("unsupported profile version")
    forbidden = profile["forbidden_host_ids"]
    if type(forbidden) is not list or not forbidden or len(forbidden) > 256:
        _fail("forbidden host identities required")
    for identity in forbidden:
        _uint(identity)
    if forbidden != [1001]:
        _fail("forbidden host identity inventory mismatch")
    uid_ranges, gid_ranges = _ranges(profile["uid_ranges"]), _ranges(profile["gid_ranges"])
    if profile["uid_ranges"] != [APPROVED_HOST_RANGE] or profile["gid_ranges"] != [APPROVED_HOST_RANGE]:
        _fail("subordinate identity ranges differ from approved deployment")
    expected = _mounts(profile["expected_mounts"])
    if expected["/sandbox/.git"]["Source"] != expected["/sandbox"]["Source"] + "/.git":
        _fail("git source is not the direct workspace metadata directory")
    supervisor = _mounts(profile["expected_supervisor_mounts"], SUPERVISOR_MOUNT_ROLES)
    for key in ("expected_workload_config", "expected_supervisor_config"):
        _config(profile[key])
    if profile["expected_workload_config"]["ReadonlyRootfs"] is not True or "/tmp" not in profile["expected_workload_config"]["Tmpfs"]:
        _fail("workload needs a read-only image and a private tmpfs")
    channel = expected["/.openshell/channel"]
    supervisor_channel = supervisor["/.openshell/channel"]
    if set(channel) != set(supervisor_channel) or any(
            channel[key] != supervisor_channel[key] for key in channel if key not in ("RW", "Mode")):
        _fail("supervisor channel differs from workload channel")
    return (forbidden, uid_ranges, gid_ranges, expected, supervisor,
            _digest(profile["workload_binary_digest"]))


def _process(container, process, uid_ranges=None, gid_ranges=None, forbidden=(), host_root=False):
    _object(process, PROCESS_KEYS, PROCESS_KEYS)
    pid, start_time, uid = _uint(process["pid"], True), _start_time(process["start_time"]), _uint(process["uid"], True)
    state, host = _object(container.get("State")), _object(container.get("HostConfig"))
    if type(state.get("Pid")) is not int or state["Pid"] != pid:
        _fail("process observation is not the inspected container process")
    if host.get("Privileged") is not False:
        _fail("container privilege mismatch")
    security = host.get("SecurityOpt")
    if type(security) is not list or security not in (["no-new-privileges"], ["no-new-privileges:true"]):
        _fail("container no-new-privileges option missing")
    uid_map, host_uids = _maps(process["uid_map"], uid_ranges, forbidden, host_root)
    gid_map, _ = _maps(process["gid_map"], gid_ranges, forbidden, host_root)
    if uid in forbidden or not any(start <= uid < end for start, end in host_uids):
        _fail("live process identity is not an admitted subordinate identity")
    for key in ("cap_eff", "cap_prm", "cap_bnd"):
        if type(process[key]) is not str or process[key] != "0000000000000000":
            _fail("process capabilities are not empty")
    if type(process["no_new_privs"]) is not int or process["no_new_privs"] != 1:
        _fail("process no-new-privileges missing")
    if type(process["seccomp"]) is not int or process["seccomp"] != 2:
        _fail("process seccomp filter missing")
    return {
        "uid": uid, "uid_map": uid_map, "gid_map": gid_map,
        "cap_eff": process["cap_eff"], "cap_prm": process["cap_prm"], "cap_bnd": process["cap_bnd"],
        "no_new_privs": 1, "seccomp": 2, "process_start_time": start_time,
    }


def _readback_mounts(mounts):
    # This complete identity-bearing readback is only for the trusted internal
    # host transport. It must never be copied into public evidence or diagnostics.
    return [{key: list(value) if type(value) is list else value
             for key, value in mounts[path].items()} for path in sorted(mounts)]


def _mount_digest(mounts):
    return _canonical_digest([mounts[path] for path in sorted(mounts)])


def _decimal(value, positive=False):
    if type(value) is not str or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        _fail("canonical decimal string required")
    number = int(value)
    if number < (1 if positive else 0) or number >= 1 << 64:
        _fail("decimal identity outside supported range")
    return number


def _device(value):
    if type(value) is not str or re.fullmatch(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)", value) is None:
        _fail("kernel device identity unavailable")
    if any(int(part) > UINT32_MAX for part in value.split(":")):
        _fail("kernel device identity overflow")
    return value


def _binding(binding):
    _object(binding, WORKSPACE_BINDING_KEYS, WORKSPACE_BINDING_KEYS)
    source = _path(binding["workspace_source"])
    if source == "/" or _path(binding["git_source"]) != source + "/.git":
        _fail("workspace metadata source mismatch")
    for key in ("workspace_device", "git_device"):
        _device(binding[key])
    for key in ("workspace_inode", "git_inode"):
        _decimal(binding[key], True)
    if type(binding["mount_namespace"]) is not str or re.fullmatch(r"mnt:\[[1-9][0-9]*\]", binding["mount_namespace"]) is None:
        _fail("kernel mount namespace unavailable")
    _decimal(binding["mount_namespace"][5:-1], True)
    if (binding["workspace_device"], binding["workspace_inode"]) == (binding["git_device"], binding["git_inode"]):
        _fail("workspace and metadata directory identities alias")


def parse_mountinfo(raw):
    """Preserve kernel table order, IDs/topology and all ten mount fields."""
    _text(raw, True)
    if len(raw.encode("utf-8")) > MAX_READ_BYTES:
        _fail("kernel mount table byte limit")
    def unescape(value):
        if re.search(r"\\(?!040|011|012|134)", value):
            _fail("unsupported kernel mount escape")
        return re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)
    rows = []
    for line in raw.splitlines():
        if line.count(" - ") != 1 or len(rows) >= 512:
            _fail("kernel mount table malformed or truncated")
        left, right = line.split(" - ", 1)
        fields, tail = left.split(), right.split()
        if len(fields) < 6 or len(tail) != 3:
            _fail("kernel mount table malformed")
        rows.append({"mount_id": fields[0], "parent_id": fields[1], "device": fields[2],
                     "root": unescape(fields[3]), "mountpoint": unescape(fields[4]),
                     "options": sorted(fields[5].split(",")), "optional": sorted(fields[6:]),
                     "filesystem": tail[0], "source": unescape(tail[1]),
                     "super_options": sorted(tail[2].split(","))})
    if not rows:
        _fail("kernel mount table empty")
    return rows


def validate_mountinfo(rows, binding, mounts, *, host_tmp_device=None):
    """Refuse unknown mounts and verify effective image/git/tmp confinement."""
    _binding(binding)
    expected = _mounts(mounts)
    if (expected["/sandbox"]["Source"] != binding["workspace_source"] or
            expected["/sandbox/.git"]["Source"] != binding["git_source"]):
        _fail("kernel workspace binding differs from mount source inventory")
    if type(rows) is not list or not rows or len(rows) > 512:
        _fail("kernel mount table unavailable")
    by_path, by_id = {}, {}
    for row in rows:
        _object(row, MOUNTINFO_KEYS, MOUNTINFO_KEYS)
        mount_id, parent_id = _decimal(row["mount_id"], True), _decimal(row["parent_id"])
        if mount_id > UINT32_MAX or parent_id > UINT32_MAX or mount_id == parent_id:
            _fail("invalid kernel mount topology")
        _device(row["device"])
        _path(row["root"])
        path = _path(row["mountpoint"])
        if path in by_path or row["mount_id"] in by_id:
            _fail("duplicate kernel mount identity or mountpoint")
        for key in ("filesystem", "source"):
            _text(row[key], True)
        for key in ("options", "optional", "super_options"):
            value = row[key]
            if type(value) is not list or len(value) > 256:
                _fail("kernel mount options unavailable")
            for option in value:
                _text(option, True)
            if value != sorted(value) or len(set(value)) != len(value):
                _fail("ambiguous kernel mount option inventory")
        if len(set(row["options"]) & {"ro", "rw"}) != 1 or len(set(row["super_options"]) & {"ro", "rw"}) != 1:
            _fail("kernel mount access flags unavailable")
        by_path[path], by_id[row["mount_id"]] = row, row
    required = {"/", "/tmp", "/proc", *MOUNT_ROLES}
    if not required <= set(by_path):
        _fail("required kernel mount missing")
    root = by_path["/"]
    if root["filesystem"] not in ("overlay", "fuse.overlayfs", "fuse-overlayfs") or "ro" not in root["options"]:
        _fail("guest image root is not a supported read-only image mount")
    for row in rows:
        visited = set()
        current = row
        while current["parent_id"] in by_id:
            if current["mount_id"] in visited:
                _fail("cyclic kernel mount topology")
            visited.add(current["mount_id"])
            current = by_id[current["parent_id"]]
        if current is not root:
            _fail("kernel mount is outside the guest image hierarchy")
        path = row["mountpoint"]
        writable = "rw" in row["options"]
        if path == "/":
            continue
        ancestors = [point for point in by_path if point == "/" or path.startswith(point + "/")]
        parent = by_path[max(ancestors, key=len)]
        if row["parent_id"] != parent["mount_id"]:
            _fail("kernel parent is not the nearest visible ancestor mount")
        if path in expected:
            if writable is not expected[path]["RW"]:
                _fail("effective kernel mount access differs from Podman inventory")
            if row["optional"]:
                _fail("payload mount is not private")
            if path == "/sandbox" and row["device"] != binding["workspace_device"]:
                _fail("workspace kernel mount device mismatch")
            if path == "/sandbox/.git" and row["device"] != binding["git_device"]:
                _fail("git kernel mount device mismatch")
            continue
        if path == "/tmp":
            if not writable or row["filesystem"] != "tmpfs" or row["root"] != "/" or row["source"] != "tmpfs" or row["optional"]:
                _fail("guest temporary directory is not a private writable tmpfs")
            if host_tmp_device is None or row["device"] == _device(host_tmp_device):
                _fail("guest temporary mount aliases the host temporary filesystem")
            continue
        if path == "/run/openshell-supervisor-ca":
            if (row["filesystem"] != "tmpfs" or row["root"] != "/" or row["source"] != "tmpfs" or
                    not writable or row["optional"] or row["device"] in {
                        binding["workspace_device"], binding["git_device"], root["device"], by_path["/tmp"]["device"]} or
                    ("/dev" in by_path and row["device"] == by_path["/dev"]["device"])):
                _fail("supervisor CA mount differs from the required tmpfs shape")
            continue
        role = INFRASTRUCTURE_MOUNTS.get(path)
        if role is None or row["filesystem"] != role[0] or writable is not role[1]:
            _fail("unknown or unapproved kernel mount")
        if row["filesystem"] == "tmpfs":
            masked = path.startswith("/proc/") and role[1] is True
            # Measured on the bound sandbox (2026-10-05): podman mounts its per-container
            # userdata tmpfs subtrees at these four paths (root under the container's own
            # userdata), and /dev/shm with source "shm". Shapes pinned from observation.
            podman_userdata = (path in ("/run/secrets", "/run/.containerenv", "/etc/hostname", "/etc/hosts")
                               and row["root"].startswith("/containers/overlay-containers/")
                               and "/userdata/" in row["root"])
            if ((row["source"] != "tmpfs" and not (path == "/dev/shm" and row["source"] == "shm")) or
                    (not masked and not podman_userdata and row["root"] != "/") or
                    (masked and row["root"] != "/null") or
                    row["optional"]):
                _fail("infrastructure tmpfs identity is not an approved shape")
            if masked and ("/dev" not in by_path or row["device"] != by_path["/dev"]["device"]):
                _fail("masked proc device does not come from guest dev tmpfs")
            if not masked and not podman_userdata and row["device"] in {binding["workspace_device"], binding["git_device"]}:
                _fail("infrastructure tmpfs aliases a payload filesystem")
        if row["filesystem"] == "proc":
            expected_root = "/" if path == "/proc" else path[len("/proc"):]
            if row["source"] != "proc" or row["root"] != expected_root:
                _fail("proc subtree identity mismatch")
            if path != "/proc" and ("/proc" not in by_path or row["device"] != by_path["/proc"]["device"]):
                _fail("proc subtree differs from the proved guest proc mount")
    workspace, git = by_path["/sandbox"], by_path["/sandbox/.git"]
    if git["mount_id"] == workspace["mount_id"] or git["parent_id"] != workspace["mount_id"]:
        _fail("git is not a distinct child kernel mount")
    distinct = {binding["workspace_device"], binding["git_device"], by_path["/"]["device"]}
    if by_path["/tmp"]["device"] in distinct:
        _fail("scratch tmpfs aliases a payload filesystem")
    if "/dev" in by_path:
        device = by_path["/dev"]["device"]
        if device in distinct or device == by_path["/tmp"]["device"]:
            _fail("dev tmpfs aliases a payload/scratch filesystem")
        for path in ("/dev/shm", "/run/openshell-supervisor-ca"):
            if path in by_path and by_path[path]["device"] in distinct | {device, by_path["/tmp"]["device"]}:
                _fail("infrastructure tmpfs aliases another filesystem")


def validate_snapshot(container, process, profile, *, workload_binary_digest=None):
    """Bind workload observations to the complete protected deployment profile.

    Every mount key/value must match. Only the read-only workload-binary bind's
    source path may vary when its fresh measured content digest matches the pin.
    Identity maps admit only declared subordinate ranges and exclude every
    forbidden host identity. The complete internal readback and its digests bind
    the private observations validated here; do not publish or log that readback.
    """
    forbidden, uid_ranges, gid_ranges, expected, _, pin = _profile(profile)
    if _digest(workload_binary_digest) != pin:
        _fail("workload binary differs from deployment pin")
    _object(container)
    actual = _mounts(container.get("Mounts"))
    binary = "/opt/openshell/bin/openshell-sandbox"
    for destination, row in actual.items():
        wanted = expected[destination]
        if set(row) != set(wanted) or any(
                row[key] != wanted[key] for key in row
                if not (destination == binary and key == "Source")):
            _fail("mount inventory differs from deployment profile")
    if _object(container.get("HostConfig")).get("NetworkMode") != "none":
        _fail("workload container network must be none")
    _configuration(container, profile["expected_workload_config"])
    isolation = _process(container, process, uid_ranges, gid_ranges, forbidden)
    isolation["workload_binary_digest"] = pin
    return {
        "mount_inventory": _readback_mounts(actual),
        "inventory_digest": _mount_digest(actual),
        "profile_digest": _canonical_digest(profile),
        "isolation": isolation,
    }


def validate_supervisor(container, process, profile):
    """Require the exact read-only channel mount and unprivileged supervisor.

    The observed supervisor uses the host network and may use the host identity
    namespace. Its map structure and live identity must agree, but the workload's
    subordinate-only and forbidden-owner rules do not apply to this control plane.
    This function obtains no observations and cannot establish their freshness.
    """
    _, _, _, _, expected, _ = _profile(profile)
    _object(container)
    actual = _mounts(container.get("Mounts"), SUPERVISOR_MOUNT_ROLES)
    if actual != expected:
        _fail("supervisor mount inventory differs from deployment profile")
    if _object(container.get("HostConfig")).get("NetworkMode") != "host":
        _fail("supervisor container network must match the host profile")
    _configuration(container, profile["expected_supervisor_config"])
    isolation = _process(container, process, host_root=True)
    return {
        "supervisor_inventory": _readback_mounts(actual),
        "supervisor_inventory_digest": _mount_digest(actual),
        "profile_digest": _canonical_digest(profile),
        "supervisor_isolation": isolation,
    }


def _workload_tmpfs(tmpfs):
    # Podman inspect reports these separately from its four raw Mounts. Exact
    # profile comparison below remains mandatory after this semantic guard.
    roles = {
        "/tmp": frozenset(("rw", "nosuid", "nodev", "mode=1777")),
        "/run/openshell-supervisor-ca": frozenset(("rw", "noexec", "nosuid", "nodev", "mode=0777", "size=1m")),
    }
    if set(tmpfs) != set(roles):
        _fail("workload tmpfs role inventory mismatch")
    for destination, required in roles.items():
        options = _text(tmpfs[destination], True)
        if len(options) > 1024:
            _fail("workload tmpfs options limit")
        tokens = options.split(",")
        actual = set(tokens)
        allowed = required | {"rprivate", "tmpcopyup"}
        if len(actual) != len(tokens) or not required <= actual or not actual <= allowed:
            _fail("workload tmpfs options mismatch")


def _config(value):
    config = _object(value, CONFIG_KEYS, CONFIG_KEYS)
    tmpfs = _object(config["Tmpfs"])
    if len(tmpfs) > 256:
        _fail("tmpfs inventory limit")
    for path, options in tmpfs.items():
        _path(path)
        _text(options)
    if (type(config["Devices"]) is not list or config["Devices"] or
            config["IpcMode"] != "shareable" or config["PidMode"] != "private" or
            type(config["ReadonlyRootfs"]) is not bool):
        _fail("container configuration differs from supported deployment")
    if config["ReadonlyRootfs"] is True:
        _workload_tmpfs(tmpfs)
    return config


def _configuration(container, expected):
    host = _object(container.get("HostConfig"))
    if any(key not in host for key in CONFIG_KEYS):
        _fail("container configuration inventory missing")
    actual = _config({key: host[key] for key in CONFIG_KEYS})
    if actual != expected:
        _fail("container configuration differs from deployment profile")


def _constraints(value, roles):
    if type(value) is not list or len(value) != len(roles):
        _fail("generation mount constraint length mismatch")
    keys, out = MOUNT_KEYS - {"Name", "Source"}, {}
    for row in value:
        _object(row, keys, keys)
        destination = _path(row["Destination"])
        if destination not in roles or destination in out:
            _fail("generation mount constraint role mismatch")
        kind, writable = roles[destination]
        if row["Type"] != kind or type(row["RW"]) is not bool or row["RW"] is not writable:
            _fail("generation mount constraint type mismatch")
        for key in ("Type", "Driver", "Mode", "Propagation"):
            _text(row[key])
        options = row["Options"]
        if type(options) is not list or len(options) > 256:
            _fail("generation mount options unavailable")
        for option in options:
            _text(option, True)
        if len(set(options)) != len(options):
            _fail("duplicate generation mount option")
        out[destination] = row
    return out


def _generation_schema(schema):
    _object(schema, GENERATION_SCHEMA_KEYS, GENERATION_SCHEMA_KEYS)
    if type(schema["version"]) is not int or schema["version"] != 1:
        _fail("unsupported generation schema")
    for key in ("expected_workload_config", "expected_supervisor_config"):
        _config(schema[key])
    if schema["expected_workload_config"]["ReadonlyRootfs"] is not True or "/tmp" not in schema["expected_workload_config"]["Tmpfs"]:
        _fail("workload needs a read-only image and a private tmpfs")
    for key in ("uid_ranges", "gid_ranges"):
        _ranges(schema[key])
        if schema[key] != [APPROVED_HOST_RANGE]:
            _fail("generation identity range differs from approved deployment")
    forbidden = schema["forbidden_host_ids"]
    if type(forbidden) is not list or any(type(value) is not int for value in forbidden) or forbidden != [1001]:
        _fail("generation forbidden identity differs from approved deployment")
    return (_constraints(schema["workload_mount_constraints"], MOUNT_ROLES),
            _constraints(schema["supervisor_mount_constraints"], SUPERVISOR_MOUNT_ROLES))


def generate_profile(workload, supervisor, uid_ranges, gid_ranges, owner_uid, pin, schema, *, trusted_workspace_source):
    """Propose fresh identities while retaining every protected invariant.

    This pure derivation grants no admission. The CLI separately requires fresh
    policy/process evidence and content+kernel-executable binding before output.
    """
    constraints, supervisor_constraints = _generation_schema(schema)
    if (_uint(owner_uid, True) != 1001 or uid_ranges != schema["uid_ranges"] or
            gid_ranges != schema["gid_ranges"] or _digest(pin) != APPROVED_BINARY_DIGEST):
        _fail("generation custody inputs differ from approved deployment")
    # Validate types before equality so bool/int aliases cannot pass identity data.
    _ranges(uid_ranges)
    _ranges(gid_ranges)
    source = _path(trusted_workspace_source)
    if source == "/":
        _fail("workspace root cannot be the host root")
    actual = _mounts(_object(workload).get("Mounts"))
    if actual["/sandbox"]["Source"] != source or actual["/sandbox/.git"]["Source"] != source + "/.git":
        _fail("proposed workspace does not match trusted registration")
    supervisor_actual = _mounts(_object(supervisor).get("Mounts"), SUPERVISOR_MOUNT_ROLES)
    for mounts, expected in ((actual, constraints), (supervisor_actual, supervisor_constraints)):
        for destination, row in mounts.items():
            if {key: value for key, value in row.items() if key not in ("Name", "Source")} != expected[destination]:
                _fail("generation mount metadata differs from protected constraints")
    _configuration(workload, schema["expected_workload_config"])
    _configuration(supervisor, schema["expected_supervisor_config"])
    proposed = strict_json(json.dumps({
        "version": 1, "expected_mounts": _readback_mounts(actual),
        "expected_supervisor_mounts": _readback_mounts(supervisor_actual),
        "expected_workload_config": schema["expected_workload_config"],
        "expected_supervisor_config": schema["expected_supervisor_config"],
        "workload_binary_digest": pin, "uid_ranges": uid_ranges, "gid_ranges": gid_ranges,
        "forbidden_host_ids": [owner_uid],
    }, ensure_ascii=False, allow_nan=False))
    _profile(proposed)
    return proposed


PROFILE_PATH = "/etc/aukora-boundary-gate/openshell-inventory.json"
PIN_PATH = "/usr/local/lib/aukora-boundary/openshell/workload-pin.json"
GENERATION_SCHEMA_PATH = "/usr/local/lib/aukora-boundary/openshell/inventory-generation-schema.json"
WORKSPACE_REGISTRATION_PATH = "/etc/aukora-boundary-gate/openshell-workspace.json"
APPROVED_BINARY_DIGEST = "sha256:5b2178f3b64a6c96eff9ed61bd7feeada4b4a4b3c68f3664e3b8f4f2b264a9b1"
MAX_QUERY_BYTES = 1024 * 1024
MAX_READ_BYTES = 256 * 1024
MAX_READBACK_BYTES = 64 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
QUERY_SECONDS = 4.0
OBSERVER_PATH = "/usr/local/lib/aukora-boundary/openshell/sandbox-inventory.py"
NS_GET_PARENT = 0xb702

# Scan only the protected registration's tree; neither cwd nor a guest/env path
# can choose its root. These are the filesystem paths from the action gate's
# KEY_PATTERNS, LINUX_HOST_PATTERNS and CORE_PATTERNS, not a content-secret
# detector. An unnamed credential copy is not qualified by this name scan.
WORKSPACE_CREDENTIAL_PATTERNS = (
    "**/state/aumlok", "**/machine-seed*.json", "**/aumlok-signer.sock",
    "**/.aukora/signer", "**/kira-memory/issuer.json", "**/kira-memory/keys",
    "**/kira-memory/key", "**/openviking/root.key", "**/auma.key",
    "**/nostr/identity.json", "**/.config/gh", "**/.git-credentials",
    "**/.netrc", "**/.ssh", "**/.gnupg", "**/.aws", "**/library/keychains",
    "**/.credentials.yaml", "**/launch-url.json", "home/aukora-gate",
    "var/lib/aukora-boundary", "run/aukora-gate", "etc/aukora*", "etc/sudoers",
    "etc/sudoers.d", "etc/shadow", "etc/gshadow", "root", "proc/*/environ",
    "proc/*/mem", "proc/*/cmdline", "proc/*/task/*/environ", "proc/*/task/*/mem",
    "**/kira-deployment-overlay.patch.yml", "**/viking-door.key",
    "**/state/launch.json", "**/state/lane-door", "**/state/eye", "**/gate-state",
    "**/kira-approve-queue", "**/owner-console", "**/*.sock",
)
MAX_WORKSPACE_SCAN_ENTRIES = 131072
MAX_WORKSPACE_SCAN_DEPTH = 64
MAX_WORKSPACE_SCAN_NAME_BYTES = 8 * 1024 * 1024
MAX_WORKSPACE_SCAN_FILE_BYTES = 128 * 1024 * 1024
MAX_WORKSPACE_SCAN_BYTES = 512 * 1024 * 1024


def _anchored_file(path, protected=False):
    """Open a regular inode through no-follow directory descriptors."""
    _path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    handle = os.open("/", flags)
    try:
        for part in path.split("/")[1:-1]:
            if protected:
                info = os.fstat(handle)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    _fail("profile ancestor custody unavailable")
            child = os.open(part, flags, dir_fd=handle)
            os.close(handle)
            handle = child
        if protected:
            info = os.fstat(handle)
            if info.st_uid != 0 or info.st_mode & 0o022:
                _fail("profile ancestor custody unavailable")
        if not hasattr(os, "O_PATH"):
            _fail("anchored Linux file observation unavailable")
        anchor = os.open(path.rsplit("/", 1)[1], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=handle)
        fd = None
        try:
            info = os.fstat(anchor)
            if not stat.S_ISREG(info.st_mode) or (protected and (info.st_uid != 0 or info.st_mode & 0o022)):
                _fail("profile/file custody unavailable")
            fd = os.open("/proc/self/fd/" + str(anchor), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino, actual.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
                _fail("file observation identity changed")
            return fd, info
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        finally:
            os.close(anchor)
    finally:
        os.close(handle)


def _read_fd(fd, limit):
    out = bytearray()
    while len(out) <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - len(out)))
        if not chunk:
            return bytes(out)
        out.extend(chunk)
    _fail("observation byte limit")


def _read_protected(path):
    fd, initial = _anchored_file(path, protected=True)
    try:
        raw = _read_fd(fd, MAX_READ_BYTES)
        final = os.fstat(fd)
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
                final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns):
            _fail("profile changed during observation")
    finally:
        os.close(fd)
    return raw.decode("utf-8", "strict")


def read_profile():
    profile = strict_json(_read_protected(PROFILE_PATH))
    _profile(profile)
    return profile


def read_workspace_registration():
    """Read only the root-reviewed registration, never a model/env path choice."""
    registration = strict_json(_read_protected(WORKSPACE_REGISTRATION_PATH))
    keys = frozenset(("version", "workspace_id", "workspace_source", "git_source"))
    version = registration.get("version") if type(registration) is dict else None
    if type(version) is not int or version not in (1, 2):
        _fail("workspace registration version unavailable")
    if version == 2:
        keys = keys | {"group_access"}
    _object(registration, keys | {"mirror_source"}, keys | {"mirror_source"})
    if (type(registration["workspace_id"]) is not str or
            re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", registration["workspace_id"]) is None):
        _fail("workspace registration identity unavailable")
    source = _path(registration["workspace_source"])
    if source == "/" or _path(registration["git_source"]) != source + "/.git":
        _fail("workspace registration metadata source mismatch")
    if version == 2:
        access_keys = frozenset(("owner_uid", "group_gid", "guest_gid"))
        access = _object(registration["group_access"], access_keys, access_keys)
        for key in access_keys:
            _uint(access[key], True)
        if (posixpath.dirname(source) != "/srv/auma-ws" or
                access["owner_uid"] != pwd.getpwnam("auma").pw_uid):
            _fail("dedicated workspace owner/source mismatch")
    mirror = registration.get("mirror_source")
    if mirror is not None:
        mirror = _path(mirror)
        if (posixpath.dirname(mirror) != "/srv/auma-mirror" or
                mirror == source or mirror == source + "/.git" or
                mirror.startswith(source + "/") or source.startswith(mirror + "/")):
            _fail("mirror registration must be a dedicated root-owned sibling")
        registration["mirror_source"] = mirror
    return registration


def _registered_sources(profile, registration):
    mounts = _mounts(profile["expected_mounts"])
    if (mounts["/sandbox"]["Source"] != registration["workspace_source"] or
            mounts["/sandbox/.git"]["Source"] != registration["git_source"]):
        _fail("deployment profile differs from reviewed workspace registration")
    mirror = registration.get("mirror_source")
    if mirror is not None and mounts["/sandbox/prime-main"]["Source"] != mirror:
        _fail("deployment profile differs from reviewed mirror registration")


def _registered_mirror_protection(registration):
    """The mirror leaf and every ancestor stay root-owned and not group/other-writable.

    The guest reads the mirror through a kernel RO bind; the source tree must be
    outside every agent-writable parent so the feed cannot be replaced underneath.
    """
    mirror = registration.get("mirror_source")
    if mirror is None:
        return
    current = "/"
    for component in (part for part in mirror.split("/") if part):
        current = posixpath.join(current, component)
        info = os.stat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            _fail("registered mirror ancestor is writable or unprotected")


def read_pin():
    pin = strict_json(_read_protected(PIN_PATH))
    keys = frozenset(("version", "workload_binary_digest"))
    _object(pin, keys, keys)
    if (type(pin["version"]) is not int or pin["version"] != 1 or
            _digest(pin["workload_binary_digest"]) != APPROVED_BINARY_DIGEST):
        _fail("protected binary pin differs from committed pin")
    return pin["workload_binary_digest"]


def read_ranges(owner_name, owner_uid):
    _text(owner_name, True)
    _uint(owner_uid, True)
    result = []
    for path in ("/etc/subuid", "/etc/subgid"):
        rows = []
        for line in _read_protected(path).splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) != 3 or any(re.fullmatch(r"[0-9]+", value) is None for value in fields[1:]):
                _fail("protected subordinate identity file malformed")
            if fields[0] in (owner_name, str(owner_uid)):
                rows.append({"host_id": int(fields[1]), "size": int(fields[2])})
        _ranges(rows)
        if rows != [APPROVED_HOST_RANGE]:
            _fail("protected subordinate range differs from approved deployment")
        result.append(rows)
    return tuple(result)


def read_generation_inputs():
    owner = pwd.getpwnam("auma")
    if owner.pw_uid != 1001:
        _fail("sandbox owner differs from approved deployment")
    pin = read_pin()
    uid_ranges, gid_ranges = read_ranges(owner.pw_name, owner.pw_uid)
    schema = strict_json(_read_protected(GENERATION_SCHEMA_PATH))
    _generation_schema(schema)
    if uid_ranges != schema["uid_ranges"] or gid_ranges != schema["gid_ranges"]:
        _fail("protected generation identity inputs disagree")
    registration = read_workspace_registration()
    return pin, uid_ranges, gid_ranges, owner.pw_uid, schema, registration


def write_candidate(path, profile):
    """Publish one private proposal exclusively; never install or overwrite it."""
    _path(path)
    if path in (PROFILE_PATH, PIN_PATH, GENERATION_SCHEMA_PATH, WORKSPACE_REGISTRATION_PATH):
        _fail("candidate output cannot be an installed authority input")
    _profile(profile)
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_READ_BYTES:
        _fail("candidate profile byte limit")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open("/", flags)
    temporary, fd = None, None
    try:
        for part in path.split("/")[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        custody = os.fstat(parent)
        if custody.st_uid != os.getuid() or custody.st_mode & 0o077:
            _fail("candidate parent must be caller-owned and private")
        leaf = path.rsplit("/", 1)[1]
        temporary = ".openshell-inventory-" + os.urandom(16).hex()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        os.fchmod(fd, 0o600)
        remaining = raw
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                _fail("candidate output unavailable")
            remaining = remaining[count:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        # Hard-link publication is atomic and fails if the output leaf exists.
        os.link(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.unlink(temporary, dir_fd=parent)
        temporary = None
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def _binary_fd_digest(fd, initial, deadline):
    digest, total = hashlib.sha256(), 0
    try:
        while True:
            if time.monotonic() >= deadline:
                _fail("binary observation deadline")
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BINARY_BYTES:
                _fail("binary observation byte limit")
            digest.update(chunk)
        final = os.fstat(fd)
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
                final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns):
            _fail("binary changed during observation")
        return "sha256:" + digest.hexdigest()
    finally:
        os.close(fd)


def binary_digest(path, deadline, runtime_pid):
    fd, initial = _anchored_file(path)
    source_digest = _binary_fd_digest(fd, initial, deadline)
    _uint(runtime_pid, True)
    # This is a deliberate kernel process binding, not an arbitrary filesystem
    # symlink. Failure of proc-exe read authority remains UNAVAILABLE; no sudo,
    # guest exec or permission change is attempted to obtain it.
    anchor = os.open("/proc/" + str(runtime_pid) + "/exe", os.O_PATH | os.O_CLOEXEC)
    runtime = None
    try:
        info = os.fstat(anchor)
        if not stat.S_ISREG(info.st_mode):
            _fail("runtime executable inode unavailable")
        runtime = os.open("/proc/self/fd/" + str(anchor), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        actual = os.fstat(runtime)
        if (actual.st_dev, actual.st_ino, actual.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
            _fail("runtime executable identity changed")
        fd, runtime = runtime, None
        running_digest = _binary_fd_digest(fd, actual, deadline)
        if source_digest != running_digest:
            _fail("runtime executable differs from observed binary bind")
        return source_digest
    finally:
        if runtime is not None:
            os.close(runtime)
        os.close(anchor)


def query(argv, deadline):
    """Bound both pipes and reap only this read-only query's owned child."""
    if time.monotonic() >= deadline:
        _fail("query deadline")
    home = pwd.getpwuid(os.getuid()).pw_dir
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": home,
           "XDG_RUNTIME_DIR": "/run/user/" + str(os.getuid()),
           "OPENSHELL_TELEMETRY_ENABLED": "false",
           "OPENSHELL_LOCAL_TLS_DIR": home + "/.local/state/openshell/tls"}
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, cwd=home, close_fds=True, pass_fds=())
    output, total = bytearray(), 0
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in (child.stdout, child.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _fail("query deadline")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > MAX_QUERY_BYTES:
                        _fail("query byte limit")
                    if key.fileobj is child.stdout:
                        output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or child.wait(timeout=remaining) != 0:
            _fail("query unavailable")
        return output.decode("utf-8", "strict")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=1)
        child.stdout.close()
        child.stderr.close()


def proc_read(pid, leaf):
    _uint(pid, True)
    # Kernel proc entries may be virtual (size zero); ordinary bounded reads only.
    with open("/proc/" + str(pid) + "/" + leaf, "rb") as stream:
        raw = stream.read(MAX_READ_BYTES + 1)
    if len(raw) > MAX_READ_BYTES:
        _fail("process observation byte limit")
    return raw.decode("utf-8", "strict")


def _registered_directory(fd, path, registration):
    """Group write is an exact registered leaf grant, never an ACL/parent grant."""
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        _fail("registered workspace source is not a directory")
    if path not in (registration["workspace_source"], registration["git_source"]):
        if info.st_uid != 0 or info.st_mode & 0o022:
            _fail("registered workspace ancestor is writable or unprotected")
        return
    access = registration["group_access"]
    if (info.st_uid != access["owner_uid"] or info.st_gid != access["group_gid"] or
            stat.S_IMODE(info.st_mode) not in (0o2750, 0o2770)):
        _fail("registered workspace owner/group/mode mismatch")
    if sys.platform != "linux":
        _fail("workspace ACL absence requires Linux observation")
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.getxattr(fd, name)
        except OSError as error:
            if error.errno != errno.ENODATA:
                raise
        else:
            _fail("workspace ACL grants are not registered")


def _open_directory(path, registration=None):
    """Anchor every component; workspace/git symlinks and gitdir files refuse."""
    _path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    current = "/"
    try:
        for component in path.split("/")[1:]:
            if not component:
                continue
            if registration is not None:
                _registered_directory(fd, current, registration)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            current = posixpath.join(current, component)
        if registration is not None:
            _registered_directory(fd, current, registration)
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def _workspace_scan_key(path):
    # Match the action gate's NFC/lowercase/trailing-dot-space segment folding.
    return "/".join(part for part in (
        unicodedata.normalize("NFC", segment).lower().rstrip(". ")
        for segment in path.split("/")) if part and part != ".")


def _workspace_scan_pattern(pattern):
    pattern = _workspace_scan_key(pattern.rstrip("/"))
    if pattern.endswith("/**"):
        pattern = pattern[:-3]
    body, index = [], 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if pattern[index:index + 2] == "**":
                if pattern[index + 2:index + 3] == "/":
                    body.append("(?:[^/]+/)*")
                    index += 3
                    continue
                body.append(".*")
                index += 2
                continue
            body.append("[^/]*")
        elif character == "?":
            body.append("[^/]")
        else:
            body.append(re.escape(character))
        index += 1
    return re.compile("^(?:" + "".join(body) + ")(?:/.*)?$")


def _workspace_scan_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _scan_registered_workspace(registration, deadline):
    """Bounded no-follow name/inode scan of the exact registered source.

    Hash reads establish the observed bytes and reject an observed change; they
    do not detect arbitrary secret content or close a later writable-tree race.
    No names, bytes or individual file hashes leave this function.
    """
    source = _path(registration["workspace_source"])
    patterns = tuple(_workspace_scan_pattern(pattern) for pattern in WORKSPACE_CREDENTIAL_PATTERNS)
    fingerprint = hashlib.sha256(b"aukora-prime.workspace-scan.v1\0")
    counts = {"entries": 0, "directories": 0, "files": 0, "bytes": 0}
    name_bytes, visited = 0, set()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC

    def check_deadline():
        if time.monotonic() >= deadline:
            _fail("registered workspace scan deadline")

    def record(value):
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8", "strict")
        fingerprint.update(len(raw).to_bytes(8, "big"))
        fingerprint.update(raw)

    def entry_name(path):
        nonlocal name_bytes
        _text(path, True)
        check_deadline()
        counts["entries"] += 1
        name_bytes += len(path.encode("utf-8", "strict"))
        if counts["entries"] > MAX_WORKSPACE_SCAN_ENTRIES or name_bytes > MAX_WORKSPACE_SCAN_NAME_BYTES:
            _fail("registered workspace scan entry/name limit")
        key = _workspace_scan_key(path)
        if any(pattern.fullmatch(key) is not None for pattern in patterns):
            _fail("registered workspace credential path refused")

    def walk(fd, path, depth, device):
        check_deadline()
        if depth > MAX_WORKSPACE_SCAN_DEPTH:
            _fail("registered workspace scan depth limit")
        initial = os.fstat(fd)
        identity = _workspace_scan_identity(initial)
        if not stat.S_ISDIR(initial.st_mode) or initial.st_dev != device:
            _fail("registered workspace scan directory/device unavailable")
        inode = (initial.st_dev, initial.st_ino)
        if inode in visited:
            _fail("registered workspace scan repeated directory")
        visited.add(inode)
        counts["directories"] += 1
        record((path, "directory", identity))
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                child_path = path + "/" + entry.name
                entry_name(child_path)
                names.append(entry.name)
        for name in sorted(names):
            check_deadline()
            child_path = path + "/" + name
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            before_identity = _workspace_scan_identity(before)
            if before.st_dev != device:
                _fail("registered workspace scan cross-device entry")
            if stat.S_ISDIR(before.st_mode):
                child = os.open(name, directory_flags, dir_fd=fd)
                try:
                    if _workspace_scan_identity(os.fstat(child)) != before_identity:
                        _fail("registered workspace scan directory replaced")
                    walk(child, child_path, depth + 1, device)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode):
                if before.st_nlink != 1 or not before.st_mode & 0o444:
                    _fail("registered workspace scan linked/unreadable file")
                if (before.st_size > MAX_WORKSPACE_SCAN_FILE_BYTES or
                        counts["bytes"] + before.st_size > MAX_WORKSPACE_SCAN_BYTES):
                    _fail("registered workspace scan byte limit")
                child = os.open(name, file_flags, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if _workspace_scan_identity(opened) != before_identity or not stat.S_ISREG(opened.st_mode):
                        _fail("registered workspace scan file replaced")
                    digest, size = hashlib.sha256(), 0
                    while True:
                        check_deadline()
                        chunk = os.read(child, 65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        counts["bytes"] += len(chunk)
                        if size > MAX_WORKSPACE_SCAN_FILE_BYTES or counts["bytes"] > MAX_WORKSPACE_SCAN_BYTES:
                            _fail("registered workspace scan byte limit")
                        digest.update(chunk)
                    if size != before.st_size or _workspace_scan_identity(os.fstat(child)) != before_identity:
                        _fail("registered workspace scan file changed")
                    record((child_path, "file", before_identity, digest.hexdigest()))
                    counts["files"] += 1
                finally:
                    os.close(child)
            elif stat.S_ISLNK(before.st_mode):
                # In-tree relative links are admitted only after resolving them against the real
                # tree: every hop re-opened no-follow from the root descriptor, the resolved path
                # must stay inside the registered root on the same device, and the target must be
                # a directory or a readable singly-linked regular file. The target's bytes are
                # hashed when the walk reaches it directly; the link never traversed, so cycles
                # and repeated inodes cannot occur. Absolute or escaping links refuse as before.
                target = os.readlink(name, dir_fd=fd)
                _text(target, True)
                if target.startswith("/"):
                    _fail("registered workspace scan symlink/special file refused")
                resolved = posixpath.normpath(posixpath.join(path, target))
                if resolved == source or not resolved.startswith(source + "/"):
                    _fail("registered workspace scan symlink/special file refused")
                hop = os.dup(root)
                try:
                    for segment in resolved[len(source) + 1:].split("/"):
                        next_hop = os.open(segment, directory_flags | os.O_NONBLOCK, dir_fd=hop)
                        os.close(hop)
                        hop = next_hop
                    resolved_info = os.fstat(hop)
                    if not stat.S_ISDIR(resolved_info.st_mode):
                        _fail("registered workspace scan symlink/special file refused")
                    if resolved_info.st_dev != device:
                        _fail("registered workspace scan symlink/special file refused")
                    record((child_path, "symlink", target, _workspace_scan_identity(resolved_info)))
                finally:
                    os.close(hop)
            else:
                _fail("registered workspace scan symlink/special file refused")
            if _workspace_scan_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != before_identity:
                _fail("registered workspace scan entry changed")
        if _workspace_scan_identity(os.fstat(fd)) != identity:
            _fail("registered workspace scan directory changed")

    root = _open_directory(source, registration if registration["version"] == 2 else None)
    try:
        initial = os.fstat(root)
        entry_name(source)
        walk(root, source, 0, initial.st_dev)
        # Re-open the registered path to reject a renamed/replaced root while
        # its old descriptor remained readable. All child opens stayed fd-relative.
        final_root = _open_directory(source, registration if registration["version"] == 2 else None)
        try:
            if _workspace_scan_identity(os.fstat(final_root)) != _workspace_scan_identity(initial):
                _fail("registered workspace scan root changed")
        finally:
            os.close(final_root)
        check_deadline()
        return {"version": 1, "digest": "sha256:" + fingerprint.hexdigest(), **counts}
    finally:
        os.close(root)


def _unchanged_workspace_scan(registration, initial, deadline):
    if _scan_registered_workspace(registration, deadline) != initial:
        _fail("registered workspace changed across admission")


def _directory_identity(fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        _fail("workspace source is not a directory")
    device = _device(str(os.major(info.st_dev)) + ":" + str(os.minor(info.st_dev)))
    inode = str(info.st_ino)
    _decimal(inode, True)
    return device, inode


def _source_directory_identities(source, registration=None):
    workspace = _open_directory(source, registration)
    git = None
    try:
        git = os.open(".git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=workspace)
        if registration is not None:
            _registered_directory(git, registration["git_source"], registration)
        return _directory_identity(workspace), _directory_identity(git)
    finally:
        if git is not None:
            os.close(git)
        os.close(workspace)


def _registered_workspace_access(registration, process):
    if registration["version"] == 1:
        return None
    access = registration["group_access"]
    if access["owner_uid"] != pwd.getpwnam("auma").pw_uid:
        _fail("workspace owner account changed")
    mapped = [row["host_id"] + access["guest_gid"] - row["container_id"]
              for row in process["gid_map"]
              if row["container_id"] <= access["guest_gid"] < row["container_id"] + row["size"]]
    if mapped != [access["group_gid"]]:
        _fail("registered workspace group differs from actual guest mapping")
    pid = process["pid"]
    before = start_time(pid)
    if before != process["start_time"] or id_map(proc_read(pid, "gid_map")) != process["gid_map"]:
        _fail("workspace group process identity or mapping changed")
    status = {}
    for line in proc_read(pid, "status").splitlines():
        key, _, value = line.partition(":")
        if key in status:
            _fail("duplicate workspace group process status")
        status[key] = value.strip()
    for key, expected in (("Uid", process["uid"]), ("Gid", access["group_gid"])):
        fields = status.get(key, "").split()
        if len(fields) != 4 or any(re.fullmatch(r"[0-9]+", field) is None or int(field) != expected for field in fields):
            _fail("actual workspace process identity differs from registration")
    identities = _source_directory_identities(registration["workspace_source"], registration)
    if before != start_time(pid) or id_map(proc_read(pid, "gid_map")) != process["gid_map"]:
        _fail("workspace group process or mapping changed during observation")
    return identities


def _kernel_directory_identities(pid):
    """Follow only the deliberate kernel root link of the already-bound PID."""
    proc = _open_directory("/proc/" + str(_uint(pid, True)))
    root = workspace = git = None
    try:
        # /proc/<pid>/root is the kernel namespace reference, not an input symlink.
        # There is no sudo/guest-exec fallback if observing it lacks authority.
        root = os.open("root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=proc)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        workspace = os.open("sandbox", flags, dir_fd=root)
        git = os.open(".git", flags, dir_fd=workspace)
        return _directory_identity(workspace), _directory_identity(git)
    finally:
        for fd in (git, workspace, root, proc):
            if fd is not None:
                os.close(fd)


def _mount_namespace(pid):
    value = os.readlink("/proc/" + str(_uint(pid, True)) + "/ns/mnt")
    if re.fullmatch(r"mnt:\[[1-9][0-9]*\]", value) is None:
        _fail("kernel mount namespace unavailable")
    return value


def _read_proc_at(directory, leaf):
    """Read a bounded, fixed kernel metadata leaf through a retained directory."""
    if leaf not in ("stat", "status"):
        _fail("unsupported anchored process observation")
    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        return _read_fd(fd, MAX_READ_BYTES).decode("utf-8", "strict")
    finally:
        os.close(fd)


def _stat_identity(raw):
    # The command name can contain spaces and closing parentheses; the last
    # closing delimiter separates it from the fixed kernel numeric fields.
    if type(raw) is not str or " (" not in raw or ") " not in raw:
        _fail("process stat identity unavailable")
    pid_text = raw.split(" (", 1)[0]
    if re.fullmatch(r"[1-9][0-9]*", pid_text) is None:
        _fail("process stat identity unavailable")
    pid = _uint(int(pid_text), True)
    fields = raw.rsplit(") ", 1)[1].split()
    if len(fields) < 20 or re.fullmatch(r"[1-9][0-9]*", fields[19]) is None:
        _fail("process stat start time unavailable")
    started = int(fields[19])
    if started > SAFE_INTEGER_MAX:
        _fail("process stat start time unavailable")
    return pid, started


def _nspid(raw):
    values = []
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if separator and key == "NSpid":
            values.append(value.split())
    if len(values) != 1 or not 1 <= len(values[0]) <= 128:
        _fail("process PID namespace identity unavailable")
    if any(re.fullmatch(r"[1-9][0-9]*", value) is None for value in values[0]):
        _fail("process PID namespace identity unavailable")
    return tuple(_uint(int(value), True) for value in values[0])


def _pid_namespace(value):
    if type(value) is not str or re.fullmatch(r"pid:\[[1-9][0-9]*\]", value) is None:
        _fail("kernel PID namespace unavailable")
    _decimal(value[5:-1], True)
    return value


def prove_private_proc(pid, expected_start):
    """Bind the mounted guest procfs to this live PID's private namespace.

    The root and namespace links below are explicit kernel references. Every
    ordinary directory and metadata leaf remains no-follow. Missing read
    authority refuses admission; no guest command or privilege fallback exists.
    """
    pid = _uint(pid, True)
    if type(expected_start) is not int or not 0 < expected_start <= SAFE_INTEGER_MAX:
        _fail("process start time unavailable")
    host = _open_directory("/proc/" + str(pid))
    root = guest_proc = guest_one = host_ns = guest_ns = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root = os.open("root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=host)
        guest_proc = os.open("proc", flags, dir_fd=root)
        guest_one = os.open("1", flags, dir_fd=guest_proc)
        host_ns = os.open("ns", flags, dir_fd=host)
        guest_ns = os.open("ns", flags, dir_fd=guest_one)

        def snapshot():
            bound_namespace = _pid_namespace(os.readlink("pid", dir_fd=host_ns))
            guest_namespace = _pid_namespace(os.readlink("pid", dir_fd=guest_ns))
            collector_namespace = _pid_namespace(os.readlink("/proc/self/ns/pid"))
            host_identity = _stat_identity(_read_proc_at(host, "stat"))
            guest_identity = _stat_identity(_read_proc_at(guest_one, "stat"))
            namespace_pids = _nspid(_read_proc_at(host, "status"))
            if (bound_namespace == collector_namespace or guest_namespace != bound_namespace or
                    host_identity != (pid, expected_start) or guest_identity != (1, expected_start) or
                    namespace_pids[0] != pid or namespace_pids[-1] != 1):
                _fail("mounted procfs does not belong to the workload PID namespace")
            return bound_namespace, guest_namespace, collector_namespace, host_identity, guest_identity, namespace_pids

        initial = snapshot()
        if snapshot() != initial:
            _fail("mounted procfs identity changed during observation")
        return initial
    finally:
        for fd in (guest_ns, host_ns, guest_one, guest_proc, root, host):
            if fd is not None:
                os.close(fd)


def _user_namespace(value):
    if type(value) is not str or re.fullmatch(r"user:\[[1-9][0-9]*\]", value) is None:
        _fail("kernel user namespace unavailable")
    _decimal(value[6:-1], True)
    return value


def _observer_rootless_context():
    """Require auma's mapped root, never host root or a guest identity."""
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        _fail("rootless namespace observer unavailable")
    owner = pwd.getpwnam("auma")
    if owner.pw_uid <= 0 or owner.pw_gid <= 0:
        _fail("rootless observer owner unavailable")
    for leaf, owner_id in (("uid_map", owner.pw_uid), ("gid_map", owner.pw_gid)):
        expected = [{"container_id": 0, "host_id": owner_id, "size": 1},
                    {"container_id": 1, **APPROVED_HOST_RANGE}]
        if id_map(proc_read(os.getpid(), leaf)) != expected:
            _fail("rootless observer mapping differs from auma custody")


def _observer_user_lineage(pid):
    """Prove the observed process user namespace is our own or a descendant.

    Linux grants capabilities down the namespace tree, not across siblings.
    A different Podman pause namespace must refuse rather than gain host-root
    help. These ioctls only return namespace descriptors; no setns is used.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC
    own = os.open("/proc/self/ns/user", flags)
    current = None
    try:
        current = os.open("/proc/" + str(_uint(pid, True)) + "/ns/user", flags)
        own_info = os.fstat(own)
        lineage, seen = [], set()
        for _ in range(33):
            info = os.fstat(current)
            identity = (info.st_dev, info.st_ino)
            if identity in seen:
                _fail("observer user namespace lineage cycle")
            seen.add(identity)
            lineage.append(_user_namespace("user:[" + str(info.st_ino) + "]"))
            if identity == (own_info.st_dev, own_info.st_ino):
                return lineage
            parent = fcntl.ioctl(current, NS_GET_PARENT)
            try:
                os.set_inheritable(parent, False)
            except BaseException:
                os.close(parent)
                raise
            os.close(current)
            current = parent
        _fail("observer does not own the workload namespace lineage")
    finally:
        if current is not None:
            os.close(current)
        os.close(own)


def _validate_private_proc_observation(value, pid, expected_start, collector_namespace, caller_user_namespace):
    keys = frozenset(("version", "pid", "start_time", "observer_user_namespace", "user_lineage", "proof"))
    _object(value, keys, keys)
    if type(value["version"]) is not int or value["version"] != 1 or type(value["start_time"]) is not int:
        _fail("private proc observer version/identity unavailable")
    if _uint(value["pid"], True) != pid or value["start_time"] != expected_start:
        _fail("private proc observer process binding mismatch")
    observer_namespace = _user_namespace(value["observer_user_namespace"])
    lineage = value["user_lineage"]
    if (type(lineage) is not list or not 1 <= len(lineage) <= 33 or
            len(set(_user_namespace(item) for item in lineage)) != len(lineage) or
            lineage[-1] != observer_namespace or caller_user_namespace in lineage or
            observer_namespace == caller_user_namespace):
        _fail("private proc observer namespace custody unavailable")
    proof_keys = frozenset(("pid_namespace", "guest_pid_namespace", "collector_pid_namespace",
                            "host_identity", "guest_identity", "namespace_pids"))
    proof = _object(value["proof"], proof_keys, proof_keys)
    bound_namespace = _pid_namespace(proof["pid_namespace"])
    guest_namespace = _pid_namespace(proof["guest_pid_namespace"])
    observed_collector = _pid_namespace(proof["collector_pid_namespace"])
    for key in ("host_identity", "guest_identity"):
        identity = proof[key]
        if (type(identity) is not list or len(identity) != 2 or
                type(identity[1]) is not int or not 0 < identity[1] <= SAFE_INTEGER_MAX):
            _fail("private proc observer typed identity unavailable")
        _uint(identity[0], True)
    namespace_pids = proof["namespace_pids"]
    if type(namespace_pids) is not list or not 1 <= len(namespace_pids) <= 128:
        _fail("private proc observer PID list unavailable")
    for namespace_pid in namespace_pids:
        _uint(namespace_pid, True)
    # The original proof conditions remain mandatory at the caller boundary as
    # well as inside the read-only observer. Namespaced UID values do not enter
    # the host-context uid/gid-map or mount validators.
    if (observed_collector != collector_namespace or bound_namespace == collector_namespace or
            guest_namespace != bound_namespace or proof["host_identity"] != [pid, expected_start] or
            proof["guest_identity"] != [1, expected_start] or
            namespace_pids[0] != pid or namespace_pids[-1] != 1):
        _fail("mounted procfs does not belong to the workload PID namespace")
    return value


def collect_private_proc_observation(pid, expected_start, deadline_ns):
    """Fixed metadata-only observer entry, executed by local podman unshare.

    The retained pidfd/proc directory and repeated identities reject observed
    exit, PID reuse and namespace drift. They do not lease the process or make
    observation and later use atomic; evidence may change after this returns.
    """
    pid = _uint(pid, True)
    if type(expected_start) is not int or not 0 < expected_start <= SAFE_INTEGER_MAX:
        _fail("process start time unavailable")
    if (type(deadline_ns) is not int or deadline_ns <= time.monotonic_ns() or
            deadline_ns - time.monotonic_ns() > int(QUERY_SECONDS * 1000000000)):
        _fail("private proc observer deadline unavailable")
    _observer_rootless_context()
    if not hasattr(os, "pidfd_open"):
        _fail("private proc observer process handle unavailable")
    handle = os.pidfd_open(pid, 0)
    proc = None
    try:
        proc = _open_directory("/proc/" + str(pid))
        def live_identity():
            with selectors.DefaultSelector() as selector:
                selector.register(handle, selectors.EVENT_READ)
                if selector.select(0):
                    _fail("private proc observer process exited")
            if (_stat_identity(_read_proc_at(proc, "stat")) != (pid, expected_start) or
                    time.monotonic_ns() >= deadline_ns):
                _fail("private proc observer process changed or expired")
        live_identity()
        own = _user_namespace(os.readlink("/proc/self/ns/user"))
        lineage = _observer_user_lineage(pid)
        proof = prove_private_proc(pid, expected_start)
        live_identity()
        if (_observer_user_lineage(pid) != lineage or
                _user_namespace(os.readlink("/proc/self/ns/user")) != own):
            _fail("private proc observer namespace changed")
        bound, guest, collector, host_identity, guest_identity, namespace_pids = proof
        return {"version": 1, "pid": pid, "start_time": expected_start,
                "observer_user_namespace": own, "user_lineage": lineage,
                "proof": {"pid_namespace": bound, "guest_pid_namespace": guest,
                          "collector_pid_namespace": collector, "host_identity": list(host_identity),
                          "guest_identity": list(guest_identity), "namespace_pids": list(namespace_pids)}}
    finally:
        if proc is not None:
            os.close(proc)
        os.close(handle)


def observe_private_proc(pid, expected_start, deadline):
    """Read private proc in auma's own Podman namespace, without a root helper.

    Trust is the local Podman/newuidmap/newgidmap installation, its protected
    subordinate ranges, this root-owned observer source and Linux nsfs/procfs.
    No guest exec, sudo, permission edit or fallback supplies missing evidence.
    """
    pid = _uint(pid, True)
    if type(expected_start) is not int or not 0 < expected_start <= SAFE_INTEGER_MAX:
        _fail("process start time unavailable")
    owner = pwd.getpwnam("auma")
    if (sys.platform != "linux" or os.getuid() != owner.pw_uid or os.geteuid() != owner.pw_uid or
            time.monotonic() >= deadline or start_time(pid) != expected_start):
        _fail("private proc observer caller/process unavailable")
    collector = _pid_namespace(os.readlink("/proc/self/ns/pid"))
    caller_user = _user_namespace(os.readlink("/proc/self/ns/user"))
    source = _read_protected(OBSERVER_PATH)
    value = strict_json(query(["/usr/bin/podman", "unshare", "/usr/bin/python3", "-I", "-S",
                              OBSERVER_PATH, "--private-proc-observer", str(pid), str(expected_start),
                              str(int(deadline * 1000000000))], deadline))
    _validate_private_proc_observation(value, pid, expected_start, collector, caller_user)
    if (start_time(pid) != expected_start or _read_protected(OBSERVER_PATH) != source or
            _pid_namespace(os.readlink("/proc/self/ns/pid")) != collector or
            _user_namespace(os.readlink("/proc/self/ns/user")) != caller_user or time.monotonic() >= deadline):
        _fail("private proc observer source/process changed")


def observe_workspace(container, profile, deadline):
    """Fresh kernel mount table and anchored source/destination inode binding."""
    if time.monotonic() >= deadline:
        _fail("workspace observation deadline")
    mounts = _mounts(profile["expected_mounts"])
    source, git_source = mounts["/sandbox"]["Source"], mounts["/sandbox/.git"]["Source"]
    if git_source != source + "/.git":
        _fail("workspace metadata source mismatch")
    pid = _uint(_object(container.get("State")).get("Pid"), True)
    before, namespace = start_time(pid), _mount_namespace(pid)
    if namespace == os.readlink("/proc/self/ns/mnt"):
        _fail("workload uses the host mount namespace")
    observe_private_proc(pid, before, deadline)
    host_workspace, host_git = _source_directory_identities(source)
    if _kernel_directory_identities(pid) != (host_workspace, host_git):
        _fail("mounted workspace does not match registered source inodes")
    rows = parse_mountinfo(proc_read(pid, "mountinfo"))
    binding = {"workspace_source": source, "git_source": git_source,
               "workspace_device": host_workspace[0], "workspace_inode": host_workspace[1],
               "git_device": host_git[0], "git_inode": host_git[1], "mount_namespace": namespace}
    temporary = _open_directory("/tmp")
    try:
        host_tmp_device = _directory_identity(temporary)[0]
    finally:
        os.close(temporary)
    validate_mountinfo(rows, binding, container["Mounts"], host_tmp_device=host_tmp_device)
    if (before != start_time(pid) or namespace != _mount_namespace(pid) or
            rows != parse_mountinfo(proc_read(pid, "mountinfo")) or
            (host_workspace, host_git) != _source_directory_identities(source) or
            (host_workspace, host_git) != _kernel_directory_identities(pid)):
        _fail("workspace/mount observation changed")
    observe_private_proc(pid, before, deadline)
    if time.monotonic() >= deadline:
        _fail("workspace observation deadline")
    return {"mountinfo": rows, "mountinfo_digest": _canonical_digest(rows), "workspace_binding": binding}


def start_time(pid):
    raw = proc_read(pid, "stat")
    fields = raw.rsplit(") ", 1)[1].split()
    value = int(fields[19])
    if value <= 0 or value > SAFE_INTEGER_MAX:
        _fail("process start time unavailable")
    return value


def id_map(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not re.fullmatch(r"[0-9]+", field) for field in fields):
            _fail("process identity map malformed")
        rows.append(dict(zip(("container_id", "host_id", "size"), map(int, fields))))
    return rows


def observe_process(container, workload=False):
    state = _object(container.get("State"))
    if state.get("Running") is not True:
        _fail("container is not running")
    pid = _uint(state.get("Pid"), True)
    before = start_time(pid)
    status = {}
    for line in proc_read(pid, "status").splitlines():
        key, _, value = line.partition(":")
        if key in status:
            _fail("duplicate process status field")
        status[key] = value.strip()
    uids = [int(value) for value in status["Uid"].split()]
    if len(uids) != 4 or len(set(uids)) != 1:
        _fail("process identities disagree")
    if workload:
        gids = [int(value) for value in status["Gid"].split()]
        groups = [int(value) for value in status["Groups"].split()]
        if len(gids) != 4 or len(set(gids)) != 1 or any(not 165536 <= value < 231072 for value in gids + groups):
            _fail("workload group identity is outside the subordinate range")
    process = {"pid": pid, "start_time": before, "uid": uids[0],
               "uid_map": id_map(proc_read(pid, "uid_map")), "gid_map": id_map(proc_read(pid, "gid_map")),
               "cap_eff": status["CapEff"], "cap_prm": status["CapPrm"], "cap_bnd": status["CapBnd"],
               "no_new_privs": int(status["NoNewPrivs"]), "seccomp": int(status["Seccomp"])}
    if before != start_time(pid):
        _fail("process identity changed during observation")
    return process


def _inspect(names, deadline):
    result = strict_json(query(["/usr/bin/podman", "inspect", *names], deadline))
    if type(result) is not list or len(result) != len(names):
        _fail("container inventory unavailable")
    for name, container in zip(names, result):
        _object(container)
        if container.get("Name", "").lstrip("/") != name or not re.fullmatch(r"[a-f0-9]{64}", container.get("Id", "")):
            _fail("container inspection identity mismatch")
    return result


def admission(sb, mode):
    if sb != "auma-ws" or mode not in ("check", "print", "id", "policy", "profile", "bootstrap", "generate"):
        _fail("unsupported admission arguments")
    if mode == "bootstrap":
        read_generation_inputs()
        return None
    deadline = time.monotonic() + QUERY_SECONDS
    generation_inputs = read_generation_inputs() if mode == "generate" else None
    registration = generation_inputs[-1] if mode == "generate" else read_workspace_registration()
    workspace_scan = _scan_registered_workspace(registration, deadline)
    profile = None if mode == "generate" else read_profile()
    if profile is not None:
        _registered_sources(profile, registration)
    _registered_mirror_protection(registration)
    if mode == "profile":
        _unchanged_workspace_scan(registration, workspace_scan, deadline)
        if read_workspace_registration() != registration:
            _fail("workspace registration changed during observation")
        return None
    p = strict_json(query(["/usr/bin/openshell", "policy", "get", sb, "--full", "-o", "json"], deadline))
    pol = dict(_object(p.get("policy")))
    pol.setdefault("network_policies", {})
    validate_policy(pol)
    if p.get("status") != "effective" or p.get("sandbox") != sb:
        _fail("effective policy unavailable")
    def local_policy(value):
        revision = value.get("config_revision")
        if (value.get("scope") != "sandbox" or value.get("policy_source") != "sandbox" or
                type(revision) is not int or not 0 <= revision < 1 << 64 or
                ("global_policy_version" in value and
                 (type(value["global_policy_version"]) is not int or value["global_policy_version"] != 0))):
            _fail("sandbox startup policy generation unavailable")
    local_policy(p)
    if mode == "policy":
        _unchanged_workspace_scan(registration, workspace_scan, deadline)
        if read_workspace_registration() != registration:
            _fail("workspace registration changed during observation")
        return None
    ver = query(["/usr/bin/openshell", "--version"], deadline).split()
    s = strict_json(query(["/usr/bin/openshell", "sandbox", "get", sb, "-o", "json"], deadline))
    sid = s.get("id")
    if type(sid) is not str or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", sid):
        _fail("sandbox identity unavailable")
    names = ["openshell-default--" + sb + "-" + sid, "openshell-supervisor-" + sid]
    listed = query(["/usr/bin/podman", "ps", "--format", "{{.Names}}"], deadline).split()
    if any(listed.count(name) != 1 for name in names):
        _fail("running container identity unavailable")
    workload, supervisor = _inspect(names, deadline)
    if mode == "generate":
        pin, uid_ranges, gid_ranges, owner_uid, schema, registration = generation_inputs
        profile = generate_profile(workload, supervisor, uid_ranges, gid_ranges, owner_uid, pin, schema,
                                   trusted_workspace_source=registration["workspace_source"])
    _registered_sources(profile, registration)
    _registered_mirror_protection(registration)
    process, supervisor_process = observe_process(workload, workload=True), observe_process(supervisor)
    source = _mounts(workload["Mounts"])["/opt/openshell/bin/openshell-sandbox"]["Source"]
    observed_digest = binary_digest(source, deadline, process["pid"])
    observed = validate_snapshot(workload, process, profile, workload_binary_digest=observed_digest)
    observed.update(validate_supervisor(supervisor, supervisor_process, profile))
    registered_access = _registered_workspace_access(registration, process)
    observed.update(observe_workspace(workload, profile, deadline))
    after = _inspect(names, deadline)
    # Reject replacement/configuration drift and PID reuse across observation.
    for initial, final, proc in zip((workload, supervisor), after, (process, supervisor_process)):
        stable = lambda value: {key: value.get(key) for key in ("Id", "Name", "Mounts", "HostConfig")} | {
            "state": {key: value.get("State", {}).get(key) for key in ("Pid", "Running", "StartedAt")},
            "config": {key: value.get("Config", {}).get(key) for key in ("Image", "User")}}
        if _canonical_digest(stable(initial)) != _canonical_digest(stable(final)) or proc["start_time"] != start_time(proc["pid"]):
            _fail("container changed during observation")
    if mode == "generate":
        if read_generation_inputs() != generation_inputs:
            _fail("generation custody inputs changed during observation")
    elif read_profile() != profile:
        _fail("deployment profile changed during observation")
    if read_workspace_registration() != registration:
        _fail("workspace registration changed during observation")
    if _registered_workspace_access(registration, process) != registered_access:
        _fail("registered workspace access changed during observation")
    cond = {}
    for condition in s.get("conditions", []):
        key = condition.get("type")
        if key in cond:
            _fail("duplicate readiness condition")
        cond[key] = condition.get("status")
    adm = _object(s.get("configuration_admission"))
    revision = s.get("current_policy_version")
    generation = (s.get("annotations") or {}).get("internal.openshell.ai/runtime-generation", "")
    policy_hash = p.get("hash")
    if (ver != ["openshell", "0.1.2"] or s.get("name") != sb or s.get("phase") != "Ready" or
            cond.get("Ready") != "True" or cond.get("ConfigurationReady") != "True" or
            type(revision) is not int or not 1 <= revision <= SAFE_INTEGER_MAX or
            type(p.get("active_version")) is not int or p.get("active_version") != revision or adm.get("state") != "accepted" or
            type(policy_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", policy_hash) or
            adm.get("policy_hash") != p.get("hash") or adm.get("policy_version") != revision or
            type(adm.get("policy_version")) is not int or
            type(generation) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", generation)):
        _fail("applied policy unavailable")
    for key in ("config_revision", "provider_env_revision"):
        if type(adm.get(key)) is not int or not 0 <= adm[key] < 1 << 64:
            _fail("configuration admission generation unavailable")
    if adm["config_revision"] != p["config_revision"]:
        _fail("configuration admission revision mismatch")
    final_policy = strict_json(query(["/usr/bin/openshell", "policy", "get", sb, "--full", "-o", "json"], deadline))
    final_sandbox = strict_json(query(["/usr/bin/openshell", "sandbox", "get", sb, "-o", "json"], deadline))
    final_pol = dict(_object(final_policy.get("policy")))
    final_pol.setdefault("network_policies", {})
    validate_policy(final_pol)
    local_policy(final_policy)
    policy_binding = lambda value: {key: value.get(key) for key in ("status", "sandbox", "hash", "active_version", "scope", "policy_source", "config_revision", "global_policy_version")}
    sandbox_binding = lambda value: {key: value.get(key) for key in ("id", "name", "phase", "current_policy_version", "configuration_admission")}
    if (_canonical_digest(final_pol) != _canonical_digest(pol) or
            _canonical_digest(policy_binding(final_policy)) != _canonical_digest(policy_binding(p)) or
            _canonical_digest(sandbox_binding(final_sandbox)) != _canonical_digest(sandbox_binding(s)) or
            (final_sandbox.get("annotations") or {}).get("internal.openshell.ai/runtime-generation") != generation or
            final_sandbox.get("conditions") != s.get("conditions")):
        _fail("applied sandbox policy changed during observation")
    final_containers = _inspect(names, deadline)
    for initial, final, old_process, workload_role in zip((workload, supervisor), final_containers, (process, supervisor_process), (True, False)):
        fresh_process = observe_process(final, workload=workload_role)
        if (_canonical_digest(stable(initial)) != _canonical_digest(stable(final)) or
                _canonical_digest(fresh_process) != _canonical_digest(old_process)):
            _fail("final workload observation changed")
    fresh_workspace = observe_workspace(final_containers[0], profile, deadline)
    if any(fresh_workspace[key] != observed[key] for key in fresh_workspace):
        _fail("final workspace binding changed")
    if read_workspace_registration() != registration:
        _fail("workspace registration changed during final observation")
    envelope = {"version": 3, "openshell_version": "0.1.2", "sandbox": sb, "state": "Ready",
                "instance_id": generation, "policy_revision": revision, "applied_revision": revision,
                "workspace_root": "/sandbox", "network_mode": "none", "policy": pol, **observed}
    if len(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_READBACK_BYTES:
        _fail("admission readback byte limit")
    if time.monotonic() >= deadline:
        _fail("admission deadline")
    if mode == "generate":
        if read_generation_inputs() != generation_inputs:
            _fail("generation custody inputs changed during final observation")
        _unchanged_workspace_scan(registration, workspace_scan, deadline)
        if read_generation_inputs() != generation_inputs:
            _fail("generation custody inputs changed during final scan")
        if time.monotonic() >= deadline:
            _fail("generation deadline")
        return profile
    if read_profile() != profile:
        _fail("deployment profile changed during final observation")
    if read_workspace_registration() != registration:
        _fail("workspace registration changed during final observation")
    _unchanged_workspace_scan(registration, workspace_scan, deadline)
    if read_workspace_registration() != registration or read_profile() != profile:
        _fail("workspace/profile custody changed during final scan")
    if time.monotonic() >= deadline:
        _fail("admission deadline")
    return envelope


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if len(args) == 4 and args[0] == "--private-proc-observer":
            if any(re.fullmatch(r"[1-9][0-9]*", value) is None for value in args[1:]):
                _fail("private proc observer arguments unavailable")
            result = collect_private_proc_observation(*(int(value) for value in args[1:]))
            print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
            return 0
        generating = len(args) == 4 and args[0:3] == ["auma-ws", "generate", "--out"]
        if generating:
            result = admission(args[0], args[1])
            write_candidate(args[3], result)
            return 0
        if len(args) != 2 or args[1] == "generate":
            _fail("unsupported admission arguments")
        result = admission(*args)
        if args[1] == "print":
            print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
        elif args[1] == "id":
            print(result["instance_id"], result["applied_revision"])
        return 0
    except Exception:
        # Never echo raw diagnostics, private profile paths or observation bytes.
        print("aukora-openshell-confinement: applied-policy-unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
