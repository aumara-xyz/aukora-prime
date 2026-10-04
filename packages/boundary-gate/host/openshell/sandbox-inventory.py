# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exact deployment-profile validation and bounded read-only admission.

Import is effect-free. The fixed host CLI obtains fresh observations; it never
installs a profile or launches a guest command. Explicit generation only emits
an operator proposal from protected invariants. Missing custody/evidence refuses.
"""

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
    "/sandbox": ("volume", True),
    "/.openshell/channel": ("volume", True),
    "/opt/openshell/bin/openshell-sandbox": ("bind", False),
}
SUPERVISOR_MOUNT_ROLES = {"/.openshell/channel": ("volume", False)}


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
    supervisor = _mounts(profile["expected_supervisor_mounts"], SUPERVISOR_MOUNT_ROLES)
    for key in ("expected_workload_config", "expected_supervisor_config"):
        _config(profile[key])
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
    for key in ("uid_ranges", "gid_ranges"):
        _ranges(schema[key])
        if schema[key] != [APPROVED_HOST_RANGE]:
            _fail("generation identity range differs from approved deployment")
    forbidden = schema["forbidden_host_ids"]
    if type(forbidden) is not list or any(type(value) is not int for value in forbidden) or forbidden != [1001]:
        _fail("generation forbidden identity differs from approved deployment")
    return (_constraints(schema["workload_mount_constraints"], MOUNT_ROLES),
            _constraints(schema["supervisor_mount_constraints"], SUPERVISOR_MOUNT_ROLES))


def generate_profile(workload, supervisor, uid_ranges, gid_ranges, owner_uid, pin, schema):
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
    actual = _mounts(_object(workload).get("Mounts"))
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
APPROVED_BINARY_DIGEST = "sha256:5b2178f3b64a6c96eff9ed61bd7feeada4b4a4b3c68f3664e3b8f4f2b264a9b1"
MAX_QUERY_BYTES = 1024 * 1024
MAX_READ_BYTES = 256 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
QUERY_SECONDS = 4.0


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
    return pin, uid_ranges, gid_ranges, owner.pw_uid, schema


def write_candidate(path, profile):
    """Publish one private proposal exclusively; never install or overwrite it."""
    _path(path)
    if path in (PROFILE_PATH, PIN_PATH, GENERATION_SCHEMA_PATH):
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
    if mode == "profile":
        read_profile()
        return None
    if mode == "bootstrap":
        read_generation_inputs()
        return None
    deadline = time.monotonic() + QUERY_SECONDS
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
        return None
    generation_inputs = read_generation_inputs() if mode == "generate" else None
    profile = None if mode == "generate" else read_profile()
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
        pin, uid_ranges, gid_ranges, owner_uid, schema = generation_inputs
        profile = generate_profile(workload, supervisor, uid_ranges, gid_ranges, owner_uid, pin, schema)
    process, supervisor_process = observe_process(workload, workload=True), observe_process(supervisor)
    source = _mounts(workload["Mounts"])["/opt/openshell/bin/openshell-sandbox"]["Source"]
    observed_digest = binary_digest(source, deadline, process["pid"])
    observed = validate_snapshot(workload, process, profile, workload_binary_digest=observed_digest)
    observed.update(validate_supervisor(supervisor, supervisor_process, profile))
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
    envelope = {"version": 2, "openshell_version": "0.1.2", "sandbox": sb, "state": "Ready",
                "instance_id": generation, "policy_revision": revision, "applied_revision": revision,
                "workspace_root": "/sandbox", "network_mode": "none", "policy": pol, **observed}
    if len(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode()) > 16384:
        _fail("admission readback byte limit")
    if time.monotonic() >= deadline:
        _fail("admission deadline")
    if mode == "generate":
        if read_generation_inputs() != generation_inputs:
            _fail("generation custody inputs changed during final observation")
        if time.monotonic() >= deadline:
            _fail("generation deadline")
        return profile
    return envelope


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
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
