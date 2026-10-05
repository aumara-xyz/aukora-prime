#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded source checks for the read-only private-proc observer.

Disposable directories stand in for fixed procfs metadata and namespace links.
They exercise the actual proof implementation, not Linux namespace authority.
The tests never run Podman, OpenShell, an installed helper or guest commands.
Removal controls execute private source copies and leave production unchanged.
"""

from contextlib import ExitStack, contextmanager
import errno
import json
import os
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "sandbox-inventory.py"
PID, START = 4321, 73
PROOF = ("pid:[700]", "pid:[700]", "pid:[600]", (PID, START), (1, START), (PID, 1))


def response():
    return {"version": 1, "pid": PID, "start_time": START,
            "observer_user_namespace": "user:[101]", "user_lineage": ["user:[102]", "user:[101]"],
            "proof": {"pid_namespace": PROOF[0], "guest_pid_namespace": PROOF[1],
                      "collector_pid_namespace": PROOF[2], "host_identity": [PID, START],
                      "guest_identity": [1, START], "namespace_pids": [PID, 1]}}


@contextmanager
def caller_fixture(module, raw=None):
    owner = SimpleNamespace(pw_uid=1001, pw_gid=1001)
    links = {"/proc/self/ns/pid": PROOF[2], "/proc/self/ns/user": "user:[100]"}
    with ExitStack() as stack:
        for target, name, value in ((module.sys, "platform", "linux"),):
            stack.enter_context(mock.patch.object(target, name, value))
        stack.enter_context(mock.patch.object(module.os, "getuid", return_value=1001))
        stack.enter_context(mock.patch.object(module.os, "geteuid", return_value=1001))
        stack.enter_context(mock.patch.object(module.pwd, "getpwnam", return_value=owner))
        stack.enter_context(mock.patch.object(module.time, "monotonic", return_value=1.0))
        stack.enter_context(mock.patch.object(module.os, "readlink", side_effect=lambda path: links[path]))
        started = stack.enter_context(mock.patch.object(module, "start_time", return_value=START))
        protected = stack.enter_context(mock.patch.object(module, "_read_protected", return_value="protected source"))
        query = stack.enter_context(mock.patch.object(module, "query", return_value=json.dumps(response()) if raw is None else raw))
        yield SimpleNamespace(query=query, protected=protected, started=started, links=links)


@contextmanager
def collector_fixture(module, *, dead=False):
    # A disposable pipe supplies the actual selector readiness contract used by
    # pidfd. It does not claim to be a Linux process handle or namespace proof.
    reader, writer = os.pipe()
    if dead:
        os.write(writer, b"exited")
    try:
        with proc_fixture(module) as paths, ExitStack() as stack:
            links = module.os.readlink
            stack.enter_context(mock.patch.object(module.os, "readlink", side_effect=lambda path, *a, **kw:
                "user:[101]" if path == "/proc/self/ns/user" else links(path, *a, **kw)))
            mapping = stack.enter_context(mock.patch.object(module, "_observer_rootless_context"))
            lineage = stack.enter_context(mock.patch.object(module, "_observer_user_lineage", return_value=["user:[102]", "user:[101]"]))
            pidfd = stack.enter_context(mock.patch.object(module.os, "pidfd_open", return_value=reader, create=True))
            stack.enter_context(mock.patch.object(module.time, "monotonic_ns", return_value=1000000000))
            yield SimpleNamespace(reader=reader, writer=writer, paths=paths, mapping=mapping, lineage=lineage, pidfd=pidfd)
    finally:
        os.close(writer)
        try:
            os.close(reader)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def source_module(source=None):
    module = ModuleType("disposable_private_proc_source")
    module.__file__ = str(SOURCE)
    exec(compile(SOURCE.read_text() if source is None else source, str(SOURCE), "exec"), module.__dict__)
    return module


def stat_line(pid, started):
    # Fields start at kernel stat field 3; index 19 is field 22, starttime.
    fields = ["S"] + ["0"] * 18 + [str(started)]
    return str(pid) + " (fixture (worker)) " + " ".join(fields) + "\n"


@contextmanager
def proc_fixture(module):
    with tempfile.TemporaryDirectory(prefix="aukora-private-proc-") as temporary:
        root = Path(temporary).resolve()
        host, guest = root / "host", root / "guest"
        (host / "ns").mkdir(parents=True)
        (guest / "proc" / "1" / "ns").mkdir(parents=True)
        (host / "root").symlink_to(guest, target_is_directory=True)
        (host / "ns" / "pid").symlink_to(PROOF[0])
        (guest / "proc" / "1" / "ns" / "pid").symlink_to(PROOF[1])
        (host / "stat").write_text(stat_line(PID, START))
        (guest / "proc" / "1" / "stat").write_text(stat_line(1, START))
        (host / "status").write_text("Name:\tfixture\nNSpid:\t4321\t1\n")
        open_directory, readlink = module._open_directory, os.readlink

        def anchored(path, registration=None):
            if path == "/proc/" + str(PID):
                return open_directory(str(host), registration)
            raise AssertionError("unexpected proc fixture path: " + path)

        def namespace_link(path, *args, **kwargs):
            if path == "/proc/self/ns/pid":
                return PROOF[2]
            return readlink(path, *args, **kwargs)

        with mock.patch.object(module, "_open_directory", side_effect=anchored), \
                mock.patch.object(module.os, "readlink", side_effect=namespace_link):
            yield host, guest


class PrivateProcProofChecks(unittest.TestCase):
    def setUp(self):
        self.module = source_module()

    def test_actual_fixed_metadata_and_links_prove_private_proc(self):
        with proc_fixture(self.module):
            self.assertEqual(self.module.prove_private_proc(PID, START), PROOF)

    def test_host_proc_and_other_guest_namespace_refuse(self):
        for host_namespace, guest_namespace in ((PROOF[2], PROOF[2]), (PROOF[0], "pid:[701]")):
            with self.subTest(host=host_namespace, guest=guest_namespace), proc_fixture(self.module) as (host, guest):
                for path, value in ((host / "ns" / "pid", host_namespace),
                                    (guest / "proc" / "1" / "ns" / "pid", guest_namespace)):
                    path.unlink()
                    path.symlink_to(value)
                with self.assertRaisesRegex(ValueError, "workload PID namespace"):
                    self.module.prove_private_proc(PID, START)

    def test_workload_and_guest_identity_binding_refuse_pid_reuse(self):
        for side, identity in (("host", (PID + 1, START)), ("host", (PID, START + 1)),
                               ("guest", (2, START)), ("guest", (1, START + 1))):
            with self.subTest(side=side, identity=identity), proc_fixture(self.module) as (host, guest):
                path = host / "stat" if side == "host" else guest / "proc" / "1" / "stat"
                path.write_text(stat_line(*identity))
                with self.assertRaisesRegex(ValueError, "workload PID namespace"):
                    self.module.prove_private_proc(PID, START)

    def test_nspid_must_bind_outer_pid_and_guest_one(self):
        for line in ("NSpid:\t4322\t1\n", "NSpid:\t4321\t2\n", "NSpid:\t4321\n", "",
                     "NSpid:\t4321\t1\nNSpid:\t4321\t1\n", "NSpid:\t4321\t0\n"):
            with self.subTest(line=line), proc_fixture(self.module) as (host, _):
                (host / "status").write_text(line)
                with self.assertRaises(ValueError):
                    self.module.prove_private_proc(PID, START)

    def test_fixed_ordinary_metadata_symlink_refuses(self):
        for side in ("host", "guest"):
            with self.subTest(side=side), proc_fixture(self.module) as (host, guest):
                path = host / "stat" if side == "host" else guest / "proc" / "1" / "stat"
                replacement = path.parent / "replacement"
                replacement.write_bytes(path.read_bytes())
                path.unlink()
                path.symlink_to(replacement)
                with self.assertRaises(OSError):
                    self.module.prove_private_proc(PID, START)

    def test_namespace_and_metadata_drift_refuse_between_snapshots(self):
        for changed_leaf in ("stat", "status", "namespace"):
            with self.subTest(leaf=changed_leaf), proc_fixture(self.module) as (host, _):
                read = self.module._read_proc_at
                changed = False

                def drift(directory, leaf):
                    nonlocal changed
                    result = read(directory, leaf)
                    # The first host status read is the last read of snapshot one.
                    if leaf == "status" and not changed:
                        changed = True
                        if changed_leaf == "stat":
                            (host / "stat").write_text(stat_line(PID, START + 1))
                        elif changed_leaf == "status":
                            (host / "status").write_text("NSpid:\t4321\t9\t1\n")
                        else:
                            (host / "ns" / "pid").unlink()
                            (host / "ns" / "pid").symlink_to("pid:[702]")
                    return result

                with mock.patch.object(self.module, "_read_proc_at", side_effect=drift), self.assertRaises(ValueError):
                    self.module.prove_private_proc(PID, START)
                self.assertTrue(changed)

    def test_missing_read_authority_never_counts_as_proof(self):
        with proc_fixture(self.module), \
                mock.patch.object(self.module, "_read_proc_at", side_effect=PermissionError(errno.EACCES, "fixture")), \
                self.assertRaises(PermissionError):
            self.module.prove_private_proc(PID, START)

    def test_c320_namespace_directory_read_denial_refuses_original_proof(self):
        original_open = os.open
        denied = []

        def deny_namespace(path, flags, *args, **kwargs):
            if path == "ns" and "dir_fd" in kwargs:
                denied.append(kwargs["dir_fd"])
                raise PermissionError(errno.EACCES, "fixture namespace directory authority")
            return original_open(path, flags, *args, **kwargs)

        with proc_fixture(self.module), mock.patch.object(self.module.os, "open", side_effect=deny_namespace), \
                self.assertRaises(PermissionError) as caught:
            self.module.prove_private_proc(PID, START)
        self.assertEqual(caught.exception.errno, errno.EACCES)
        self.assertEqual(len(denied), 1)

    def test_boolean_invalid_pid_and_start_refuse(self):
        for pid, started in ((True, START), (0, START), (PID, True), (PID, 0), (PID, 1 << 54)):
            with self.subTest(pid=pid, started=started), self.assertRaises(ValueError), \
                    mock.patch.object(self.module, "_open_directory") as opened:
                self.module.prove_private_proc(pid, started)
            opened.assert_not_called()


class PrivateProcCallerChecks(unittest.TestCase):
    def setUp(self):
        self.module = source_module()

    def test_fixed_local_unshare_query_and_protected_source_binding(self):
        with caller_fixture(self.module) as fixture:
            self.assertIsNone(self.module.observe_private_proc(PID, START, 3.0))
        fixture.query.assert_called_once_with([
            "/usr/bin/podman", "unshare", "/usr/bin/python3", "-I", "-S", self.module.OBSERVER_PATH,
            "--private-proc-observer", str(PID), str(START), "3000000000"], 3.0)
        self.assertEqual(fixture.protected.call_args_list,
                         [mock.call(self.module.OBSERVER_PATH), mock.call(self.module.OBSERVER_PATH)])
        self.assertEqual(fixture.started.call_args_list, [mock.call(PID), mock.call(PID)])

    def test_closed_typed_response_rejects_malformed_bindings(self):
        changes = [(("version",), True), (("version",), 2), (("pid",), True), (("pid",), PID + 1),
                   (("start_time",), True), (("start_time",), START + 1), (("extra",), 0),
                   (("observer_user_namespace",), "user:[100]"), (("user_lineage",), []),
                   (("user_lineage",), ["user:[101]", "user:[101]"]),
                   (("user_lineage",), ["user:[100]", "user:[101]"]),
                   (("user_lineage",), ["user:[102]", "user:[100]", "user:[101]"]),
                   (("user_lineage",), ["user:[102]"]), (("user_lineage",), "user:[101]"),
                   (("proof", "extra"), 0), (("proof", "pid_namespace"), "pid:[600]"),
                   (("proof", "guest_pid_namespace"), "pid:[701]"),
                   (("proof", "collector_pid_namespace"), "pid:[601]"),
                   (("proof", "host_identity"), [PID, START + 1]), (("proof", "host_identity"), [True, START]),
                   (("proof", "guest_identity"), [2, START]), (("proof", "guest_identity"), [1, True]),
                   (("proof", "namespace_pids"), [PID, 2]), (("proof", "namespace_pids"), [PID + 1, 1]),
                   (("proof", "namespace_pids"), [PID, True])]
        for path, value in changes:
            with self.subTest(path=path, value=value):
                altered = response()
                target = altered
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with caller_fixture(self.module, json.dumps(altered)), self.assertRaises(ValueError):
                    self.module.observe_private_proc(PID, START, 3.0)

    def test_duplicate_missing_and_invalid_json_response_refuse(self):
        good = json.dumps(response())
        missing = response()
        del missing["proof"]["guest_identity"]
        for raw in (good[:-1] + ',"pid":4321}', json.dumps(missing), "[]", "null", "{", good + "{}"):
            with self.subTest(raw=raw[:100]), caller_fixture(self.module, raw), self.assertRaises(ValueError):
                self.module.observe_private_proc(PID, START, 3.0)

    def test_process_source_and_namespace_drift_after_query_refuse(self):
        for changed in ("start", "source", "pid_namespace", "user_namespace", "deadline"):
            with self.subTest(changed=changed), caller_fixture(self.module) as fixture:
                if changed == "start":
                    fixture.started.side_effect = [START, START + 1]
                elif changed == "source":
                    fixture.protected.side_effect = ["protected source", "changed source"]
                elif changed in ("pid_namespace", "user_namespace"):
                    def query(*args):
                        leaf = "/proc/self/ns/pid" if changed == "pid_namespace" else "/proc/self/ns/user"
                        fixture.links[leaf] = "pid:[601]" if changed == "pid_namespace" else "user:[999]"
                        return json.dumps(response())
                    fixture.query.side_effect = query
                else:
                    self.module.time.monotonic.side_effect = [1.0, 4.0]
                with self.assertRaises(ValueError):
                    self.module.observe_private_proc(PID, START, 3.0)

    def test_caller_root_and_wrong_process_refuse_before_any_query(self):
        for changed in ("host_root", "wrong_start", "deadline"):
            with self.subTest(changed=changed), caller_fixture(self.module) as fixture:
                if changed == "host_root":
                    self.module.os.getuid.return_value = 0
                elif changed == "wrong_start":
                    fixture.started.return_value = START + 1
                else:
                    self.module.time.monotonic.return_value = 4.0
                with self.assertRaises(ValueError):
                    self.module.observe_private_proc(PID, START, 3.0)
                fixture.query.assert_not_called()

    def test_query_authority_failure_and_missing_protected_source_refuse(self):
        for leaf in ("query", "protected"):
            with self.subTest(leaf=leaf), caller_fixture(self.module) as fixture:
                getattr(fixture, leaf).side_effect = PermissionError(errno.EACCES, "fixture authority")
                with self.assertRaises(PermissionError):
                    self.module.observe_private_proc(PID, START, 3.0)
                if leaf == "protected":
                    fixture.query.assert_not_called()

    def test_exact_start_binding_removal_control_is_detected(self):
        original = SOURCE.read_text()
        guard = 'value["start_time"] != expected_start'
        self.assertEqual(original.count(guard), 1)
        mutant = source_module(original.replace(guard, "False"))
        altered = response()
        altered["start_time"] = START + 1

        def refusal_witness(module):
            with caller_fixture(module, json.dumps(altered)), self.assertRaises(ValueError):
                module.observe_private_proc(PID, START, 3.0)

        refusal_witness(self.module)
        with self.assertRaises(AssertionError):
            refusal_witness(mutant)
        self.assertEqual(SOURCE.read_text(), original)


class RootlessObserverChecks(unittest.TestCase):
    def setUp(self):
        self.module = source_module()

    @contextmanager
    def mapping_fixture(self, uid_map="0 1001 1\n1 165536 65536\n", gid_map=None, *, module=None):
        module = self.module if module is None else module
        values = {"uid_map": uid_map, "gid_map": uid_map if gid_map is None else gid_map}
        with mock.patch.object(module.sys, "platform", "linux"), \
                mock.patch.object(module.os, "getuid", return_value=0), \
                mock.patch.object(module.os, "geteuid", return_value=0), \
                mock.patch.object(module.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001, pw_gid=1001)), \
                mock.patch.object(module, "proc_read", side_effect=lambda pid, leaf: values[leaf]):
            yield

    def test_exact_mapped_root_context_is_required(self):
        with self.mapping_fixture():
            self.assertIsNone(self.module._observer_rootless_context())
        for mapping in ("0 0 4294967295\n", "0 1002 1\n1 165536 65536\n", "0 1001 1\n1 165536 1024\n",
                        "0 1001 1\n1 165537 65536\n", "0 1001 1\n", "0 1001 1\n1 165536 65536\n65537 900000 1\n"):
            for kind in ("uid", "gid"):
                with self.subTest(kind=kind, mapping=mapping), \
                        self.mapping_fixture(mapping if kind == "uid" else "0 1001 1\n1 165536 65536\n",
                                             mapping if kind == "gid" else None), self.assertRaises(ValueError):
                    self.module._observer_rootless_context()

    def test_child_actual_proof_and_process_handle_are_required(self):
        with collector_fixture(self.module) as fixture:
            self.assertEqual(self.module.collect_private_proc_observation(PID, START, 2000000000), response())
        fixture.mapping.assert_called_once_with()
        fixture.pidfd.assert_called_once_with(PID, 0)
        self.assertEqual(fixture.lineage.call_args_list, [mock.call(PID), mock.call(PID)])
        with self.assertRaises(OSError) as caught:
            os.fstat(fixture.reader)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_exited_process_handle_refuses_before_proof(self):
        with collector_fixture(self.module, dead=True), \
                mock.patch.object(self.module, "prove_private_proc") as proof, self.assertRaisesRegex(ValueError, "process exited"):
            self.module.collect_private_proc_observation(PID, START, 2000000000)
        proof.assert_not_called()

    def test_missing_process_handle_and_namespace_authority_refuse(self):
        for missing in ("pidfd", "lineage"):
            with self.subTest(missing=missing), collector_fixture(self.module) as fixture, \
                    mock.patch.object(self.module, "prove_private_proc") as proof:
                getattr(fixture, missing).side_effect = PermissionError(errno.EPERM, "fixture handle")
                with self.assertRaises(PermissionError):
                    self.module.collect_private_proc_observation(PID, START, 2000000000)
                proof.assert_not_called()

    def test_child_retained_process_identity_and_lineage_drift_refuse(self):
        for changed in ("before_start", "after_start", "lineage", "user_namespace", "deadline"):
            with self.subTest(changed=changed), collector_fixture(self.module) as fixture, ExitStack() as changes:
                if changed == "before_start":
                    (fixture.paths[0] / "stat").write_text(stat_line(PID, START + 1))
                elif changed == "lineage":
                    fixture.lineage.side_effect = [["user:[102]", "user:[101]"], ["user:[103]", "user:[101]"]]
                elif changed == "user_namespace":
                    readlink_original = self.module.os.readlink.side_effect
                    reads = iter(("user:[101]", "user:[105]"))
                    self.module.os.readlink.side_effect = lambda path, *a, **kw: next(reads) if path == "/proc/self/ns/user" else readlink_original(path, *a, **kw)
                elif changed == "deadline":
                    self.module.time.monotonic_ns.side_effect = [1000000000, 1000000000, 1000000000, 2100000000]
                else:
                    proof_original = self.module.prove_private_proc
                    def drift(*args):
                        proof = proof_original(*args)
                        (fixture.paths[0] / "stat").write_text(stat_line(PID, START + 1))
                        return proof
                    changes.enter_context(mock.patch.object(self.module, "prove_private_proc", side_effect=drift))
                with self.assertRaises(ValueError):
                    self.module.collect_private_proc_observation(PID, START, 2000000000)

    def test_stale_process_handle_removal_control_is_detected(self):
        original = SOURCE.read_text()
        guard = "if selector.select(0):"
        self.assertEqual(original.count(guard), 1)
        mutant = source_module(original.replace(guard, "if False:"))

        def refusal_witness(module):
            with collector_fixture(module, dead=True), self.assertRaisesRegex(ValueError, "process exited"):
                module.collect_private_proc_observation(PID, START, 2000000000)

        refusal_witness(self.module)
        with self.assertRaises(AssertionError):
            refusal_witness(mutant)
        self.assertEqual(SOURCE.read_text(), original)

    def test_mapped_root_custody_call_removal_control_is_detected(self):
        original = SOURCE.read_text()
        guard = "    _observer_rootless_context()\n"
        self.assertEqual(original.count(guard), 1)
        mutant = source_module(original.replace(guard, ""))

        def custody_witness(module):
            actual_custody = module._observer_rootless_context
            with collector_fixture(module) as fixture, \
                    self.mapping_fixture("0 1002 1\n1 165536 65536\n", module=module):
                fixture.mapping.side_effect = actual_custody
                with self.assertRaisesRegex(ValueError, "mapping differs from auma custody"):
                    module.collect_private_proc_observation(PID, START, 2000000000)

        custody_witness(self.module)
        with self.assertRaises(AssertionError):
            custody_witness(mutant)
        self.assertEqual(SOURCE.read_text(), original)


class UserNamespaceLineageChecks(unittest.TestCase):
    def setUp(self):
        self.module = source_module()

    @contextmanager
    def namespace_fixture(self, labels, parents):
        with tempfile.TemporaryDirectory(prefix="aukora-user-lineage-") as temporary:
            root = Path(temporary).resolve()
            for label in labels:
                (root / label).write_text("disposable namespace descriptor fixture")
            identities = {label: "user:[" + str((root / label).stat().st_ino) + "]" for label in labels}
            original_open = os.open
            opened, descriptor_labels = [], {}

            def descriptor(label):
                fd = original_open(str(root / label), os.O_RDONLY | os.O_CLOEXEC)
                opened.append(fd)
                descriptor_labels[fd] = label
                return fd

            def namespace_open(path, flags):
                self.assertEqual(flags, os.O_RDONLY | os.O_CLOEXEC)
                if path == "/proc/self/ns/user":
                    return descriptor("own")
                self.assertEqual(path, "/proc/" + str(PID) + "/ns/user")
                return descriptor("target")

            def parent_ioctl(fd, request):
                self.assertEqual(request, self.module.NS_GET_PARENT)
                parent = parents[descriptor_labels[fd]]
                if isinstance(parent, BaseException):
                    raise parent
                return descriptor(parent)

            with mock.patch.object(self.module.os, "open", side_effect=namespace_open), \
                    mock.patch.object(self.module.fcntl, "ioctl", side_effect=parent_ioctl) as ioctl:
                yield SimpleNamespace(identities=identities, opened=opened, ioctl=ioctl)
            # Descriptor numbers can be reused; all handles are closed at exit.
            for fd in set(opened):
                with self.assertRaises(OSError) as caught:
                    os.fstat(fd)
                self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_descendant_chain_requires_exact_retained_owner_namespace(self):
        with self.namespace_fixture(["own", "target", "middle"], {"target": "middle", "middle": "own"}) as fixture:
            expected = [fixture.identities[key] for key in ("target", "middle", "own")]
            self.assertEqual(self.module._observer_user_lineage(PID), expected)
        self.assertEqual(fixture.ioctl.call_count, 2)

    def test_own_namespace_accepts_without_parent_ioctl(self):
        with self.namespace_fixture(["own", "target"], {}) as fixture:
            original_open = self.module.os.open.side_effect

            def same_namespace(path, flags):
                # Two retained descriptors point to the same fixture inode.
                return original_open("/proc/self/ns/user", flags)

            self.module.os.open.side_effect = same_namespace
            self.assertEqual(self.module._observer_user_lineage(PID), [fixture.identities["own"]])
        fixture.ioctl.assert_not_called()

    def test_sibling_or_missing_parent_authority_refuses_and_closes_handles(self):
        with self.namespace_fixture(["own", "target"], {"target": PermissionError(errno.EPERM, "fixture sibling")}) as fixture:
            with self.assertRaises(PermissionError):
                self.module._observer_user_lineage(PID)
        self.assertEqual(fixture.ioctl.call_count, 1)

    def test_repeated_namespace_inode_refuses_cycle(self):
        with self.namespace_fixture(["own", "target"], {"target": "target"}) as fixture:
            with self.assertRaisesRegex(ValueError, "lineage cycle"):
                self.module._observer_user_lineage(PID)
        self.assertEqual(fixture.ioctl.call_count, 1)

    def test_lineage_depth_bound_refuses_long_chain(self):
        chain = ["target"] + ["parent" + str(index) for index in range(33)] + ["own"]
        parents = dict(zip(chain, chain[1:]))
        with self.namespace_fixture(chain, parents) as fixture:
            with self.assertRaisesRegex(ValueError, "does not own"):
                self.module._observer_user_lineage(PID)
        self.assertEqual(fixture.ioctl.call_count, 33)


class WorkspaceObserverJoinChecks(unittest.TestCase):
    def setUp(self):
        self.module = source_module()

    @contextmanager
    def workspace_fixture(self, module):
        with tempfile.TemporaryDirectory(prefix="aukora-workspace-observer-") as temporary, ExitStack() as stack:
            host = Path(temporary).resolve()
            fixed_open = module._open_directory
            for name, value in (("start_time", START), ("_mount_namespace", "mnt:[800]"),
                                ("_source_directory_identities", ((1, 2), (1, 3))),
                                ("_kernel_directory_identities", ((1, 2), (1, 3))),
                                ("proc_read", "fixture mountinfo"), ("parse_mountinfo", []),
                                ("_mounts", {"/sandbox": {"Source": "/fixture/workspace"},
                                             "/sandbox/.git": {"Source": "/fixture/workspace/.git"}})):
                stack.enter_context(mock.patch.object(module, name, return_value=value))
            stack.enter_context(mock.patch.object(module, "_open_directory", side_effect=lambda path: fixed_open(str(host))))
            stack.enter_context(mock.patch.object(module.os, "readlink", return_value="mnt:[600]"))
            stack.enter_context(mock.patch.object(module.time, "monotonic", return_value=1.0))
            stack.enter_context(mock.patch.object(module, "validate_mountinfo"))
            observer = stack.enter_context(mock.patch.object(module, "observe_private_proc"))
            yield observer

    def workspace_witness(self, module):
        with self.workspace_fixture(module) as observer:
            result = module.observe_workspace({"State": {"Pid": PID}, "Mounts": []}, {"expected_mounts": []}, 3.0)
        self.assertEqual(observer.call_args_list, [mock.call(PID, START, 3.0), mock.call(PID, START, 3.0)])
        self.assertEqual(result["workspace_binding"]["workspace_source"], "/fixture/workspace")

    def test_workspace_checks_fixed_observer_before_and_after_mount_observation(self):
        self.workspace_witness(self.module)

    def test_observer_refusal_prevents_successful_workspace_admission(self):
        with self.workspace_fixture(self.module) as observer:
            observer.side_effect = PermissionError(errno.EACCES, "fixture missing observer authority")
            with self.assertRaises(PermissionError):
                self.module.observe_workspace({"State": {"Pid": PID}, "Mounts": []}, {"expected_mounts": []}, 3.0)
        observer.assert_called_once_with(PID, START, 3.0)

    def test_required_observer_invocation_removal_control_is_detected(self):
        original = SOURCE.read_text()
        guard = "    observe_private_proc(pid, before, deadline)\n"
        self.assertEqual(original.count(guard), 2)
        mutant = source_module(original.replace(guard, ""))
        self.workspace_witness(self.module)
        with self.assertRaises(AssertionError):
            self.workspace_witness(mutant)
        self.assertEqual(SOURCE.read_text(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
