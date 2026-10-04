#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure mocked sink-watchdog regressions; no guest or host process starts."""

import collections
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


# Importing definitions must not create another artifact or enter guest main.
sys.dont_write_bytecode = True
source = Path(__file__).resolve().parent.parent / "guest" / "exec.py"
spec = importlib.util.spec_from_file_location("aukora_guest_carrier_check", source)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


def channel(size=0, progress_at=10.0, sink="control"):
    return {
        "kind": "control" if sink == "control" else None,
        "sink": sink,
        "queue": collections.deque([memoryview(bytes(size))]) if size else collections.deque(),
        "bytes": size,
        "read": sink == "control",
        "end": False,
        "write_closed": False,
        "progress_at": progress_at,
    }


def carrier(*channels):
    result = guest.Carrier.__new__(guest.Carrier)
    result.channels = {100 + index: value for index, value in enumerate(channels)}
    result.cleanup_at = None
    return result


class InputStallChecks(unittest.TestCase):
    def stalled(self, instance, now):
        with patch.object(guest.time, "monotonic", return_value=now):
            with self.assertRaises(guest.Refused) as raised:
                instance.check_input_stall()
        self.assertEqual(raised.exception.code, "INPUT_STALLED")

    def test_stall_fires_at_exact_time_and_high_water_bounds(self):
        for sink in ("stdin", "control"):
            with self.subTest(sink=sink):
                instance = carrier(channel(guest.HIGH_WATER, sink=sink))
                deadline = 10.0 + guest.INPUT_STALL_SECONDS
                with patch.object(guest.time, "monotonic", return_value=deadline - 0.001):
                    instance.check_input_stall()
                self.stalled(instance, deadline)

    def test_empty_below_water_and_output_channels_do_not_stall(self):
        instance = carrier(
            channel(0, progress_at=None),
            channel(guest.HIGH_WATER - 1, sink="stdin"),
            channel(guest.HIGH_WATER + 1, sink=None),
        )
        with patch.object(guest.time, "monotonic", return_value=1000.0):
            instance.check_input_stall()

    def test_enqueue_growth_does_not_extend_first_pending_deadline(self):
        pending = channel(0, progress_at=None)
        instance = carrier(pending)
        with patch.object(guest.time, "monotonic", return_value=10.0):
            instance.enqueue("control", bytes(guest.HIGH_WATER))
        self.assertEqual(pending["progress_at"], 10.0)
        with patch.object(guest.time, "monotonic", return_value=11.0):
            instance.enqueue("control", b"more")
        self.assertEqual(pending["progress_at"], 10.0)
        self.stalled(instance, 10.0 + guest.INPUT_STALL_SECONDS)

    def test_positive_real_write_progress_resets_the_deadline(self):
        pending = channel(guest.HIGH_WATER + 128)
        instance = carrier(pending)
        progress_time = 10.0 + guest.INPUT_STALL_SECONDS - 0.25
        with patch.object(guest.os, "write", return_value=32) as write, \
                patch.object(guest.time, "monotonic", return_value=progress_time):
            instance.write_channel(100, pending)
        write.assert_called_once()
        self.assertEqual(write.call_args.args[0], 100)
        self.assertEqual(pending["bytes"], guest.HIGH_WATER + 96)
        self.assertEqual(pending["progress_at"], progress_time)
        with patch.object(guest.time, "monotonic", return_value=10.0 + guest.INPUT_STALL_SECONDS + 0.5):
            instance.check_input_stall()
        self.stalled(instance, progress_time + guest.INPUT_STALL_SECONDS)

    def test_zero_write_refuses_without_claiming_progress(self):
        pending = channel(guest.HIGH_WATER)
        instance = carrier(pending)
        with patch.object(guest.os, "write", return_value=0), \
                patch.object(guest.time, "monotonic", return_value=11.0):
            with self.assertRaises(guest.Refused) as raised:
                instance.write_channel(100, pending)
        self.assertEqual(raised.exception.code, "CHANNEL_CLOSED")
        self.assertEqual(pending["bytes"], guest.HIGH_WATER)
        self.assertEqual(pending["progress_at"], 10.0)
        self.stalled(instance, 10.0 + guest.INPUT_STALL_SECONDS)

    def test_run_loop_stalled_input_starts_cleanup(self):
        pending = channel(guest.HIGH_WATER)
        instance = carrier(pending)
        now = 10.0 + guest.INPUT_STALL_SECONDS
        instance.spec = {"grace_ms": 10}
        instance.input_buffer = bytearray()
        instance.stop_requested = False
        instance.fatal_code = None
        instance.ready = True
        instance.cleanup_limit = None
        instance.cleanup_unknown = False
        instance.quiet = False
        instance.host_live = True
        instance.output = collections.deque()
        instance.output_bytes = 0
        instance.tree = Mock(root_status=None)
        instance.tree.census.return_value = ([], False)
        instance.selector = Mock()
        instance.launch = Mock()
        instance.close_channel = Mock()
        # Bound this check to one iteration in both implementations: removing
        # the run-loop watchdog returns success instead of hanging the test.
        instance.finish_if_drained = Mock(return_value=True)
        forbidden = AssertionError("mocked run-loop check attempted real I/O")
        with patch.object(guest.time, "monotonic", return_value=now), \
                patch.object(guest.signal, "signal"), \
                patch.object(guest.os, "fork", side_effect=forbidden), \
                patch.object(guest.os, "openpty", side_effect=forbidden), \
                patch.object(guest.os, "read", side_effect=forbidden), \
                patch.object(guest.os, "write", side_effect=forbidden), \
                patch.object(guest.os, "close", side_effect=forbidden):
            result = instance.run()
        self.assertEqual(result, 1, "stalled input must fail from the real run-loop watchdog")
        self.assertEqual(instance.fatal_code, "INPUT_STALLED")
        self.assertEqual(instance.cleanup_at, now)
        self.assertEqual(pending["bytes"], 0)
        self.assertFalse(pending["queue"])
        self.assertTrue(pending["end"])
        self.assertIsNone(pending["progress_at"])
        frames = [guest.json.loads(bytes(frame)) for frame in instance.output]
        self.assertEqual(frames, [{"type": "error", "error": "INPUT_STALLED"}])
        instance.launch.assert_called_once_with()
        instance.tree.census.assert_called_once_with()
        instance.tree.deliver.assert_not_called()
        instance.tree.close.assert_called_once_with()
        instance.selector.select.assert_not_called()
        instance.selector.close.assert_called_once_with()


def owned_tree():
    result = guest.OwnedTree.__new__(guest.OwnedTree)
    result.pid = 400
    result.root = 501
    result.root_status = None
    result.records = {}
    result.signaling_closed = False
    result.finalized = False
    return result


def process_fact(pid, parent=400):
    return {"pid": pid, "parent": parent, "state": b"S", "group": pid,
            "session": 501, "tty": 1, "started": pid * 7, "term_sent": False}


def exited(pid, code=None, status=0):
    return SimpleNamespace(si_pid=pid, si_code=guest.os.CLD_EXITED if code is None else code,
                           si_status=status)


class ReservedChildChecks(unittest.TestCase):
    def setUp(self):
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        # Linux wait constants are explicit fixtures even when checks run on a
        # different POSIX source host. No real child/wait/signal is permitted.
        for name, value in (("P_PID", 1), ("WEXITED", 4), ("WNOHANG", 1),
                            ("WNOWAIT", 0x01000000), ("CLD_EXITED", 1),
                            ("CLD_KILLED", 2), ("CLD_DUMPED", 3)):
            self.patches.enter_context(patch.object(guest.os, name, value, create=True))
        forbidden = AssertionError("ownership check attempted an unmocked OS operation")
        self.waitid = self.patches.enter_context(patch.object(guest.os, "waitid", side_effect=forbidden, create=True))
        self.waitpid = self.patches.enter_context(patch.object(guest.os, "waitpid", side_effect=forbidden))
        self.kill = self.patches.enter_context(patch.object(guest.os, "kill", side_effect=forbidden))
        self.children = self.patches.enter_context(patch.object(guest, "child_pids", side_effect=forbidden))
        self.fact = self.patches.enter_context(patch.object(guest, "proc_stat", side_effect=forbidden))

    def test_sigchld_default_prevents_inherited_auto_reap(self):
        libc = Mock()
        libc.prctl.return_value = 0
        with patch.object(guest.sys, "platform", "linux"), \
                patch.object(guest.ctypes, "CDLL", return_value=libc), \
                patch.object(guest.signal, "signal") as disposition, \
                patch.object(guest.os, "getpid", return_value=400):
            tree = guest.OwnedTree()
        disposition.assert_called_once_with(guest.signal.SIGCHLD, guest.signal.SIG_DFL)
        self.assertFalse(tree.signaling_closed)
        self.waitid.assert_not_called()
        self.waitpid.assert_not_called()

    def test_adoption_reserves_children_until_every_signal_is_over(self):
        tree = owned_tree()
        tree.records[501] = process_fact(501)
        direct = {501}
        statuses = {501: None, 701: None}
        events = []

        def wait(id_type, pid, flags):
            self.assertEqual(id_type, guest.os.P_PID)
            self.assertTrue(flags & guest.os.WNOWAIT, "a custody observation must never reap")
            self.assertTrue(flags & 0x40000000, "clone children must remain in scope")
            self.assertIn(pid, direct)
            events.append(("observe", pid))
            return statuses[pid]

        def deliver(pid, number):
            self.assertIn(pid, direct)
            self.assertIsNone(statuses[pid])
            self.assertFalse(tree.signaling_closed)
            events.append(("signal", pid))
            statuses[pid] = exited(pid, guest.os.CLD_KILLED, number)
            if pid == 501:
                direct.add(701)  # Linux subreaper adoption after owner death.

        def reap(pid, flags):
            self.assertEqual(pid, -1)
            self.assertTrue(flags & 0x40000000, "final reap must include clone children")
            self.assertTrue(tree.signaling_closed)
            self.assertTrue(all(statuses[child] is not None for child in direct))
            if not direct:
                raise ChildProcessError()
            child = min(direct)
            direct.remove(child)
            events.append(("reap", child))
            return child, statuses[child].si_status

        self.waitid.side_effect = wait
        self.kill.side_effect = deliver
        self.waitpid.side_effect = reap
        self.children.side_effect = lambda pid: set(direct) if pid == 400 else self.fail("non-direct cleanup census")
        self.fact.side_effect = process_fact
        live, quiet = tree.census()
        self.assertFalse(quiet)
        self.assertEqual([item["pid"] for item in live], [501])
        tree.deliver(live[0], guest.signal.SIGTERM)
        live, quiet = tree.census()
        self.assertFalse(quiet)
        self.assertEqual([item["pid"] for item in live], [701])
        self.assertIn(501, tree.records, "dead owner identity must stay reserved")
        self.waitpid.assert_not_called()
        tree.deliver(live[0], guest.signal.SIGTERM)
        live, quiet = tree.census()
        self.assertEqual(live, [])
        self.assertTrue(quiet)
        self.assertTrue(tree.finalized)
        self.assertEqual(tree.root_status, guest.signal.SIGTERM)
        self.assertEqual(tree.records, {})
        signal_positions = [index for index, event in enumerate(events) if event[0] == "signal"]
        reap_positions = [index for index, event in enumerate(events) if event[0] == "reap"]
        self.assertLess(max(signal_positions), min(reap_positions))

    def test_non_child_ledger_entry_cannot_authorize_a_pid_signal(self):
        tree = owned_tree()
        borrowed = process_fact(777)
        tree.records[777] = borrowed
        self.waitid.side_effect = ChildProcessError()
        with self.assertRaises(guest.Refused) as raised:
            tree.deliver(borrowed, guest.signal.SIGKILL)
        self.assertEqual(raised.exception.code, "OWNERSHIP_UNKNOWN")
        self.kill.assert_not_called()
        self.waitpid.assert_not_called()

    def test_live_child_blocks_final_reaping(self):
        tree = owned_tree()
        tree.records[501] = process_fact(501)
        self.children.side_effect = None
        self.children.return_value = {501}
        self.waitid.side_effect = None
        self.waitid.return_value = None
        self.assertFalse(tree.reap_final())
        self.assertFalse(tree.signaling_closed)
        self.waitpid.assert_not_called()

    def test_echild_and_leftover_children_never_certify_finalization(self):
        for ending in ("excluded-clone", "leftover-child"):
            with self.subTest(ending=ending):
                tree = owned_tree()
                tree.records[501] = process_fact(501)
                self.waitid.side_effect = None
                self.waitid.return_value = exited(501)
                self.children.side_effect = [{501}, {501}, {999}]
                self.waitpid.side_effect = [ChildProcessError()] if ending == "excluded-clone" else [(501, 0), ChildProcessError()]
                with self.assertRaises(guest.Refused) as raised:
                    tree.reap_final()
                self.assertEqual(raised.exception.code, "OWNERSHIP_UNKNOWN")
                self.assertFalse(tree.finalized)
                self.assertEqual(tree.census(), ([], False))
                self.assertTrue(self.waitpid.call_args.args[1] & 0x40000000)
                self.kill.assert_not_called()

    def test_tty_int_and_tstp_use_kernel_group_selection(self):
        instance = carrier(channel())
        instance.channels[100]["kind"] = "output"
        instance.foreground = Mock(return_value={"processGroupId": 777, "inputWaiting": False})
        with patch.object(guest.os, "tcgetpgrp", return_value=777), \
                patch.object(guest, "tty_signal_ioctl", return_value=0x40045436), \
                patch.object(guest.fcntl, "ioctl", return_value=0) as ioctl:
            for name in ("SIGINT", "SIGTSTP"):
                self.assertEqual(instance.signal_foreground(name), 777)
                ioctl.assert_called_with(100, 0x40045436, guest.SIGNALS[name])
        self.kill.assert_not_called()
        self.waitpid.assert_not_called()

    def test_non_direct_foreground_term_kill_hup_are_refused(self):
        instance = carrier(channel())
        instance.channels[100]["kind"] = "output"
        instance.foreground = Mock(return_value={"processGroupId": 777, "inputWaiting": False})
        instance.tree = owned_tree()
        instance.tree.records[501] = process_fact(501)
        instance.tree.observations = Mock(return_value=[process_fact(777, parent=501)])
        with patch.object(guest.os, "tcgetpgrp", return_value=777):
            for name in ("SIGTERM", "SIGKILL", "SIGHUP"):
                with self.assertRaises(guest.Refused) as raised:
                    instance.signal_foreground(name)
                self.assertEqual(raised.exception.code, "FOREGROUND_SIGNAL_UNAVAILABLE")
        self.waitid.assert_not_called()
        self.kill.assert_not_called()
        self.waitpid.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
