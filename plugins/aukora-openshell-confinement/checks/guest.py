#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pure mocked sink-watchdog regressions; no guest or host process starts."""

import collections
import importlib.util
from pathlib import Path
import sys
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
