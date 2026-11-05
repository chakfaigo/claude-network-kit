#!/usr/bin/env python3
"""Offline tests: import guarded, temporary files, no real notifications."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
notify = None


def forbidden(*args, **kwargs):
    raise AssertionError("External operations are forbidden in consumer tests")


class NotifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="notify-case-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        notify.STATE_DIR = Path(self.temp.name) / "local"
        notify.STATUS_PATH = Path(self.temp.name) / "public.json"
        self.now = 1000
        self.calls = []
        self.outcomes = []
        self.owner = 0
        self.permissions = 0o644

    def document(self, mode="home", phase="healthy", **extra):
        value = {"version": 1, "mode": mode, "phase": phase, "policy": "home_open" if phase == "healthy" else mode + "_blocked", "successes": 2 if phase == "healthy" else 0, "event_id": 1, "reason": "verified", "notice": "recovery" if phase == "healthy" else "fault", "updated_at": self.now, "core_running": True}
        value.update(extra)
        return value

    def fake_notify(self, argv, **kwargs):
        self.assertEqual(argv[:2], ["/usr/bin/osascript", "-"])
        self.assertEqual(kwargs["input"], notify.NOTIFICATION_SCRIPT)
        self.calls.append(argv)
        outcome = self.outcomes.pop(0) if self.outcomes else 0
        if isinstance(outcome, BaseException):
            raise outcome
        return subprocess.CompletedProcess(argv, outcome, "", "")

    def cycle(self, document=None, advance=30):
        if document is None:
            notify.STATUS_PATH.unlink(missing_ok=True)
        else:
            notify.STATUS_PATH.write_text(json.dumps(document))
        real_fstat = os.fstat
        def root_metadata(fd):
            values = list(real_fstat(fd))
            values[4] = self.owner
            values[0] = (values[0] & ~0o777) | self.permissions
            return os.stat_result(values)
        mask = os.umask(0o077)
        try:
            with mock.patch.object(notify.os, "fstat", side_effect=root_metadata), mock.patch.object(notify.subprocess, "run", side_effect=self.fake_notify), mock.patch.object(notify.time, "time", return_value=self.now):
                self.assertEqual(notify.main(), 0)
        finally:
            os.umask(mask)
        self.now += advance
        return notify.load_state()

    def test_initial_healthy_is_quiet(self):
        self.cycle(self.document())
        self.assertEqual(self.calls, [])

    def test_missed_short_outage_emits_one_current_recovery_summary(self):
        self.cycle(self.document(request_id="same-request", event_id=2))
        self.cycle(self.document(request_id="same-request", event_id=4))
        self.cycle(self.document(request_id="same-request", event_id=4))
        self.assertEqual([call[-1] for call in self.calls], ["recovery"])
        self.assertIn("短暂异常", self.calls[0][-2])
        self.assertIn("现已恢复", self.calls[0][-3])

    def test_multiple_missed_transitions_are_one_summary_per_observation(self):
        self.cycle(self.document(request_id="same-request", event_id=2))
        self.cycle(self.document(request_id="same-request", event_id=8))
        self.cycle(self.document(request_id="same-request", event_id=10))
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all("短暂异常" in call[-2] for call in self.calls))

    def test_new_install_new_request_and_event_reset_do_not_report_history(self):
        self.cycle(self.document(request_id="request-a", event_id=20))
        self.cycle(self.document(request_id="request-b", event_id=100))
        self.cycle(self.document(request_id="request-b", event_id=2))
        self.cycle(self.document(request_id="request-b", event_id=2))
        self.assertEqual(self.calls, [])

    def test_missing_or_bad_request_identity_does_not_invent_an_outage(self):
        self.cycle(self.document(request_id="request-a", event_id=2))
        for identity in (None, "", 7, [], {}):
            self.cycle(self.document(request_id=identity, event_id=100))
        self.cycle(self.document(event_id=100))
        self.cycle(self.document(request_id="request-a", event_id=200))
        self.assertEqual(self.calls, [])

    def test_bad_cached_identity_is_discarded_and_baseline_rebuilt(self):
        self.cycle(self.document(request_id="request-a", event_id=2))
        for request, event in (([], 1), ("request-a", "2"), ("request-a", True), ("request-a", -1)):
            cached = notify.load_state()
            cached.update(request_id=request, event_id=event)
            notify.write_local("state.json", cached)
            self.cycle(self.document(request_id="request-a", event_id=100))
        self.assertEqual(self.calls, [])

    def test_failed_short_outage_summary_retries_without_losing_specific_text(self):
        self.cycle(self.document(request_id="request-a", event_id=2))
        self.outcomes = [1, 0]
        self.assertIsNotNone(self.cycle(self.document(request_id="request-a", event_id=4))["pending"])
        self.cycle(self.document(request_id="request-a", event_id=4))
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.cycle(self.document(request_id="request-a", event_id=4))["pending"])
        self.cycle(self.document(request_id="request-a", event_id=4))
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all("短暂异常" in call[-2] for call in self.calls))

    def test_pending_outage_summary_is_not_replayed_after_request_changes(self):
        self.cycle(self.document(request_id="request-a", event_id=2))
        self.outcomes = [1]
        self.cycle(self.document(request_id="request-a", event_id=4))
        self.assertIsNone(self.cycle(self.document(request_id="request-b", event_id=20))["pending"])
        self.cycle(self.document(request_id="request-b", event_id=20))
        self.assertEqual(len(self.calls), 1)

    def test_missing_and_stale_status_are_one_continuous_fault(self):
        self.cycle()
        self.cycle(self.document(updated_at=0))
        self.cycle()
        self.assertEqual([c[-1] for c in self.calls], ["fault"])
        self.assertIn("无法确认", self.calls[0][-2])

    def test_missing_status_recovers_once(self):
        self.cycle()
        self.cycle(self.document())
        self.cycle(self.document())
        self.assertEqual([c[-1] for c in self.calls], ["fault", "recovery"])

    def test_blocked_then_verified_recovers_once(self):
        self.cycle(self.document(phase="blocked", reason="unreachable"))
        self.cycle(self.document(phase="blocked", successes=1, reason="verifying"))
        self.cycle(self.document())
        self.cycle(self.document())
        self.assertEqual([c[-1] for c in self.calls], ["fault", "recovery"])

    def test_initial_original_explicitly_says_claude_disabled(self):
        self.cycle(self.document(mode="original", phase="blocked"))
        self.cycle(self.document(mode="original", phase="blocked"))
        self.assertEqual([c[-1] for c in self.calls], ["original"])
        self.assertIn("Claude 保持禁用", self.calls[0][-2])

    def test_original_can_never_emit_fake_home_recovery(self):
        self.cycle(self.document(mode="original", phase="blocked"))
        self.cycle(self.document(mode="original", phase="healthy"))
        self.assertEqual([c[-1] for c in self.calls], ["original", "fault"])

    def test_stopped_core_blocks_both_healthy_and_original_normal_notice(self):
        for mode, phase in (("home", "healthy"), ("original", "blocked")):
            with self.subTest(mode=mode):
                result = notify.classify_status(self.document(mode=mode, phase=phase, core_running=False), self.now)
                self.assertEqual(result["condition"], "fault")
                self.assertIn("普通网络", result["message"])
                self.assertEqual("恢复原网络" in result["message"], mode == "home")
        self.assertEqual(notify.classify_status(self.document(core_running=1), self.now)["condition"], "fault")

    def test_switch_home_to_original_and_back_notifies_precisely(self):
        self.cycle(self.document())
        self.cycle(self.document(mode="original", phase="blocked"))
        self.cycle(self.document())
        self.assertEqual([c[-1] for c in self.calls], ["original", "recovery"])

    def test_non_root_or_writable_status_is_never_trusted(self):
        self.owner = 501
        self.cycle(self.document())
        self.assertEqual(self.calls[-1][-1], "fault")
        self.owner, self.permissions = 0, 0o666
        self.cycle(self.document())
        self.assertEqual(len(self.calls), 1)
        self.permissions = 0o644
        self.cycle(self.document())
        self.assertEqual(self.calls[-1][-1], "recovery")

    def test_invalid_schema_and_corrupt_timestamp_are_faults(self):
        values = [None, {}, [], self.document(successes=1), self.document(updated_at=10 ** 1000), self.document(updated_at=float("nan")), self.document(updated_at=self.now + 50), self.document(event_id=True), self.document(policy="direct")]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(notify.classify_status(value, self.now)["condition"], "fault")

    def test_failed_notification_retries_without_losing_state(self):
        self.outcomes = [1, 0]
        self.assertIsNotNone(self.cycle()["pending"])
        self.cycle()
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.cycle()["pending"])
        self.assertEqual(len(self.calls), 2)
        self.cycle()
        self.assertEqual(len(self.calls), 2)

    def test_notification_timeout_remains_pending(self):
        self.outcomes = [subprocess.TimeoutExpired("fake", 20)]
        self.assertIsNotNone(self.cycle()["pending"])

    def test_pending_failure_changes_to_current_recovery(self):
        self.outcomes = [1, 0]
        self.cycle()
        self.cycle(self.document())
        self.assertEqual([c[-1] for c in self.calls], ["fault", "recovery"])

    def test_corrupt_local_state_resets_without_crash(self):
        self.cycle()
        state = notify.load_state()
        state["last_attempt"] = 10 ** 1000
        notify.write_local("state.json", state)
        self.assertEqual(notify.load_state()["last_attempt"], 0)

    def test_lock_reentry_does_not_read_or_notify(self):
        notify.STATE_DIR.mkdir()
        with (notify.STATE_DIR / "watch.lock").open("w") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with mock.patch.object(notify, "read_status", side_effect=AssertionError("must not read")):
                self.cycle()
        self.assertEqual(self.calls, [])

    def test_private_state_and_bounded_log(self):
        self.cycle()
        self.assertEqual(notify.STATE_DIR.stat().st_mode & 0o777, 0o700)
        for path in notify.STATE_DIR.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(notify.read_local("events.json", [])), 1)


def main():
    global notify
    captured = io.StringIO()
    with contextlib.ExitStack() as guards:
        for name in ("Popen", "run", "call", "check_call", "check_output"):
            guards.enter_context(mock.patch.object(subprocess, name, side_effect=forbidden))
        for name in ("socket", "create_connection", "getaddrinfo"):
            guards.enter_context(mock.patch.object(socket, name, side_effect=forbidden))
        for name in ("system", "popen", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                guards.enter_context(mock.patch.object(os, name, side_effect=forbidden))
        spec = importlib.util.spec_from_file_location("guard_notify_test_subject", ROOT / "guard_notify.py")
        notify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notify)
        result = unittest.TextTestRunner(stream=captured, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NotifyTests))
    report = {"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "passed": result.wasSuccessful(), "real_network_or_system_changes": False, "real_notifications": 0, "details": captured.getvalue()}
    (ROOT / "notify-test-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "details"}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
