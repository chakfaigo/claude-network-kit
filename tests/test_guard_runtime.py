#!/usr/bin/env python3
"""Real supervisor logic with denied external calls and a temporary write jail."""
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
JAIL = None
GUARDED = False
runtime = health = None


def forbidden(*args, **kwargs):
    raise AssertionError("Offline harness forbids external operations")


def allowed_write(path):
    if isinstance(path, int):
        return
    resolved = Path(os.fsdecode(path)).resolve()
    if resolved != JAIL and JAIL not in resolved.parents:
        raise AssertionError("Offline harness forbids writes outside temporary directory")


def audit(event, args):
    if not GUARDED:
        return
    if event.startswith(("socket.", "subprocess.")) or event in ("os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.kill", "os.killpg"):
        forbidden()
    if event == "open" and len(args) > 2 and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        allowed_write(args[0])
    if event in ("os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.utime"):
        allowed_write(args[0])
    if event in ("os.rename", "os.link"):
        allowed_write(args[0]); allowed_write(args[1])
    if event == "os.symlink":
        allowed_write(args[1])


class FakeChild:
    def __init__(self, pid, events, exited=False, stubborn=False):
        self.pid, self.events = pid, events
        self.status = 1 if exited else None
        self.stubborn = stubborn
        self.killed = False

    def poll(self):
        return self.status

    def terminate(self):
        self.events.append(("terminate", self.pid))
        if not self.stubborn:
            self.status = 0

    def wait(self, timeout):
        if self.stubborn and not self.killed:
            raise subprocess.TimeoutExpired("fake-child", timeout)
        return self.status

    def kill(self):
        self.events.append(("kill", self.pid))
        self.killed, self.status = True, -9


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        case_root = Path(tempfile.mkdtemp(prefix="case-", dir=JAIL))
        def cleanup():
            for path in sorted(case_root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
                path.rmdir() if path.is_dir() and not path.is_symlink() else path.unlink()
            case_root.rmdir()
        self.addCleanup(cleanup)
        runtime.ROOT = case_root
        runtime.PRIVATE = runtime.ROOT / "private"
        runtime.STATUS = runtime.ROOT / "public/status.json"
        runtime.PRIVATE.mkdir()
        runtime.STATUS.parent.mkdir()
        self.events, self.children = [], []
        self.clock = 10.0
        self.wall_offset = 1000.0
        self.listen = self.route = True
        self.wrong_listener = self.early_exit = self.stubborn = False
        self.guard_valid = True
        self.guard_error = self.pf_error = self.check_error = None
        self.probe_outputs = []
        self.config_names = ("original", "home_direct_blocked", "home_direct", "home_relay_blocked", "home_relay")
        self.bundle = {"configs": {name: {"fixture": name} for name in self.config_names}}
        for name, config in self.bundle["configs"].items():
            (runtime.PRIVATE / (name + ".json")).write_text(json.dumps(config))
        patches = (
            mock.patch.object(runtime, "ensure_pf", side_effect=self.ensure_pf),
            mock.patch.object(runtime, "guard_ok", side_effect=self.guard_ok),
            mock.patch.object(runtime, "trusted", side_effect=lambda path, directory=False: self.events.append(("trusted", str(path)))),
            mock.patch.object(runtime.time, "monotonic", side_effect=lambda: self.clock),
            mock.patch.object(runtime.time, "time", side_effect=lambda: self.clock + self.wall_offset),
            mock.patch.object(runtime.time, "sleep", side_effect=self.sleep),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.supervisor = runtime.Supervisor(health, types.SimpleNamespace(), self.bundle, runner=self.runner, probe_fn=self.probe, popen=self.popen)
        self.addCleanup(self.supervisor.stop)

    def sleep(self, seconds):
        self.clock += seconds

    def ensure_pf(self, pfmod, initial=False):
        self.events.append(("pf", initial))
        if self.pf_error:
            raise self.pf_error

    def guard_ok(self, pfmod):
        self.events.append(("guard",))
        if self.guard_error:
            raise self.guard_error
        return self.guard_valid

    def runner(self, argv, check=True, timeout=20):
        argv = [str(x) for x in argv]
        binary = Path(argv[0]).name
        self.events.append((binary, argv))
        if binary == "sing-box":
            self.assertEqual(argv[1:3], ["check", "-c"])
            if self.check_error:
                raise self.check_error
            return subprocess.CompletedProcess(argv, 0, "", "")
        if binary == "lsof":
            child = self.supervisor.child
            self.assertEqual(argv[1:], ["-a", "-p", str(child.pid), "-iTCP:10808", "-sTCP:LISTEN", "-t"])
            return subprocess.CompletedProcess(argv, 0 if self.listen else 1, str(child.pid + int(self.wrong_listener)) + "\n" if self.listen else "", "")
        if binary == "route":
            self.assertEqual(argv[1:], ["-n", "get", "1.1.1.1"])
            return subprocess.CompletedProcess(argv, 0, " interface: " + ("utun99" if self.route else "en0") + "\n", "")
        raise AssertionError("Unexpected command attempted: " + binary)

    def popen(self, argv, **kwargs):
        self.events.append(("spawn", argv))
        self.assertEqual(argv[1:3], ["run", "-c"])
        self.assertEqual(kwargs["env"], runtime.ENV)
        child = FakeChild(100 + len(self.children), self.events, self.early_exit, self.stubborn)
        self.children.append(child)
        return child

    def probe(self):
        self.events.append(("probe",))
        answer = self.probe_outputs.pop(0) if self.probe_outputs else [health.EXPECTED_IP, health.EXPECTED_IP]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def begin(self, mode="home", request="request-one"):
        self.supervisor.begin({"id": request, "mode": mode})

    def healthy(self):
        self.begin()
        self.supervisor.round()
        self.supervisor.round()
        self.assertEqual(self.status()["phase"], "healthy")

    def status(self):
        return json.loads(runtime.STATUS.read_text())

    def run_loops(self, count, hook=None, intent=None):
        """Advance the real loop using simulated wall/monotonic clocks only."""
        class Finished(Exception):
            pass
        snapshots = []
        def tick(seconds):
            self.assertEqual(seconds, 1)
            snapshots.append((self.clock, self.status(), self.supervisor.child))
            if len(snapshots) >= count:
                raise Finished()
            self.sleep(seconds)
            if hook:
                hook(len(snapshots))
        with mock.patch.object(self.supervisor, 'read_intent', side_effect=lambda: intent or self.supervisor.intent), mock.patch.object(runtime.time, 'sleep', side_effect=tick):
            with self.assertRaises(Finished):
                self.supervisor.run()
        return snapshots

    def test_wake_closes_old_core_before_any_probe_and_preserves_request(self):
        self.healthy()
        old = self.supervisor.child
        event = self.status()['event_id']
        saved = (runtime.PRIVATE / 'selection.json').read_bytes()
        self.events.clear()
        def wake(step):
            self.wall_offset += 3600
            self.events.clear()
        snapshots = self.run_loops(2, wake)
        status = snapshots[-1][1]
        self.assertIsNotNone(old.poll())
        self.assertNotIn(('probe',), self.events)
        self.assertEqual((status['reason'], status['successes'], status['policy']), ('starting', 0, 'home_blocked'))
        self.assertEqual(status['event_id'], event + 1)
        self.assertEqual(status['request_id'], 'request-one')
        self.assertFalse(self.supervisor.selecting)
        self.assertEqual((runtime.PRIVATE / 'selection.json').read_bytes(), saved)

    def test_wake_requires_spaced_successes_and_only_two_core_rebuilds(self):
        self.healthy()
        old_count = len(self.children)
        def wake(step):
            if step == 1:
                self.wall_offset += 3600
        snapshots = self.run_loops(25, wake)
        verifying = [(t, s) for t, s, c in snapshots if s['reason'] == 'verifying']
        recovered = [(t, s) for t, s, c in snapshots[1:] if s['phase'] == 'healthy']
        self.assertTrue(verifying)
        self.assertTrue(recovered)
        self.assertGreaterEqual(recovered[0][0] - verifying[0][0], 20)
        self.assertTrue(all(s['policy'] == 'home_blocked' for t, s, c in snapshots[1:] if t < recovered[0][0]))
        self.assertEqual(len(self.children), old_count + 2)

    def test_failed_recovery_resets_success_without_restarting_blocked_core(self):
        self.healthy()
        self.probe_outputs = [[None, None], [health.EXPECTED_IP], [None, None], [health.EXPECTED_IP], [health.EXPECTED_IP]]
        old_count = len(self.children)
        snapshots = self.run_loops(81)
        by_time = {int(t - snapshots[0][0]): s for t, s, c in snapshots}
        self.assertEqual(by_time[0]['reason'], 'unreachable')
        self.assertEqual(by_time[20]['successes'], 1)
        self.assertEqual(by_time[40]['successes'], 0)
        self.assertEqual(by_time[60]['successes'], 1)
        self.assertEqual(by_time[80]['phase'], 'healthy')
        self.assertTrue(all(s['phase'] == 'blocked' for t, s, c in snapshots[:-1]))
        self.assertEqual(len(self.children), old_count + 2)

    def test_wake_keeps_saved_relay_and_does_not_fall_back_on_failures(self):
        (runtime.PRIVATE / 'selection.json').write_text(json.dumps({'id': 'request-one', 'choice': 'relay'}))
        self.healthy()
        self.probe_outputs = [[None, None]] * 5
        def wake(step):
            if step == 1:
                self.wall_offset += 3600
        self.run_loops(65, wake)
        self.assertEqual(self.supervisor.choice, 'relay')
        self.assertEqual(self.supervisor.current, 'home_relay_blocked')
        self.assertFalse(self.supervisor.selecting)
        self.assertEqual(self.status()['mode'], 'home')

    def test_origin_is_not_rebuilt_on_wake(self):
        self.begin('original')
        old = self.supervisor.child
        self.run_loops(4, lambda step: setattr(self, 'wall_offset', self.wall_offset + 3600))
        self.assertIs(self.supervisor.child, old)
        self.assertEqual(self.status()['policy'], 'original_blocked')
        self.assertNotIn(('probe',), self.events)

    def test_new_manual_intent_takes_precedence_over_wake(self):
        self.healthy()
        intent = dict(self.supervisor.intent)
        def wake(step):
            self.wall_offset += 3600
            intent.update(id='new-origin', mode='original')
        with mock.patch.object(self.supervisor, 'resume_home', wraps=self.supervisor.resume_home) as resume:
            self.run_loops(3, wake, intent)
            resume.assert_not_called()
        self.assertEqual(self.status()['request_id'], 'new-origin')
        self.assertEqual(self.status()['policy'], 'original_blocked')

    def test_slow_probe_and_normal_poll_do_not_trigger_wake_rebuild(self):
        self.healthy()
        old = self.supervisor.child
        def slow_probe():
            self.clock += 14
            return [health.EXPECTED_IP]
        self.supervisor.probe_fn = slow_probe
        self.run_loops(45)
        self.assertIs(self.supervisor.child, old)
        self.assertEqual(self.status()['phase'], 'healthy')

    def test_sleep_inside_successful_probe_cannot_keep_old_core_open(self):
        self.healthy()
        old = self.supervisor.child
        def interrupted_probe():
            self.wall_offset += 3600
            return [health.EXPECTED_IP]
        self.supervisor.probe_fn = interrupted_probe
        self.supervisor.round()
        self.assertIsNotNone(old.poll())
        self.assertEqual(self.status()['reason'], 'starting')
        self.assertEqual(self.status()['successes'], 0)
        self.assertEqual(self.status()['policy'], 'home_blocked')

    def test_sleep_inside_second_success_cannot_finish_recovery(self):
        self.healthy()
        self.probe_outputs = [[None, None], [health.EXPECTED_IP]]
        self.supervisor.round()
        self.supervisor.round()
        self.assertEqual(self.status()['successes'], 1)
        def interrupted_probe():
            self.wall_offset += 3600
            return [health.EXPECTED_IP]
        self.supervisor.probe_fn = interrupted_probe
        self.supervisor.round()
        self.assertEqual(self.status()['successes'], 0)
        self.assertEqual(self.status()['policy'], 'home_blocked')

    def test_slow_guard_work_is_excluded_from_idle_gap(self):
        self.healthy()
        old = self.supervisor.child
        def slow_guard(pfmod):
            self.clock += 18
            return True
        with mock.patch.object(runtime, 'guard_ok', side_effect=slow_guard):
            self.run_loops(25)
        self.assertIs(self.supervisor.child, old)
        self.assertEqual(self.status()['phase'], 'healthy')

    def test_wake_discards_partial_validation_and_resets_startup_failures(self):
        self.begin()
        self.supervisor.round()
        self.supervisor.startup_failures = 1
        self.supervisor.resume_home()
        self.assertEqual(self.status()['successes'], 0)
        self.assertEqual(self.supervisor.startup_failures, 0)
        self.assertTrue(self.supervisor.selecting)
        self.supervisor.round()
        self.assertEqual(self.status()['phase'], 'blocked')
        self.assertEqual(self.status()['successes'], 1)

    def test_resume_config_failure_stops_old_core_and_publishes_block(self):
        self.healthy()
        old = self.supervisor.child
        self.check_error = RuntimeError('simulated bad config')
        with self.assertRaises(RuntimeError):
            self.supervisor.resume_home()
        self.assertIsNotNone(old.poll())
        self.assertIsNone(self.supervisor.child)
        self.assertEqual(self.status()['policy'], 'home_blocked')
        self.assertEqual(self.status()['reason'], 'monitor_error')
        self.assertFalse(self.status()['core_running'])

    def test_manual_selection_keeps_fast_initial_validation(self):
        self.begin()
        snapshots = self.run_loops(3)
        self.assertEqual(snapshots[0][1]['reason'], 'verifying')
        self.assertEqual(snapshots[2][1]['phase'], 'healthy')
        self.assertEqual(snapshots[2][0] - snapshots[0][0], 2)

    def test_backward_clock_jump_is_conservatively_revalidated(self):
        self.healthy()
        self.run_loops(2, lambda step: setattr(self, 'wall_offset', self.wall_offset - 3600))
        self.assertEqual(self.status()['reason'], 'starting')
        self.assertEqual(self.status()['policy'], 'home_blocked')

    def test_pf_and_config_check_precede_core_spawn_and_ready_publish(self):
        self.begin()
        names = [item[0] for item in self.events]
        self.assertLess(names.index("pf"), names.index("sing-box"))
        self.assertLess(names.index("sing-box"), names.index("spawn"))
        self.assertLess(names.index("spawn"), names.index("lsof"))
        self.assertLess(names.index("lsof"), names.index("route"))
        self.assertEqual((self.status()["policy"], self.status()["core_running"]), ("home_blocked", True))

    def test_initial_block_then_two_rounds_open(self):
        self.begin()
        self.supervisor.round()
        self.assertEqual((self.status()["phase"], self.status()["successes"]), ("blocked", 1))
        self.supervisor.round()
        self.assertEqual((self.status()["policy"], self.status()["core_running"]), ("home_open", True))
        self.assertEqual(self.supervisor.current, "home_direct")

    def test_wrong_exit_stops_open_connections_and_applies_block(self):
        self.healthy()
        old = self.supervisor.child
        self.probe_outputs = [["203.0.113.10", health.EXPECTED_IP]]
        self.supervisor.round()
        self.assertIsNotNone(old.poll())
        self.assertIn(("terminate", old.pid), self.events)
        self.assertEqual((self.status()["policy"], self.status()["reason"]), ("home_blocked", "wrong_exit"))

    def test_unreachable_is_immediate_and_recovery_needs_two_rounds(self):
        self.healthy()
        self.probe_outputs = [[None, None]]
        self.supervisor.round()
        self.assertEqual(self.status()["phase"], "blocked")
        self.supervisor.round()
        self.assertEqual(self.status()["phase"], "blocked")
        self.supervisor.round()
        self.assertEqual(self.status()["phase"], "healthy")

    def test_failed_config_validation_cannot_leave_old_open_core(self):
        self.healthy()
        old = self.supervisor.child
        (runtime.PRIVATE / "home_direct_blocked.json").write_text('{"changed":true}')
        self.probe_outputs = [[None, None]]
        with self.assertRaises(RuntimeError):
            self.supervisor.round()
        self.assertIsNotNone(old.poll())
        self.assertIsNone(self.supervisor.child)
        self.assertFalse(self.status()["core_running"])
        self.assertEqual(self.status()["phase"], "blocked")

    def test_check_failure_stops_old_core_before_check(self):
        self.healthy()
        old = self.supervisor.child
        self.events.clear()
        self.check_error = RuntimeError("offline bad config")
        self.probe_outputs = [[None, None]]
        with self.assertRaises(RuntimeError):
            self.supervisor.round()
        names = [event[0] for event in self.events]
        self.assertLess(names.index("terminate"), names.index("sing-box"))
        self.assertIsNotNone(old.poll())

    def test_core_death_restarts_blocked_with_pf_retained(self):
        self.healthy()
        self.supervisor.child.status = 1
        self.supervisor.round()
        self.assertEqual((self.status()["phase"], self.status()["reason"]), ("blocked", "core_restart"))
        self.assertEqual(self.supervisor.current, "home_direct_blocked")
        self.assertFalse(any(event[0] == "pfctl" for event in self.events))

    def test_route_loss_blocks_both_modes_before_proxy_probe_and_rebuilds(self):
        for mode in ("home", "original"):
            with self.subTest(mode=mode):
                self.route = True
                self.healthy() if mode == "home" else self.begin("original")
                old = self.supervisor.child
                self.events.clear()
                self.route = False
                self.supervisor.round()
                self.assertIsNotNone(old.poll())
                self.assertIsNone(self.supervisor.child)
                self.assertEqual((self.status()["phase"], self.status()["reason"],
                                  self.status()["core_running"]), ("blocked", "network_not_ready", False))
                self.assertNotIn(("probe",), self.events)
                self.route = True
                self.supervisor.round()
                self.assertTrue(self.status()["core_running"])
                self.assertEqual(self.status()["policy"], mode + "_blocked")
                if mode == "home":
                    self.supervisor.round()
                    self.assertEqual(self.status()["policy"], "home_blocked")
                    self.supervisor.round()
                    self.assertEqual(self.status()["policy"], "home_open")

    def test_lost_or_replaced_listener_cannot_remain_healthy(self):
        for field in ("listen", "wrong_listener"):
            with self.subTest(field=field):
                self.listen, self.wrong_listener = True, False
                self.healthy()
                old = self.supervisor.child
                setattr(self, field, field == "wrong_listener")
                self.events.clear()
                self.supervisor.round()
                self.assertIsNotNone(old.poll())
                self.assertFalse(self.status()["core_running"])
                self.assertEqual(self.status()["policy"], "home_blocked")
                self.assertNotIn(("probe",), self.events)

    def test_readiness_query_timeout_fails_closed(self):
        self.healthy()
        old = self.supervisor.child
        with mock.patch.object(self.supervisor, "runner", side_effect=subprocess.TimeoutExpired("lsof", 2)):
            self.supervisor.round()
        self.assertIsNotNone(old.poll())
        self.assertEqual(self.status()["reason"], "network_not_ready")
        self.assertFalse(self.status()["core_running"])

    def test_dead_core_cannot_publish_healthy(self):
        self.healthy()
        self.supervisor.child.status = 1
        self.supervisor.publish()
        self.assertEqual((self.status()["phase"], self.status()["core_running"]), ("blocked", False))

    def test_policy_mismatch_cannot_publish_healthy(self):
        self.healthy()
        self.supervisor.current = "home_direct_blocked"
        self.supervisor.publish()
        self.assertEqual((self.status()["phase"], self.status()["core_running"]), ("blocked", False))

    def test_original_stays_blocked_and_does_not_probe(self):
        self.begin("original")
        for _ in range(3):
            self.supervisor.round()
        self.assertEqual((self.status()["policy"], self.status()["core_running"]), ("original_blocked", True))
        self.assertFalse(any(event[0] == "probe" for event in self.events))

    def test_explicit_request_switch_stops_previous_core(self):
        self.healthy()
        old = self.supervisor.child
        self.begin("original", "request-two")
        self.assertIsNotNone(old.poll())
        self.assertEqual((self.status()["request_id"], self.status()["policy"]), ("request-two", "original_blocked"))
        self.begin("home", "request-three")
        self.assertEqual((self.status()["route"], self.status()["policy"]), ("direct", "home_blocked"))

    def test_startup_direct_then_relay_then_original_fallback(self):
        self.begin()
        self.probe_outputs = [[None, None]] * 4
        self.supervisor.round()
        self.supervisor.round()
        self.assertEqual(self.supervisor.current, "home_relay_blocked")
        self.supervisor.round()
        self.supervisor.round()
        self.assertEqual(self.supervisor.current, "original")
        self.assertEqual(self.status()["policy"], "original_blocked")
        self.assertEqual(json.loads((runtime.PRIVATE / "selection.json").read_text())["choice"], "original")

    def test_fresh_mac_without_relay_falls_back_to_protected_origin(self):
        self.bundle['has_relay'] = False
        self.begin()
        self.probe_outputs = [[None, None]] * 2
        self.supervisor.round()
        self.supervisor.round()
        self.assertEqual(self.supervisor.current, 'original')
        self.assertEqual(self.status()['policy'], 'original_blocked')
        self.assertFalse(any('home_relay' in str(e) for e in self.events))

    def test_fresh_mac_rejects_stale_relay_selection(self):
        self.bundle['has_relay'] = False
        (runtime.PRIVATE / 'selection.json').write_text('{"id":"request-one","choice":"relay"}')
        self.begin()
        self.assertEqual(self.supervisor.current, 'home_direct_blocked')

    def test_running_home_failure_never_switches_route(self):
        self.healthy()
        self.probe_outputs = [[None, None]] * 4
        for _ in range(4):
            self.supervisor.round()
        self.assertEqual(self.supervisor.choice, "direct")
        self.assertEqual(self.supervisor.current, "home_direct_blocked")

    def test_saved_choice_only_applies_to_same_request(self):
        (runtime.PRIVATE / "selection.json").write_text('{"id":"request-one","choice":"relay"}')
        self.begin()
        self.assertEqual(self.supervisor.current, "home_relay_blocked")
        self.begin(request="new-request")
        self.assertEqual(self.supervisor.current, "home_direct_blocked")

    def test_corrupt_selection_cache_never_prevents_safe_manual_recovery(self):
        for raw in ('{broken', '[]', 'null'):
            with self.subTest(raw=raw):
                (runtime.PRIVATE / 'selection.json').write_text(raw)
                self.begin()
                self.assertEqual(self.supervisor.current, 'home_direct_blocked')
                self.assertEqual(self.status()['phase'], 'blocked')
                self.begin(mode='original')
                self.assertEqual(self.supervisor.current, 'original')
                self.assertEqual(self.status()['policy'], 'original_blocked')

    def test_guard_failure_stops_core_and_retains_blocking_pf(self):
        self.healthy()
        old = self.supervisor.child
        self.guard_valid = False
        self.supervisor.round()
        self.assertIsNotNone(old.poll())
        self.assertEqual((self.status()["reason"], self.status()["core_running"]), ("firewall_error", False))
        self.assertIn(("pf", True), self.events)

    def test_guard_exception_stops_core_before_raising(self):
        self.healthy()
        old = self.supervisor.child
        self.guard_error = RuntimeError("offline PF failure")
        with self.assertRaises(RuntimeError):
            self.supervisor.round()
        self.assertIsNotNone(old.poll())
        self.assertEqual((self.status()["phase"], self.status()["core_running"]), ("blocked", False))

    def test_probe_exception_stops_core_before_raising(self):
        self.healthy()
        self.probe_outputs = [RuntimeError("offline probe failure")]
        with self.assertRaises(RuntimeError):
            self.supervisor.round()
        self.assertIsNone(self.supervisor.child)
        self.assertFalse(self.status()["core_running"])

    def test_pf_install_failure_never_spawns_core_or_rolls_back_pf(self):
        self.pf_error = RuntimeError("offline PF failure")
        with self.assertRaises(RuntimeError):
            self.begin()
        self.assertEqual(self.children, [])
        self.assertEqual([event[0] for event in self.events], ["pf"])

    def test_no_listener_times_out_within_ten_seconds_and_stops(self):
        self.listen = False
        start = self.clock
        with self.assertRaisesRegex(RuntimeError, "10 秒"):
            self.begin()
        self.assertLessEqual(self.clock - start, 10.01)
        self.assertIsNone(self.supervisor.child)
        self.assertIsNotNone(self.children[-1].poll())
        self.assertIsNone(self.supervisor.log)

    def test_listener_owned_by_other_pid_is_not_ready(self):
        self.wrong_listener = True
        with self.assertRaises(RuntimeError):
            self.begin()
        self.assertFalse(any(event[0] == "route" for event in self.events))
        self.assertIsNone(self.supervisor.child)

    def test_wrong_tun_times_out_and_stops(self):
        self.route = False
        with self.assertRaises(RuntimeError):
            self.begin("original")
        self.assertIsNone(self.supervisor.child)
        self.assertIsNotNone(self.children[-1].poll())

    def test_core_early_exit_is_not_ready(self):
        self.early_exit = True
        with self.assertRaisesRegex(RuntimeError, "就绪前退出"):
            self.begin()
        self.assertIsNone(self.supervisor.child)
        self.assertFalse(self.supervisor.ready)

    def test_stubborn_core_is_killed_and_reaped(self):
        self.stubborn = True
        self.begin()
        child = self.supervisor.child
        self.supervisor.stop()
        self.assertIn(("kill", child.pid), self.events)
        self.assertIsNone(self.supervisor.child)
        self.assertIsNone(self.supervisor.log)

    def test_probe_commands_force_proxy_ipv4_and_no_direct_fallback(self):
        calls = []
        outputs = [subprocess.TimeoutExpired("fake", 7), subprocess.CompletedProcess([], 0, "ip=" + health.EXPECTED_IP + "\n", "")]
        def fake_command(argv, **kwargs):
            calls.append(argv)
            value = outputs.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        with mock.patch.object(runtime, "command", side_effect=fake_command):
            self.assertEqual(runtime.probe(), [None, health.EXPECTED_IP])
        self.assertEqual(len(calls), 2)
        for argv in calls:
            self.assertEqual(argv[:2], ["/usr/bin/curl", "-q"])
            self.assertEqual(argv[argv.index("--proxy") + 1], "http://127.0.0.1:10808")
            self.assertEqual(argv[argv.index("--noproxy") + 1], "")
            self.assertIn("-4", argv)

    def test_trace_parser_rejects_duplicate_ip_and_wrong_ip_is_preserved(self):
        self.assertIsNone(runtime.parse_probe("ip=203.0.113.1\nip=" + health.EXPECTED_IP))
        self.assertEqual(runtime.parse_probe("ip=203.0.113.1\r\n"), "203.0.113.1")

    def test_probe_logs_timeout_stage_and_success_without_response_secrets(self):
        outputs = [
            subprocess.CompletedProcess([], 28, 'sensitive-response\nGUARD_METRICS 000 200 0.001 0.000 0.000 3.001', 'sensitive-error'),
            subprocess.CompletedProcess([], 0, 'ip=' + health.EXPECTED_IP + '\nsecret=sensitive-response\nGUARD_METRICS 200 200 0.001 0.900 1.100 1.200', ''),
        ]
        with mock.patch.object(runtime, 'command', side_effect=outputs):
            result = runtime.probe()
        self.assertEqual(result, [None, health.EXPECTED_IP])
        path = runtime.PRIVATE / 'health-probes.jsonl'
        text = path.read_text()
        self.assertNotIn('sensitive', text)
        self.assertNotIn('secret=', text)
        record = json.loads(text)
        self.assertEqual(record['supervisor_pid'], os.getpid())
        first, second = record['checks']
        self.assertEqual(first['curl_exit'], 28)
        self.assertEqual(first['proxy_connect_status'], 200)
        self.assertEqual(first['tls_ready_s'], 0)
        self.assertEqual(second['tls_ready_s'], 0.9)
        self.assertEqual(second['result_ip'], health.EXPECTED_IP)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_probe_http_error_retains_status_but_never_authorizes_ip(self):
        response = subprocess.CompletedProcess([], 22, 'ip=' + health.EXPECTED_IP + '\nGUARD_METRICS 403 200 0.001 1.0 1.1 1.2', '')
        with mock.patch.object(runtime, 'command', return_value=response):
            self.assertEqual(runtime.probe(), [None, None])
        checks = json.loads((runtime.PRIVATE / 'health-probes.jsonl').read_text())['checks']
        self.assertTrue(all(c['http_status'] == 403 and c['result_ip'] is None for c in checks))

    def test_probe_command_timeout_and_spawn_failure_have_safe_error_labels(self):
        outputs = [subprocess.TimeoutExpired('sensitive-command', 7, output='sensitive-output'), OSError('sensitive-error')]
        with mock.patch.object(runtime, 'command', side_effect=outputs):
            self.assertEqual(runtime.probe(), [None, None])
        text = (runtime.PRIVATE / 'health-probes.jsonl').read_text()
        checks = json.loads(text)['checks']
        self.assertEqual([c['error'] for c in checks], ['command_timeout', 'command_unavailable'])
        self.assertNotIn('sensitive', text)

    def test_probe_diagnostic_disk_failure_does_not_change_health_results(self):
        response = subprocess.CompletedProcess([], 0, 'ip=' + health.EXPECTED_IP + '\nGUARD_METRICS 200 200 0.001 1 1.1 1.2', '')
        with mock.patch.object(runtime, 'command', return_value=response), mock.patch.object(runtime.os, 'open', side_effect=OSError('disk full')):
            results = runtime.probe()
        self.assertEqual(results, [health.EXPECTED_IP, health.EXPECTED_IP])
        self.assertEqual(health.decide_health(None, 'home', results)['reason'], 'verifying')

    def test_probe_log_rotation_keeps_previous_and_respects_file_permissions(self):
        path = runtime.PRIVATE / 'health-probes.jsonl'
        path.write_text('old log\n')
        with mock.patch.object(runtime, 'PROBE_LOG_LIMIT', 1):
            self.assertTrue(runtime.log_probe_round(self.clock, []))
        self.assertEqual((runtime.PRIVATE / 'health-probes.previous.jsonl').read_text(), 'old log\n')
        self.assertEqual(len(path.read_text().splitlines()), 1)
        first = path.read_text()
        with mock.patch.object(runtime, 'PROBE_LOG_LIMIT', 1):
            self.assertTrue(runtime.log_probe_round(self.clock + 1, []))
        self.assertEqual((runtime.PRIVATE / 'health-probes.previous.jsonl').read_text(), first)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_probe_log_symlink_is_not_followed(self):
        target = runtime.PRIVATE / 'unrelated.txt'
        target.write_text('unchanged')
        (runtime.PRIVATE / 'health-probes.jsonl').symlink_to(target)
        self.assertFalse(runtime.log_probe_round(self.clock, []))
        self.assertEqual(target.read_text(), 'unchanged')

    def test_probe_metrics_do_not_hide_wrong_or_duplicate_ip(self):
        for body, expected in [('ip=203.0.113.10\n', '203.0.113.10'), ('ip=203.0.113.10\nip=' + health.EXPECTED_IP, None)]:
            response = subprocess.CompletedProcess([], 0, body + '\nGUARD_METRICS 200 200 0.001 1 1.1 1.2', '')
            with mock.patch.object(runtime, 'command', return_value=response):
                self.assertEqual(runtime.probe(), [expected, expected])

    def test_invalid_metrics_cannot_change_validated_ip_or_emit_nonfinite_json(self):
        for metrics in ('200 200 0 NaN 1 2', '200 200 0 Inf 1 2', '200 200 0 -1 1 2', '200 200 0 601 1 2', 'malformed'):
            output = 'ip=' + health.EXPECTED_IP + '\nGUARD_METRICS ' + metrics
            body, parsed = runtime.probe_metrics(output)
            self.assertEqual(parsed, {})
            self.assertEqual(runtime.parse_probe(body), health.EXPECTED_IP)

    def test_curl_limits_and_targets_are_unchanged_by_diagnostics(self):
        response = subprocess.CompletedProcess([], 0, 'ip=' + health.EXPECTED_IP, '')
        with mock.patch.object(runtime, 'command', return_value=response) as command:
            runtime.probe()
        for call in command.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[argv.index('--connect-timeout') + 1], '3')
            self.assertEqual(argv[argv.index('--max-time') + 1], '5')
            self.assertEqual(argv[argv.index('--write-out') + 1], runtime.PROBE_METRICS)
            self.assertEqual(call.kwargs['timeout'], 7)
        self.assertEqual([c.args[0][-1] for c in command.call_args_list],
                         ['https://1.1.1.1/cdn-cgi/trace', 'https://www.cloudflare.com/cdn-cgi/trace'])

    def main_modules(self, name):
        self.events.append(("module", name))
        if name == "guard_pf":
            return types.SimpleNamespace()
        if name == "guard_health":
            return health
        if name == "guard_config":
            def validate(bundle):
                self.events.append(("validate_bundle",))
                if self.check_error:
                    raise self.check_error
            return types.SimpleNamespace(validate_bundle=validate)
        raise AssertionError("Unexpected module")

    def test_main_bad_bundle_installs_pf_before_loading_or_rejecting_config(self):
        (runtime.PRIVATE / "bundle.json").write_text("invalid-json")
        with mock.patch.object(runtime, "module", side_effect=self.main_modules), mock.patch.object(runtime.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                runtime.main()
        self.assertLess(self.events.index(("pf", False)), self.events.index(("module", "guard_health")))
        self.assertLess(self.events.index(("pf", False)), self.events.index(("module", "guard_config")))
        self.assertEqual((self.status()["phase"], self.status()["core_running"]), ("blocked", False))
        self.assertEqual(self.children, [])

    def test_main_bundle_validation_failure_retains_pf_and_publishes_block(self):
        (runtime.PRIVATE / "bundle.json").write_text(json.dumps(self.bundle))
        self.check_error = RuntimeError("offline invalid bundle")
        with mock.patch.object(runtime, "module", side_effect=self.main_modules), mock.patch.object(runtime.os, "geteuid", return_value=0):
            with self.assertRaises(RuntimeError):
                runtime.main()
        self.assertLess(self.events.index(("pf", False)), self.events.index(("validate_bundle",)))
        self.assertEqual(self.status()["reason"], "startup_error")
        self.assertEqual(self.children, [])

    def test_main_pf_failure_does_not_load_bundle_or_start_core(self):
        self.pf_error = RuntimeError("offline PF unavailable")
        with mock.patch.object(runtime, "module", side_effect=self.main_modules), mock.patch.object(runtime.os, "geteuid", return_value=0):
            with self.assertRaises(RuntimeError):
                runtime.main()
        self.assertNotIn(("module", "guard_config"), self.events)
        self.assertFalse(self.status()["core_running"])
        self.assertEqual(self.children, [])

    def test_harness_denies_external_calls_and_outside_writes(self):
        with self.assertRaises(AssertionError):
            subprocess.Popen(["/usr/bin/true"])
        with self.assertRaises(AssertionError):
            socket.create_connection(("127.0.0.1", 1))
        with self.assertRaisesRegex(AssertionError, "outside temporary"):
            (ROOT / "forbidden-write").write_text("must not be written")


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    global JAIL, GUARDED, runtime, health
    captured = io.StringIO()
    sys.dont_write_bytecode = True
    sys.addaudithook(audit)
    with tempfile.TemporaryDirectory(prefix="runtime-jail-", dir=ROOT) as directory:
        JAIL = Path(directory).resolve()
        GUARDED = True
        with contextlib.ExitStack() as guards:
            for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"):
                guards.enter_context(mock.patch.object(subprocess, name, side_effect=forbidden))
            for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
                guards.enter_context(mock.patch.object(socket, name, side_effect=forbidden))
            for name in dir(os):
                if name in ("system", "popen", "posix_spawn", "posix_spawnp", "fork", "forkpty") or name.startswith(("exec", "spawn")):
                    if callable(getattr(os, name)):
                        guards.enter_context(mock.patch.object(os, name, side_effect=forbidden))
            health, runtime = load("guard_health"), load("guard_runtime")
            health.EXPECTED_IP = "93.184.216.34"
            result = unittest.TextTestRunner(stream=captured, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeTests))
        GUARDED = False
    report = {"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "passed": result.wasSuccessful(), "source_sha256": hashlib.sha256((ROOT / "guard_runtime.py").read_bytes()).hexdigest(), "real_network_calls": 0, "real_system_commands": 0, "real_notifications": 0, "writes_during_test": "temporary directory only, enforced by audit hook", "guards_active_before_import": True, "details": captured.getvalue()}
    (ROOT / "runtime-test-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "details"}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
