#!/usr/bin/env python3
"""Offline functional tests; real process and networking APIs are disabled."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
health = None


def forbidden(*args, **kwargs):
    raise AssertionError("External operations are forbidden in health tests")


class HealthTests(unittest.TestCase):
    def initial(self, mode="home"):
        return health.decide_health(None, mode, [])

    def step(self, previous, probes=None, mode="home"):
        return health.decide_health(previous, mode, [health.EXPECTED_IP] if probes is None else probes)

    def healthy(self):
        return self.step(self.step(self.initial()))

    def test_initial_is_blocked(self):
        state = self.initial()
        self.assertEqual((state["phase"], state["policy"], state["successes"]), ("blocked", "home_blocked", 0))

    def test_startup_requires_two_distinct_rounds(self):
        first = self.step(self.initial(), [health.EXPECTED_IP, health.EXPECTED_IP])
        self.assertEqual((first["phase"], first["successes"]), ("blocked", 1))
        self.assertEqual(self.step(first)["policy"], "home_open")

    def test_outage_blocks_in_same_round(self):
        state = self.step(self.healthy(), [None, None])
        self.assertEqual((state["phase"], state["reason"], state["successes"]), ("blocked", "unreachable", 0))

    def test_wrong_ip_blocks_even_if_another_probe_is_expected(self):
        for probes in (["203.0.113.1"], [health.EXPECTED_IP, "203.0.113.1"], ["203.0.113.1", health.EXPECTED_IP], ["2001:db8::1"]):
            with self.subTest(probes=probes):
                self.assertEqual(self.step(self.healthy(), probes)["reason"], "wrong_exit")

    def test_fallback_expected_ip_is_one_successful_round(self):
        state = self.step(self.initial(), [None, health.EXPECTED_IP])
        self.assertEqual((state["phase"], state["successes"]), ("blocked", 1))

    def test_recovery_requires_two_consecutive_passes(self):
        state = self.step(self.healthy(), [None, None])
        state = self.step(state)
        self.assertEqual(state["phase"], "blocked")
        state = self.step(state, [None, None])
        self.assertEqual(state["successes"], 0)
        state = self.step(state)
        self.assertEqual(state["phase"], "blocked")
        self.assertEqual(self.step(state)["phase"], "healthy")

    def test_fault_and_recovery_event_ids_do_not_repeat(self):
        state = self.healthy()
        self.assertEqual(state["event_id"], self.step(state)["event_id"])
        fault = self.step(state, [None, None])
        self.assertEqual(fault["event_id"], state["event_id"] + 1)
        self.assertEqual(self.step(fault, [None, None])["event_id"], fault["event_id"])
        verifying = self.step(fault)
        self.assertEqual(verifying["event_id"], fault["event_id"])
        restored = self.step(verifying)
        self.assertEqual((restored["event_id"], restored["notice"]), (fault["event_id"] + 1, "recovery"))

    def test_original_mode_always_blocks_without_fake_recovery(self):
        state = health.decide_health(self.healthy(), "original", [health.EXPECTED_IP])
        for _ in range(5):
            state = health.decide_health(state, "original", [health.EXPECTED_IP])
            self.assertEqual((state["policy"], state["successes"], state["notice"]), ("original_blocked", 0, "fault"))

    def test_switch_back_home_starts_new_verification(self):
        state = health.decide_health(self.healthy(), "original", [])
        state = self.step(state)
        self.assertEqual((state["policy"], state["successes"]), ("home_blocked", 1))
        self.assertEqual(self.step(state)["policy"], "home_open")

    def test_invalid_mode_and_probe_shapes_never_open(self):
        for mode in ("typo", None, 42):
            with self.subTest(mode=mode):
                self.assertEqual(health.decide_health(self.healthy(), mode, [health.EXPECTED_IP])["policy"], "home_blocked")
        for probes in (None, "93.184.216.34", {}, [health.EXPECTED_IP] * 3, [False], ["not-an-ip"]):
            with self.subTest(probes=probes):
                state = health.decide_health(self.healthy(), "home", probes)
                self.assertEqual((state["phase"], state["reason"]), ("blocked", "monitor_error"))

    def test_corrupt_previous_state_is_blocked(self):
        for state in ({}, {"version": 1}, [], "bad", dict(self.healthy(), successes=-1), dict(self.healthy(), event_id=True)):
            with self.subTest(state=state):
                output = self.step(state)
                self.assertEqual((output["phase"], output["reason"]), ("blocked", "monitor_error"))

    def test_unexpected_parser_error_blocks(self):
        previous = self.healthy()
        with mock.patch.object(health.ipaddress, "ip_address", side_effect=RuntimeError("offline injected failure")):
            state = self.step(previous)
        self.assertEqual((state["phase"], state["reason"]), ("blocked", "monitor_error"))

    def test_unexpected_state_validator_error_blocks(self):
        with mock.patch.object(health, "_valid_previous", side_effect=RuntimeError("offline injected failure")):
            state = health.decide_health(None, "home", [health.EXPECTED_IP])
        self.assertEqual((state["phase"], state["reason"]), ("blocked", "monitor_error"))

    def test_no_input_mutation_and_public_state_has_no_credentials(self):
        previous = self.healthy()
        original = dict(previous)
        probes = [None, health.EXPECTED_IP]
        output = self.step(previous, probes)
        self.assertEqual(previous, original)
        self.assertEqual(probes, [None, health.EXPECTED_IP])
        self.assertEqual(set(output), {"version", "mode", "phase", "policy", "reason", "successes", "event_id", "notice"})
        json.dumps(output)


def main():
    global health
    captured = io.StringIO()
    with contextlib.ExitStack() as guards:
        for name in ("Popen", "run", "call", "check_call", "check_output"):
            guards.enter_context(mock.patch.object(subprocess, name, side_effect=forbidden))
        for name in ("socket", "create_connection", "getaddrinfo"):
            guards.enter_context(mock.patch.object(socket, name, side_effect=forbidden))
        for name in ("system", "popen", "posix_spawn", "posix_spawnp"):
            if hasattr(os, name):
                guards.enter_context(mock.patch.object(os, name, side_effect=forbidden))
        spec = importlib.util.spec_from_file_location("guard_health_test_subject", ROOT / "guard_health.py")
        health = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(health)
        health.EXPECTED_IP = "93.184.216.34"
        result = unittest.TextTestRunner(stream=captured, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(HealthTests))
    report = {"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "passed": result.wasSuccessful(), "real_network_or_system_changes": False, "details": captured.getvalue()}
    (ROOT / "health-test-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "details"}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
