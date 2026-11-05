"""Pure health decisions. No imports of service, network, or filesystem APIs.

The supervisor alone probes, applies policy, and publishes committed state.
Each call represents one round, even when it contains two probe results.
"""

import ipaddress

EXPECTED_IP = None  # Set only from the validated root-owned bundle.
MODES = ("home", "original")


def _valid_previous(state):
    if state is None:
        return True
    if type(state) is not dict or state.get("version") != 1:
        return False
    mode, phase = state.get("mode"), state.get("phase")
    successes, event = state.get("successes"), state.get("event_id")
    if mode not in MODES or phase not in ("blocked", "healthy"):
        return False
    if type(successes) is not int or type(event) is not int or event < 1:
        return False
    if phase == "healthy":
        return mode == "home" and successes == 2 and state.get("policy") == "home_open" and state.get("notice") == "recovery"
    return successes in (0, 1) and (mode != "original" or successes == 0) and state.get("policy") == mode + "_blocked" and state.get("notice") == "fault"


def _result(previous, mode, phase, reason, successes):
    changed = previous is None or previous["phase"] != phase
    return {
        "version": 1,
        "mode": mode,
        "phase": phase,
        "policy": "home_open" if phase == "healthy" else mode + "_blocked",
        "reason": reason,
        "successes": successes,
        "event_id": (previous["event_id"] if previous else 0) + int(changed),
        "notice": "recovery" if phase == "healthy" else "fault",
    }


def decide_health(previous, mode, probes):
    """Return a new JSON-safe decision without mutating inputs.

    mode is home/original; probes is 1–2 parsed IP strings or None for a
    failed probe. [] means no completed probe. A non-list/tuple means a
    monitor error. Invalid state/input always produces a blocked policy.
    """
    old = None
    safe_mode = "home"
    blocked = lambda reason: _result(old, safe_mode, "blocked", reason, 0)
    try:
        valid_previous = _valid_previous(previous)
        old = previous if valid_previous else None
        safe_mode = mode if mode in MODES else "home"
        if mode not in MODES or not valid_previous:
            return blocked("monitor_error")
        if mode == "original":
            return blocked("original_mode")
        if type(probes) not in (list, tuple) or len(probes) > 2:
            return blocked("monitor_error")
        if not probes:
            return blocked("starting" if old is None else "unreachable")
        expected = False
        invalid = False
        wrong_exit = False
        for probe in probes:
            if probe is None:
                continue
            if type(probe) is not str:
                invalid = True
                continue
            try:
                address = str(ipaddress.ip_address(probe))
            except ValueError:
                invalid = True
                continue
            expected = expected or address == EXPECTED_IP
            wrong_exit = wrong_exit or address != EXPECTED_IP
        # A fallback success must never hide a valid wrong exit.
        if wrong_exit:
            return blocked("wrong_exit")
        if invalid:
            return blocked("monitor_error")
        if not expected:
            return blocked("unreachable")
        successes = min(2, (old["successes"] if old and old["mode"] == mode else 0) + 1)
        if successes < 2:
            return _result(old, mode, "blocked", "verifying", successes)
        return _result(old, mode, "healthy", "verified", successes)
    except Exception:
        # Unexpected parser/state-machine failures never authorize an opening.
        return blocked("monitor_error")
