#!/usr/bin/env python3
"""User-session consumer of root health status. Never probes or changes network."""

import fcntl
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

STATUS_PATH = Path("/Library/Application Support/ClaudeResidential/public/status.json")
STATE_DIR = Path.home() / "Library/Application Support/ClaudeResidentialWatch"
STALE_SECONDS = 120
RETRY_SECONDS = 60
MAX_BYTES = 65536

NOTIFICATION_SCRIPT = '''on run argv
    set noticeTitle to item 1 of argv
    set noticeText to item 2 of argv
    set noticeKind to item 3 of argv
    if noticeKind is "recovery" then
        display notification noticeText with title noticeTitle sound name "Glass"
    else
        try
            display notification noticeText with title noticeTitle sound name "Basso"
        end try
        display alert noticeTitle message noticeText buttons {"知道了"} default button "知道了" giving up after 15
    end if
end run
'''


def fault(message):
    return {"condition": "fault", "kind": "fault", "title": "Claude 家宽保护异常", "message": message}


def event_identity(value):
    request, event = value.get("request_id"), value.get("event_id")
    if type(request) is str and request and type(event) is int and event >= 1:
        return request, event
    return None, None


def classify_status(document, now):
    """Pure public-schema validation; stale/malformed status is always a fault."""
    invalid = fault("家宽保护状态无法确认，Claude 请暂停使用。请检查家宽服务。")
    try:
        if type(document) is not dict or document.get("version") != 1:
            return invalid
        updated = document.get("updated_at")
        if type(updated) not in (int, float) or not math.isfinite(updated):
            return invalid
        if not -5 <= now - updated <= STALE_SECONDS:
            return invalid
        if document.get("core_running") is not True:
            message = "家宽保护服务未就绪或已停止，Claude 请暂停使用；普通网络也可能受影响。请检查家宽服务。"
            if document.get("mode") == "home" and document.get("reason") not in ("starting", "verifying"):
                message += "需要其他应用联网时，可点击‘恢复原网络’；Claude 仍保持禁用。"
            return fault(message)
        mode, phase = document.get("mode"), document.get("phase")
        successes, event = document.get("successes"), document.get("event_id")
        if type(successes) is not int or type(event) is not int or event < 1:
            return invalid
        if mode == "original" and phase == "blocked" and successes == 0 and document.get("policy") == "original_blocked":
            return {"condition": "original", "kind": "original", "title": "Claude 已禁用", "message": "当前为原网络模式，Claude 保持禁用。重新启用家宽并验证通过后才可使用。"}
        if mode == "home" and phase == "healthy" and successes == 2 and document.get("policy") == "home_open":
            request, event = event_identity(document)
            return {"condition": "healthy", "kind": "recovery", "title": "Claude 家宽已恢复", "message": "家宽已连续两轮验证通过，Claude 现可继续使用。", "request_id": request, "event_id": event}
        if mode == "home" and phase == "blocked" and successes in (0, 1) and document.get("policy") == "home_blocked":
            reason = document.get("reason")
            if reason in ("starting", "verifying"):
                return fault("正在验证家宽连接，Claude 暂时禁用。连续两轮通过后会提醒。")
            if reason == "wrong_exit":
                return fault("家宽出口不符，Claude 已暂停使用。需要其他应用联网时，可点击‘恢复原网络’；Claude 仍保持禁用。")
            return fault("家宽连接异常，Claude 已暂停使用。不会自动切换其他出口。需要其他应用联网时，可点击‘恢复原网络’；Claude 仍保持禁用。")
    except (TypeError, ValueError, OverflowError):
        return invalid
    return invalid


def read_status(now):
    try:
        fd = os.open(STATUS_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                return classify_status(None, now)
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return classify_status(None, now)
        return classify_status(json.loads(raw), now)
    except (OSError, ValueError, UnicodeError):
        return classify_status(None, now)


def read_local(name, default):
    try:
        fd = os.open(STATE_DIR / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return default
            raw = stream.read(MAX_BYTES + 1)
        return json.loads(raw) if len(raw) <= MAX_BYTES else default
    except (OSError, ValueError, UnicodeError):
        return default


def write_local(name, value):
    temporary = STATE_DIR / ("." + name + "." + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE_DIR / name)
    finally:
        temporary.unlink(missing_ok=True)


def load_state():
    initial = {"version": 2, "condition": None, "pending": None, "last_attempt": 0}
    state = read_local("state.json", initial)
    try:
        if type(state) is not dict or state.get("version") != 2 or state.get("condition") not in (None, "healthy", "fault", "original"):
            return initial
        attempt = state.get("last_attempt")
        if type(attempt) not in (int, float) or not math.isfinite(attempt):
            return initial
        pending = state.get("pending")
        if pending is not None and (type(pending) is not dict or pending.get("kind") not in ("fault", "recovery", "original") or any(type(pending.get(k)) is not str for k in ("title", "message"))):
            return initial
        state["request_id"], state["event_id"] = event_identity(state)
        return state
    except (ValueError, OverflowError):
        return initial


def update_state(state, observation):
    old, new = state["condition"], observation["condition"]
    old_request, old_event = event_identity(state)
    request, event = event_identity(observation)
    same_request = request is not None and request == old_request and old_event is not None
    continuous_health = old == new == "healthy" and same_request and event >= old_event
    missed_outage = continuous_health and event >= old_event + 2
    pending = state["pending"]
    retry_summary = continuous_health and pending is not None and pending.get("brief_outage") is True
    if missed_outage or retry_summary:
        observation = dict(observation, brief_outage=True, title="家宽曾短暂异常，现已恢复",
                           message="两次提醒检查之间，家宽曾短暂异常；现已连续两轮验证通过，Claude 可继续使用。")
    if old != new or missed_outage:
        state["pending"] = observation if new != "healthy" or old is not None else None
        state["last_attempt"] = 0
    elif pending is not None:
        # A failed notification retries the current text, never stale wording.
        state["pending"] = None if pending.get("brief_outage") is True and not continuous_health else observation
    state["condition"] = new
    state["request_id"], state["event_id"] = request, event


def deliver_pending(state, now):
    notice = state["pending"]
    if notice is None or 0 <= now - state["last_attempt"] < RETRY_SECONDS:
        return
    state["last_attempt"] = now
    write_local("state.json", state)
    try:
        completed = subprocess.run(
            ["/usr/bin/osascript", "-", notice["title"], notice["message"], notice["kind"]],
            input=NOTIFICATION_SCRIPT, text=True, capture_output=True, timeout=20, check=False,
        )
        accepted = completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        accepted = False
    if accepted:
        state["pending"] = None
        write_local("state.json", state)
    events = read_local("events.json", [])
    if type(events) is not list:
        events = []
    events.append({"time": now, "kind": notice["kind"], "accepted": accepted})
    write_local("events.json", events[-60:])


def main():
    os.umask(0o077)
    if STATE_DIR.is_symlink():
        raise RuntimeError("Notification state directory must not be a symlink")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    fd = os.open(STATE_DIR / "watch.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        now = time.time()
        state = load_state()
        update_state(state, read_status(now))
        write_local("state.json", state)
        deliver_pending(state, now)
    finally:
        os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
