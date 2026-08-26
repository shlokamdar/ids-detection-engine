"""
Alert deduplication state (Phase 5).

Since run_cycle.py is triggered fresh by cron every 60 seconds, there is no
long-lived Python process to hold "last alert time per IP" in memory. This
module persists that state to a small JSON file on disk so dedup logic
survives across cron runs.

Rule: don't alert on the same source IP more than once per 5 minutes,
UNLESS the new alert's severity is higher than the last one we logged
for that IP.
"""

import json
import os

STATE_FILE = "alert_state.json"
COOLDOWN_SECONDS = 300  # 5 minutes

SEVERITY_RANK = {"MEDIUM": 1, "HIGH": 2}


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def should_alert(state, src_ip, event_ts, new_severity):
    """
    Returns True if a new alert for src_ip should be logged right now.
    """
    prev = state.get(src_ip)
    if prev is None:
        return True

    time_since_last = event_ts - prev["last_alert_ts"]
    if time_since_last >= COOLDOWN_SECONDS:
        return True

    if SEVERITY_RANK.get(new_severity, 0) > SEVERITY_RANK.get(prev["last_severity"], 0):
        return True

    return False


def record_alert(state, src_ip, event_ts, severity):
    """
    Update state after logging an alert. If a higher-severity alert was
    already recorded within the cooldown window, keep that severity but
    still refresh the timestamp (so the 5-minute clock restarts).
    """
    prev = state.get(src_ip)
    if prev and SEVERITY_RANK.get(prev["last_severity"], 0) > SEVERITY_RANK.get(severity, 0):
        severity = prev["last_severity"]
    state[src_ip] = {"last_alert_ts": event_ts, "last_severity": severity}
