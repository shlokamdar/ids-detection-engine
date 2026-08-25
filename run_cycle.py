"""
Phase 5: single-cycle IDS run.

Fetch latest flow logs -> parse -> aggregate into 60s windows ->
detect (rule layer, then z-score layer) -> dedup -> append new alerts to
alerts.jsonl -> print the CLI dashboard.

Designed to be triggered every 60 seconds by cron, e.g. add this line with
`crontab -e` on the detection EC2 instance:

    * * * * * cd /home/ubuntu/ids && /usr/bin/python3 run_cycle.py >> cycle.log 2>&1

Each run is stateless in memory (cron starts a fresh process every time),
so all dedup state is persisted to alert_state.json between runs via
state_manager.py.
"""

import json
import time
from datetime import datetime

from fetcher import fetch_recent_flow_logs
from parser import parse_all_records
from aggregator import aggregate_all_windows
from detection_engine import rule_detect, zscore_detect, ZSCORE_FEATURES
from state_manager import load_state, save_state, should_alert, record_alert
from dashboard import print_dashboard

BASELINE_FILE = "baseline_profile.json"
ALERTS_FILE = "alerts.jsonl"

# Fetch slightly more than the 60s cron interval so a delayed cron tick
# (or a slow CloudWatch write) doesn't silently drop a window. Any
# records we've effectively already reacted to are naturally absorbed
# by the dedup layer, not by trying to de-overlap fetch windows here.
FETCH_MINUTES_BACK = 2


def load_baseline():
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def _ensure_trailing_newline(path):
    import os
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return
    with open(path, "rb") as f:
        f.seek(-1, os.SEEK_END)
        last_byte = f.read(1)
    if last_byte != b"\n":
        with open(path, "a") as f:
            f.write("\n")


def run_cycle():
    print(f"\n[{datetime.utcnow().isoformat()}] Starting detection cycle...")

    baseline = load_baseline()
    state = load_state()

    raw_events = fetch_recent_flow_logs(minutes_back=FETCH_MINUTES_BACK)
    if not raw_events:
        print("No new flow log events this cycle.")
        print_dashboard(ALERTS_FILE, BASELINE_FILE)
        return

    parsed = parse_all_records(raw_events)
    feature_vectors = aggregate_all_windows(parsed, window_size=60)

    new_alerts = []

    for fv in feature_vectors:
        src_ip = fv["src_ip"]
        event_ts = fv.get("window_start", int(time.time()))
        ts_str = datetime.utcfromtimestamp(event_ts).strftime("%Y-%m-%d %H:%M:%S")

        candidate_alerts = []

        # Layer 1: deterministic rules
        for alert in rule_detect(fv):
            candidate_alerts.append({
                "timestamp": ts_str,
                "src_ip": src_ip,
                "alert_type": alert["type"],
                "severity": alert["severity"],
                "confidence": alert["confidence"],
                "triggering_method": "RULE",
                "reason": alert["reason"],
                "features": {k: fv.get(k) for k in ZSCORE_FEATURES},
            })

        # Layer 2: statistical anomaly (still runs even if a rule already
        # fired, so both alert types are visible in the log — dedup below
        # decides whether either actually gets written this cycle)
        is_anomaly, max_z, trigger = zscore_detect(fv, baseline)
        if is_anomaly:
            candidate_alerts.append({
                "timestamp": ts_str,
                "src_ip": src_ip,
                "alert_type": "STATISTICAL_ANOMALY",
                "severity": "MEDIUM",
                "confidence": round(min(max_z / 10.0, 1.0), 3),
                "triggering_method": "ZSCORE",
                "reason": f"max_z_score={max_z:.2f}, trigger={trigger}",
                "features": {k: fv.get(k) for k in ZSCORE_FEATURES},
            })

        if not candidate_alerts:
            continue

        # Dedup is applied per source IP per cycle, using the highest
        # severity among this cycle's candidate alerts for that IP.
        max_severity = "HIGH" if any(a["severity"] == "HIGH" for a in candidate_alerts) else "MEDIUM"

        if should_alert(state, src_ip, event_ts, max_severity):
            new_alerts.extend(candidate_alerts)
            record_alert(state, src_ip, event_ts, max_severity)
        else:
            print(f"  [dedup] suppressed repeat alert for {src_ip} "
                  f"(cooldown active, severity not higher)")

    if new_alerts:
        # Guard: if the existing file's last line is missing its trailing
        # newline (can happen with older writers that used "w" mode),
        # appending directly would glue our first alert onto that line.
        _ensure_trailing_newline(ALERTS_FILE)
        with open(ALERTS_FILE, "a") as f:
            for alert in new_alerts:
                f.write(json.dumps(alert) + "\n")
        print(f"Logged {len(new_alerts)} new alert(s) this cycle.")
    else:
        print("No new alerts this cycle.")

    save_state(state)
    print_dashboard(ALERTS_FILE, BASELINE_FILE)


if __name__ == "__main__":
    run_cycle()