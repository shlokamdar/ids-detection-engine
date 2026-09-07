"""
Web dashboard v3.

Changes from v2:
  - "STATISTICAL_ANOMALY" rows now show WHAT was unusual (e.g. "Unusual
    Connection Rate", not just a repeated generic label), parsed from the
    alert's own `reason` field.
  - Added a "Top Source IPs" bar chart — who's actually triggering alerts.
  - Added an "Alerts Over Time" line chart — trend over the last 2 hours,
    so you can see bursts (like an attack) instead of just a flat count.
  - All of the above (stat cards, severity donut, top IPs, time trend)
    are computed in ONE pass over alerts.jsonl per page load, not four
    separate file reads — matters since this file only grows and is
    already 50k+ lines.

Run on the Detection-Server:
    python3 web_dashboard.py
Then visit http://<detection_public_ip>:5000
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import Flask

from dashboard import load_last_n_alerts, load_active_blocks
from timezone_utils import utc_dt_to_ist, IST

app = Flask(__name__)

ALERTS_FILE = "alerts.jsonl"
BASELINE_FILE = "baseline_profile.json"
REFRESH_SECONDS = 10

# Turns raw feature names into plain-English labels for the alert table.
FRIENDLY_FEATURE_NAMES = {
    "connections_per_second": "Connection Rate",
    "unique_dst_ports": "Port Diversity",
    "total_connections": "Connection Count",
    "avg_bytes_per_conn": "Data Volume per Connection",
    "avg_packets_per_conn": "Packet Volume per Connection",
    "reject_ratio": "Rejection Rate",
    "total_packets": "Packet Count",
    "total_bytes": "Data Transferred",
    "avg_duration_seconds": "Session Duration",
}

ZSCORE_REASON_RE = re.compile(r"max_z_score=([\d.]+),\s*trigger=(\w+)")


def friendly_reason(alert):
    """
    Turns a raw alert record into a short, human-readable description of
    WHY it fired — e.g. "Unusual Connection Rate (z=4.75)" instead of
    just the generic alert_type "STATISTICAL_ANOMALY" repeated on every
    row with no distinguishing detail.
    """
    if alert.get("triggering_method") == "ZSCORE":
        match = ZSCORE_REASON_RE.search(alert.get("reason", ""))
        if match:
            z_value, feature = match.groups()
            label = FRIENDLY_FEATURE_NAMES.get(feature, feature.replace("_", " ").title())
            return f"Unusual {label} (z={float(z_value):.1f})"
        return "Unusual Traffic Pattern"
    else:
        # RULE-based: explicit mapping instead of .title(), since that
        # would mangle acronyms ("Ssh Brute Force" instead of "SSH
        # Brute Force").
        rule_labels = {
            "PORT_SCAN": "Port Scan",
            "SSH_BRUTE_FORCE": "SSH Brute Force",
            "ICMP_FLOOD": "ICMP Flood",
        }
        alert_type = alert.get("alert_type", "Unknown")
        return rule_labels.get(alert_type, alert_type.replace("_", " ").title())


def _severity_class(severity):
    return "sev-high" if severity == "HIGH" else "sev-medium"


def scan_alerts_file(alerts_file, time_bucket_minutes=10, time_window_hours=2):
    """
    Single pass over the full alerts file. Returns everything the other
    panels need, so we only read this (growing, currently 50k+ line)
    file once per page load instead of three or four times.
    """
    stats = {"total": 0, "high": 0, "medium": 0, "rule": 0, "zscore": 0}
    ip_counts = defaultdict(int)
    now_utc = datetime.now(timezone.utc)
    window_start = now_utc - timedelta(hours=time_window_hours)
    bucket_counts = defaultdict(int)

    if not os.path.exists(alerts_file):
        return stats, ip_counts, bucket_counts, window_start, now_utc

    with open(alerts_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue

            stats["total"] += 1
            if a.get("severity") == "HIGH":
                stats["high"] += 1
            else:
                stats["medium"] += 1
            if a.get("triggering_method") == "RULE":
                stats["rule"] += 1
            else:
                stats["zscore"] += 1

            ip_counts[a.get("src_ip", "unknown")] += 1

            try:
                ts = datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except (ValueError, KeyError):
                continue
            if ts >= window_start:
                bucket_key = ts.replace(
                    minute=(ts.minute // time_bucket_minutes) * time_bucket_minutes,
                    second=0, microsecond=0,
                )
                bucket_counts[bucket_key] += 1

    return stats, ip_counts, bucket_counts, window_start, now_utc


def build_time_series(bucket_counts, window_start, now_utc, bucket_minutes=10):
    """Fills in empty buckets with 0 so the line chart doesn't skip gaps."""
    labels, values = [], []
    bucket = window_start.replace(
        minute=(window_start.minute // bucket_minutes) * bucket_minutes,
        second=0, microsecond=0,
    )
    while bucket <= now_utc:
        labels.append(utc_dt_to_ist(bucket).split(" ")[1][:5])  # just HH:MM in IST
        values.append(bucket_counts.get(bucket, 0))
        bucket += timedelta(minutes=bucket_minutes)
    return labels, values


def render_dashboard_html(alerts, blocks, baseline, stats, top_ips, time_labels, time_values, generated_at):
    alert_rows = "".join(
        f"<tr><td>{a['timestamp']}</td><td>{a['src_ip']}</td>"
        f"<td>{friendly_reason(a)}</td>"
        f"<td><span class='badge {_severity_class(a['severity'])}'>{a['severity']}</span></td>"
        f"<td>{a['triggering_method']}</td></tr>"
        for a in reversed(alerts)
    ) or "<tr><td colspan='5' class='empty'>No alerts yet</td></tr>"

    block_rows = "".join(
        f"<tr class='block-row'><td>{b['ip']}</td><td>{b['expiry']}</td><td>{b['reason']}</td></tr>"
        for b in blocks
    ) or "<tr><td colspan='3' class='empty'>No active blocks</td></tr>"

    baseline_rows = "".join(
        f"<tr><td>{feature}</td><td>{s['mean']:.3f}</td><td>{s['std']:.3f}</td></tr>"
        for feature, s in baseline.items()
    ) or "<tr><td colspan='3' class='empty'>No baseline profile found</td></tr>"

    block_count_label = f"{len(blocks)} ACTIVE" if blocks else "NONE ACTIVE"
    block_count_class = "count-active" if blocks else "count-clear"

    top_ips_labels = json.dumps([ip for ip, _ in top_ips])
    top_ips_values = json.dumps([count for _, count in top_ips])
    time_labels_json = json.dumps(time_labels)
    time_values_json = json.dumps(time_values)

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>IDS Dashboard</title>
    <meta http-equiv="refresh" content="{REFRESH_SECONDS}">
    <meta charset="utf-8">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
                background: #0f1115; color: #e6e6e6; margin: 0; padding: 24px; }}
        .header-row {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }}
        h1 {{ margin: 0; font-size: 22px; }}
        .subtitle {{ color: #888; font-size: 13px; margin-top: 4px; }}
        .live-badge {{ display: flex; align-items: center; gap: 8px; background: #16341f;
                       color: #6bff8f; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .live-dot {{ width: 8px; height: 8px; border-radius: 50%; background: #6bff8f;
                     animation: pulse 1.5s infinite; }}
        @keyframes pulse {{
            0% {{ box-shadow: 0 0 0 0 rgba(107,255,143,0.6); }}
            70% {{ box-shadow: 0 0 0 8px rgba(107,255,143,0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(107,255,143,0); }}
        }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }}
        .stat-card {{ background: #171a21; border: 1px solid #2a2e38; border-radius: 8px; padding: 16px 18px; }}
        .stat-card .label {{ color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-card .value {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
        .stat-card.alert-total .value {{ color: #7dc4ff; }}
        .stat-card.alert-high .value {{ color: #ff6b6b; }}
        .stat-card.blocks .value {{ color: #ffc861; }}
        .stat-card.rule .value {{ color: #6bff8f; }}
        .panel {{ background: #171a21; border: 1px solid #2a2e38; border-radius: 8px;
                  padding: 16px 20px; margin-bottom: 20px; }}
        .panel h2 {{ font-size: 15px; margin: 0 0 12px 0; color: #aab; text-transform: uppercase;
                     letter-spacing: 0.5px; display: flex; justify-content: space-between; align-items: center; }}
        .chart-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
        .two-col {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ text-align: left; color: #777; font-weight: 500; padding: 6px 8px; border-bottom: 1px solid #2a2e38; }}
        td {{ padding: 6px 8px; border-bottom: 1px solid #1e222b; }}
        tr:last-child td {{ border-bottom: none; }}
        .empty {{ color: #555; text-align: center; padding: 16px; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; white-space: nowrap; }}
        .sev-high {{ background: #4a1620; color: #ff6b6b; }}
        .sev-medium {{ background: #4a3d16; color: #ffc861; }}
        .count-active {{ background: #4a1620; color: #ff6b6b; padding: 2px 10px; border-radius: 12px; font-size: 12px; }}
        .count-clear {{ background: #16341f; color: #6bff8f; padding: 2px 10px; border-radius: 12px; font-size: 12px; }}
        .block-row {{ animation: rowGlow 2s infinite; }}
        @keyframes rowGlow {{
            0%, 100% {{ background: transparent; }}
            50% {{ background: rgba(255,107,107,0.08); }}
        }}
        .chart-wrap {{ position: relative; height: 220px; }}
    </style>
</head>
<body>
    <div class="header-row">
        <div>
            <h1>🛡️ IDS Dashboard</h1>
            <div class="subtitle">Auto-refreshes every {REFRESH_SECONDS}s &middot; Last updated {generated_at}</div>
        </div>
        <div class="live-badge"><span class="live-dot"></span> MONITORING LIVE</div>
    </div>

    <div class="stat-grid">
        <div class="stat-card alert-total">
            <div class="label">Total Alerts</div>
            <div class="value">{stats['total']}</div>
        </div>
        <div class="stat-card alert-high">
            <div class="label">High Severity</div>
            <div class="value">{stats['high']}</div>
        </div>
        <div class="stat-card blocks">
            <div class="label">Active Blocks</div>
            <div class="value">{len(blocks)}</div>
        </div>
        <div class="stat-card rule">
            <div class="label">Rule-Based Catches</div>
            <div class="value">{stats['rule']}</div>
        </div>
    </div>

    <div class="panel">
        <h2>Active Blocks <span class="{block_count_class}">{block_count_label}</span></h2>
        <table>
            <tr><th>IP Address</th><th>Expires</th><th>Reason</th></tr>
            {block_rows}
        </table>
    </div>

    <div class="chart-row">
        <div class="panel">
            <h2>Alerts Over Time (last 2h)</h2>
            <div class="chart-wrap"><canvas id="timeChart"></canvas></div>
        </div>
        <div class="panel">
            <h2>Top Source IPs</h2>
            <div class="chart-wrap"><canvas id="topIpsChart"></canvas></div>
        </div>
    </div>

    <div class="two-col">
        <div class="panel">
            <h2>Recent Alerts</h2>
            <table>
                <tr><th>Time</th><th>Source IP</th><th>What Happened</th><th>Severity</th><th>Method</th></tr>
                {alert_rows}
            </table>
        </div>

        <div class="panel">
            <h2>Detection Breakdown</h2>
            <div class="chart-wrap"><canvas id="severityChart"></canvas></div>
        </div>
    </div>

    <div class="panel">
        <h2>Baseline Statistics</h2>
        <table>
            <tr><th>Feature</th><th>Mean</th><th>Std Dev</th></tr>
            {baseline_rows}
        </table>
    </div>

    <script>
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['HIGH (Rule)', 'MEDIUM (Z-Score)'],
                datasets: [{{
                    data: [{stats['high']}, {stats['medium']}],
                    backgroundColor: ['#ff6b6b', '#ffc861'],
                    borderColor: '#171a21',
                    borderWidth: 3
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#aab', font: {{ size: 11 }} }} }} }}
            }}
        }});

        new Chart(document.getElementById('topIpsChart'), {{
            type: 'bar',
            data: {{
                labels: {top_ips_labels},
                datasets: [{{
                    label: 'Alerts',
                    data: {top_ips_values},
                    backgroundColor: '#7dc4ff'
                }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#aab' }}, grid: {{ color: '#2a2e38' }} }},
                    y: {{ ticks: {{ color: '#aab', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
                }}
            }}
        }});

        new Chart(document.getElementById('timeChart'), {{
            type: 'line',
            data: {{
                labels: {time_labels_json},
                datasets: [{{
                    label: 'Alerts',
                    data: {time_values_json},
                    borderColor: '#6bff8f',
                    backgroundColor: 'rgba(107,255,143,0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 2
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#aab', maxTicksLimit: 8, font: {{ size: 10 }} }}, grid: {{ display: false }} }},
                    y: {{ beginAtZero: true, ticks: {{ color: '#aab' }}, grid: {{ color: '#2a2e38' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>"""


@app.route("/")
def index():
    alerts = load_last_n_alerts(ALERTS_FILE, 10)
    blocks = load_active_blocks()

    stats, ip_counts, bucket_counts, window_start, now_utc = scan_alerts_file(ALERTS_FILE)
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    time_labels, time_values = build_time_series(bucket_counts, window_start, now_utc)

    baseline = {}
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            baseline = json.load(f)

    generated_at = utc_dt_to_ist(datetime.now(timezone.utc))
    return render_dashboard_html(alerts, blocks, baseline, stats, top_ips, time_labels, time_values, generated_at)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)