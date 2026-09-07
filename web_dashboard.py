"""
Web dashboard v4 — visual redesign.

Same data/logic as v3 (friendly_reason, scan_alerts_file, build_time_series
all unchanged) — this pass only changes render_dashboard_html's HTML/CSS,
moving away from the generic SaaS-dashboard look (near-black + 4 identical
shadowed rounded cards + ALL-CAPS labels + pulsing status pill) toward a
deliberate security-console aesthetic: monochrome by default, color
reserved only for genuine danger states, monospace for tabular data.

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
from timezone_utils import utc_dt_to_ist

app = Flask(__name__)

ALERTS_FILE = "alerts.jsonl"
BASELINE_FILE = "baseline_profile.json"
REFRESH_SECONDS = 10

FRIENDLY_FEATURE_NAMES = {
    "connections_per_second": "connection rate",
    "unique_dst_ports": "port diversity",
    "total_connections": "connection count",
    "avg_bytes_per_conn": "data volume per connection",
    "avg_packets_per_conn": "packet volume per connection",
    "reject_ratio": "rejection rate",
    "total_packets": "packet count",
    "total_bytes": "data transferred",
    "avg_duration_seconds": "session duration",
}

ZSCORE_REASON_RE = re.compile(r"max_z_score=([\d.]+),\s*trigger=(\w+)")

RULE_LABELS = {
    "PORT_SCAN": "port scan",
    "SSH_BRUTE_FORCE": "SSH brute force",
    "ICMP_FLOOD": "ICMP flood",
}


def friendly_reason(alert):
    if alert.get("triggering_method") == "ZSCORE":
        match = ZSCORE_REASON_RE.search(alert.get("reason", ""))
        if match:
            z_value, feature = match.groups()
            label = FRIENDLY_FEATURE_NAMES.get(feature, feature.replace("_", " "))
            return f"unusual {label} (z={float(z_value):.1f})"
        return "unusual traffic pattern"
    else:
        alert_type = alert.get("alert_type", "unknown")
        return RULE_LABELS.get(alert_type, alert_type.replace("_", " ").lower())


def scan_alerts_file(alerts_file, time_bucket_minutes=10, time_window_hours=2):
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
    labels, values = [], []
    bucket = window_start.replace(
        minute=(window_start.minute // bucket_minutes) * bucket_minutes,
        second=0, microsecond=0,
    )
    while bucket <= now_utc:
        labels.append(utc_dt_to_ist(bucket).split(" ")[1][:5])
        values.append(bucket_counts.get(bucket, 0))
        bucket += timedelta(minutes=bucket_minutes)
    return labels, values


def render_dashboard_html(alerts, blocks, baseline, stats, top_ips, time_labels, time_values, generated_at):
    alert_rows = "".join(
        f"<tr><td class='mono'>{a['timestamp']}</td><td class='mono'>{a['src_ip']}</td>"
        f"<td>{friendly_reason(a)}</td>"
        f"<td><span class='sev sev-{a['severity'].lower()}'>{a['severity'].lower()}</span></td>"
        f"<td class='mono muted'>{a['triggering_method'].lower()}</td></tr>"
        for a in reversed(alerts)
    ) or "<tr><td colspan='5' class='empty'>No alerts recorded yet.</td></tr>"

    has_blocks = bool(blocks)
    block_rows = "".join(
        f"<tr><td class='mono'>{b['ip']}</td><td class='mono muted'>{b['expiry']}</td><td>{b['reason'].replace('_', ' ').lower()}</td></tr>"
        for b in blocks
    ) or "<tr><td colspan='3' class='empty'>No active blocks. Nothing is currently contained.</td></tr>"

    baseline_rows = "".join(
        f"<tr><td>{feature.replace('_', ' ')}</td><td class='mono'>{s['mean']:.3f}</td><td class='mono muted'>{s['std']:.3f}</td></tr>"
        for feature, s in baseline.items()
    ) or "<tr><td colspan='3' class='empty'>No baseline profile found.</td></tr>"

    top_ips_labels = json.dumps([ip for ip, _ in top_ips])
    top_ips_values = json.dumps([count for _, count in top_ips])
    time_labels_json = json.dumps(time_labels)
    time_values_json = json.dumps(time_values)

    high_pct = (stats["high"] / stats["total"] * 100) if stats["total"] else 0
    medium_pct = 100 - high_pct

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>IDS Console</title>
    <meta http-equiv="refresh" content="{REFRESH_SECONDS}">
    <meta charset="utf-8">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg: #0B0E13;
            --surface: #12151C;
            --border: #232833;
            --border-strong: #2E3542;
            --text: #E4E7EC;
            --text-muted: #7C8697;
            --text-faint: #4B5563;
            --accent-alert: #FF6A39;
            --accent-alert-dim: #3A2419;
            --accent-calm: #4FD1C5;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'IBM Plex Sans', sans-serif;
            background: var(--bg); color: var(--text);
            margin: 0; padding: 32px 40px; font-size: 14px;
        }}
        .mono {{ font-family: 'IBM Plex Mono', monospace; }}
        .muted {{ color: var(--text-muted); }}
        .faint {{ color: var(--text-faint); }}

        header {{
            display: flex; justify-content: space-between; align-items: baseline;
            padding-bottom: 20px; border-bottom: 1px solid var(--border);
            margin-bottom: 0;
        }}
        h1 {{ font-size: 18px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }}
        .system-desc {{ color: var(--text-muted); font-size: 13px; margin-top: 3px; }}
        .clock {{ font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: var(--text-muted); text-align: right; }}
        .clock .blink {{ animation: blink 1.4s step-start infinite; }}
        @keyframes blink {{ 50% {{ opacity: 0.15; }} }}

        .status-strip {{
            display: grid; grid-template-columns: repeat(4, 1fr);
            border-bottom: 1px solid var(--border); margin-bottom: 28px;
        }}
        .status-cell {{
            padding: 18px 20px; border-right: 1px solid var(--border);
        }}
        .status-cell:last-child {{ border-right: none; }}
        .status-cell .n {{ font-family: 'IBM Plex Mono', monospace; font-size: 26px; font-weight: 500; }}
        .status-cell .n.alert {{ color: var(--accent-alert); }}
        .status-cell .label {{ color: var(--text-muted); font-size: 12.5px; margin-top: 2px; }}

        section {{ margin-bottom: 28px; }}
        .section-title {{
            font-size: 13px; color: var(--text-muted); font-weight: 500;
            margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;
        }}

        .panel {{
            border: 1px solid var(--border); border-radius: 3px; background: var(--surface);
        }}
        .panel.alert-border {{ border-color: var(--accent-alert); }}

        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{
            text-align: left; color: var(--text-faint); font-weight: 500; font-size: 12px;
            padding: 10px 16px; border-bottom: 1px solid var(--border);
        }}
        td {{ padding: 9px 16px; border-bottom: 1px solid var(--border); }}
        tr:last-child td {{ border-bottom: none; }}
        .empty {{ color: var(--text-faint); padding: 18px 16px; }}

        .sev {{ font-size: 12px; }}
        .sev-high {{ color: var(--accent-alert); font-weight: 600; }}
        .sev-medium {{ color: var(--text-muted); }}

        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .split-col {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }}
        .chart-wrap {{ position: relative; height: 200px; padding: 16px; }}

        .ratio-bar {{
            display: flex; height: 8px; border-radius: 2px; overflow: hidden;
            margin: 14px 16px 10px 16px; background: var(--border);
        }}
        .ratio-bar .seg-high {{ background: var(--accent-alert); }}
        .ratio-bar .seg-medium {{ background: var(--accent-calm); opacity: 0.55; }}
        .ratio-legend {{ display: flex; justify-content: space-between; padding: 0 16px 16px 16px; font-size: 12.5px; }}
        .ratio-legend .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }}

        footer {{ color: var(--text-faint); font-size: 12px; padding-top: 16px; }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>IDS Console</h1>
            <div class="system-desc">Monitoring traffic across the attacker, target and detection instances</div>
        </div>
        <div class="clock">{generated_at.replace(':', '<span class="blink">:</span>', 1)}<br><span class="faint">refreshes every {REFRESH_SECONDS}s</span></div>
    </header>

    <div class="status-strip">
        <div class="status-cell">
            <div class="n">{stats['total']:,}</div>
            <div class="label">alerts recorded</div>
        </div>
        <div class="status-cell">
            <div class="n {'alert' if stats['high'] else ''}">{stats['high']}</div>
            <div class="label">high severity</div>
        </div>
        <div class="status-cell">
            <div class="n {'alert' if blocks else ''}">{len(blocks)}</div>
            <div class="label">active block{'s' if len(blocks) != 1 else ''}</div>
        </div>
        <div class="status-cell">
            <div class="n">{stats['rule']}</div>
            <div class="label">rule-based catches</div>
        </div>
    </div>

    <section>
        <div class="section-title">Active blocks</div>
        <div class="panel {'alert-border' if has_blocks else ''}">
            <table>
                <tr><th>address</th><th>expires</th><th>reason</th></tr>
                {block_rows}
            </table>
        </div>
    </section>

    <div class="two-col">
        <section>
            <div class="section-title">Alert volume, last 2 hours</div>
            <div class="panel"><div class="chart-wrap"><canvas id="timeChart"></canvas></div></div>
        </section>
        <section>
            <div class="section-title">Top sources</div>
            <div class="panel"><div class="chart-wrap"><canvas id="topIpsChart"></canvas></div></div>
        </section>
    </div>

    <div class="split-col">
        <section>
            <div class="section-title">Recent activity</div>
            <div class="panel">
                <table>
                    <tr><th>time</th><th>source</th><th>what happened</th><th>severity</th><th>method</th></tr>
                    {alert_rows}
                </table>
            </div>
        </section>

        <section>
            <div class="section-title">Detection mix</div>
            <div class="panel">
                <div class="ratio-bar">
                    <div class="seg-high" style="width:{high_pct}%"></div>
                    <div class="seg-medium" style="width:{medium_pct}%"></div>
                </div>
                <div class="ratio-legend">
                    <span><span class="dot" style="background:var(--accent-alert)"></span>rule-based: {stats['high']}</span>
                    <span class="muted"><span class="dot" style="background:var(--accent-calm);opacity:.55"></span>z-score: {stats['medium']}</span>
                </div>
            </div>
        </section>
    </div>

    <section>
        <div class="section-title">Baseline profile</div>
        <div class="panel">
            <table>
                <tr><th>feature</th><th>mean</th><th>std dev</th></tr>
                {baseline_rows}
            </table>
        </div>
    </section>

    <footer>Detection engine baseline built from 45–60 minutes of captured normal traffic. Z-score threshold: 4.0σ.</footer>

    <script>
        Chart.defaults.font.family = "'IBM Plex Mono', monospace";
        Chart.defaults.color = '#7C8697';

        new Chart(document.getElementById('topIpsChart'), {{
            type: 'bar',
            data: {{
                labels: {top_ips_labels},
                datasets: [{{ data: {top_ips_values}, backgroundColor: '#2E3542', borderRadius: 2 }}]
            }},
            options: {{
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ font: {{ size: 10 }} }}, grid: {{ color: '#1A1E27' }} }},
                    y: {{ ticks: {{ font: {{ size: 10 }} }}, grid: {{ display: false }} }}
                }}
            }}
        }});

        new Chart(document.getElementById('timeChart'), {{
            type: 'line',
            data: {{
                labels: {time_labels_json},
                datasets: [{{
                    data: {time_values_json},
                    borderColor: '#4FD1C5', backgroundColor: 'rgba(79,209,197,0.06)',
                    fill: true, tension: 0.25, pointRadius: 0, borderWidth: 1.5
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ maxTicksLimit: 7, font: {{ size: 10 }} }}, grid: {{ display: false }} }},
                    y: {{ beginAtZero: true, ticks: {{ font: {{ size: 10 }} }}, grid: {{ color: '#1A1E27' }} }}
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