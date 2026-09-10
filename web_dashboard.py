"""
Web dashboard v5 — light theme, card-based redesign.

Visual direction explicitly requested: light background, white rounded
cards with soft shadows, colored icon-badge KPI cards, donut chart with
legend + table, pill-style status badges. Adapted from a referenced
hotel-management dashboard's visual language into IDS/security data.

Same underlying data functions as v4 (friendly_reason, scan_alerts_file,
build_time_series unchanged) — this pass changes render_dashboard_html's
HTML/CSS only.

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
    "PORT_SCAN": "Port scan",
    "SSH_BRUTE_FORCE": "SSH brute force",
    "ICMP_FLOOD": "ICMP flood",
}

# --- Inline SVG icons (no external icon font dependency) ---
ICON_BELL = '<path d="M12 3a5 5 0 0 0-5 5v3.2c0 .5-.2 1-.5 1.4L5 15h14l-1.5-2.4c-.3-.4-.5-.9-.5-1.4V8a5 5 0 0 0-5-5z"/><path d="M9.5 18a2.5 2.5 0 0 0 5 0"/>'
ICON_WARNING = '<path d="M12 4 3 19h18L12 4z"/><path d="M12 10v4"/><circle cx="12" cy="17" r="0.5" fill="currentColor"/>'
ICON_SHIELD = '<path d="M12 3 4 6v6c0 4.5 3 7.5 8 9 5-1.5 8-4.5 8-9V6l-8-3z"/>'
ICON_CHECK = '<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.3 2.3L16 10"/>'


def icon_svg(path, size=20):
    return f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{path}</svg>'


def friendly_reason(alert):
    if alert.get("triggering_method") == "ZSCORE":
        match = ZSCORE_REASON_RE.search(alert.get("reason", ""))
        if match:
            z_value, feature = match.groups()
            label = FRIENDLY_FEATURE_NAMES.get(feature, feature.replace("_", " "))
            return f"Unusual {label} (z={float(z_value):.1f})"
        return "Unusual traffic pattern"
    else:
        alert_type = alert.get("alert_type", "unknown")
        return RULE_LABELS.get(alert_type, alert_type.replace("_", " ").title())


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
    has_blocks = bool(blocks)
    high_pct = (stats["high"] / stats["total"] * 100) if stats["total"] else 0

    alert_rows = "".join(
        f"<tr><td class='mono muted'>{a['timestamp']}</td><td class='mono'>{a['src_ip']}</td>"
        f"<td>{friendly_reason(a)}</td>"
        f"<td><span class='pill pill-{a['severity'].lower()}'>{a['severity'].title()}</span></td></tr>"
        for a in reversed(alerts)
    ) or "<tr><td colspan='4' class='empty'>No alerts recorded yet.</td></tr>"

    block_rows = "".join(
        f"<tr><td class='mono'>{b['ip']}</td><td class='mono muted'>{b['expiry']}</td>"
        f"<td><span class='pill pill-high'>{b['reason'].replace('_', ' ').title()}</span></td></tr>"
        for b in blocks
    ) or "<tr><td colspan='3' class='empty'>No active blocks right now.</td></tr>"

    baseline_rows = "".join(
        f"<tr><td>{feature.replace('_', ' ').title()}</td><td class='mono'>{s['mean']:.3f}</td><td class='mono muted'>{s['std']:.3f}</td></tr>"
        for feature, s in baseline.items()
    ) or "<tr><td colspan='3' class='empty'>No baseline profile found.</td></tr>"

    top_ip_rows = "".join(
        f"<div class='ip-row'><span class='mono'>{ip}</span><span class='ip-count'>{count}</span></div>"
        for ip, count in top_ips[:6]
    ) or "<div class='empty'>No source data yet.</div>"

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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg: #F4F5FA;
            --card: #FFFFFF;
            --border: #ECEDF3;
            --text: #1F2430;
            --text-muted: #8A8FA3;
            --text-faint: #B7BBCB;
            --orange: #FF6A45;
            --orange-soft: #FFF0EB;
            --blue: #4C6FFF;
            --blue-soft: #EEF1FF;
            --amber: #FFB020;
            --amber-soft: #FFF6E5;
            --green: #22C55E;
            --green-soft: #E9FBF0;
            --red: #EF4444;
            --red-soft: #FDEAEA;
            --shadow: 0 2px 10px rgba(31,36,48,0.05), 0 1px 2px rgba(31,36,48,0.04);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg); color: var(--text);
            margin: 0; padding: 28px 36px; font-size: 14px;
        }}
        .mono {{ font-family: 'IBM Plex Mono', monospace; font-size: 12.5px; }}
        .muted {{ color: var(--text-muted); }}

        header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }}
        .brand {{ display: flex; align-items: center; gap: 10px; }}
        .brand-icon {{
            width: 36px; height: 36px; border-radius: 10px; background: var(--orange);
            display: flex; align-items: center; justify-content: center; color: white;
        }}
        h1 {{ font-size: 17px; font-weight: 700; margin: 0; }}
        .brand-sub {{ font-size: 12px; color: var(--text-muted); }}
        .status-badge {{
            display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--text-muted);
        }}
        .live-dot {{ width: 7px; height: 7px; border-radius: 50%; background: var(--green); }}

        .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; margin-bottom: 20px; }}
        .kpi-card {{
            background: var(--card); border-radius: 14px; padding: 18px 20px;
            box-shadow: var(--shadow);
        }}
        .kpi-top {{ display: flex; justify-content: space-between; align-items: flex-start; }}
        .kpi-icon {{ width: 38px; height: 38px; border-radius: 10px; display: flex; align-items: center; justify-content: center; }}
        .kpi-icon.orange {{ background: var(--orange-soft); color: var(--orange); }}
        .kpi-icon.red {{ background: var(--red-soft); color: var(--red); }}
        .kpi-icon.blue {{ background: var(--blue-soft); color: var(--blue); }}
        .kpi-icon.green {{ background: var(--green-soft); color: var(--green); }}
        .kpi-value {{ font-size: 25px; font-weight: 700; margin-top: 12px; }}
        .kpi-label {{ font-size: 12.5px; color: var(--text-muted); margin-top: 2px; }}
        .kpi-bar {{ height: 5px; border-radius: 3px; background: var(--border); margin-top: 12px; overflow: hidden; }}
        .kpi-bar-fill {{ height: 100%; border-radius: 3px; }}

        .row-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-bottom: 18px; }}
        .row-split {{ display: grid; grid-template-columns: 1fr 1.4fr; gap: 18px; margin-bottom: 18px; }}

        .card {{ background: var(--card); border-radius: 14px; padding: 20px 22px; box-shadow: var(--shadow); }}
        .card-title {{ font-size: 14.5px; font-weight: 600; margin-bottom: 4px; }}
        .card-subtitle {{ font-size: 12px; color: var(--text-muted); margin-bottom: 14px; }}

        .ip-row {{
            display: flex; justify-content: space-between; align-items: center;
            padding: 9px 0; border-bottom: 1px solid var(--border);
        }}
        .ip-row:last-child {{ border-bottom: none; }}
        .ip-count {{
            background: var(--orange-soft); color: var(--orange); font-weight: 600; font-size: 12px;
            padding: 2px 9px; border-radius: 20px;
        }}

        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ text-align: left; color: var(--text-faint); font-weight: 600; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.03em; padding: 8px 10px; border-bottom: 1px solid var(--border); }}
        td {{ padding: 10px; border-bottom: 1px solid var(--border); }}
        tr:last-child td {{ border-bottom: none; }}
        .empty {{ color: var(--text-faint); padding: 16px 10px; }}

        .pill {{ font-size: 11.5px; font-weight: 600; padding: 3px 11px; border-radius: 20px; }}
        .pill-high {{ background: var(--red-soft); color: var(--red); }}
        .pill-medium {{ background: var(--amber-soft); color: #B8760A; }}

        .chart-wrap {{ position: relative; height: 190px; }}
        .donut-wrap {{ display: flex; align-items: center; gap: 20px; }}
        .donut-canvas {{ position: relative; width: 140px; height: 140px; flex-shrink: 0; }}
        .donut-legend {{ flex: 1; }}
        .legend-item {{ display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 13px; }}
        .legend-dot {{ width: 10px; height: 10px; border-radius: 3px; }}
        .legend-value {{ margin-left: auto; font-weight: 600; }}

        footer {{ color: var(--text-faint); font-size: 12px; margin-top: 8px; text-align: center; }}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <div class="brand-icon">{icon_svg(ICON_SHIELD, 20)}</div>
            <div>
                <h1>IDS Dashboard</h1>
                <div class="brand-sub">Attacker, target and detection instance monitoring</div>
            </div>
        </div>
        <div class="status-badge"><span class="live-dot"></span>Updated {generated_at} &middot; refreshes every {REFRESH_SECONDS}s</div>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-top">
                <div class="kpi-icon orange">{icon_svg(ICON_BELL)}</div>
            </div>
            <div class="kpi-value">{stats['total']:,}</div>
            <div class="kpi-label">Total alerts</div>
            <div class="kpi-bar"><div class="kpi-bar-fill" style="width:100%;background:var(--orange)"></div></div>
        </div>
        <div class="kpi-card">
            <div class="kpi-top">
                <div class="kpi-icon red">{icon_svg(ICON_WARNING)}</div>
            </div>
            <div class="kpi-value">{stats['high']}</div>
            <div class="kpi-label">High severity</div>
            <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{max(high_pct, 3)}%;background:var(--red)"></div></div>
        </div>
        <div class="kpi-card">
            <div class="kpi-top">
                <div class="kpi-icon blue">{icon_svg(ICON_SHIELD)}</div>
            </div>
            <div class="kpi-value">{len(blocks)}</div>
            <div class="kpi-label">Active block{'s' if len(blocks) != 1 else ''}</div>
            <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{'100' if blocks else '4'}%;background:var(--blue)"></div></div>
        </div>
        <div class="kpi-card">
            <div class="kpi-top">
                <div class="kpi-icon green">{icon_svg(ICON_CHECK)}</div>
            </div>
            <div class="kpi-value">{stats['rule']}</div>
            <div class="kpi-label">Rule-based catches</div>
            <div class="kpi-bar"><div class="kpi-bar-fill" style="width:100%;background:var(--green)"></div></div>
        </div>
    </div>

    <div class="row-2">
        <div class="card">
            <div class="card-title">Active blocks</div>
            <div class="card-subtitle">Automatically contained by the response engine</div>
            <table>
                <tr><th>Address</th><th>Expires</th><th>Reason</th></tr>
                {block_rows}
            </table>
        </div>
        <div class="card">
            <div class="card-title">Top sources</div>
            <div class="card-subtitle">Most frequent alert origins</div>
            {top_ip_rows}
        </div>
    </div>

    <div class="row-split">
        <div class="card">
            <div class="card-title">Detection breakdown</div>
            <div class="card-subtitle">Rule-based vs. statistical</div>
            <div class="donut-wrap">
                <div class="donut-canvas"><canvas id="donutChart"></canvas></div>
                <div class="donut-legend">
                    <div class="legend-item"><span class="legend-dot" style="background:var(--red)"></span>Rule-based<span class="legend-value">{stats['high']}</span></div>
                    <div class="legend-item"><span class="legend-dot" style="background:var(--amber)"></span>Z-score<span class="legend-value">{stats['medium']}</span></div>
                </div>
            </div>
        </div>
        <div class="card">
            <div class="card-title">Alert volume, last 2 hours</div>
            <div class="card-subtitle">Alerts recorded per 10-minute window</div>
            <div class="chart-wrap"><canvas id="timeChart"></canvas></div>
        </div>
    </div>

    <div class="row-2">
        <div class="card" style="grid-column: span 2;">
            <div class="card-title">Recent alerts</div>
            <div class="card-subtitle">Last 10 detections across all sources</div>
            <table>
                <tr><th>Time</th><th>Source</th><th>What happened</th><th>Severity</th></tr>
                {alert_rows}
            </table>
        </div>
    </div>

    <div class="card" style="margin-bottom: 20px;">
        <div class="card-title">Baseline profile</div>
        <div class="card-subtitle">Learned from 45&ndash;60 minutes of normal traffic &middot; Z-score threshold 4.0&sigma;</div>
        <table>
            <tr><th>Feature</th><th>Mean</th><th>Std dev</th></tr>
            {baseline_rows}
        </table>
    </div>

    <footer>IDS Dashboard &middot; auto-refreshing view, no action required</footer>

    <script>
        Chart.defaults.font.family = "'Inter', sans-serif";
        Chart.defaults.color = '#8A8FA3';

        new Chart(document.getElementById('donutChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Rule-based', 'Z-score'],
                datasets: [{{
                    data: [{stats['high']}, {stats['medium']}],
                    backgroundColor: ['#EF4444', '#FFB020'],
                    borderColor: '#FFFFFF',
                    borderWidth: 3
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false, cutout: '70%',
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});

        new Chart(document.getElementById('timeChart'), {{
            type: 'line',
            data: {{
                labels: {time_labels_json},
                datasets: [{{
                    data: {time_values_json},
                    borderColor: '#4C6FFF', backgroundColor: 'rgba(76,111,255,0.06)',
                    fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ maxTicksLimit: 7, font: {{ size: 10 }} }}, grid: {{ display: false }} }},
                    y: {{ beginAtZero: true, ticks: {{ font: {{ size: 10 }} }}, grid: {{ color: '#F0F1F6' }} }}
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