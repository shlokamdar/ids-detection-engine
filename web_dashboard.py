"""
Web dashboard (extends Phase 5/6 CLI dashboard.py into a browser view).

Reuses the exact same data-loading functions as the CLI dashboard
(load_last_n_alerts, load_active_blocks) so both views are always
guaranteed to show identical, correct data — no separate logic to
drift out of sync.

Run on the Detection-Server:
    python3 web_dashboard.py

Then visit http://<detection_public_ip>:5000 in a browser. Auto-refreshes
every 10 seconds so it can be left open during a live demo.

NOTE: requires port 5000 to be opened on the Detection-Server's Security
Group (see the Terraform change alongside this file) — restricted to your
own management IP, same as SSH.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask

from dashboard import load_last_n_alerts, load_active_blocks
from timezone_utils import utc_dt_to_ist

app = Flask(__name__)

ALERTS_FILE = "alerts.jsonl"
BASELINE_FILE = "baseline_profile.json"
REFRESH_SECONDS = 10


def _severity_class(severity):
    return "sev-high" if severity == "HIGH" else "sev-medium"


def render_dashboard_html(alerts, blocks, baseline, generated_at):
    """
    Pure rendering function — takes already-loaded data and returns an
    HTML string. Kept separate from the Flask route so it can be tested
    without a running server.
    """
    alert_rows = "".join(
        f"<tr><td>{a['timestamp']}</td><td>{a['src_ip']}</td>"
        f"<td>{a['alert_type']}</td>"
        f"<td><span class='badge {_severity_class(a['severity'])}'>{a['severity']}</span></td>"
        f"<td>{a['triggering_method']}</td></tr>"
        for a in reversed(alerts)
    ) or "<tr><td colspan='5' class='empty'>No alerts yet</td></tr>"

    block_rows = "".join(
        f"<tr><td>{b['ip']}</td><td>{b['expiry']}</td><td>{b['reason']}</td></tr>"
        for b in blocks
    ) or "<tr><td colspan='3' class='empty'>No active blocks</td></tr>"

    baseline_rows = "".join(
        f"<tr><td>{feature}</td><td>{stats['mean']:.3f}</td><td>{stats['std']:.3f}</td></tr>"
        for feature, stats in baseline.items()
    ) or "<tr><td colspan='3' class='empty'>No baseline profile found</td></tr>"

    block_count_label = f"{len(blocks)} ACTIVE" if blocks else "NONE ACTIVE"
    block_count_class = "count-active" if blocks else "count-clear"

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>IDS Dashboard</title>
    <meta http-equiv="refresh" content="{REFRESH_SECONDS}">
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif;
                background: #0f1115; color: #e6e6e6; margin: 0; padding: 24px; }}
        h1 {{ margin: 0 0 4px 0; font-size: 22px; }}
        .subtitle {{ color: #888; font-size: 13px; margin-bottom: 24px; }}
        .panel {{ background: #171a21; border: 1px solid #2a2e38; border-radius: 8px;
                  padding: 16px 20px; margin-bottom: 20px; }}
        .panel h2 {{ font-size: 15px; margin: 0 0 12px 0; color: #aab; text-transform: uppercase;
                     letter-spacing: 0.5px; display: flex; justify-content: space-between; align-items: center; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ text-align: left; color: #777; font-weight: 500; padding: 6px 8px; border-bottom: 1px solid #2a2e38; }}
        td {{ padding: 6px 8px; border-bottom: 1px solid #1e222b; }}
        tr:last-child td {{ border-bottom: none; }}
        .empty {{ color: #555; text-align: center; padding: 16px; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .sev-high {{ background: #4a1620; color: #ff6b6b; }}
        .sev-medium {{ background: #4a3d16; color: #ffc861; }}
        .count-active {{ background: #4a1620; color: #ff6b6b; padding: 2px 10px; border-radius: 12px; font-size: 12px; }}
        .count-clear {{ background: #16341f; color: #6bff8f; padding: 2px 10px; border-radius: 12px; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🛡️ IDS Dashboard</h1>
    <div class="subtitle">Auto-refreshes every {REFRESH_SECONDS}s &middot; Last updated {generated_at}</div>

    <div class="panel">
        <h2>Active Blocks <span class="{block_count_class}">{block_count_label}</span></h2>
        <table>
            <tr><th>IP Address</th><th>Expires</th><th>Reason</th></tr>
            {block_rows}
        </table>
    </div>

    <div class="panel">
        <h2>Recent Alerts</h2>
        <table>
            <tr><th>Time</th><th>Source IP</th><th>Alert Type</th><th>Severity</th><th>Method</th></tr>
            {alert_rows}
        </table>
    </div>

    <div class="panel">
        <h2>Baseline Statistics</h2>
        <table>
            <tr><th>Feature</th><th>Mean</th><th>Std Dev</th></tr>
            {baseline_rows}
        </table>
    </div>
</body>
</html>"""


@app.route("/")
def index():
    alerts = load_last_n_alerts(ALERTS_FILE, 10)
    blocks = load_active_blocks()

    baseline = {}
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            baseline = json.load(f)

    generated_at = utc_dt_to_ist(datetime.now(timezone.utc))
    return render_dashboard_html(alerts, blocks, baseline, generated_at)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)