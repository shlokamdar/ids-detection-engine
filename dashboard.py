"""
CLI/text dashboard (Phase 5 deliverable, updated for Phase 6).

Prints:
  1. Last 5 alerts
  2. Current active blocks — now queries the Target Security Group directly
     via boto3, so this reflects real auto-blocks created by the add-block
     Lambda (Phase 6), not a placeholder file.
  3. Baseline statistics summary
"""

import json
import os
from datetime import datetime, timezone

import boto3

from blocklist_utils import parse_description
from config import AWS_REGION
from timezone_utils import utc_str_to_ist, utc_dt_to_ist

TARGET_SG_NAME = "target-sg"


def load_last_n_alerts(alerts_file, n=5):
    if not os.path.exists(alerts_file):
        return []
    with open(alerts_file, "r") as f:
        lines = [line for line in f if line.strip()]
    alerts = [json.loads(line) for line in lines[-n:]]
    for a in alerts:
        a["timestamp"] = utc_str_to_ist(a["timestamp"])
    return alerts


def load_active_blocks():
    """
    Queries the live Target Security Group and returns every ingress rule
    that carries our auto-blocked tag AND hasn't expired yet. This is the
    real Phase 6 state — no local file, no separate bookkeeping — the
    Security Group itself is the single source of truth.
    """
    try:
        ec2 = boto3.client("ec2", region_name=AWS_REGION)
        response = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [TARGET_SG_NAME]}]
        )
        security_groups = response.get("SecurityGroups", [])
        if not security_groups:
            return []

        sg = security_groups[0]
        now = datetime.now(timezone.utc)
        active = []

        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                parsed = parse_description(ip_range.get("Description"))
                if parsed is None:
                    continue  # not one of ours (e.g. your own management-IP rule)
                if parsed["expiry"] > now:
                    active.append({
                        "ip": ip_range["CidrIp"],
                        "expiry": utc_dt_to_ist(parsed["expiry"]),
                        "reason": parsed["reason"],
                    })

        return active

    except Exception as e:
        # Don't let a permissions hiccup or network blip crash the whole
        # dashboard render — just show the section as unavailable this cycle.
        print(f"  [dashboard] could not query active blocks: {e}")
        return []


def print_dashboard(alerts_file="alerts.jsonl", baseline_file="baseline_profile.json"):
    print("\n" + "=" * 70)
    print("IDS DASHBOARD".center(70))
    print("=" * 70)

    # --- Last 5 alerts ---
    print("\nLAST 5 ALERTS")
    print("-" * 70)
    alerts = load_last_n_alerts(alerts_file, 5)
    if not alerts:
        print("  (no alerts yet)")
    else:
        for a in alerts:
            print(f"  [{a['timestamp']}] {a['src_ip']:16} {a['alert_type']:20} "
                  f"{a['severity']:6} via {a['triggering_method']}")

    # --- Active blocks ---
    print("\nACTIVE BLOCKS")
    print("-" * 70)
    blocks = load_active_blocks()
    if not blocks:
        print("  (none currently active)")
    else:
        for b in blocks:
            print(f"  {b['ip']:16} expires {b['expiry']}  reason={b['reason']}")

    # --- Baseline summary ---
    print("\nBASELINE STATISTICS SUMMARY")
    print("-" * 70)
    if os.path.exists(baseline_file):
        with open(baseline_file, "r") as f:
            baseline = json.load(f)
        for feature, stats in baseline.items():
            print(f"  {feature:24} mean={stats['mean']:.3f}  std={stats['std']:.3f}")
    else:
        print("  (no baseline profile found)")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    print_dashboard()