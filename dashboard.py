"""
CLI/text dashboard (Phase 5 deliverable).

Prints:
  1. Last 5 alerts
  2. Current active blocks (populated once Phase 6 Lambda auto-block exists;
     shows empty gracefully until then)
  3. Baseline statistics summary
"""

import json
import os


def load_last_n_alerts(alerts_file, n=5):
    if not os.path.exists(alerts_file):
        return []
    with open(alerts_file, "r") as f:
        lines = [line for line in f if line.strip()]
    return [json.loads(line) for line in lines[-n:]]


def load_active_blocks(blocks_file="active_blocks.json"):
    """
    Phase 6's add-block Lambda will write/update this file (or an
    equivalent Security-Group query) when it blocks an IP. Until Phase 6
    is wired up, this simply returns an empty list rather than failing.
    """
    if not os.path.exists(blocks_file):
        return []
    with open(blocks_file, "r") as f:
        return json.load(f)


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
        print("  (none — Phase 6 automated response not yet integrated)")
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