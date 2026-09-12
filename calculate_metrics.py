"""
Phase 7: Metrics calculator (multi-attacker capable).

Run this ON THE DETECTION-SERVER after a mixed_test.sh run.

Reads:
  - decision_log.jsonl   (written automatically by run_cycle.py - every
                           window it looked at during the test, and
                           whether it flagged that window or not)
  - ground_truth.json    (you create this manually from the timestamps
                           mixed_test.sh printed on each Attacker)

ground_truth.json format - MULTI-ATTACKER (preferred, use this when
testing with attacker + attacker2 simultaneously or staggered):
{
  "test_start": "2026-08-26T09:00:00+00:00",
  "test_end":   "2026-08-26T09:20:00+00:00",
  "attackers": [
    {"attacker_ip": "10.0.1.70",  "attack_start": "2026-08-26T09:10:00+00:00", "attack_end": "2026-08-26T09:12:00+00:00"},
    {"attacker_ip": "10.0.1.194", "attack_start": "2026-08-26T09:11:00+00:00", "attack_end": "2026-08-26T09:13:00+00:00"}
  ]
}

ground_truth.json format - SINGLE-ATTACKER (still supported, for a plain
one-attacker run):
{
  "attacker_ip": "10.0.1.70",
  "test_start":   "2026-08-26T09:00:00+00:00",
  "attack_start": "2026-08-26T09:10:00+00:00",
  "attack_end":   "2026-08-26T09:12:00+00:00",
  "test_end":     "2026-08-26T09:17:00+00:00"
}

Outputs:
  - One COMBINED confusion matrix across all attackers (TP / FP / TN / FN)
  - Combined Detection Rate / False Positive Rate
  - A PER-ATTACKER breakdown table, including each attacker's own
    Response Time (useful evidence that detection still works promptly
    even when multiple sources attack at once)
"""

import json
from datetime import datetime, timezone

DECISION_LOG_FILE = "decision_log.jsonl"
GROUND_TRUTH_FILE = "ground_truth.json"


def load_ground_truth():
    with open(GROUND_TRUTH_FILE, "r") as f:
        raw = json.load(f)

    test_start = datetime.fromisoformat(raw["test_start"])
    test_end = datetime.fromisoformat(raw["test_end"])

    if "attackers" in raw:
        attackers = [
            {
                "attacker_ip": a["attacker_ip"],
                "attack_start": datetime.fromisoformat(a["attack_start"]),
                "attack_end": datetime.fromisoformat(a["attack_end"]),
            }
            for a in raw["attackers"]
        ]
    else:
        attackers = [{
            "attacker_ip": raw["attacker_ip"],
            "attack_start": datetime.fromisoformat(raw["attack_start"]),
            "attack_end": datetime.fromisoformat(raw["attack_end"]),
        }]

    return {"test_start": test_start, "test_end": test_end, "attackers": attackers}


def load_decision_log_in_window(test_start, test_end):
    """
    Reads decision_log.jsonl ONE LINE AT A TIME and keeps only entries
    within [test_start, test_end]. This file is written to on every
    cron cycle (every window examined, not just alerts), so after weeks
    of running it can be far too large to fit in memory as a fully
    parsed list — loading it all first (the old approach) caused an
    out-of-memory kill on a t3.micro. Filtering during the read instead
    means memory use stays proportional to your ~20-minute test window,
    not the whole multi-week file.
    """
    entries = []
    with open(DECISION_LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            window_dt = datetime.fromtimestamp(row["window_start"], tz=timezone.utc)
            if test_start <= window_dt <= test_end:
                row["window_dt"] = window_dt
                entries.append(row)
    return entries


def is_attack_window(entry, attackers):
    for a in attackers:
        if entry["src_ip"] == a["attacker_ip"] and a["attack_start"] <= entry["window_dt"] < a["attack_end"]:
            return a
    return None


def calculate_metrics():
    gt = load_ground_truth()
    entries = load_decision_log_in_window(gt["test_start"], gt["test_end"])

    if not entries:
        print("No decision_log.jsonl entries found within the test window.")
        print("Check that ground_truth.json timestamps match when the test actually ran,")
        print("and that run_cycle.py (with decision logging) was running via cron during the test.")
        return

    tp = fp = tn = fn = 0
    per_attacker_first_tp = {a["attacker_ip"]: None for a in gt["attackers"]}

    for e in entries:
        matching_attacker = is_attack_window(e, gt["attackers"])
        detected = e["detected"]

        if matching_attacker and detected:
            tp += 1
            ip = matching_attacker["attacker_ip"]
            if per_attacker_first_tp[ip] is None or e["window_dt"] < per_attacker_first_tp[ip]:
                per_attacker_first_tp[ip] = e["window_dt"]
        elif matching_attacker and not detected:
            fn += 1
        elif not matching_attacker and detected:
            fp += 1
        else:
            tn += 1

    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else None
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else None

    print("=" * 70)
    print("PHASE 7 - DETECTION METRICS (multi-attacker)")
    print("=" * 70)
    print(f"Test window: {gt['test_start']}  ->  {gt['test_end']}")
    print(f"Attackers:   {len(gt['attackers'])}")
    for a in gt["attackers"]:
        print(f"  - {a['attacker_ip']}: attack window {a['attack_start']} -> {a['attack_end']}")
    print(f"Total windows analysed within test period: {len(entries)}")
    print("-" * 70)
    print("COMBINED CONFUSION MATRIX (across all attackers)")
    print(f"  True Positives  (TP): {tp}")
    print(f"  False Positives (FP): {fp}")
    print(f"  True Negatives  (TN): {tn}")
    print(f"  False Negatives (FN): {fn}")
    print("-" * 70)
    print("COMBINED DERIVED METRICS")
    if detection_rate is not None:
        print(f"  Detection Rate       = TP/(TP+FN) = {detection_rate:.3f}")
    else:
        print("  Detection Rate: N/A (no attack windows found)")
    if false_positive_rate is not None:
        print(f"  False Positive Rate  = FP/(FP+TN) = {false_positive_rate:.3f}")
    else:
        print("  False Positive Rate: N/A (no normal windows found)")
    print("-" * 70)
    print("PER-ATTACKER RESPONSE TIME")
    for a in gt["attackers"]:
        ip = a["attacker_ip"]
        first_tp = per_attacker_first_tp[ip]
        if first_tp is not None:
            rt = (first_tp - a["attack_start"]).total_seconds()
            print(f"  {ip}: {rt:.0f} seconds (first detection at {first_tp})")
        else:
            print(f"  {ip}: N/A - no True Positive recorded during this attacker's window")
    print("=" * 70)

    print("\nMarkdown table for your Phase 8 report:\n")
    print("| Metric | Value |")
    print("|---|---|")
    print(f"| True Positives | {tp} |")
    print(f"| False Positives | {fp} |")
    print(f"| True Negatives | {tn} |")
    print(f"| False Negatives | {fn} |")
    print(f"| Detection Rate | {detection_rate:.3f} |" if detection_rate is not None else "| Detection Rate | N/A |")
    print(f"| False Positive Rate | {false_positive_rate:.3f} |" if false_positive_rate is not None else "| False Positive Rate | N/A |")
    for a in gt["attackers"]:
        ip = a["attacker_ip"]
        first_tp = per_attacker_first_tp[ip]
        rt_str = f"{(first_tp - a['attack_start']).total_seconds():.0f}" if first_tp else "N/A"
        print(f"| Response Time - {ip} (s) | {rt_str} |")


if __name__ == "__main__":
    calculate_metrics()