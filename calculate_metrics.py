"""
Phase 7: Metrics calculator.

Run this ON THE DETECTION-SERVER after a mixed_test.sh run.

Reads:
  - decision_log.jsonl   (written automatically by run_cycle.py — every
                           window it looked at during the test, and
                           whether it flagged that window or not)
  - ground_truth.json    (you create this manually from the timestamps
                           mixed_test.sh printed on the Attacker)

ground_truth.json format:
{
  "attacker_ip": "10.0.1.40",
  "test_start":   "2026-08-26T09:00:00+00:00",
  "attack_start": "2026-08-26T09:10:00+00:00",
  "attack_end":   "2026-08-26T09:12:00+00:00",
  "test_end":     "2026-08-26T09:17:00+00:00"
}

Outputs:
  - Confusion matrix (TP / FP / TN / FN)
  - Detection Rate = TP / (TP + FN)
  - False Positive Rate = FP / (FP + TN)
  - Response Time = time from attack_start to the first TP detection
"""

import json
from datetime import datetime, timezone

DECISION_LOG_FILE = "decision_log.jsonl"
GROUND_TRUTH_FILE = "ground_truth.json"


def load_ground_truth():
    with open(GROUND_TRUTH_FILE, "r") as f:
        raw = json.load(f)
    return {
        "attacker_ip": raw["attacker_ip"],
        "test_start": datetime.fromisoformat(raw["test_start"]),
        "attack_start": datetime.fromisoformat(raw["attack_start"]),
        "attack_end": datetime.fromisoformat(raw["attack_end"]),
        "test_end": datetime.fromisoformat(raw["test_end"]),
    }


def load_decision_log():
    entries = []
    with open(DECISION_LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            row["window_dt"] = datetime.fromtimestamp(row["window_start"], tz=timezone.utc)
            entries.append(row)
    return entries


def calculate_metrics():
    gt = load_ground_truth()
    all_entries = load_decision_log()

    # Only consider windows that fall within the test period
    entries = [e for e in all_entries if gt["test_start"] <= e["window_dt"] <= gt["test_end"]]

    if not entries:
        print("No decision_log.jsonl entries found within the test window.")
        print("Check that ground_truth.json timestamps match when the test actually ran,")
        print("and that run_cycle.py (with decision logging) was running via cron during the test.")
        return

    tp = fp = tn = fn = 0
    first_tp_time = None

    for e in entries:
        is_attack_window = (
            e["src_ip"] == gt["attacker_ip"]
            and gt["attack_start"] <= e["window_dt"] < gt["attack_end"]
        )
        detected = e["detected"]

        if is_attack_window and detected:
            tp += 1
            if first_tp_time is None or e["window_dt"] < first_tp_time:
                first_tp_time = e["window_dt"]
        elif is_attack_window and not detected:
            fn += 1
        elif not is_attack_window and detected:
            fp += 1
        else:
            tn += 1

    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else None
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else None
    response_time = (first_tp_time - gt["attack_start"]).total_seconds() if first_tp_time else None

    print("=" * 70)
    print("PHASE 7 — DETECTION METRICS")
    print("=" * 70)
    print(f"Test window:    {gt['test_start']}  ->  {gt['test_end']}")
    print(f"Attack window:  {gt['attack_start']}  ->  {gt['attack_end']}")
    print(f"Attacker IP:    {gt['attacker_ip']}")
    print(f"Total windows analysed within test period: {len(entries)}")
    print("-" * 70)
    print("CONFUSION MATRIX")
    print(f"  True Positives  (TP): {tp}")
    print(f"  False Positives (FP): {fp}")
    print(f"  True Negatives  (TN): {tn}")
    print(f"  False Negatives (FN): {fn}")
    print("-" * 70)
    print("DERIVED METRICS")
    print(f"  Detection Rate       = TP/(TP+FN) = "
          f"{detection_rate:.3f}" if detection_rate is not None else "  Detection Rate: N/A (no attack windows found)")
    print(f"  False Positive Rate  = FP/(FP+TN) = "
          f"{false_positive_rate:.3f}" if false_positive_rate is not None else "  False Positive Rate: N/A (no normal windows found)")
    if response_time is not None:
        print(f"  Response Time        = {response_time:.0f} seconds "
              f"(first detection at {first_tp_time})")
    else:
        print("  Response Time: N/A — no True Positive was ever recorded during the attack window")
    print("=" * 70)

    # Also dump a small results table you can paste straight into your report
    print("\nMarkdown table for your Phase 8 report:\n")
    print("| Metric | Value |")
    print("|---|---|")
    print(f"| True Positives | {tp} |")
    print(f"| False Positives | {fp} |")
    print(f"| True Negatives | {tn} |")
    print(f"| False Negatives | {fn} |")
    print(f"| Detection Rate | {detection_rate:.3f} |" if detection_rate is not None else "| Detection Rate | N/A |")
    print(f"| False Positive Rate | {false_positive_rate:.3f} |" if false_positive_rate is not None else "| False Positive Rate | N/A |")
    print(f"| Response Time (s) | {response_time:.0f} |" if response_time is not None else "| Response Time (s) | N/A |")


if __name__ == "__main__":
    calculate_metrics()
