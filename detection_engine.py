import json
import statistics
import math
from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================

FEATURES_FILE = "features_20260824_132034.json"  # <-- your file
BASELINE_FILE = "baseline_profile.json"
ALERTS_FILE   = "alerts.jsonl"
Z_THRESHOLD   = 4.0          # raised from 3.0: with log-transformed volume features
                              # (see LOG_TRANSFORM_FEATURES), the baseline std dev is
                              # tighter and more representative, so 3 sigma over-fires
                              # on ordinary variation. 4 sigma restores a realistic
                              # false-positive rate (~3.6% here) while still catching
                              # genuine outliers.
MIN_STD_FLOOR = 0.01         # prevent division by zero

# Features we track with Z-Score.
# NOTE: Sparse/binary count features (port_22_count, port_80_count, port_443_count)
# were removed. Z-scores assume a roughly continuous distribution with real variance -
# these features are almost always 0, so any single hit produces an artificially huge
# z-score (e.g. z=100) that isn't a meaningful statistical signal. They're better suited
# to deterministic rule_detect() thresholds instead, which already cover port_22_count.
ZSCORE_FEATURES = [
    "total_connections",
    "unique_dst_ports",
    "avg_packets_per_conn",
    "avg_bytes_per_conn",
    "connections_per_second",
    "reject_ratio",
    "total_packets",
    "total_bytes",
    "avg_duration_seconds"
]

# Volume features are heavily right-skewed: most connections are a few hundred
# bytes, but rare legitimate events (apt update, scp, curl of a large file) carry
# tens of millions of bytes in a single window. A raw mean/std z-score assumes
# roughly-normal data, so these rare-but-real spikes distort the baseline's std
# dev and produce misleadingly huge z-scores. Log-transforming (log1p) these
# features before computing stats/z-scores is standard practice for network
# traffic volume data - it compresses the influence of rare large transfers
# while still surfacing genuinely anomalous volume (e.g. real exfiltration still
# shows up as an elevated log-value).
LOG_TRANSFORM_FEATURES = {
    "avg_packets_per_conn",
    "avg_bytes_per_conn",
    "total_packets",
    "total_bytes",
}


def transform_value(feature, value):
    """Apply log1p to heavy-tailed volume features; pass everything else through."""
    if feature in LOG_TRANSFORM_FEATURES:
        return math.log1p(max(value, 0))
    return value


# ============================================================
# PHASE 3: STATISTICAL PROFILING (Z-SCORE)
# ============================================================

def is_baseline_traffic(fv):
    """
    Select which feature vectors represent NORMAL traffic for the baseline.

    This dataset (features_20260824_132034.json) was captured during a clean
    45-60 min window before any attacks were run - so EVERYTHING in it is normal
    traffic by definition, including the constant background internet scanning
    that every public-facing EC2 receives (this is not malicious, it's ambient
    noise). Filtering to only "10.0.x.x" traffic excluded that scanner noise from
    the baseline, which is what caused ~75% of windows to be flagged as anomalies -
    the detector had never seen that traffic shape as "normal."

    Once you start running deliberate attacks (Phase 7), swap this back to a
    time-based cutoff, e.g.:
        return fv.get("window_start", 0) < ATTACK_START_TIMESTAMP
    so only the pre-attack portion of future captures is used to (re)build the
    baseline, and post-attack windows get evaluated against it.
    """
    return True


def compute_baseline(feature_vectors):
    """Compute mean and std dev for each feature from normal traffic."""
    baseline = {}
    for feature in ZSCORE_FEATURES:
        values = [transform_value(feature, fv[feature]) for fv in feature_vectors if feature in fv]
        if not values:
            continue
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        if std < MIN_STD_FLOOR:
            std = MIN_STD_FLOOR
        baseline[feature] = {"mean": mean, "std": std}
    return baseline


def zscore_detect(fv, baseline):
    """
    Returns: (is_anomaly: bool, max_z: float, trigger_feature: str)
    Uses the MAX absolute Z-Score across all features.
    """
    max_z = 0.0
    trigger = None

    for feature, stats in baseline.items():
        if feature not in fv:
            continue
        val = transform_value(feature, fv[feature])
        z = abs((val - stats["mean"]) / stats["std"])
        if z > max_z:
            max_z = z
            trigger = feature

    is_anomaly = max_z > Z_THRESHOLD
    return is_anomaly, max_z, trigger


# ============================================================
# PHASE 4: RULE-BASED DETECTION
# ============================================================

def rule_detect(fv):
    """
    Deterministic signature detection.
    Returns a list of alert dicts.
    """
    alerts = []

    # --- Port Scan Rule ---
    if (fv.get("unique_dst_ports", 0) > 40 and
        fv.get("avg_bytes_per_conn", 0) < 100 and
        fv.get("reject_ratio", 0) > 0.8):
        alerts.append({
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "confidence": 1.0,
            "reason": (f"unique_dst_ports={fv['unique_dst_ports']}, "
                       f"avg_bytes={fv['avg_bytes_per_conn']:.1f}, "
                       f"reject={fv['reject_ratio']:.2f}")
        })

    # --- SSH Brute Force Rule ---
    if (fv.get("port_22_count", 0) > 0 and
        fv.get("total_connections", 0) > 100 and
        fv.get("avg_bytes_per_conn", 0) < 150):
        alerts.append({
            "type": "SSH_BRUTE_FORCE",
            "severity": "HIGH",
            "confidence": 1.0,
            "reason": (f"port_22_count={fv['port_22_count']}, "
                       f"connections={fv['total_connections']}")
        })

    # --- ICMP Flood Rule (optional) ---
    if (fv.get("primary_protocol") == 1 and
        fv.get("total_packets", 0) > 500):
        alerts.append({
            "type": "ICMP_FLOOD",
            "severity": "HIGH",
            "confidence": 1.0,
            "reason": f"protocol=ICMP, packets={fv['total_packets']}"
        })

    return alerts


# ============================================================
# PHASE 5: DECISION FUSION & OUTPUT
# ============================================================

def run_detection():
    # 1. Load feature vectors
    with open(FEATURES_FILE, "r") as f:
        all_vectors = json.load(f)

    # 2. Split: baseline (normal) vs everything to analyse
    baseline_vectors = [fv for fv in all_vectors if is_baseline_traffic(fv)]
    analyse_vectors  = all_vectors  # analyse everything

    print(f"Total vectors loaded: {len(all_vectors)}")
    print(f"Baseline vectors (normal): {len(baseline_vectors)}")
    print(f"Z-Score threshold: {Z_THRESHOLD} sigma\n")

    if len(baseline_vectors) < 5:
        print("WARNING: Your baseline has fewer than 5 vectors.")
        print("Edit is_baseline_traffic() to include more normal traffic.")
        return

    # 3. Compute baseline statistics
    baseline = compute_baseline(baseline_vectors)

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"Saved baseline profile to: {BASELINE_FILE}\n")

    # 4. Run detection on every vector
    alerts_log = []
    detection_count = {"PORT_SCAN": 0, "SSH_BRUTE_FORCE": 0, "ICMP_FLOOD": 0, "ZSCORE_ANOMALY": 0}

    print("=" * 70)
    print("DETECTION RESULTS")
    print("=" * 70)

    for fv in analyse_vectors:
        ts = datetime.utcfromtimestamp(fv["window_start"]).strftime('%Y-%m-%d %H:%M:%S')
        src_ip = fv["src_ip"]

        # Layer 1: Rules
        rule_alerts = rule_detect(fv)

        # Layer 2: Z-Score
        is_anomaly, max_z, trigger = zscore_detect(fv, baseline)

        # Decision Fusion: Rule OR Z-Score
        if rule_alerts or is_anomaly:
            print(f"\n[{ts}] Source: {src_ip}")

            for alert in rule_alerts:
                detection_count[alert["type"]] += 1
                alert_record = {
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "alert_type": alert["type"],
                    "severity": alert["severity"],
                    "confidence": alert["confidence"],
                    "triggering_method": "RULE",
                    "reason": alert["reason"],
                    "features": {k: fv.get(k) for k in ZSCORE_FEATURES}
                }
                alerts_log.append(alert_record)
                print(f"  [RULE] {alert['type']:15} | {alert['severity']} | {alert['reason']}")

            if is_anomaly:
                detection_count["ZSCORE_ANOMALY"] += 1
                alert_record = {
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "alert_type": "STATISTICAL_ANOMALY",
                    "severity": "MEDIUM",
                    "confidence": round(min(max_z / 10.0, 1.0), 3),
                    "triggering_method": "ZSCORE",
                    "reason": f"max_z_score={max_z:.2f}, trigger={trigger}",
                    "features": {k: fv.get(k) for k in ZSCORE_FEATURES}
                }
                alerts_log.append(alert_record)
                print(f"  [Z-SC] ANOMALY         | MEDIUM | z={max_z:.2f} (trigger: {trigger})")
                print(f"         conn={fv['total_connections']}, ports={fv['unique_dst_ports']}, "
                      f"bytes={fv['avg_bytes_per_conn']:.1f}, reject={fv['reject_ratio']:.2f}")

    # 5. Save alerts
    with open(ALERTS_FILE, "w") as f:
        for alert in alerts_log:
            f.write(json.dumps(alert) + "\n")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for k, v in detection_count.items():
        if v > 0:
            print(f"  {k:20}: {v}")
    print(f"\nAlerts written to: {ALERTS_FILE}")


if __name__ == "__main__":
    run_detection()