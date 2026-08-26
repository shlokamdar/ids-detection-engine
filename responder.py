"""
Phase 6 integration: invokes the add-block Lambda via boto3 whenever the
detection engine logs a new HIGH-severity (rule-based) alert.

Design decision: only RULE-based HIGH alerts trigger an automatic block,
not MEDIUM z-score anomalies. Z-score alerts are statistical deviations —
useful signal for a human/dashboard, but not confident enough on their own
to justify automatically cutting off an IP. Rule-based alerts are
deterministic signature matches (PORT_SCAN, SSH_BRUTE_FORCE, ICMP_FLOOD)
with confidence=1.0, which is the right bar for an automated action with
real consequences. Worth stating explicitly in the Phase 8 report as a
deliberate design choice, not an oversight.
"""

import json
import os

import boto3

from config import AWS_REGION

ADD_BLOCK_FUNCTION_NAME = os.environ.get("ADD_BLOCK_FUNCTION_NAME", "ids-add-block")
DEFAULT_BLOCK_DURATION_MINUTES = 15

_lambda_client = None


def _get_lambda_client():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda", region_name=AWS_REGION)
    return _lambda_client


def invoke_add_block(src_ip, reason, duration_minutes=DEFAULT_BLOCK_DURATION_MINUTES):
    """
    Fire-and-forget invoke of the add-block Lambda (InvocationType="Event"),
    so the detection cycle doesn't block waiting for the Lambda to finish.
    Returns True if the invoke request was accepted, False if it failed
    (e.g. Lambda not deployed yet, or an IAM permission gap) — logged but
    never raised, since a failed block shouldn't crash the whole cron cycle.
    """
    payload = {
        "ip": src_ip,
        "duration_minutes": duration_minutes,
        "reason": reason,
    }
    try:
        response = _get_lambda_client().invoke(
            FunctionName=ADD_BLOCK_FUNCTION_NAME,
            InvocationType="Event",
            Payload=json.dumps(payload).encode("utf-8"),
        )
        print(f"  [respond] invoked add-block for {src_ip} (reason={reason})")
        return response.get("StatusCode") == 202
    except Exception as e:
        print(f"  [respond] FAILED to invoke add-block for {src_ip}: {e}")
        return False
