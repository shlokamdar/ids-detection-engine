"""
Shared helpers for the Phase 6 automated-response Lambdas.

Both add_block.py and remove_expired_blocks.py need to:
  - build/parse the "auto-blocked|<timestamp>|expiry-<timestamp>|reason-<reason>"
    tag stored in a Security Group ingress rule's Description field
  - check an IP against the whitelist (management IP, AWS metadata service)

Kept here once so the two Lambdas can't drift out of sync on the format.
"""

import ipaddress
import re
from datetime import datetime, timedelta, timezone

# AWS's link-local metadata service address. Never block this — every
# instance (including the ones we manage) depends on it.
METADATA_SERVICE_CIDR = "169.254.169.254/32"

DESCRIPTION_PREFIX = "auto-blocked"
# NOTE: AWS Security Group rule descriptions only allow a specific charset
# (letters, digits, spaces, and . _ - : / ( ) # , @ [ ] + = ; { } ! $ *).
# The pipe character "|" used in the original phase-brief example
# ("auto-blocked|<ts>|expiry-<ts>|reason-X") is NOT in that allowed set and
# will raise InvalidParameterValue if you try to send it. We use ";" and
# "=" instead — both are AWS-allowed — while keeping the same intent/fields.
DESCRIPTION_RE = re.compile(
    r"^auto-blocked;blocked_at=(?P<blocked_at>[^;]+);expiry=(?P<expiry>[^;]+);reason=(?P<reason>.+)$"
)


def build_description(blocked_at, expiry, reason):
    """
    blocked_at / expiry: timezone-aware datetime objects (UTC).
    Returns the tag string stored in the SG rule's Description field.
    """
    return (
        f"{DESCRIPTION_PREFIX};blocked_at={blocked_at.isoformat()};"
        f"expiry={expiry.isoformat()};reason={reason}"
    )


def parse_description(description):
    """
    Returns a dict {blocked_at, expiry, reason} with datetimes parsed,
    or None if the description doesn't match our auto-blocked tag format
    (e.g. a manually-added rule that isn't ours to touch).
    """
    if not description:
        return None
    match = DESCRIPTION_RE.match(description)
    if not match:
        return None
    try:
        blocked_at = datetime.fromisoformat(match.group("blocked_at"))
        expiry = datetime.fromisoformat(match.group("expiry"))
    except ValueError:
        return None
    return {
        "blocked_at": blocked_at,
        "expiry": expiry,
        "reason": match.group("reason"),
    }


def compute_expiry(duration_minutes, now=None):
    now = now or datetime.now(timezone.utc)
    return now, now + timedelta(minutes=duration_minutes)


def is_whitelisted(ip, whitelist_cidrs):
    """
    whitelist_cidrs: list of CIDR strings, e.g. ["203.0.113.5/32", "169.254.169.254/32"]
    Always treats the AWS metadata service as whitelisted even if the
    caller forgot to include it explicitly.
    """
    try:
        candidate = ipaddress.ip_address(ip)
    except ValueError:
        # Malformed IP — treat as whitelisted (fail safe: don't block garbage input)
        return True

    all_cidrs = list(whitelist_cidrs) + [METADATA_SERVICE_CIDR]
    for cidr in all_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if candidate in network:
            return True
    return False
