"""
Shared timezone display helper.

All timestamps are STORED in UTC throughout the system (alerts.jsonl,
decision_log.jsonl, Security Group rule descriptions, etc.) — that's
deliberate and shouldn't change, since UTC avoids daylight-saving/timezone
ambiguity in the underlying data and log correlation.

This module only converts for DISPLAY, in the CLI and web dashboards.
"""

from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))


def utc_str_to_ist(utc_str, fmt_in="%Y-%m-%d %H:%M:%S"):
    """Converts a naive UTC timestamp string (as stored in alerts.jsonl) to an IST display string."""
    dt = datetime.strptime(utc_str, fmt_in).replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime("%Y-%m-%d %I:%M:%S %p IST")


def utc_dt_to_ist(dt):
    """Converts a timezone-aware UTC datetime object to an IST display string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST).strftime("%Y-%m-%d %I:%M:%S %p IST")