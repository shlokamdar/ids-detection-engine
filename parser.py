"""Parse raw VPC Flow Log records into structured dictionaries."""

from config import FLOW_LOG_FIELDS


def parse_flow_log_record(raw_message):
    """
    Parse a single VPC Flow Log line into a dictionary.
    
    Example input:
    "2 123456789 eni-abc123 10.0.1.10 10.0.1.20 54321 22 6 10 840 1620000000 1620000005 ACCEPT OK"
    
    Returns:
        dict with typed fields, or None if parsing fails.
    """
    parts = raw_message.split()
    
    if len(parts) != len(FLOW_LOG_FIELDS):
        # Some lines might be malformed; skip them
        return None
        
    record = {}
    for i, field_name in enumerate(FLOW_LOG_FIELDS):
        value = parts[i]
        
        # Type conversions
        if field_name in ["version", "packets", "bytes", "start", "end"]:
            try:
                value = int(value)
            except ValueError:
                value = 0
        elif field_name in ["srcport", "dstport", "protocol"]:
            try:
                value = int(value)
            except ValueError:
                value = None
                
        record[field_name] = value
        
    return record


def parse_all_records(raw_events):
    """
    Parse a list of raw CloudWatch log events.
    
    Returns:
        List of parsed record dicts.
    """
    parsed = []
    for event in raw_events:
        record = parse_flow_log_record(event["message"])
        if record:
            record["_ingestion_timestamp"] = event["timestamp"]
            parsed.append(record)
    return parsed