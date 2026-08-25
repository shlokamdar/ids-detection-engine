"""Configuration for the IDS detection engine."""

AWS_REGION = "ap-south-1"
LOG_GROUP_NAME = "/aws/vpc/ids-flow-logs"

# Time window for aggregation (seconds)
WINDOW_SIZE = 60

# VPC Flow Log format (version 2 fields)
# https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
FLOW_LOG_FIELDS = [
    "version",
    "account_id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
]