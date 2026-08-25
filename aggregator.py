"""
Aggregate parsed flow log records into 60-second behavioural windows per source IP.
This is where features are engineered.
"""

from collections import defaultdict
import statistics


def assign_to_windows(records, window_size=60):
    """
    Group records into time windows based on their 'start' timestamp.
    
    Returns:
        dict: {(src_ip, window_start): [records]}
    """
    windows = defaultdict(list)
    
    for record in records:
        start_ts = record.get("start", 0)
        if start_ts == 0:
            continue
            
        # Window start is the beginning of the 60-second bucket
        window_start = (start_ts // window_size) * window_size
        key = (record["srcaddr"], window_start)
        windows[key].append(record)
        
    return windows


def compute_features(window_records):
    """
    Compute behavioural features from a single window of flow records.
    
    Input: List of parsed flow log records (all from same src IP, same 60s window)
    Output: Feature dictionary
    """
    if not window_records:
        return {}
        
    # Basic counts
    total_connections = len(window_records)
    
    # Unique destination ports contacted
    dst_ports = [r["dstport"] for r in window_records if r.get("dstport") is not None]
    unique_dst_ports = len(set(dst_ports))
    
    # Protocols used
    protocols = [r["protocol"] for r in window_records if r.get("protocol") is not None]
    unique_protocols = len(set(protocols))
    primary_protocol = max(set(protocols), key=protocols.count) if protocols else None
    
    # Packet and byte statistics
    packets_list = [r["packets"] for r in window_records if r.get("packets") is not None]
    bytes_list = [r["bytes"] for r in window_records if r.get("bytes") is not None]
    
    avg_packets = statistics.mean(packets_list) if packets_list else 0
    avg_bytes = statistics.mean(bytes_list) if bytes_list else 0
    total_packets = sum(packets_list)
    total_bytes = sum(bytes_list)
    
    # ACCEPT vs REJECT ratio
    actions = [r["action"] for r in window_records]
    reject_count = actions.count("REJECT")
    reject_ratio = reject_count / total_connections if total_connections > 0 else 0
    
    # Connection frequency
    window_duration = 60  # seconds
    connections_per_second = total_connections / window_duration
    
    # Target port analysis
    port_22_count = sum(1 for p in dst_ports if p == 22)
    port_80_count = sum(1 for p in dst_ports if p == 80)
    port_443_count = sum(1 for p in dst_ports if p == 443)
    
    # Most targeted port
    if dst_ports:
        most_targeted_port = max(set(dst_ports), key=dst_ports.count)
    else:
        most_targeted_port = None
        
    # Duration of connections
    durations = []
    for r in window_records:
        if r.get("end") and r.get("start"):
            durations.append(r["end"] - r["start"])
    avg_duration = statistics.mean(durations) if durations else 0
    
    feature_vector = {
        # Identity
        "src_ip": window_records[0]["srcaddr"],
        "window_start": window_records[0].get("start", 0),
        
        # Core behavioural features
        "total_connections": total_connections,
        "unique_dst_ports": unique_dst_ports,
        "unique_protocols": unique_protocols,
        "primary_protocol": primary_protocol,
        
        # Volume features
        "avg_packets_per_conn": round(avg_packets, 2),
        "avg_bytes_per_conn": round(avg_bytes, 2),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        
        # Rate features
        "connections_per_second": round(connections_per_second, 4),
        
        # Success/failure features
        "reject_ratio": round(reject_ratio, 4),
        "reject_count": reject_count,
        
        # Port-specific features
        "port_22_count": port_22_count,
        "port_80_count": port_80_count,
        "port_443_count": port_443_count,
        "most_targeted_port": most_targeted_port,
        
        # Temporal features
        "avg_duration_seconds": round(avg_duration, 2),
    }
    
    return feature_vector


def aggregate_all_windows(records, window_size=60):
    """
    Main aggregation pipeline.
    
    Returns:
        List of feature vectors, one per (src_ip, window) combination.
    """
    windows = assign_to_windows(records, window_size)
    
    feature_vectors = []
    for (src_ip, window_start), window_records in windows.items():
        features = compute_features(window_records)
        if features:
            feature_vectors.append(features)
            
    # Sort by window start time
    feature_vectors.sort(key=lambda x: x["window_start"])
    
    return feature_vectors