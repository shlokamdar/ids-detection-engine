"""Main pipeline: fetch → parse → aggregate → display."""

from fetcher import fetch_recent_flow_logs
from parser import parse_all_records
from aggregator import aggregate_all_windows
import json
from datetime import datetime


def run_pipeline(minutes_back=60):
    print("=" * 60)
    print("IDS Detection Engine — Feature Extraction Pipeline")
    print("=" * 60)
    
    # Step 1: Fetch
    print("\n[1/3] Fetching flow logs from CloudWatch...")
    raw_events = fetch_recent_flow_logs(minutes_back=minutes_back)
    
    if not raw_events:
        print("No flow log records found. Is traffic being generated?")
        return []
    
    # DEBUG: Show first 3 raw messages
    print("\n--- DEBUG: First 3 raw messages ---")
    for e in raw_events[:3]:
        ts = datetime.utcfromtimestamp(e["timestamp"] / 1000).strftime('%Y-%m-%d %H:%M:%S UTC')
        print(f"[{ts}] {e['message'][:100]}...")
    print("--- END DEBUG ---\n")
        
    # Step 2: Parse
    print("\n[2/3] Parsing raw flow log records...")
    parsed_records = parse_all_records(raw_events)
    print(f"Successfully parsed {len(parsed_records)} records.")
    
    # Step 3: Aggregate
    print("\n[3/3] Aggregating into 60-second behavioural windows...")
    feature_vectors = aggregate_all_windows(parsed_records, window_size=60)
    print(f"Generated {len(feature_vectors)} feature vectors.")
    
    # Display results
    print("\n" + "=" * 60)
    print("SAMPLE FEATURE VECTORS")
    print("=" * 60)
    
    for fv in feature_vectors[:5]:
        print(f"\nSource IP: {fv['src_ip']}")
        print(f"Window: {datetime.utcfromtimestamp(fv['window_start']).strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print("-" * 40)
        for key, value in fv.items():
            if key not in ["src_ip", "window_start"]:
                print(f"  {key}: {value}")
                
    # Save to file for later use
    output_file = f"features_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(feature_vectors, f, indent=2)
    print(f"\nSaved all feature vectors to: {output_file}")
    
    return feature_vectors


if __name__ == "__main__":
    run_pipeline(minutes_back=60)