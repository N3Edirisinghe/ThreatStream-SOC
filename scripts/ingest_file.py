import sys
import json
import time
import requests

def ingest_file(filepath):
    url = "http://localhost:8001/api/v1/ingest/batch"
    print(f"Ingesting {filepath} to {url} ...")
    
    with open(filepath, "r") as f:
        events = []
        total_sent = 0
        
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                events.append({
                    "source_type": data.get("source_type", "generic"),
                    "host": data.get("host", "unknown"),
                    "message": json.dumps(data),
                    "timestamp": data.get("timestamp"),
                    "metadata": {k: v for k, v in data.items() if k not in ("source_type", "host", "message", "timestamp")}
                })
            except Exception as e:
                print(f"Parse error: {e}")
                
            if len(events) >= 500:
                resp = requests.post(url, json={"events": events})
                if resp.status_code == 202:
                    total_sent += len(events)
                    print(f"Sent batch of {len(events)} events (Total: {total_sent})")
                else:
                    print(f"Error {resp.status_code}: {resp.text}")
                events = []
                time.sleep(0.5)  # slight delay to not overwhelm kafka initially
                
        # send remainder
        if events:
            resp = requests.post(url, json={"events": events})
            if resp.status_code == 202:
                total_sent += len(events)
                print(f"Sent final batch of {len(events)} events (Total: {total_sent})")
            else:
                print(f"Error {resp.status_code}: {resp.text}")
                
    print(f"Successfully ingested {total_sent} events.")

if __name__ == "__main__":
    filepath = "data/sample_logs/synthetic_attacks_ground_truth.jsonl"
    ingest_file(filepath)
