import time
import requests
import sys

API_URL = "http://localhost:8000/analyze"

def ingest_zeek_log(filepath):
    print(f"[*] Starting ingestion of {filepath}")
    
    with open(filepath, 'r') as f:
        # Find index mapping from Zeek header
        ts_idx, query_idx, orig_h_idx = -1, -1, -1
        
        for line in f:
            line = line.strip()
            
            # Parse Zeek headers to find column indices
            if line.startswith("#fields"):
                fields = line.split('\t')
                # Subtract 1 because data rows don't start with '#fields' prefix
                ts_idx = fields.index("ts") - 1
                query_idx = fields.index("query") - 1
                orig_h_idx = fields.index("id.orig_h") - 1
                continue
                
            if line.startswith("#"):
                continue
                
            # If we don't have fields parsed somehow, skip
            if ts_idx == -1: continue
            
            parts = line.split('\t')
            if len(parts) <= max(ts_idx, query_idx, orig_h_idx):
                continue
            
            ts = float(parts[ts_idx])
            query = parts[query_idx]
            source_ip = parts[orig_h_idx]
            
            if query == "-" or query == "(empty)": 
                continue # Skip empty queries
            
            # Send to backend
            payload = {
                "timestamp": ts,
                "query": query,
                "source_ip": source_ip
            }
            
            try:
                # We simulate real-time by sleeping slightly between logs
                print(f"[>] Sending query: {query} from {source_ip}")
                req = requests.post(API_URL, json=payload)
                if req.status_code == 200:
                    result = req.json()
                    print(f"    --> Risk Level: {result.get('risk_level')}")
                
                time.sleep(1.2) # Sleep to mimic streaming
            except Exception as e:
                print(f"[!] Error sending log: {str(e)}")

if __name__ == "__main__":
    import os
    # Default to the sample log we just created
    default_log = os.path.join(os.path.dirname(__file__), "..", "data", "sample_dns.log")
    
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_log
    
    if not os.path.exists(log_path):
        print(f"Error: File not found: {log_path}")
        sys.exit(1)
        
    ingest_zeek_log(log_path)
