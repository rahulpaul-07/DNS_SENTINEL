import requests

def seed_block():
    # 1. Trigger a critical alert
    data = {"query": "malicious-c2.top", "source_ip": "172.16.0.42"}
    res = requests.post("http://localhost:8000/analyze", json=data).json()
    log_id = res.get('db_id')

    if log_id:
        # 2. Manually block it
        block_res = requests.post(f"http://localhost:8000/alerts/{log_id}/block").json()
        print(f"Created Block: {block_res}")

if __name__ == "__main__":
    seed_block()
