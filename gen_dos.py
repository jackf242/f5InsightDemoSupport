#!/usr/bin/env python3
"""
F5 L7 HTTP DoS Vector Traffic Generator
Generates high-rate HTTP DoS flood requests to trigger BIG-IP DoS vector detection & rate limiting.
Targeting primary application site VIPs (10.1.10.50 HTTP/HTTPS).
"""

import requests
import warnings
import time
import random
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

TARGETS = [
    "http://10.1.10.50/",
    "https://10.1.10.50/",
    "https://shop.demo.f5/",
    "https://bank.demo.f5/",
]

DOS_PATHS = [
    "",
    "search?q=dos_vector_test",
    "login",
    "api/v1/heavy_query",
    "cart/checkout",
    "static/large_image.jpg",
]

USER_AGENTS = [
    "F5-DoS-Generator/1.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DoS-Bot/2.1",
    "Python-urllib/3.10 DoS-Attack-Sim",
    "curl/7.81.0 (x86_64-pc-linux-gnu)",
]

def flood_worker(worker_id):
    """Generates continuous HTTP DoS requests at high TPS to breach DoS profile thresholds."""
    s = requests.Session()
    s.verify = False
    
    print(f"Starting DoS Flood Worker {worker_id}", flush=True)
    req_count = 0
    
    while True:
        target = random.choice(TARGETS)
        path = random.choice(DOS_PATHS)
        url = f'{target}{path}'
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-Forwarded-For": f"198.51.100.{random.randint(1, 254)}",
            "Cache-Control": "no-cache",
        }
        
        try:
            r = s.get(url, headers=headers, timeout=3)
            req_count += 1
            if req_count % 100 == 0:
                print(f"[DOS-FLOOD] Worker:{worker_id} Target:{url} Status:{r.status_code} (Total Requests: {req_count})", flush=True)
        except Exception as e:
            print(f"[DOS-FLOOD-ERR] Worker:{worker_id} Target:{url}: {e}", flush=True)
            
        time.sleep(random.uniform(0.01, 0.05))  # High burst rate

def main():
    print("Starting Multi-Threaded L7 HTTP DoS Vector Traffic Generator", flush=True)
    print(f"Targets: {TARGETS}", flush=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(flood_worker, i) for i in range(8)]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    main()
