#!/usr/bin/env python3
import time
import random
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "F5-Demo-Mobile-App/1.0 (iOS; CPU OS 17_4 like Mac OS X)",
]

def generate_xff():
    """Generate a random public-looking IP."""
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        first = int(ip.split(".")[0])
        if first not in [10, 127] and not ip.startswith("192.168.") and not ip.startswith("172."):
            return ip

TARGET = "https://api.sentence.com:8443"

ENDPOINTS = [
    # Active API Endpoints
    {"path": "/", "method": "GET"},
    {"path": "/locations", "method": "GET"},
    {"path": "/names", "method": "GET"},
    {"path": "/adjectives", "method": "GET"},
    {"path": "/animals", "method": "GET"},
    
    # Shadow API Endpoints
    {"path": "/v2/sentence", "method": "POST", "json": {"prompt": "generate sentence"}},
    {"path": "/internal/admin/config", "method": "GET"},
    {"path": "/api/v2/user-telemetry", "method": "POST", "json": {"client": "app-v2.1"}},
    
    # Zombie API Endpoints
    {"path": "/v1/legacy-sentence", "method": "GET"},
    {"path": "/deprecated/v1/quotes", "method": "GET"},
]

print("Starting ASLE API Traffic Generator against", TARGET, flush=True)

session = requests.Session()
session.verify = False

while True:
    try:
        ep = random.choice(ENDPOINTS)
        url = TARGET + ep["path"]
        method = ep["method"]
        p = ep["path"]
        
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-Forwarded-For": generate_xff(),
            "Accept": "application/json"
        }
        
        if method == "GET":
            with session.get(url, headers=headers, timeout=5) as resp:
                status_code = resp.status_code
        elif method == "POST":
            with session.post(url, headers=headers, json=ep.get("json", {}), timeout=5) as resp:
                status_code = resp.status_code
            
        t_str = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{t_str}] {method} {p} (IP: {headers['X-Forwarded-For']}) -> Status {status_code}", flush=True)
    except Exception as e:
        print(f"Request error: {e}", flush=True)
    
    # Realistic human think time jitter
    time.sleep(random.uniform(0.5, 4.5))
