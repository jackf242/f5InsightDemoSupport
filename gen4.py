#!/usr/bin/env python3
import os
import requests
import random
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agents = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 Edg/109.0.1518.78",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Firefox on Android
    "Mozilla/5.0 (Android 12; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
    # Mobile Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Chrome on iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.0.0 Mobile/15E148 Safari/604.1",
    # Samsung Internet Browser
    "Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/21.0 Chrome/92.0.4515.131 Mobile Safari/537.36",
    # UC Browser on Android
    "Mozilla/5.0 (Linux; U; Android 10; en-US; SM-N976N Build/QP1A.190711.020) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 UCBrowser/13.3.5.1305 Mobile Safari/537.36",
    # Opera Desktop
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/98.0.4759.15",
    # Brave Browser
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/124.0.0.0"
]

accepts = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json",
    "application/xml",
    "*/*"
]

content_types = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain"
]

# Only using GET/HEAD
methods = ["GET", "HEAD"]

url_list = [
    "https://ast.demo.f5",
    "https://ast.demo.f5",
    "https://ast.demo.f5",
    "https://ast50.demo.f5",
    "https://ast55.demo.f5",
    "https://ast42.demo.f5",
    "https://ast42.demo.f5:7443",
    "https://ast66.demo.f5",
    "http://ast50.demo.f5",
    "https://sslo.demo.f5",
    "https://accounts.demo.f5",
    "https://ast80.demo.f5:9443",
    "https://watchmen.demo.f5:8443",
    "https://anotherapp.demo.f5"
]

# ===== error URLs with weights =====
error_urls = [
    ("https://accounts.demo.f5/400", 3),  # medium
    ("https://accounts.demo.f5/401", 3),  # medium
    ("https://accounts.demo.f5/403", 1),  # least
    ("https://accounts.demo.f5/404", 6),  # most
]

weighted_error_urls = []
for url, weight in error_urls:
    weighted_error_urls.extend([url] * weight)

ERROR_REQUEST_INTERVAL_SECONDS = 4.0  # ~1 error hit per second

# Pre-generate random XFFs to avoid per-request
XFF_POOL = [
    ".".join(str(random.randint(1, 254)) for _ in range(4))
    for _ in range(1000)
]

# Shared session for connection reuse, with tuned connection pool
session = requests.Session()
adapter = HTTPAdapter(pool_connections=50, pool_maxsize=84)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Log every N requests instead of every one
LOG_EVERY = 100

# ===== file upload config =====
UPLOAD_URL = "https://asmupload.demo.f5:8888/enrollment/upload"
UPLOAD_FILE = os.path.expanduser("~/scripts/doc_upload_file.txt")


def send_request(i):
    url = random.choice(url_list)
    headers = {
        "X-Forwarded-For": random.choice(XFF_POOL),
        "User-Agent": random.choice(user_agents),
        "Accept": random.choice(accepts),
        "Content-Type": random.choice(content_types),
    }
    method = random.choice(methods)

    try:
        response = session.request(
            method,
            url,
            headers=headers,
            timeout=5,
            verify=False,
        )
        if i % LOG_EVERY == 0:
            print(f"Request {i+1}: {method} {url} -- Status: {response.status_code}")
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"Request {i+1} failed: {e}")


def send_error_request(i):
    url = random.choice(weighted_error_urls)
    try:
        response = session.get(url, timeout=5, verify=False)
        print(f"Error {i+1}: GET {url} -- Status: {response.status_code}")
    except Exception as e:
        print(f"Error {i+1}: GET {url} failed: {e}")


def send_upload_request(i):
    """Upload waf-test-upload.txt as multipart/form-data (attachment field)."""
    if not os.path.isfile(UPLOAD_FILE):
        if i % LOG_EVERY == 0:
            print(f"Upload {i+1}: file not found at {UPLOAD_FILE}")
        return

    headers = {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": random.choice(XFF_POOL),
        "Accept": random.choice(accepts),
    }

    try:
        with open(UPLOAD_FILE, "rb") as f:
            files = {
                "attachment": ("waf-test-upload.txt", f, "text/plain"),
            }
            resp = session.post(
                UPLOAD_URL,
                headers=headers,
                files=files,
                timeout=10,
                verify=False,
            )
        if i % LOG_EVERY == 0:
            print(f"Upload {i+1}: POST {UPLOAD_URL} -- Status: {resp.status_code}")
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"Upload {i+1} failed: {e}")


# Number of requests and concurrent threads (adjust as needed)
total_requests = 4000
max_workers = 80  # tune based on vCPU

error_counter = 0
upload_counter = 0
last_error_ts = 0.0
last_upload_ts = 0.0
UPLOAD_INTERVAL_SECONDS = 10.0  # one upload about every 10s

while True:  # run indefinitely
    # normal traffic batch
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(send_request, range(total_requests))

    # periodic error request
    now = time.time()
    if now - last_error_ts >= ERROR_REQUEST_INTERVAL_SECONDS:
        error_counter += 1
        send_error_request(error_counter)
        last_error_ts = now

    # periodic file upload request
    if now - last_upload_ts >= UPLOAD_INTERVAL_SECONDS:
        upload_counter += 1
        send_upload_request(upload_counter)
        last_upload_ts = now

    time.sleep(3)
