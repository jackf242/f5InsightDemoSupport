#!/usr/bin/env python3
"""
gen5.py — Unified F5 Demo Traffic Generator with Application Profiles

Combines high-throughput batch traffic with multi-application profiles
(E-Commerce, Banking, SaaS Analytics, Healthcare, Media Streaming, Mobile API)
and rule-driven fingerprint traffic (FingerprintTrafficGenerator) in a single process.

Batch engine:
  - Runs indefinitely via ThreadPoolExecutor (configurable workers / batch size)
  - Configurable web application profiles (--apps, --app-weights)
  - Optional multi-step stateful user journey simulation (--user-sessions)
  - Three traffic types: normal application traffic, weighted errors, file uploads
  - XFF drawn from a shared realistic pool

Fingerprint engine (opt-in via --rules):
  - Loads a YAML rules file and generates 70% fingerprint-match / 30% noise
  - Runs on its own daemon thread alongside the batch engine
  - Targets a separate VIP (--fp-target / --fp-port) at a controlled TPS
  - Supports --dry-run to log without sending

Usage examples:
  # All web applications (default)
  python3 gen5.py

  # Specific web application mix with custom weights
  python3 gen5.py --apps ecommerce,banking,saas --app-weights 50,30,20

  # Enable stateful multi-step user sessions
  python3 gen5.py --user-sessions

  # With fingerprint engine
  python3 gen5.py --rules combined_rules.snapshot.yaml --fp-target 10.1.10.50 --fp-port 443 --fp-duration 30 --fp-tps 10

  # Tune batch engine
  python3 gen5.py --workers 60 --batch-size 2000
"""

import os
import sys
import ssl
import json
import random
import time
import argparse
import threading
import urllib.request
import urllib.error
import urllib3

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Shared SSL context (fingerprint engine uses urllib directly)
# ---------------------------------------------------------------------------
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# ---------------------------------------------------------------------------
# Shared data pools
# ---------------------------------------------------------------------------
USER_AGENTS = [
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
    # Samsung Internet
    "Mozilla/5.0 (Linux; Android 10; SAMSUNG SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/21.0 Chrome/92.0.4515.131 Mobile Safari/537.36",
    # UC Browser
    "Mozilla/5.0 (Linux; U; Android 10; en-US; SM-N976N Build/QP1A.190711.020) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 UCBrowser/13.3.5.1305 Mobile Safari/537.36",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/98.0.4759.15",
    # Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/124.0.0.0",
    # curl / scripted clients (noise)
    "curl/8.1.2",
    "python-requests/2.31.0",
    "PostmanRuntime/7.35.0",
]

MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 DemoApp/2.4.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 DemoApp/2.4.1",
    "DemoApp/2.4.1 (iOS 17.4; iPhone14,2)",
    "DemoApp/2.4.0 (Android 13; Pixel 7)",
]

ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json",
    "application/xml",
    "*/*",
]

CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
]

METHODS = ["GET", "HEAD"]


def _random_private_ip() -> str:
    """Generate a random RFC-1918 private IP."""
    choice = random.choice(["10", "172", "192"])
    if choice == "10":
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    elif choice == "172":
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def _random_public_ip() -> str:
    """Generate a random public-looking IP (avoids reserved ranges)."""
    while True:
        ip = (
            f"{random.randint(1,223)}.{random.randint(0,255)}"
            f".{random.randint(0,255)}.{random.randint(1,254)}"
        )
        first = int(ip.split(".")[0])
        if first not in [10, 127] and not ip.startswith("192.168.") and not ip.startswith("172."):
            return ip


def generate_xff() -> str:
    """Generate a realistic X-Forwarded-For value."""
    return _random_public_ip()


# Pre-warm an XFF pool for the high-throughput batch engine
XFF_POOL = [generate_xff() for _ in range(1000)]

# ---------------------------------------------------------------------------
# Shared requests.Session
# ---------------------------------------------------------------------------
session = requests.Session()
_adapter = HTTPAdapter(pool_connections=100, pool_maxsize=200)
session.mount("http://", _adapter)
session.mount("https://", _adapter)


# ---------------------------------------------------------------------------
# Web Application Profiles
# ---------------------------------------------------------------------------

@dataclass
class AppRequestSpec:
    """Specification for a web request within an application profile."""
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None
    is_json: bool = False


class BaseAppProfile:
    """Base class for Web Application Profiles."""
    name: str = "base"
    host: str = "demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        """Returns (method, url, headers, body, is_json)"""
        raise NotImplementedError

    def get_user_journey(self) -> List[AppRequestSpec]:
        """Returns a list of sequential request specs simulating a user journey."""
        return []


class ECommerceProfile(BaseAppProfile):
    name = "ecommerce"
    host = "shop.demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        item_id = random.randint(100, 9999)
        category = random.choice(["electronics", "clothing", "home", "sports", "books"])
        
        specs = [
            ("GET", f"https://{self.host}/", {}, None, False),
            ("GET", f"https://{self.host}/category/{category}", {"Referer": f"https://{self.host}/"}, None, False),
            ("GET", f"https://{self.host}/products/view?id={item_id}", {"Referer": f"https://{self.host}/category/{category}"}, None, False),
            ("POST", f"https://{self.host}/cart/add", {"Referer": f"https://{self.host}/products/view?id={item_id}"}, {"product_id": item_id, "quantity": random.randint(1, 3)}, True),
            ("POST", f"https://{self.host}/checkout/payment", {"Referer": f"https://{self.host}/cart"}, {"amount": round(random.uniform(19.99, 499.99), 2), "currency": "USD"}, True),
            ("GET", f"https://{self.host}/api/v1/recommendations?user={random.randint(1000,9999)}", {"Accept": "application/json"}, None, False),
        ]
        method, url, extra_headers, body, is_json = random.choice(specs)
        headers = {
            "Host": self.host,
            "Cookie": f"session_id=sess_{random.randint(10000,99999)}; cart_token=cart_{random.randint(100000,999999)}",
        }
        headers.update(extra_headers)
        return method, url, headers, body, is_json

    def get_user_journey(self) -> List[AppRequestSpec]:
        item_id = random.randint(100, 9999)
        category = random.choice(["electronics", "clothing", "home"])
        return [
            AppRequestSpec("GET", f"https://{self.host}/"),
            AppRequestSpec("GET", f"https://{self.host}/category/{category}", {"Referer": f"https://{self.host}/"}),
            AppRequestSpec("GET", f"https://{self.host}/products/view?id={item_id}", {"Referer": f"https://{self.host}/category/{category}"}),
            AppRequestSpec("POST", f"https://{self.host}/cart/add", {"Referer": f"https://{self.host}/products/view?id={item_id}"}, {"product_id": item_id, "quantity": 1}, True),
            AppRequestSpec("POST", f"https://{self.host}/checkout/payment", {"Referer": f"https://{self.host}/cart"}, {"amount": 89.99, "currency": "USD"}, True),
        ]


class BankingProfile(BaseAppProfile):
    name = "banking"
    host = "bank.demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        acc_id = random.randint(100000, 999999)
        specs = [
            ("GET", f"https://{self.host}/login", {}, None, False),
            ("POST", f"https://{self.host}/auth/mfa-verify", {}, {"mfa_code": str(random.randint(100000, 999999))}, True),
            ("GET", f"https://{self.host}/dashboard", {}, None, False),
            ("GET", f"https://{self.host}/accounts/summary", {"Accept": "application/json"}, None, False),
            ("GET", f"https://{self.host}/api/v2/balance?account={acc_id}", {"Accept": "application/json"}, None, False),
            ("POST", f"https://{self.host}/transfers/wire", {}, {"from_account": str(acc_id), "to_account": str(random.randint(100000, 999999)), "amount": round(random.uniform(50.0, 2500.0), 2)}, True),
            ("OPTIONS", f"https://{self.host}/api/v2/balance", {"Access-Control-Request-Method": "GET"}, None, False),
        ]
        method, url, extra_headers, body, is_json = random.choice(specs)
        headers = {
            "Host": self.host,
            "Authorization": f"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_{random.randint(10000,99999)}",
            "X-Transaction-ID": f"tx_{random.randint(10000000,99999999)}",
            "X-Client-App-Version": "3.2.0",
        }
        headers.update(extra_headers)
        return method, url, headers, body, is_json

    def get_user_journey(self) -> List[AppRequestSpec]:
        acc_id = random.randint(100000, 999999)
        return [
            AppRequestSpec("GET", f"https://{self.host}/login"),
            AppRequestSpec("POST", f"https://{self.host}/auth/mfa-verify", {}, {"mfa_code": "492019"}, True),
            AppRequestSpec("GET", f"https://{self.host}/dashboard"),
            AppRequestSpec("GET", f"https://{self.host}/api/v2/balance?account={acc_id}"),
            AppRequestSpec("POST", f"https://{self.host}/transfers/wire", {}, {"from_account": str(acc_id), "to_account": "882019", "amount": 250.00}, True),
        ]


class SaaSAnalyticsProfile(BaseAppProfile):
    name = "saas"
    host = "dashboard.demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        org_id = f"org_{random.randint(100,999)}"
        graphql_queries = [
            '{"query": "{ user { id email name organization { id name } } }"}',
            '{"query": "{ metrics(timeframe: \\"24h\\") { timestamp tps latency errors } }"}',
            '{"query": "{ teamMembers { id role lastLogin } }"}',
        ]
        specs = [
            ("GET", f"https://{self.host}/api/v1/metrics", {"Accept": "application/json"}, None, False),
            ("GET", f"https://{self.host}/api/v1/reports/export?format=csv", {}, None, False),
            ("GET", f"https://{self.host}/settings/team", {}, None, False),
            ("POST", f"https://{self.host}/graphql", {"Content-Type": "application/json"}, random.choice(graphql_queries), False),
            ("GET", f"https://{self.host}/ws/telemetry", {"Upgrade": "websocket"}, None, False),
        ]
        method, url, extra_headers, body, is_json = random.choice(specs)
        headers = {
            "Host": self.host,
            "X-Organization-ID": org_id,
            "X-Api-Key": f"key_live_{random.randint(1000000,9999999)}",
        }
        headers.update(extra_headers)
        return method, url, headers, body, is_json


class HealthcareProfile(BaseAppProfile):
    name = "healthcare"
    host = "health.demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        patient_id = random.randint(10000, 99999)
        specs = [
            ("GET", f"https://{self.host}/patient/login", {}, None, False),
            ("GET", f"https://{self.host}/records/v1/lab-results?patient={patient_id}", {"Accept": "application/fhir+json"}, None, False),
            ("POST", f"https://{self.host}/appointments/schedule", {"Accept": "application/json"}, {"patient_id": patient_id, "doctor_id": random.randint(100, 999), "slot": "14:00"}, True),
            ("GET", f"https://{self.host}/doctors/search?specialty=cardiology", {}, None, False),
            ("POST", f"https://{self.host}/prescriptions/refill", {}, {"rx_number": f"RX-{random.randint(100000,999999)}"}, True),
        ]
        method, url, extra_headers, body, is_json = random.choice(specs)
        headers = {
            "Host": self.host,
            "X-HIPAA-Consent": "true",
            "Cookie": f"patient_session=ptsess_{random.randint(10000,99999)}",
        }
        headers.update(extra_headers)
        return method, url, headers, body, is_json


class MediaStreamingProfile(BaseAppProfile):
    name = "media"
    host = "media.demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        chunk_id = random.randint(1000, 9999)
        specs = [
            ("GET", f"https://{self.host}/stream/live/chunk_{chunk_id}.m4s", {"Range": "bytes=0-1048575", "Accept": "video/mp2t"}, None, False),
            ("GET", f"https://{self.host}/media/hls/playlist.m3u8", {"Accept": "application/x-mpegURL"}, None, False),
            ("GET", f"https://{self.host}/assets/images/banner_{random.randint(1,10)}.jpg", {"Accept": "image/avif,image/webp,*/*"}, None, False),
            ("GET", f"https://{self.host}/api/v1/videos/trending", {"Accept": "application/json"}, None, False),
            ("HEAD", f"https://{self.host}/stream/live/chunk_{chunk_id}.m4s", {}, None, False),
        ]
        method, url, extra_headers, body, is_json = random.choice(specs)
        headers = {"Host": self.host}
        headers.update(extra_headers)
        return method, url, headers, body, is_json


class MobileApiProfile(BaseAppProfile):
    name = "mobile"
    host = "api.demo.f5"

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        specs = [
            ("POST", f"https://{self.host}/v1/auth/token", {}, {"grant_type": "refresh_token", "refresh_token": f"ref_{random.randint(100000,999999)}"}, True),
            ("GET", f"https://{self.host}/v1/feed?page=1&limit=20", {"Accept": "application/json"}, None, False),
            ("POST", f"https://{self.host}/v1/push/register", {}, {"device_token": f"tok_{random.randint(100000,999999)}", "platform": random.choice(["ios", "android"])}, True),
            ("POST", f"https://{self.host}/v1/sync", {}, {"last_sync_timestamp": int(time.time()) - 3600}, True),
        ]
        method, url, extra_headers, body, is_json = random.choice(specs)
        headers = {
            "Host": self.host,
            "User-Agent": random.choice(MOBILE_USER_AGENTS),
            "X-Device-UUID": f"dev_{random.randint(10000000,99999999)}",
        }
        headers.update(extra_headers)
        return method, url, headers, body, is_json


class LegacyDefaultProfile(BaseAppProfile):
    name = "legacy"
    host = "ast.demo.f5"

    URL_LIST = [
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
        "https://anotherapp.demo.f5",
    ]

    def get_request_spec(self) -> Tuple[str, str, Dict[str, str], Optional[Any], bool]:
        url = random.choice(self.URL_LIST)
        method = random.choice(METHODS)
        headers = {}
        return method, url, headers, None, False


ALL_PROFILES: Dict[str, BaseAppProfile] = {
    "ecommerce": ECommerceProfile(),
    "banking": BankingProfile(),
    "saas": SaaSAnalyticsProfile(),
    "healthcare": HealthcareProfile(),
    "media": MediaStreamingProfile(),
    "mobile": MobileApiProfile(),
    "legacy": LegacyDefaultProfile(),
}


# ---------------------------------------------------------------------------
# Batch engine configuration
# ---------------------------------------------------------------------------
ACTIVE_PROFILES: List[BaseAppProfile] = list(ALL_PROFILES.values())
PROFILE_WEIGHTS: List[float] = [1.0] * len(ACTIVE_PROFILES)
SIMULATE_USER_SESSIONS: bool = False

ERROR_URLS_WEIGHTED = []
for _url, _w in [
    ("https://accounts.demo.f5/400", 3),
    ("https://accounts.demo.f5/401", 3),
    ("https://accounts.demo.f5/403", 1),
    ("https://accounts.demo.f5/404", 6),
]:
    ERROR_URLS_WEIGHTED.extend([_url] * _w)

ERROR_INTERVAL_SECONDS = 4.0
UPLOAD_INTERVAL_SECONDS = 10.0
UPLOAD_URL = "https://asmupload.demo.f5:8888/enrollment/upload"
UPLOAD_FILE = os.path.expanduser("~/scripts/doc_upload_file.txt")
LOG_EVERY = 100


# ---------------------------------------------------------------------------
# Batch engine request functions
# ---------------------------------------------------------------------------

def send_normal_request(i: int) -> None:
    profile = random.choices(ACTIVE_PROFILES, weights=PROFILE_WEIGHTS, k=1)[0]
    
    if SIMULATE_USER_SESSIONS and profile.get_user_journey():
        journey = profile.get_user_journey()
        session_id = f"sess_{random.randint(10000,99999)}"
        client_ip = random.choice(XFF_POOL)
        ua = random.choice(USER_AGENTS)
        
        for step in journey:
            headers = {
                "X-Forwarded-For": client_ip,
                "User-Agent": ua,
                "Accept": random.choice(ACCEPTS),
                "Cookie": f"session_id={session_id}",
            }
            headers.update(step.headers)
            try:
                if step.is_json and step.body:
                    resp = session.request(step.method, step.path, json=step.body, headers=headers, timeout=5, verify=False)
                else:
                    resp = session.request(step.method, step.path, data=step.body, headers=headers, timeout=5, verify=False)
            except Exception:
                pass
        if i % LOG_EVERY == 0:
            print(f"[BATCH][JOURNEY] {i+1}: Executed {len(journey)}-step journey for app [{profile.name}]")
        return

    method, url, extra_headers, body, is_json = profile.get_request_spec()
    headers = {
        "X-Forwarded-For": random.choice(XFF_POOL),
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPTS),
        "Content-Type": random.choice(CONTENT_TYPES),
    }
    headers.update(extra_headers)

    try:
        if is_json and body:
            resp = session.request(method, url, json=body, headers=headers, timeout=5, verify=False)
        elif body:
            resp = session.request(method, url, data=body, headers=headers, timeout=5, verify=False)
        else:
            resp = session.request(method, url, headers=headers, timeout=5, verify=False)

        if i % LOG_EVERY == 0:
            print(f"[BATCH][{profile.name.upper()}] Request {i+1}: {method} {url} -- {resp.status_code}")
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"[BATCH][{profile.name.upper()}] Request {i+1} failed: {e}")


def send_error_request(i: int) -> None:
    url = random.choice(ERROR_URLS_WEIGHTED)
    try:
        resp = session.get(url, timeout=5, verify=False)
        print(f"[BATCH][ERROR] {i+1}: GET {url} -- {resp.status_code}")
    except Exception as e:
        print(f"[BATCH][ERROR] {i+1}: GET {url} failed: {e}")


def send_upload_request(i: int) -> None:
    """Upload doc_upload_file.txt as multipart/form-data."""
    if not os.path.isfile(UPLOAD_FILE):
        if i % LOG_EVERY == 0:
            print(f"[BATCH][UPLOAD] {i+1}: file not found at {UPLOAD_FILE}")
        return
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random.choice(XFF_POOL),
        "Accept": random.choice(ACCEPTS),
    }
    try:
        with open(UPLOAD_FILE, "rb") as f:
            resp = session.post(
                UPLOAD_URL,
                headers=headers,
                files={"attachment": ("waf-test-upload.txt", f, "text/plain")},
                timeout=10,
                verify=False,
            )
        if i % LOG_EVERY == 0:
            print(f"[BATCH][UPLOAD] {i+1}: POST {UPLOAD_URL} -- {resp.status_code}")
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"[BATCH][UPLOAD] {i+1} failed: {e}")


def run_batch_engine(total_requests: int = 4000, max_workers: int = 80) -> None:
    """
    Run the high-throughput batch engine indefinitely.
    Normal traffic batches are dispatched via ThreadPoolExecutor.
    Error and upload requests fire on their own independent timers.
    """
    error_counter = 0
    upload_counter = 0
    last_error_ts = 0.0
    last_upload_ts = 0.0

    app_names = [p.name for p in ACTIVE_PROFILES]
    print(f"[BATCH] Starting batch engine — {max_workers} workers, {total_requests} req/batch")
    print(f"[BATCH] Active application profiles: {', '.join(app_names)}")

    while True:
        # ---- normal traffic batch ----
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(send_normal_request, range(total_requests))

        # ---- error traffic (independent timer, checked after each batch) ----
        now = time.time()
        if now - last_error_ts >= ERROR_INTERVAL_SECONDS:
            error_counter += 1
            send_error_request(error_counter)
            last_error_ts = now

        # ---- upload traffic (independent timer) ----
        if now - last_upload_ts >= UPLOAD_INTERVAL_SECONDS:
            upload_counter += 1
            send_upload_request(upload_counter)
            last_upload_ts = now

        time.sleep(3)


# ---------------------------------------------------------------------------
# Fingerprint engine
# ---------------------------------------------------------------------------

@dataclass
class FingerprintRequest:
    """Represents a generated fingerprint test request."""
    rule_id: Optional[str]
    rule_label: Optional[str]
    methods_matched: List[str]
    uri: str
    headers: Dict[str, str]
    cookies: Dict[str, str]


INTERNAL_DOMAINS = [
    "app01.corp.local", "grafana.internal", "prometheus.lab.local",
    "k8s-dashboard.infra.local", "jenkins.ci.internal", "gitlab.dev.local",
    "kibana.logging.internal", "argocd.gitops.local", "harbor.registry.internal",
    "vault.secrets.local", "consul.service.internal", "traefik.ingress.local",
    "minio.storage.internal", "clickhouse.analytics.local", "redis.cache.internal",
    "postgres.db.local", "mongodb.nosql.internal", "elastic.search.local",
    "airflow.data.internal", "mlflow.ml.local", "jupyter.notebooks.internal",
    "sap.erp.local", "salesforce.crm.internal", "servicenow.itsm.local",
]

PUBLIC_DOMAINS = [
    "dashboard.example.com", "api.acmecorp.io", "app.widgets-inc.com",
    "portal.bigcompany.net", "admin.startup.io", "platform.enterprise.com",
    "console.cloudservice.io", "manage.saasprovider.com", "hub.techfirm.net",
    "ops.devshop.io", "monitor.infraco.com", "data.analyticspro.io",
]

NOISE_URIS = [
    "/", "/index.html", "/api/v1/status", "/health", "/favicon.ico",
    "/static/js/main.js", "/static/css/style.css", "/images/logo.png",
    "/login", "/logout", "/dashboard", "/settings", "/profile",
    "/api/users", "/api/data", "/api/config", "/search", "/contact", 
    "/abort",
]


def _pick_host() -> str:
    if random.random() < 0.5:
        return random.choice(INTERNAL_DOMAINS)
    return random.choice(PUBLIC_DOMAINS)


def _clean_header_pattern(pattern: str):
    """Extract (header_name, value) from a rule pattern like 'x-header:.*value'."""
    if ":" not in pattern or pattern.endswith("-"):
        header_name = pattern.rstrip("-").strip()
        if header_name:
            return (f"{header_name}-id", f"test-{random.randint(1000,9999)}")
        return None

    parts = pattern.split(":", 1)
    header_name = parts[0].strip()
    value = parts[1].strip() if len(parts) > 1 else ""

    # Strip regex artifacts to produce a concrete value
    for rx in [".*", "^", "$", r"\\;version:\\1", r"\\;confidence:\\d+",
               ";version:", ";confidence:", "?", "+", r"([\\d.]+)",
               r"[\\d.]+", r"(\\d+)", r"\\d+", "(.+)", ".+",
               r"\\s", r"\\d", "[", "]", "(", ")", r"\\1"]:
        value = value.replace(rx, "")
    value = value.replace("1", "").strip()

    if not value or value.isspace():
        value = f"test-{random.randint(1000,9999)}"

    return (header_name, value.strip())


class FingerprintTrafficGenerator:
    """
    Generates rule-driven fingerprint traffic against a target VIP.
    Uses the shared requests.Session for connection reuse.
    70% fingerprint-match requests, 30% noise.
    """

    def __init__(self, rules_file: str, target: str, port: int = 443):
        self.target = target
        self.port = port
        self.base_url = f"https://{target}:{port}"
        self.rules = self._load_rules(rules_file)
        self.rules_hit: set = set()
        self.request_count = 0
        self.match_count = 0
        self.noise_count = 0
        self._xff_pool = [generate_xff() for _ in range(500)]

    def _load_rules(self, rules_file: str) -> List[Dict[str, Any]]:
        """Parse a simple YAML rules file without external dependencies."""
        rules = []
        current_rule = None
        current_key = None

        with open(rules_file, "r") as f:
            for line in f:
                line = line.rstrip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("- id:"):
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {"id": line.split(":", 1)[1].strip().strip('"')}
                    current_key = None
                elif current_rule is not None:
                    if line.startswith("  ") and ":" in line and not line.strip().startswith("-"):
                        key, value = line.strip().split(":", 1)
                        key, value = key.strip(), value.strip()

                        if value.startswith("[") and value.endswith("]"):
                            items = value[1:-1]
                            current_rule[key] = (
                                [s.strip().strip('"').strip("'") for s in items.split(",") if s.strip()]
                                if items else []
                            )
                            current_key = None
                        elif value == "[]":
                            current_rule[key] = []
                            current_key = None
                        elif value.startswith("["):
                            current_key = key
                            current_rule[key] = []
                        elif value:
                            current_rule[key] = value.strip('"').strip("'")
                            current_key = None
                        else:
                            current_key = key
                            current_rule[key] = []
                    elif line.strip().startswith("- ") and current_key:
                        item = line.strip()[2:].strip().strip('"').strip("'")
                        if item and item != "]":
                            current_rule[current_key].append(item)

        if current_rule:
            rules.append(current_rule)

        return [
            r for r in rules
            if r.get("uri_substr") or r.get("header_any") or r.get("cookie_any") or r.get("ua_any")
        ]

    def _generate_fingerprint_request(self, rule: Dict[str, Any], multi_match: bool = False) -> Optional[FingerprintRequest]:
        methods_matched = []
        uri = "/"
        headers = {
            "Host": _pick_host(),
            "X-Forwarded-For": random.choice(self._xff_pool),
            "X-Real-IP": _random_private_ip(),
            "Accept": random.choice(ACCEPTS),
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        cookies: Dict[str, str] = {}

        available = [
            m for m in ("uri", "header", "cookie", "ua")
            if rule.get({"uri": "uri_substr", "header": "header_any",
                         "cookie": "cookie_any", "ua": "ua_any"}[m])
        ]
        if not available:
            return None

        methods_to_use = (
            random.sample(available, min(random.randint(2, 3), len(available)))
            if multi_match and len(available) > 1
            else [random.choice(available)]
        )

        for method in methods_to_use:
            if method == "uri":
                pattern = random.choice(rule["uri_substr"])
                clean = pattern.split(";")[0]
                for rx in [r"\/", "^", "$", ".*", ".+", "?", "https?://",
                            "[^/]+", "(?:", ")", "(", "|", "[", "]"]:
                    clean = clean.replace(rx, "")
                if not clean.startswith("/"):
                    clean = "/" + clean.split("/", 1)[-1] if "/" in clean else "/" + clean
                if random.random() < 0.3:
                    clean += f"?id={random.randint(1,1000)}"
                uri = clean if clean and clean != "/" else "/api/test"
                methods_matched.append(f"uri_substr:{pattern[:30]}")

            elif method == "header":
                pattern = random.choice(rule["header_any"])
                result = _clean_header_pattern(pattern)
                if result:
                    h_name, h_value = result
                    h_name = "-".join(w.capitalize() for w in h_name.split("-"))
                    headers[h_name] = h_value
                    methods_matched.append(f"header:{h_name}")

            elif method == "cookie":
                cookie_name = random.choice(rule["cookie_any"]).replace("*", "").strip()
                if cookie_name:
                    cookies[cookie_name] = f"test_{random.randint(1000,9999)}"
                    methods_matched.append(f"cookie:{cookie_name}")

            elif method == "ua":
                ua = random.choice(rule["ua_any"])
                headers["User-Agent"] = f"{ua}/{random.randint(1,5)}.{random.randint(0,20)}.{random.randint(0,10)}"
                methods_matched.append(f"ua:{ua}")

        if "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(USER_AGENTS)

        return FingerprintRequest(
            rule_id=rule["id"],
            rule_label=rule.get("label", rule["id"]),
            methods_matched=methods_matched,
            uri=uri,
            headers=headers,
            cookies=cookies,
        )

    def _generate_noise_request(self) -> FingerprintRequest:
        headers = {
            "Host": _pick_host(),
            "X-Forwarded-For": random.choice(self._xff_pool),
            "X-Real-IP": _random_private_ip(),
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(ACCEPTS),
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        if random.random() < 0.3:
            headers["X-Request-ID"] = str(random.randint(100000, 999999))
        if random.random() < 0.2:
            headers["X-Custom-Header"] = "some-value"

        cookies: Dict[str, str] = {}
        if random.random() < 0.4:
            cookies["session_id"] = f"sess_{random.randint(10000,99999)}"
        if random.random() < 0.2:
            cookies["user_pref"] = "dark_mode"

        return FingerprintRequest(
            rule_id=None,
            rule_label="NOISE",
            methods_matched=["none"],
            uri=random.choice(NOISE_URIS),
            headers=headers,
            cookies=cookies,
        )

    def _next_request(self) -> FingerprintRequest:
        if random.random() < 0.70 and self.rules:
            rule = random.choice(self.rules)
            req = self._generate_fingerprint_request(rule, multi_match=(random.random() < 0.2))
            if req:
                self.match_count += 1
                if rule["id"]:
                    self.rules_hit.add(rule["id"])
                return req
        self.noise_count += 1
        return self._generate_noise_request()

    def _send(self, req: FingerprintRequest) -> bool:
        url = f"{self.base_url}{req.uri}"
        try:
            resp = session.get(
                url,
                headers=req.headers,
                cookies=req.cookies,
                timeout=5,
                verify=False,
            )
            return resp.status_code < 500
        except Exception:
            return False

    def _log(self, req: FingerprintRequest, success: bool) -> None:
        status_str = "OK" if success else "FAIL"
        methods = ",".join(req.methods_matched)
        print(f"[FP] #{self.request_count} [{status_str}] Rule: {req.rule_id} ({req.rule_label}) | Match: {methods} | URI: {req.uri}")

    def run(self, duration_minutes: int, tps: float = 5.0, dry_run: bool = False) -> None:
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        interval = 1.0 / tps if tps > 0 else 0.2

        print(f"[FP] Fingerprint generator started: target={self.base_url}, duration={duration_minutes}m, tps={tps}, dry_run={dry_run}")
        print(f"[FP] Loaded {len(self.rules)} rules from snapshot")

        while datetime.now() < end_time:
            t0 = time.time()
            self.request_count += 1

            req = self._next_request()

            if dry_run:
                self._log(req, True)
            else:
                success = self._send(req)
                if self.request_count % 10 == 0:
                    self._log(req, success)

            elapsed = time.time() - t0
            sleep_time = interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

        print(f"[FP] Completed: total={self.request_count}, matches={self.match_count}, noise={self.noise_count}, unique_rules_hit={len(self.rules_hit)}")


# ---------------------------------------------------------------------------
# CLI Argument Parser & Entrypoint
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="gen5.py — Unified F5 Demo Traffic Generator with App Profiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    batch = p.add_argument_group("Batch engine configuration")
    batch.add_argument("--workers", "-w", type=int, default=80,
                       help="ThreadPoolExecutor worker threads (default: 80)")
    batch.add_argument("--batch-size", "-b", type=int, default=4000,
                       help="Normal requests per batch (default: 4000)")
    batch.add_argument("--apps", type=str, default="all",
                       help="Comma-separated application profiles: ecommerce,banking,saas,healthcare,media,mobile,legacy or 'all' (default: all)")
    batch.add_argument("--app-weights", type=str, default=None,
                       help="Comma-separated weights for selected apps (e.g. 50,30,20)")
    batch.add_argument("--user-sessions", action="store_true",
                       help="Enable multi-step stateful user journey simulation")

    fp = p.add_argument_group("Fingerprint engine (disabled if --rules is omitted)")
    fp.add_argument("--rules", "-r", default=None,
                    help="Path to fingerprint rules YAML file")
    fp.add_argument("--fp-target", "-t", default="192.168.100.10",
                    help="Fingerprint target VIP address")
    fp.add_argument("--fp-port", "-p", type=int, default=443,
                    help="Fingerprint target port")
    fp.add_argument("--fp-duration", "-d", type=int, default=60,
                    help="Fingerprint engine duration in minutes")
    fp.add_argument("--fp-tps", type=float, default=5.0,
                    help="Fingerprint engine target TPS")
    fp.add_argument("--dry-run", action="store_true",
                    help="Generate and log fingerprint requests without sending")

    return p.parse_args()


def main() -> None:
    global ACTIVE_PROFILES, PROFILE_WEIGHTS, SIMULATE_USER_SESSIONS
    args = parse_args()

    # ---- Configure Application Profiles ----
    if args.apps.lower() == "all":
        ACTIVE_PROFILES = list(ALL_PROFILES.values())
    else:
        selected_keys = [a.strip().lower() for a in args.apps.split(",") if a.strip().lower() in ALL_PROFILES]
        if selected_keys:
            ACTIVE_PROFILES = [ALL_PROFILES[k] for k in selected_keys]
        else:
            print(f"[MAIN] WARNING: Unknown apps specified [{args.apps}]. Defaulting to all profiles.")
            ACTIVE_PROFILES = list(ALL_PROFILES.values())

    if args.app_weights:
        try:
            weights = [float(w.strip()) for w in args.app_weights.split(",")]
            if len(weights) == len(ACTIVE_PROFILES):
                PROFILE_WEIGHTS = weights
            else:
                print(f"[MAIN] WARNING: Weight count ({len(weights)}) mismatch profile count ({len(ACTIVE_PROFILES)}). Using uniform weights.")
                PROFILE_WEIGHTS = [1.0] * len(ACTIVE_PROFILES)
        except Exception:
            PROFILE_WEIGHTS = [1.0] * len(ACTIVE_PROFILES)
    else:
        PROFILE_WEIGHTS = [1.0] * len(ACTIVE_PROFILES)

    SIMULATE_USER_SESSIONS = args.user_sessions

    # ---- Fingerprint engine (optional, daemon thread) ----
    if args.rules:
        if not os.path.isfile(args.rules):
            print(f"[FP] ERROR: rules file not found: {args.rules}", file=sys.stderr)
            sys.exit(1)

        fp_gen = FingerprintTrafficGenerator(args.rules, args.fp_target, args.fp_port)

        fp_thread = threading.Thread(
            target=fp_gen.run,
            kwargs={
                "duration_minutes": args.fp_duration,
                "tps": args.fp_tps,
                "dry_run": args.dry_run,
            },
            name="fingerprint-engine",
            daemon=True,
        )
        fp_thread.start()
        print(f"[MAIN] Fingerprint engine started (thread: {fp_thread.name})")
    else:
        fp_thread = None
        print("[MAIN] No --rules file provided; fingerprint engine disabled.")

    # ---- Batch engine (main thread) ----
    try:
        run_batch_engine(
            total_requests=args.batch_size,
            max_workers=args.workers,
        )
    except KeyboardInterrupt:
        print("\n[MAIN] Interrupted — shutting down.")
        if fp_thread and fp_thread.is_alive():
            fp_thread.join(timeout=5)


if __name__ == "__main__":
    main()
