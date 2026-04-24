#!/usr/bin/env python3
"""
gen5.py — Unified F5 Demo Traffic Generator

Combines high-throughput batch traffic (gen4) with rule-driven fingerprint
traffic (FingerprintTrafficGenerator) in a single process.

Batch engine:
  - Runs indefinitely via ThreadPoolExecutor (configurable workers / batch size)
  - Three traffic types: normal, error (weighted), file upload
  - XFF drawn from a shared realistic pool

Fingerprint engine (opt-in via --rules):
  - Loads a YAML rules file and generates 70% fingerprint-match / 30% noise
  - Runs on its own daemon thread alongside the batch engine
  - Targets a separate VIP (--fp-target / --fp-port) at a controlled TPS
  - Supports --dry-run to log without sending

Usage examples:
  # Batch only (same as gen4 behavior)
  python3 gen5.py

  # With fingerprint engine
  python3 gen5.py --rules combined_rules.snapshot.yaml --fp-target 10.1.10.50 --fp-port 443 --fp-duration 30 --fp-tps 10

  # Dry run (fingerprint generates + logs without sending)
  python3 gen5.py --rules combined_rules.snapshot.yaml --dry-run

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
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

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


# Proxy-chain lambdas for realistic XFF construction
# Simplified 24apr26 because we are getting 4 XFF headers
_PROXY_CHAINS = [
    #lambda client: client,
    lambda client: f"{_random_public_ip()}"
  #  lambda client: (
  #      f"{client}, 10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
  #      f", {_random_public_ip()}"
  #  ),
  #  lambda client: (
  #      f"{client}, 192.168.{random.randint(0,255)}.{random.randint(1,254)}"
  #      f", 10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
  #      f", {_random_public_ip()}"
    ),
]


def generate_xff() -> str:
    """Generate a realistic X-Forwarded-For value using proxy chain patterns."""
    client = _random_private_ip() if random.random() < 0.6 else _random_public_ip()
    return random.choice(_PROXY_CHAINS)(client)


# Pre-warm an XFF pool for the high-throughput batch engine
XFF_POOL = [generate_xff() for _ in range(1000)]

# ---------------------------------------------------------------------------
# Shared requests.Session (batch engine + fingerprint engine both use this)
# ---------------------------------------------------------------------------
session = requests.Session()
_adapter = HTTPAdapter(pool_connections=50, pool_maxsize=100)
session.mount("http://", _adapter)
session.mount("https://", _adapter)

# ---------------------------------------------------------------------------
# Batch engine configuration
# ---------------------------------------------------------------------------
URL_LIST = [
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
    "https://anotherapp.demo.f5",
]

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
    url = random.choice(URL_LIST)
    method = random.choice(METHODS)
    headers = {
        "X-Forwarded-For": random.choice(XFF_POOL),
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPTS),
        "Content-Type": random.choice(CONTENT_TYPES),
    }
    try:
        resp = session.request(method, url, headers=headers, timeout=5, verify=False)
        if i % LOG_EVERY == 0:
            print(f"[BATCH] Request {i+1}: {method} {url} -- {resp.status_code}")
    except Exception as e:
        if i % LOG_EVERY == 0:
            print(f"[BATCH] Request {i+1} failed: {e}")


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

    print(f"[BATCH] Starting batch engine — {max_workers} workers, {total_requests} req/batch")

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
                for rx in [r"\\/", "^", "$", ".*", ".+", "?", "https?://",
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
        """70% fingerprint match, 30% noise; prioritize un-hit rules."""
        unhit = [r for r in self.rules if r["id"] not in self.rules_hit]
        if unhit and random.random() < 0.8:
            rule = random.choice(unhit)
            req = self._generate_fingerprint_request(rule, multi_match=random.random() < 0.3)
            if req:
                self.rules_hit.add(rule["id"])
                return req

        if random.random() < 0.7:
            rule = random.choice(self.rules)
            req = self._generate_fingerprint_request(rule, multi_match=random.random() < 0.3)
            if req:
                self.rules_hit.add(rule["id"])
                return req

        return self._generate_noise_request()

    def _send(self, req: FingerprintRequest) -> bool:
        """Send a fingerprint request using the shared session."""
        try:
            url = f"{self.base_url}{req.uri}"
            headers = dict(req.headers)
            if req.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in req.cookies.items())
            resp = session.get(url, headers=headers, timeout=5, verify=False)
            return True
        except Exception:
            return False

    def _log(self, req: FingerprintRequest, success: bool) -> None:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        status = "OK  " if success else "FAIL"
        if req.rule_id:
            methods_str = ", ".join(req.methods_matched)
            print(f"[FP][{ts}][{status}] MATCH rule={req.rule_id:<25} methods=[{methods_str}]")
            print(f"[FP]           URI={req.uri[:60]}")
            if any("header:" in m for m in req.methods_matched):
                for k, v in req.headers.items():
                    if k.lower().startswith("x-") or k.lower() in ("server", "via", "powered"):
                        print(f"[FP]           {k}: {v[:50]}")
            if any("cookie:" in m for m in req.methods_matched):
                print(f"[FP]           Cookies: {req.cookies}")
            self.match_count += 1
        else:
            print(f"[FP][{ts}][{status}] NOISE  URI={req.uri}")
            self.noise_count += 1
        self.request_count += 1

    def run(self, duration_minutes: int, tps: float = 5.0, dry_run: bool = False) -> None:
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        interval = 1.0 / tps

        print("=" * 70)
        print(f"[FP] Fingerprint Traffic Generator")
        print(f"[FP] Target : {self.base_url}")
        print(f"[FP] Duration: {duration_minutes} min  |  TPS: {tps}  |  Rules: {len(self.rules)}")
        print(f"[FP] Mode   : {'DRY RUN' if dry_run else 'LIVE'}")
        print("=" * 70)

        try:
            while datetime.now() < end_time:
                t0 = time.time()
                req = self._next_request()
                success = True if dry_run else self._send(req)
                self._log(req, success)
                sleep_for = interval - (time.time() - t0)
                if sleep_for > 0:
                    time.sleep(sleep_for)
        except KeyboardInterrupt:
            pass

        # Summary
        total = max(1, self.request_count)
        unhit = [r["id"] for r in self.rules if r["id"] not in self.rules_hit]
        print()
        print("=" * 70)
        print("[FP] SUMMARY")
        print(f"[FP] Total requests    : {self.request_count}")
        print(f"[FP] Fingerprint matches: {self.match_count} ({100*self.match_count/total:.1f}%)")
        print(f"[FP] Noise requests    : {self.noise_count} ({100*self.noise_count/total:.1f}%)")
        print(f"[FP] Rules hit         : {len(self.rules_hit)} / {len(self.rules)}")
        if unhit:
            display = ", ".join(unhit[:20])
            suffix = f" (+{len(unhit)-20} more)" if len(unhit) > 20 else ""
            print(f"[FP] Rules never hit   : {display}{suffix}")
        print("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="gen5 — Unified F5 Demo Traffic Generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    batch = p.add_argument_group("Batch engine")
    batch.add_argument("--workers", type=int, default=80,
                       help="ThreadPoolExecutor worker count")
    batch.add_argument("--batch-size", type=int, default=4000,
                       help="Normal requests per batch")

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
    args = parse_args()

    # ---- Fingerprint engine (optional, runs on its own daemon thread) ----
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

    # ---- Batch engine (runs on the main thread indefinitely) ----
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
