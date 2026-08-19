#!/usr/bin/env python3
"""
Enhanced F5 APM Traffic & Session Lifecycle Generator
Generates full APM session metrics for F5 Insight Fleet APM Dashboard:
1. Active Concurrent Sessions
2. Session Creation / Logon Rates
3. Access Denied / Failed Logins
4. Session Terminations / Logouts
"""

import requests
import warnings
import time
import random
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

def generate_xff():
    """Generate a random public-looking IP."""
    while True:
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        first = int(ip.split(".")[0])
        if first not in [10, 127] and not ip.startswith("192.168.") and not ip.startswith("172."):
            return ip

BASES = [
    "https://ast42.demo.f5:8443",
    "https://ast42.demo.f5:8444",
]

WEBTOP_URI = "/vdesk/"
LOGOUT_URI = "/vdesk/hangup.php3"
ACCESS_URIS = [
    "/vdesk/",
    "/app1/",
    "/dashboard/",
    "/api/user/profile",
]

VALID_USERS = [
    ("user1", "user1"),
    ("user2", "user2"),
    ("user3", "user3"),
    ("user4", "user4"),
    ("user5", "user5"),
    ("user6", "user6"),
    ("user7", "user7"),
    ("user8", "user8"),
]

INVALID_USERS = [
    ("admin", "wrongpass123"),
    ("baduser", "invalidpass"),
    ("user1", "wrongpassword"),
    ("guest", "guest123"),
    ("testuser", "testfail"),
]

def get_user_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": generate_xff()
    }

def perform_valid_login_flow(base, username, password, headers):
    """Executes a successful APM authentication flow."""
    s = requests.Session()
    s.verify = False
    s.headers.update(headers)
    try:
        with s.get(f"{base}{WEBTOP_URI}", timeout=5, allow_redirects=True) as r:
            pass
        payload = {"username": username, "password": password}
        with s.post(f"{base}/my.policy", data=payload, timeout=5, allow_redirects=True) as r:
            status_code = r.status_code
        with s.get(f"{base}{WEBTOP_URI}", timeout=5, allow_redirects=True) as r:
            pass
        print(f"[APM-SUCCESS] {base} User:{username} Status:{status_code} MRH:{s.cookies.get('MRHSession')}")
        return s
    except Exception as e:
        print(f"[APM-SUCCESS-ERR] {base} User:{username}: {e}")
        s.close()
        return None

def perform_failed_login_attempt(base, username, password, headers):
    """Simulates an authentication failure to populate Denied/Failure metrics."""
    s = requests.Session()
    s.verify = False
    s.headers.update(headers)
    try:
        with s.get(f"{base}{WEBTOP_URI}", timeout=5, allow_redirects=True) as r:
            pass
        payload = {"username": username, "password": password}
        with s.post(f"{base}/my.policy", data=payload, timeout=5, allow_redirects=True) as r:
            print(f"[APM-FAILED-LOGIN] {base} User:{username} Status:{r.status_code} URL:{r.url}")
    except Exception as e:
        print(f"[APM-FAIL-ERR] {base} User:{username}: {e}")
    finally:
        s.close()

def perform_session_logout(s, base):
    """Closes an active APM session cleanly via hangup to populate termination stats."""
    try:
        with s.get(f"{base}{LOGOUT_URI}", timeout=5, allow_redirects=True) as r:
            print(f"[APM-LOGOUT] {base} Status:{r.status_code}")
    except Exception as e:
        print(f"[APM-LOGOUT-ERR] {base}: {e}")
    finally:
        s.close()

def worker_thread(worker_id):
    """Continuous APM lifecycle worker simulating full user session dynamics."""
    print(f"Starting APM Session Worker {worker_id}")
    active_sessions = {}  # (base, user) -> (requests.Session, headers)

    while True:
        try:
            action = random.choices(
                ["valid_request", "new_login", "failed_login", "logout"],
                weights=[50, 25, 15, 10]
            )[0]

            base = random.choice(BASES)

            if action == "new_login" or not active_sessions:
                u, p = random.choice(VALID_USERS)
                headers = get_user_headers()
                s = perform_valid_login_flow(base, u, p, headers)
                if s:
                    active_sessions[(base, u)] = (s, headers)

            elif action == "failed_login":
                u, p = random.choice(INVALID_USERS)
                headers = get_user_headers()
                perform_failed_login_attempt(base, u, p, headers)

            elif action == "logout" and active_sessions:
                key = random.choice(list(active_sessions.keys()))
                s, _ = active_sessions.pop(key)
                perform_session_logout(s, key[0])

            elif action == "valid_request" and active_sessions:
                key = random.choice(list(active_sessions.keys()))
                s, headers = active_sessions[key]
                uri = random.choice(ACCESS_URIS)
                try:
                    with s.get(f"{key[0]}{uri}", timeout=5) as r:
                        r_url = r.url
                        r_status = r.status_code
                    if "/my.policy" in r_url:
                        # Session expired, re-auth
                        active_sessions.pop(key, None)
                        s.close()
                        u, p = next((usr, pwd) for usr, pwd in VALID_USERS if usr == key[1])
                        ns = perform_valid_login_flow(key[0], u, p, headers)
                        if ns:
                            active_sessions[key] = (ns, headers)
                    else:
                        print(f"[APM-ACTIVE-REQ] {key[0]} User:{key[1]} URI:{uri} Status:{r_status}")
                except Exception as e:
                    print(f"[APM-REQ-ERR] {key[0]} User:{key[1]}: {e}")
                    active_sessions.pop(key, None)
                    s.close()

        except Exception as e:
            print(f"[WORKER-ERR] {e}")

        time.sleep(random.uniform(0.5, 2.0))

def main():
    print("Starting Multi-Threaded APM Session Lifecycle Generator")
    print(f"Target APM Bases: {BASES}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(worker_thread, i) for i in range(4)]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    main()
