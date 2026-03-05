import requests
import warnings
import time
import random
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

BASES = [
    "https://ast42.demo.f5:8443",
    "https://ast42.demo.f5:6443",
]

WEBTOP_URI    = "/vdesk/"
PROTECTED_URI = "/vdesk/"

USERS = [
    ("user1", "user1"),
    ("user2", "user2"),
    ("user3", "user3"),
    ("user4", "user4"),
    ("user5", "user5"),
    ("user6", "user6"),
    ("user7", "user7"),
    ("user8", "user8"),
]

def login_and_start_apm_session(base, username, password):
    s = requests.Session()
    s.verify = False  # lab only

    # 1) Hit webtop to start APM flow
    s.get(f"{base}{WEBTOP_URI}", allow_redirects=True)

    # 2) Logon
    payload = {"username": username, "password": password}
    r = s.post(f"{base}/my.policy", data=payload, allow_redirects=True)

    # 3) Hit webtop once after auth
    r_webtop = s.get(f"{base}{WEBTOP_URI}", allow_redirects=True)

    print(f"[login] {base} {username} status={r.status_code} "
          f"webtop={r_webtop.status_code} cookies={s.cookies.get_dict()}")
    return s

# map (base, username) -> session
sessions = {}
for base in BASES:
    for u, p in USERS:
        try:
            sessions[(base, u)] = login_and_start_apm_session(base, u, p)
        except requests.exceptions.RequestException as e:
            print(f"[login-error] {base} {u}: {e}")

keys = list(sessions.keys())
i = 0

while True:
    base, user = random.choice(keys)
    s = sessions[(base, user)]
    pwd = next(p for (u, p) in USERS if u == user)

    try:
        r = s.get(
            f"{base}{PROTECTED_URI}",
            headers={"User-Agent": "apm-loadgen-python"},
            allow_redirects=True,
        )
    except requests.exceptions.RequestException as e:
        print(f"[req-error] {base} {user}: {e}")
        time.sleep(random.randint(4, 12))
        continue

    if "/my.policy" in r.url:
        print(f"[relogin] APM session expired for {user} on {base}, re-authenticating")
        try:
            sessions[(base, user)] = login_and_start_apm_session(base, user, pwd)
        except requests.exceptions.RequestException as e:
            print(f"[relogin-error] {base} {user}: {e}")
    else:
        print(i, r.status_code, "base=", base, "user=", user,
              "MRHSession=", s.cookies.get("MRHSession"))
        i += 1

    time.sleep(random.randint(4, 12))
