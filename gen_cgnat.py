#!/usr/bin/env python3
import time
import urllib.request
import ssl

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

url = 'http://10.1.10.42:80/'
print(f'Starting CGNAT Traffic Generator targeting {url}')

while True:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'F5-CGNAT-TrafficGen/1.0'})
        with urllib.request.urlopen(req, timeout=3, context=ssl_context) as resp:
            pass
    except Exception:
        pass
    time.sleep(0.2)
