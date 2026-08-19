#!/usr/bin/env python3
"""
F5 GTM / DNS Multi-Record Traffic Generator
Generates A, CNAME, MX, NAPTR, and SRV queries to populate Insight Device GTM Dashboard.
Targeting BIG-IP GTM Listeners (10.1.10.42 / 10.1.10.5).
"""

import sys
import time
import random
import concurrent.futures
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype

DNS_SERVERS = [
    "10.1.10.42",
    "10.1.10.5",
]

# (Domain, RecordType, Weight)
QUERY_CONFIGS = [
    # A / AAAA Records (40%)
    ("test2.f5demo.com", dns.rdatatype.A, 15),
    ("shop.demo.f5", dns.rdatatype.A, 10),
    ("bank.demo.f5", dns.rdatatype.A, 10),
    ("f5demo.com", dns.rdatatype.AAAA, 5),

    # CNAME Records (30%)
    ("cname.f5demo.com", dns.rdatatype.CNAME, 15),
    ("shop.cname.demo.f5", dns.rdatatype.CNAME, 10),
    ("app.cname.f5demo.com", dns.rdatatype.CNAME, 5),

    # MX Records (10%)
    ("mail.f5demo.com", dns.rdatatype.MX, 5),
    ("f5demo.com", dns.rdatatype.MX, 5),

    # NAPTR Records (10%)
    ("sip.f5demo.com", dns.rdatatype.NAPTR, 5),
    ("telephony.f5demo.com", dns.rdatatype.NAPTR, 5),

    # SRV Records (10%)
    ("_sip._udp.f5demo.com", dns.rdatatype.SRV, 5),
    ("_autodiscover._tcp.f5demo.com", dns.rdatatype.SRV, 5),
]

DOMAINS, RTYPES, WEIGHTS = zip(*QUERY_CONFIGS)

def query_worker(worker_id):
    """Sends continuous multi-record UDP/TCP DNS queries."""
    print(f"Starting Multi-Record DNS Query Worker {worker_id}", flush=True)
    
    while True:
        server = random.choice(DNS_SERVERS)
        # Select domain and rtype according to weights
        idx = random.choices(range(len(QUERY_CONFIGS)), weights=WEIGHTS)[0]
        domain = DOMAINS[idx]
        rtype = RTYPES[idx]
        
        use_tcp = (random.random() < 0.15)  # 15% TCP queries
        
        try:
            q = dns.message.make_query(domain, rtype)
            if use_tcp:
                response = dns.query.tcp(q, server, timeout=2.0)
            else:
                response = dns.query.udp(q, server, timeout=2.0)
                
            rcode_name = dns.rcode.to_text(response.rcode())
            print(f"[DNS-QUERY] Worker:{worker_id} Server:{server} Domain:{domain} Type:{dns.rdatatype.to_text(rtype)} Proto:{'TCP' if use_tcp else 'UDP'} RCode:{rcode_name}", flush=True)
        except Exception as e:
            print(f"[DNS-ERR] Worker:{worker_id} Server:{server} Domain:{domain}: {e}", flush=True)
            
        time.sleep(random.uniform(0.04, 0.15))  # High steady rate

def main():
    print("Starting Multi-Threaded F5 GTM / DNS Multi-Record Generator (A, CNAME, MX, NAPTR, SRV)", flush=True)
    print(f"Target DNS Listeners: {DNS_SERVERS}", flush=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(query_worker, i) for i in range(6)]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    main()
