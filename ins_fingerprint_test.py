#!/usr/bin/env python3
"""
Fingerprint Traffic Generator
Sends HTTP requests to a BIG-IP VIP to test iRule fingerprinting logic.
70% requests match fingerprint rules, 30% random noise.

No external dependencies - uses only Python 3 standard library.
"""

import json
import random
import time
import argparse
import sys
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Create SSL context that ignores cert validation
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

@dataclass
class GeneratedRequest:
    """Represents a generated test request"""
    rule_id: Optional[str]
    rule_label: Optional[str]
    methods_matched: List[str]
    uri: str
    headers: Dict[str, str]
    cookies: Dict[str, str]

class FingerprintTrafficGenerator:
    def __init__(self, rules_file: str, target: str, port: int = 80):
        self.target = target
        self.port = port
        self.base_url = f"https://{target}:{port}"
        self.rules = self._load_rules(rules_file)
        self.rules_hit = set()
        self.request_count = 0
        self.match_count = 0
        self.noise_count = 0
        
        # Internal-looking domains
        self.internal_domains = [
            "app01.corp.local", "grafana.internal", "prometheus.lab.local",
            "k8s-dashboard.infra.local", "jenkins.ci.internal", "gitlab.dev.local",
            "kibana.logging.internal", "argocd.gitops.local", "harbor.registry.internal",
            "vault.secrets.local", "consul.service.internal", "traefik.ingress.local",
            "minio.storage.internal", "clickhouse.analytics.local", "redis.cache.internal",
            "postgres.db.local", "mongodb.nosql.internal", "elastic.search.local",
            "airflow.data.internal", "mlflow.ml.local", "jupyter.notebooks.internal",
            "sap.erp.local", "salesforce.crm.internal", "servicenow.itsm.local"
        ]
        
        # Public-looking domains
        self.public_domains = [
            "dashboard.example.com", "api.acmecorp.io", "app.widgets-inc.com",
            "portal.bigcompany.net", "admin.startup.io", "platform.enterprise.com",
            "console.cloudservice.io", "manage.saasprovider.com", "hub.techfirm.net",
            "ops.devshop.io", "monitor.infraco.com", "data.analyticspro.io"
        ]
        
        # Realistic proxy chains for XFF
        self.proxy_chains = [
            # Simple single proxy
            lambda client: f"{client}",
            # CDN -> client
            lambda client: f"{client}, {self._random_public_ip()}",
            # Client -> Corp proxy -> CDN
            lambda client: f"{client}, 10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}, {self._random_public_ip()}",
            # Full chain: client -> proxy -> lb -> cdn
            lambda client: f"{client}, 192.168.{random.randint(0,255)}.{random.randint(1,254)}, 10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}, {self._random_public_ip()}",
        ]
        
        # Common user agents for noise
        self.noise_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "curl/8.1.2",
            "python-requests/2.31.0",
            "PostmanRuntime/7.35.0",
        ]
        
        # Noise URIs
        self.noise_uris = [
            "/", "/index.html", "/api/v1/status", "/health", "/favicon.ico",
            "/static/js/main.js", "/static/css/style.css", "/images/logo.png",
            "/login", "/logout", "/dashboard", "/settings", "/profile",
            "/api/users", "/api/data", "/api/config", "/search", "/contact"
        ]

    def _load_rules(self, rules_file: str) -> List[Dict[str, Any]]:
        """Load fingerprint rules from YAML file (simple parser, no external deps)"""
        rules = []
        current_rule = None
        current_key = None
        
        with open(rules_file, 'r') as f:
            for line in f:
                line = line.rstrip()
                if not line or line.startswith('#'):
                    continue
                
                # New rule starts with "- id:"
                if line.startswith('- id:'):
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {'id': line.split(':', 1)[1].strip().strip('"')}
                    current_key = None
                elif current_rule is not None:
                    # Handle key: value pairs
                    if line.startswith('  ') and ':' in line and not line.strip().startswith('-'):
                        key, value = line.strip().split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if value.startswith('[') and value.endswith(']'):
                            # Inline list like ["/api/", "/data/"]
                            items = value[1:-1]
                            if items:
                                current_rule[key] = [s.strip().strip('"').strip("'") for s in items.split(',') if s.strip()]
                            else:
                                current_rule[key] = []
                            current_key = None
                        elif value == '[]':
                            current_rule[key] = []
                            current_key = None
                        elif value.startswith('['):
                            # Multi-line list starting
                            current_key = key
                            current_rule[key] = []
                        elif value:
                            current_rule[key] = value.strip('"').strip("'")
                            current_key = None
                        else:
                            current_key = key
                            current_rule[key] = []
                    elif line.strip().startswith('- ') and current_key:
                        # List item
                        item = line.strip()[2:].strip().strip('"').strip("'")
                        if item and item != ']':
                            current_rule[current_key].append(item)
        
        if current_rule:
            rules.append(current_rule)
        
        # Filter to rules that have at least one detection method
        valid_rules = []
        for rule in rules:
            if (rule.get('uri_substr') or rule.get('header_any') or 
                rule.get('cookie_any') or rule.get('ua_any')):
                valid_rules.append(rule)
        return valid_rules

    def _random_private_ip(self) -> str:
        """Generate a random RFC1918 private IP"""
        choice = random.choice(['10', '172', '192'])
        if choice == '10':
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        elif choice == '172':
            return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

    def _random_public_ip(self) -> str:
        """Generate a random public-looking IP (avoiding reserved ranges)"""
        while True:
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            first_octet = int(ip.split('.')[0])
            # Avoid private, loopback, link-local
            if first_octet not in [10, 127] and not ip.startswith('192.168.') and not ip.startswith('172.'):
                return ip

    def _generate_xff(self) -> str:
        """Generate realistic X-Forwarded-For header"""
        client_ip = self._random_private_ip() if random.random() < 0.6 else self._random_public_ip()
        chain_func = random.choice(self.proxy_chains)
        return chain_func(client_ip)

    def _pick_host(self) -> str:
        """Pick a random hostname (mix of internal/public)"""
        if random.random() < 0.5:
            return random.choice(self.internal_domains)
        else:
            return random.choice(self.public_domains)

    def _clean_header_pattern(self, pattern: str) -> tuple:
        """Extract header name and generate a matching value from pattern like 'x-header:.*value'"""
        # Handle patterns like "x-databricks-" (header prefix only)
        if ':' not in pattern or pattern.endswith('-'):
            header_name = pattern.rstrip('-').strip()
            if header_name:
                # Generate a header name with a suffix and a value
                return (f"{header_name}-id", f"test-{random.randint(1000,9999)}")
            return None
        
        parts = pattern.split(':', 1)
        header_name = parts[0].strip()
        value_pattern = parts[1].strip() if len(parts) > 1 else ''
        
        # Clean up regex patterns to generate actual values
        value_pattern = value_pattern.replace('.*', '').replace('^', '').replace('$', '')
        value_pattern = value_pattern.replace('\\;version:\\1', '').replace('\\;confidence:\\d+', '')
        value_pattern = value_pattern.replace(';version:', '').replace(';confidence:', '')
        value_pattern = value_pattern.replace('?', '').replace('+', '').replace('*', '')
        value_pattern = value_pattern.replace(r'([\d.]+)', '1.0.0').replace(r'[\d.]+', '1.0.0')
        value_pattern = value_pattern.replace(r'(\d+)', '1').replace(r'\d+', '1')
        value_pattern = value_pattern.replace('(.+)', 'value').replace('.+', 'value')
        value_pattern = value_pattern.replace('\\s', ' ').replace('\\d', '1')
        value_pattern = value_pattern.replace('[', '').replace(']', '').replace('(', '').replace(')', '')
        value_pattern = value_pattern.replace('\\1', '').replace('1', '').strip()
        
        if not value_pattern or value_pattern.isspace():
            value_pattern = f"test-{random.randint(1000,9999)}"
        
        return (header_name, value_pattern.strip())

    def _generate_fingerprint_request(self, rule: Dict[str, Any], multi_match: bool = False) -> GeneratedRequest:
        """Generate a request that matches the given fingerprint rule"""
        methods_matched = []
        uri = "/"
        headers = {
            "Host": self._pick_host(),
            "X-Forwarded-For": self._generate_xff(),
            "X-Real-IP": self._random_private_ip(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        cookies = {}
        
        # Decide which methods to use
        available_methods = []
        if rule.get('uri_substr'):
            available_methods.append('uri')
        if rule.get('header_any'):
            available_methods.append('header')
        if rule.get('cookie_any'):
            available_methods.append('cookie')
        if rule.get('ua_any'):
            available_methods.append('ua')
        
        if not available_methods:
            return None
        
        # For multi-match, use multiple methods; otherwise pick one
        if multi_match and len(available_methods) > 1:
            methods_to_use = random.sample(available_methods, min(random.randint(2, 3), len(available_methods)))
        else:
            methods_to_use = [random.choice(available_methods)]
        
        # Apply each method
        for method in methods_to_use:
            if method == 'uri' and rule.get('uri_substr'):
                uri_patterns = rule['uri_substr']
                # Pick a pattern and clean it up
                pattern = random.choice(uri_patterns)
                # Remove regex artifacts and confidence markers
                clean_uri = pattern.split(';')[0]  # Remove ;confidence:XX
                clean_uri = clean_uri.replace('\\/', '/').replace('^', '').replace('$', '')
                clean_uri = clean_uri.replace('.*', '').replace('.+', '').replace('?', '')
                clean_uri = clean_uri.replace('https?://', '').replace('[^/]+', '')
                clean_uri = clean_uri.replace('(?:', '').replace(')', '').replace('(', '')
                clean_uri = clean_uri.replace('|', '').replace('[', '').replace(']', '')
                
                # Ensure it starts with /
                if not clean_uri.startswith('/'):
                    if '/' in clean_uri:
                        clean_uri = '/' + clean_uri.split('/', 1)[-1]
                    else:
                        clean_uri = '/' + clean_uri
                
                # Add some random suffix sometimes
                if random.random() < 0.3:
                    clean_uri += f"?id={random.randint(1,1000)}"
                
                uri = clean_uri if clean_uri and clean_uri != '/' else '/api/test'
                methods_matched.append(f"uri_substr:{pattern[:30]}")
            
            elif method == 'header' and rule.get('header_any'):
                header_patterns = rule['header_any']
                pattern = random.choice(header_patterns)
                result = self._clean_header_pattern(pattern)
                if result:
                    header_name, header_value = result
                    # Normalize header name (capitalize properly)
                    header_name = '-'.join(word.capitalize() for word in header_name.split('-'))
                    headers[header_name] = header_value
                    methods_matched.append(f"header:{header_name}")
            
            elif method == 'cookie' and rule.get('cookie_any'):
                cookie_names = rule['cookie_any']
                cookie_name = random.choice(cookie_names)
                # Clean up cookie name
                cookie_name = cookie_name.replace('*', '').strip()
                if cookie_name:
                    cookies[cookie_name] = f"test_{random.randint(1000,9999)}"
                    methods_matched.append(f"cookie:{cookie_name}")
            
            elif method == 'ua' and rule.get('ua_any'):
                ua_patterns = rule['ua_any']
                ua = random.choice(ua_patterns)
                # Add version info to make it realistic
                headers['User-Agent'] = f"{ua}/{random.randint(1,5)}.{random.randint(0,20)}.{random.randint(0,10)}"
                methods_matched.append(f"ua:{ua}")
        
        # Add default User-Agent if not set by ua_any
        if 'User-Agent' not in headers:
            headers['User-Agent'] = random.choice(self.noise_user_agents)
        
        return GeneratedRequest(
            rule_id=rule['id'],
            rule_label=rule.get('label', rule['id']),
            methods_matched=methods_matched,
            uri=uri,
            headers=headers,
            cookies=cookies
        )

    def _generate_noise_request(self) -> GeneratedRequest:
        """Generate a random noise request that shouldn't match any fingerprint"""
        headers = {
            "Host": self._pick_host(),
            "X-Forwarded-For": self._generate_xff(),
            "X-Real-IP": self._random_private_ip(),
            "User-Agent": random.choice(self.noise_user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        
        # Sometimes add random headers
        if random.random() < 0.3:
            headers["X-Request-ID"] = f"{random.randint(100000,999999)}"
        if random.random() < 0.2:
            headers["X-Custom-Header"] = "some-value"
        
        # Sometimes add random cookies
        cookies = {}
        if random.random() < 0.4:
            cookies["session_id"] = f"sess_{random.randint(10000,99999)}"
        if random.random() < 0.2:
            cookies["user_pref"] = "dark_mode"
        
        return GeneratedRequest(
            rule_id=None,
            rule_label="NOISE",
            methods_matched=["none"],
            uri=random.choice(self.noise_uris),
            headers=headers,
            cookies=cookies
        )

    def generate_request(self) -> GeneratedRequest:
        """Generate a single request (70% fingerprint match, 30% noise)"""
        # First priority: hit rules we haven't hit yet
        unhit_rules = [r for r in self.rules if r['id'] not in self.rules_hit]
        
        if unhit_rules and random.random() < 0.8:  # 80% chance to prioritize unhit rules
            rule = random.choice(unhit_rules)
            multi_match = random.random() < 0.3  # 30% chance for multi-match
            req = self._generate_fingerprint_request(rule, multi_match)
            if req:
                self.rules_hit.add(rule['id'])
                return req
        
        # Normal distribution: 70% fingerprint, 30% noise
        if random.random() < 0.7:
            rule = random.choice(self.rules)
            multi_match = random.random() < 0.3
            req = self._generate_fingerprint_request(rule, multi_match)
            if req:
                self.rules_hit.add(rule['id'])
                return req
        
        return self._generate_noise_request()

    def send_request(self, req: GeneratedRequest) -> bool:
        """Send the request to the target VIP"""
        try:
            url = f"{self.base_url}{req.uri}"
            
            # Build headers
            headers = dict(req.headers)
            
            # Add cookies as Cookie header
            if req.cookies:
                cookie_str = '; '.join(f"{k}={v}" for k, v in req.cookies.items())
                headers['Cookie'] = cookie_str
            
            request = urllib.request.Request(url, headers=headers, method='GET')
            
            with urllib.request.urlopen(request, timeout=5, context=ssl_context) as response:
                _ = response.read()
            return True
        except urllib.error.HTTPError:
            # HTTP errors (4xx, 5xx) still mean we connected
            return True
        except Exception as e:
            return False

    def log_request(self, req: GeneratedRequest, success: bool, elapsed_ms: float):
        """Log the request details"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        status = "OK" if success else "FAIL"
        
        if req.rule_id:
            methods_str = ", ".join(req.methods_matched)
            print(f"[{timestamp}] [{status}] MATCH rule={req.rule_id:<25} methods=[{methods_str}]")
            print(f"           URI={req.uri[:60]}")
            if any('header:' in m for m in req.methods_matched):
                # Show matched headers
                for k, v in req.headers.items():
                    if k.lower().startswith('x-') or k.lower() in ['server', 'via', 'powered']:
                        print(f"           Header: {k}: {v[:50]}")
            if any('cookie:' in m for m in req.methods_matched):
                print(f"           Cookies: {req.cookies}")
            self.match_count += 1
        else:
            print(f"[{timestamp}] [{status}] NOISE  URI={req.uri}")
            self.noise_count += 1
        
        self.request_count += 1

    def run(self, duration_minutes: int, tps: float = 5.0, dry_run: bool = False):
        """Run the traffic generator for the specified duration"""
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        interval = 1.0 / tps
        
        print("=" * 80)
        print(f"Fingerprint Traffic Generator")
        print(f"Target: {self.base_url}")
        print(f"Duration: {duration_minutes} minutes")
        print(f"Target TPS: {tps}")
        print(f"Total rules loaded: {len(self.rules)}")
        print(f"Mode: {'DRY RUN (not sending)' if dry_run else 'LIVE'}")
        print("=" * 80)
        print()
        
        try:
            while datetime.now() < end_time:
                start = time.time()
                
                req = self.generate_request()
                
                if dry_run:
                    success = True
                else:
                    success = self.send_request(req)
                
                elapsed_ms = (time.time() - start) * 1000
                self.log_request(req, success, elapsed_ms)
                
                # Sleep to maintain TPS
                sleep_time = interval - (time.time() - start)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
        
        # Print summary
        print()
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total requests sent: {self.request_count}")
        print(f"Fingerprint matches: {self.match_count} ({100*self.match_count/max(1,self.request_count):.1f}%)")
        print(f"Noise requests:      {self.noise_count} ({100*self.noise_count/max(1,self.request_count):.1f}%)")
        print(f"Rules hit at least once: {len(self.rules_hit)} / {len(self.rules)}")
        print()
        
        # Show rules never hit
        unhit = [r['id'] for r in self.rules if r['id'] not in self.rules_hit]
        if unhit and len(unhit) <= 20:
            print(f"Rules never hit: {', '.join(unhit[:20])}")
        elif unhit:
            print(f"Rules never hit: {len(unhit)} rules (too many to list)")


def main():
    parser = argparse.ArgumentParser(description='Fingerprint Traffic Generator')
    parser.add_argument('--rules', '-r', default='combined_rules.snapshot.yaml',
                        help='Path to rules YAML file')
    parser.add_argument('--target', '-t', default='192.168.100.10',
                        help='Target VIP IP address')
    parser.add_argument('--port', '-p', type=int, default=80,
                        help='Target port')
    parser.add_argument('--duration', '-d', type=int, default=5,
                        help='Duration in minutes')
    parser.add_argument('--tps', type=float, default=5.0,
                        help='Target transactions per second')
    parser.add_argument('--dry-run', action='store_true',
                        help='Generate and log requests without sending')
    
    args = parser.parse_args()
    
    generator = FingerprintTrafficGenerator(args.rules, args.target, args.port)
    generator.run(args.duration, args.tps, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
