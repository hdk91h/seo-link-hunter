import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import socket
import whois
import time
import random
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

class ExpiredLinkHunter:
    def __init__(self, debug=False, max_depth=1):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]

        self.found_opportunities = []
        self.debug = debug
        self.max_depth = max_depth
        self.scanned_urls = set()

        # Load config (File > Default)
        self.deep_scan_domains = self.load_config_file("hubs.txt", defaults=["github.com", "awesome-", "github.io"])

        default_blacklist = ["google.", "microsoft.com", "twitter.com", "facebook.com",
                             "apple.com", "wikipedia.org", "medium.com", "linkedin.com",
                             "instagram.com", "youtube.com", "amazon.", "cloudflare.com", "tiktok.com"]
        self.blacklist = self.load_config_file("blacklist.txt", defaults=default_blacklist)

    def load_config_file(self, filename, defaults):
        """Reads a list from file, ignores comments (#)."""
        if not os.path.exists(filename):
            if self.debug: print(f"[i] Config '{filename}' not found. Using defaults.")
            return defaults

        with open(filename, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if self.debug: print(f"[i] Loaded {len(lines)} entries from '{filename}'.")
        return lines

    def get_random_header(self):
        return {'User-Agent': random.choice(self.user_agents)}

    def get_domain(self, url):
        return urlparse(url).netloc

    def check_dns_status(self, domain):
        """
        Checks if the domain still has DNS records (NXDOMAIN Check).
        Return: (has_ip: bool, message: str)
        """
        try:
            socket.gethostbyname(domain)
            return True, "Has IP"
        except socket.gaierror:
            return False, "NXDOMAIN (No IP)"

    def is_whois_free(self, domain):
        """Slow but accurate check via WHOIS."""
        try:
            w = whois.whois(domain)
            # If domain_name is missing/null, it's often free
            return not bool(w.domain_name)
        except:
            return True  # Whois errors often indicate free domains

    def check_single_link(self, url, source_domain, current_depth):
        domain = self.get_domain(url)
        if not domain or url in self.scanned_urls: return
        self.scanned_urls.add(url)

        # 1. Deep Scan Logic
        if any(ds in domain for ds in self.deep_scan_domains) and current_depth < self.max_depth:
            if self.debug: print(f"    [DEEP] Diving into Hub: {url[:50]}")
            self.scan_url(url, current_depth + 1)
            return

        # 2. Filter
        if domain == source_domain: return
        if any(b in domain for b in self.blacklist): return

        # Setup session with retries (prevents false positives due to network blips)
        session = requests.Session()
        retries = Retry(total=1, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        try:
            # Try HEAD first, fallback to GET
            try:
                res = session.head(url, headers=self.get_random_header(), timeout=(3, 5), allow_redirects=True)
            except:
                res = session.get(url, headers=self.get_random_header(), timeout=(3, 5), allow_redirects=True,
                                  stream=True)

            if self.debug: print(f"    [CHECK] {url[:50]} -> Status: {res.status_code}")

            if res.status_code >= 400:
                # HTTP Error -> Check if domain still has DNS
                has_ip, msg = self.check_dns_status(domain)
                if not has_ip:
                    self.found_opportunities.append((domain, url, "DNS_MISSING"))
                    print(f"\n    >>> 🚀 FOUND: {domain} (404 + No IP)")
                elif self.is_whois_free(domain):
                    self.found_opportunities.append((domain, url, "WHOIS_FREE"))
                    print(f"\n    >>> 🚀 FOUND: {domain} (404 + Whois Free)")

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            # KEY IMPROVEMENT: Timeout does not automatically mean dead.
            # We check DNS. If DNS is gone -> Jackpot.
            has_ip, msg = self.check_dns_status(domain)

            if not has_ip:
                self.found_opportunities.append((domain, url, "TIMEOUT_NO_DNS"))
                if self.debug: print(f"    [TIMEOUT] {domain} -> No IP (Jackpot?)")
                print(f"\n    >>> 🚀 FOUND: {domain} (Unreachable + No DNS)")
            else:
                # Domain has IP but timeouts. Could be 'Parked'.
                # Verify via Whois just to be sure.
                if self.debug: print(f"    [TIMEOUT] {domain} -> Has IP (Server Down?)")
                if self.is_whois_free(domain):
                    self.found_opportunities.append((domain, url, "TIMEOUT_WHOIS_FREE"))
                    print(f"\n    >>> 🚀 FOUND: {domain} (Timeout + Whois Free)")

    def scan_url(self, target_url, current_depth=0):
        if target_url in self.scanned_urls and current_depth > 0: return
        self.scanned_urls.add(target_url)

        indent = "  " * current_depth
        print(f"\n{indent}[*] Level {current_depth} Target: {target_url}")

        try:
            source_domain = self.get_domain(target_url)
            # Standard request without retries for the main target (faster)
            response = requests.get(target_url, headers=self.get_random_header(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            all_anchors = soup.find_all('a', href=True)
            valid_links = list(set([l['href'] for l in all_anchors if l['href'].startswith('http')]))
            valid_links = [l for l in valid_links if "#" not in l]

            total = len(valid_links)
            print(f"{indent}[*] Found {total} unique links. Hunting...")

            # Performance: 20 threads (1 in debug mode)
            workers = 1 if self.debug else 20

            with ThreadPoolExecutor(max_workers=workers) as executor:
                for url in valid_links:
                    executor.submit(self.check_single_link, url, source_domain, current_depth)

        except Exception as e:
            print(f"\n[!] Error scanning {target_url}: {e}")

    def write_results(self):
        if self.found_opportunities:
            # Sort by reason
            unique_results = sorted(list(set(self.found_opportunities)), key=lambda x: x[2])

            file_exists = os.path.exists("results.md")

            with open("results.md", "a", encoding='utf-8') as f:
                # Write header (only if file didn't exist)
                if not file_exists:
                    f.write("# 🕵️ Link Hunter Results Log\n\n")

                # Append timestamp block for this run
                f.write(f"\n## 📅 Scan Run: {time.strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"Found **{len(unique_results)}** opportunities.\n\n")
                f.write("| Domain | Reason | Source |\n| :--- | :--- | :--- |\n")

                for domain, source, reason in unique_results:
                    f.write(f"| **{domain}** | {reason} | {source} |\n")

            print(f"\n[+] Results appended to results.md")
        else:
            print(f"\n[i] No expired domains found this time.")