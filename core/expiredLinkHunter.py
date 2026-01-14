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
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set a global timeout for all socket operations to prevent freezing
socket.setdefaulttimeout(3)


class ExpiredLinkHunter:
    def __init__(self, debug=False, max_depth=1, tld_filter=None):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]

        self.found_opportunities = []
        self.debug = debug
        self.max_depth = max_depth
        self.tld_filter = tld_filter
        self.scanned_urls = set()

        # Cloud platforms that should not be checked for expiry
        self.cloud_blacklist = [
            'glitch.me', 'github.io', 'fly.dev', 'herokuapp.com',
            'vercel.app', 'netlify.app', 'pages.dev', 'azurewebsites.net'
        ]

        # Load config (File > Default)
        self.deep_scan_domains = self.load_config_file("hubs.txt", defaults=["github.com", "awesome-", "github.io"])

        default_blacklist = ["google.", "microsoft.com", "twitter.com", "facebook.com",
                             "apple.com", "wikipedia.org", "medium.com", "linkedin.com",
                             "instagram.com", "youtube.com", "amazon.", "cloudflare.com", "tiktok.com",
                             "googleapis.com"]
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

    def is_registerable(self, domain):
        """Filters out non-registerable cloud subdomains."""
        if any(domain.endswith(cloud) for cloud in self.cloud_blacklist):
            return False
        return True

    def check_dns_status(self, domain):
        """Checks for NXDOMAIN status."""
        try:
            socket.gethostbyname(domain)
            return True, "Has IP"
        except (socket.gaierror, socket.timeout):
            return False, "NXDOMAIN / Timeout"

    def is_whois_free(self, domain):
        """Checks if WHOIS data suggests the domain is available."""
        try:
            # WHOIS is slow, we only call it when DNS is present but site is down
            w = whois.whois(domain)
            return not bool(w.domain_name)
        except:
            return True

    def check_single_link(self, url, source_domain, current_depth):
        """Main analysis logic for a single URL."""
        domain = self.get_domain(url)

        # 1. Filters: Validity, Duplicates, and Cloud-Blocklist
        if not domain or url in self.scanned_urls or not self.is_registerable(domain):
            return

        if self.tld_filter:
            tld = domain.split('.')[-1].lower()
            if tld not in self.tld_filter:
                return

        self.scanned_urls.add(url)

        # 2. Deep Scan Logic
        if any(ds in domain for ds in self.deep_scan_domains) and current_depth < self.max_depth:
            if self.debug: print(f"    [DEEP] Diving into Hub: {url[:50]}")
            self.scan_url(url, current_depth + 1)
            return

        # 3. Exclude internal links and general blacklist
        if domain == source_domain: return
        if any(b in domain for b in self.blacklist): return

        # Setup session with tight timeouts
        session = requests.Session()
        retries = Retry(total=0)  # No retries to save time during mass scans
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        try:
            # Short timeout: 2s to connect, 3s to read data
            try:
                res = session.head(url, headers=self.get_random_header(), timeout=(2, 3), allow_redirects=True)
            except:
                res = session.get(url, headers=self.get_random_header(), timeout=(2, 3), allow_redirects=True,
                                  stream=True)

            # Immediately close the connection to prevent hanging
            res.close()

            if self.debug: print(f"    [CHECK] {url[:50]} -> Status: {res.status_code}")

            if res.status_code >= 400:
                has_ip, msg = self.check_dns_status(domain)
                if not has_ip:
                    self.found_opportunities.append((domain, url, "DNS_MISSING"))
                    print(f"\n    >>> 🚀 FOUND: {domain} (404 + No IP)")
                else:
                    if self.is_whois_free(domain):
                        self.found_opportunities.append((domain, url, "WHOIS_FREE"))
                        print(f"\n    >>> 🚀 FOUND: {domain} (404 + Whois Free)")

        # This block catches EVERY timeout (Request, DNS, etc.) and moves on
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, socket.timeout):
            has_ip, msg = self.check_dns_status(domain)
            if not has_ip:
                self.found_opportunities.append((domain, url, "TIMEOUT_NO_DNS"))
                print(f"\n    >>> 🚀 FOUND: {domain} (Unreachable + No DNS)")
            else:
                if self.is_whois_free(domain):
                    self.found_opportunities.append((domain, url, "TIMEOUT_WHOIS_FREE"))
                    print(f"\n    >>> 🚀 FOUND: {domain} (Timeout + Whois Free)")
        except Exception as e:
            if self.debug: print(f"    [!] Error skipping {url[:30]}: {e}")
            pass  # Just move to the next link

    def scan_url(self, target_url, current_depth=0):
        if target_url in self.scanned_urls and current_depth > 0: return
        self.scanned_urls.add(target_url)

        indent = "  " * current_depth
        print(f"\n{indent}[*] Level {current_depth} Target: {target_url}")

        try:
            source_domain = self.get_domain(target_url)
            response = requests.get(target_url, headers=self.get_random_header(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            all_anchors = soup.find_all('a', href=True)
            valid_links = list(set([l['href'] for l in all_anchors if l['href'].startswith('http')]))
            valid_links = [l for l in valid_links if "#" not in l]

            total = len(valid_links)
            print(f"{indent}[*] Found {total} unique links. Hunting...")

            workers = 1 if self.debug else 10
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(self.check_single_link, url, source_domain, current_depth) for url in
                           valid_links]

                completed = 0
                for _ in as_completed(futures):
                    completed += 1
                    if completed % 5 == 0 or completed == total:
                        print(f"\r{indent}[{completed}/{total}] links checked...", end="", flush=True)
            print()

        except Exception as e:
            print(f"\n[!] Error scanning {target_url}: {e}")

    def write_results(self):
        if self.found_opportunities:
            unique_results = sorted(list(set(self.found_opportunities)), key=lambda x: x[2])
            file_exists = os.path.exists("results.md")
            with open("results.md", "a", encoding='utf-8') as f:
                if not file_exists:
                    f.write("# 🕵️ Link Hunter Results Log\n\n")
                f.write(f"\n## 📅 Scan Run: {time.strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"Found **{len(unique_results)}** opportunities.\n\n")
                f.write("| Domain | Reason | Source |\n| :--- | :--- | :--- |\n")
                for domain, source, reason in unique_results:
                    f.write(f"| **{domain}** | {reason} | {source} |\n")
            print(f"\n[+] Results appended to results.md")
        else:
            print(f"\n[i] No expired domains found this time.")