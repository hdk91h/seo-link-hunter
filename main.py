from core.expiredLinkHunter import ExpiredLinkHunter
import os

if __name__ == "__main__":
    # Example: filter for .de and .com domains
    hunter = ExpiredLinkHunter(debug=True, max_depth=2, tld_filter=['de', 'com'])

    targets_file = "targets.txt"

    if os.path.exists(targets_file):
        with open(targets_file, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for url in urls:
            hunter.scan_url(url)

        hunter.write_results()
    else:
        print(f"[!] {targets_file} not found.")