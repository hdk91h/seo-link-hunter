from core.expiredLinkHunter import ExpiredLinkHunter
import os

if __name__ == "__main__":
    # depth=0: only the URLs in targets.txt
    # depth=1: targets + one level of external hubs (e.g., GitHub Repos)
    hunter = ExpiredLinkHunter(debug=False, max_depth=1)

    targets_file = "targets.txt"

    if os.path.exists(targets_file):
        with open(targets_file, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for url in urls:
            hunter.scan_url(url)

        hunter.write_results()
    else:
        print(f"[!] {targets_file} not found.")