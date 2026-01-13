# 🚀 SEO Link Hunter: The "Unfair Advantage" Script

Most SEO tools stop when a website times out. **Link Hunter goes deeper.** This Python tool is designed for developers who want to build a powerful expired domain strategy. It recursively scans resource lists (like "Awesome" lists), handles connection timeouts intelligently, and verifies DNS records to find domains that are truly available.

## 🔥 Key Features

- **Smart Timeout Analysis**: Distinguishes between "Server Down" (useless) and **"NXDOMAIN" (No IP = Potentially Free)**.
- **Deep Scan Mode**: Automatically detects Hubs (like GitHub Repositories) and dives one level deeper to find hidden links in READMEs.
- **Anti-Blocking**: Rotates User-Agents and uses exponential backoff retries to mimic real browser behavior.
- **Internal Filter**: Automatically ignores internal links to keep your results clean.
- **GitHub Actions Ready**: Runs on a schedule for free, alerting you via Issues when gems are found.

## 🛠 Usage

1. **Add Targets**: Put URLs you want to scan into `targets.txt`.
2. **Run**:
   ```bash
   python main.py
   ```
3. Check Results: Findings are written to results.md with a specific reason code:

* DNS_MISSING: The domain has no IP address (High probability of availability).

* WHOIS_FREE: The domain exists but has no active WHOIS record.

## ⚙️ Configuration (in `main.py`)
```python
# Enable Debug to see every request
hunter = ExpiredLinkHunter(debug=True)

# Set Deep Scan depth (1 = Scan target + linked GitHub Repos)
hunter = ExpiredLinkHunter(max_depth=1)
```

## 📦 Installation
```bash
pip install -r requirements.txt
```

## 📄 License
This project is open source and available under the **MIT License**.

If you use this script in a commercial project or content, please include a link back to the original article:
> [SEO Strategies Guide for Programmers](https://blogkurs.de/blog/seo-lernen-guide-programmierer/)

**Disclaimer:** This tool is for educational purposes only. Use it responsibly. The author is not responsible for blocked IP addresses or misuse.