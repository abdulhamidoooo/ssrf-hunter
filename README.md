# Advanced SSRF Vulnerability Scanner

## Overview

`ssrf_scanner.py` is a command-line utility that automates discovery and exploitation of Server-Side Request Forgery (SSRF) injection points.
It systematically mutates URL parameters, request bodies and HTTP headers with a variety of crafted payloads, then analyses responses for potential
vulnerabilities.

---

### Features

* Parameter discovery and payload injection (URL, body, headers)
* Classic, protocol-fuzz and filter-evasion payload lists (easily extensible)
* Multi-threaded scanning for speed
* Proxy support (Burp, TOR, etc.)
* Custom header / body support
* JSON report generation

---

## Installation

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage Examples

1. Basic GET scan:

```bash
python ssrf_scanner.py -u "http://victim.com/page?url=abc"
```

2. POST request with body parameters and custom collaborator URL:

```bash
python ssrf_scanner.py -u "http://victim.com/api" -X POST -d "url=abc&id=1" --collab "http://x.your-burpcollaborator.net"
```

3. Through a local Burp proxy with 10 concurrent threads:

```bash
python ssrf_scanner.py -u "http://victim.com/page?url=abc" --proxy "http://127.0.0.1:8080" --threads 10
```

After the scan finishes a `ssrf_report.json` file is written containing full results.

---

## Disclaimer

This tool is intended **solely for authorized security testing**. Unauthorized use against
systems you do not have permission to test is illegal.