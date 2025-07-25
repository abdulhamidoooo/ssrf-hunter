# 🔥 Advanced SSRF Vulnerability Scanner

A comprehensive Server-Side Request Forgery (SSRF) vulnerability detection tool with advanced payload injection, evasion techniques, and detailed reporting capabilities.

## ✨ Features

- **Multiple Injection Points**: Tests GET/POST parameters and HTTP headers
- **Comprehensive Payload Database**: 200+ payloads covering various scenarios
- **Protocol Fuzzing**: Tests HTTP, HTTPS, FTP, Gopher, File, and more
- **Filter Evasion**: IP obfuscation, encoding, and bypass techniques
- **Cloud Metadata Detection**: AWS, GCP, Azure, DigitalOcean endpoints
- **Multithreading**: High-performance parallel testing
- **Out-of-Band Detection**: Collaborator URL support
- **Detailed Reporting**: JSON and HTML export formats
- **Proxy Support**: Compatible with Burp Suite and other proxies

## 🚀 Quick Start

### Installation

```bash
# Clone or download the scanner
git clone <repository-url>
cd ssrf-scanner

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x ssrf_scanner.py
```

### Basic Usage

```bash
# Test a URL with GET parameters
python ssrf_scanner.py -u "http://target.com/page?url=test"

# Test with POST data
python ssrf_scanner.py -u "http://target.com/api" -d "url=test&callback=test"

# Use collaborator for out-of-band detection
python ssrf_scanner.py -u "http://target.com" -c "your-id.burpcollaborator.net"

# Export results
python ssrf_scanner.py -u "http://target.com" -o results.json --format json
python ssrf_scanner.py -u "http://target.com" -o report.html --format html
```

## 📖 Usage Examples

### 1. Basic SSRF Testing

```bash
# Test URL with parameters
python ssrf_scanner.py -u "http://example.com/fetch?url=https://google.com"

# Test with custom threads and timeout
python ssrf_scanner.py -u "http://example.com/api" -t 20 --timeout 15
```

### 2. POST Data Testing

```bash
# Form data testing
python ssrf_scanner.py -u "http://example.com/submit" -d "url=test&redirect=test"

# JSON data testing
python ssrf_scanner.py -u "http://example.com/api" -d '{"url": "test", "webhook": "test"}'
```

### 3. Advanced Features

```bash
# Use proxy (Burp Suite)
python ssrf_scanner.py -u "http://example.com" --proxy "http://127.0.0.1:8080"

# Disable threading for debugging
python ssrf_scanner.py -u "http://example.com" --no-threading

# Export detailed HTML report
python ssrf_scanner.py -u "http://example.com" -o detailed_report.html --format html
```

### 4. Collaborator Integration

```bash
# Using Burp Collaborator
python ssrf_scanner.py -u "http://example.com" -c "xyz123.burpcollaborator.net"

# Using webhook.site
python ssrf_scanner.py -u "http://example.com" -c "unique-id.webhook.site"

# Custom collaborator domain
python ssrf_scanner.py -u "http://example.com" -c "ssrf.your-domain.com"
```

## 🎯 Payload Categories

The scanner includes comprehensive payloads across multiple categories:

### Cloud Metadata
- AWS EC2 metadata endpoints
- Google Cloud metadata
- Azure instance metadata
- DigitalOcean metadata
- Oracle Cloud endpoints

### File Access
- Linux system files (`/etc/passwd`, `/proc/version`)
- Windows system files (`C:\Windows\System32\drivers\etc\hosts`)
- Application configuration files
- SSH keys and certificates

### Network Services
- Internal service enumeration (HTTP, SSH, MySQL, Redis, etc.)
- Gopher protocol for service interaction
- Dict protocol for Memcached/Redis

### IP Obfuscation
- Decimal notation (`2130706433` = `127.0.0.1`)
- Hexadecimal notation (`0x7f000001`)
- Octal notation (`0177.0.0.1`)
- IPv6 representations
- URL encoding variations

### Bypass Techniques
- URL manipulation (`127.0.0.1@evil.com`)
- Protocol confusion
- Path traversal
- Null byte injection
- Case variations
- Double encoding

## 📊 Output Examples

### Console Output
```
🔥 Advanced SSRF Vulnerability Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: http://example.com/fetch?url=test
Collaborator: None
Threads: 10
Timeout: 10s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[*] Testing GET parameters: ['url']
[*] Testing POST parameters
[*] Testing HTTP headers: ['X-Forwarded-For', 'Referer', ...]
[*] Running 847 tests with 10 threads
[*] Completed 50/847 tests
[*] Completed 100/847 tests
...

🎯 SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total tests: 847
Potentially vulnerable: 3

🚨 POTENTIAL SSRF VULNERABILITIES:

[VULN] GET:url
  URL: http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/
  Payload: http://169.254.169.254/latest/meta-data/
  Status: 200
  Evidence:
    • Response contains: instance-id
    • AWS metadata detected
```

### JSON Export
```json
[
  {
    "url": "http://example.com/fetch?url=http://127.0.0.1",
    "payload": "http://127.0.0.1",
    "method": "GET",
    "injection_point": "GET:url",
    "status_code": 200,
    "response_time": 0.85,
    "response_length": 1024,
    "vulnerable": true,
    "evidence": ["Response contains: localhost"],
    "timestamp": 1640995200.0
  }
]
```

## 🛠️ Command Line Options

```
usage: ssrf_scanner.py [-h] -u URL [-c COLLABORATOR] [-d DATA] [-t THREADS]
                       [--timeout TIMEOUT] [--proxy PROXY] [-o OUTPUT]
                       [--format {json,html}] [--no-threading]

🔥 Advanced SSRF Vulnerability Scanner

required arguments:
  -u URL, --url URL     Target URL to scan

optional arguments:
  -h, --help            Show help message
  -c COLLABORATOR       Collaborator URL for out-of-band detection
  -d DATA               POST data to test (form or JSON format)
  -t THREADS            Number of threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080)
  -o OUTPUT             Output file for results
  --format {json,html}  Output format (default: json)
  --no-threading        Disable multithreading

Examples:
  python ssrf_scanner.py -u "http://target.com/page?url=test"
  python ssrf_scanner.py -u "http://target.com/api" -d "url=test&callback=test"
  python ssrf_scanner.py -u "http://target.com" -c "your-collab.burpcollaborator.net"
  python ssrf_scanner.py -u "http://target.com" -t 20 --proxy "http://127.0.0.1:8080"
```

## 🔧 Architecture

### Core Components

1. **SSRFScanner**: Main scanner class handling test orchestration
2. **SSRFPayloads**: Payload database with categorized attack vectors
3. **SSRFResult**: Result container for test outcomes
4. **PayloadGenerator**: Dynamic payload generation utilities

### Key Features

- **Thread-Safe**: Concurrent execution with result aggregation
- **Modular Design**: Extensible payload and analysis modules
- **Error Handling**: Robust exception handling and timeout management
- **Response Analysis**: Intelligent vulnerability detection logic

## 🧪 Detection Logic

The scanner identifies potential SSRF vulnerabilities through:

1. **Response Content Analysis**: Searches for internal service indicators
2. **Status Code Analysis**: Identifies unusual server responses
3. **Timing Analysis**: Detects response time anomalies
4. **Error Message Analysis**: Looks for connection errors and timeouts
5. **Cloud Metadata Detection**: Identifies AWS/GCP/Azure metadata responses

### Vulnerability Indicators

- Connection refused/timeout errors
- Internal service responses (SSH banners, HTTP responses)
- Cloud metadata content (instance-id, ami-id, etc.)
- File system content (/etc/passwd, Windows files)
- Database service responses
- Unusual HTTP status codes (500, 502, 503, 504)

## 🚨 Security Considerations

⚠️ **Important**: This tool is for authorized security testing only.

- Only test applications you own or have explicit permission to test
- Be mindful of rate limiting and server resources
- Use responsibly and in accordance with applicable laws
- Consider using a controlled environment for testing

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional payload categories
- Enhanced detection algorithms
- New bypass techniques
- Performance optimizations
- Integration with security frameworks

## 📚 References

- [OWASP SSRF Testing Guide](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [SSRFMap Tool](https://github.com/swisskyrepo/SSRFmap)
- [Burp Suite Collaborator](https://portswigger.net/burp/documentation/collaborator)

## 📄 License

This project is provided for educational and authorized security testing purposes only.

---

**Happy Bug Hunting! 🐛🔍**