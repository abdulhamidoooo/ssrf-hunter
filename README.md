# 🔥 Advanced SSRF Vulnerability Scanner

A comprehensive Server-Side Request Forgery (SSRF) vulnerability scanner that implements advanced detection techniques including parameter injection, header-based testing, protocol fuzzing, and filter evasion.

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

- Only use this tool on systems you own or have explicit permission to test
- Unauthorized testing of systems may violate laws and regulations
- The authors are not responsible for any misuse of this tool
- Always obtain proper authorization before conducting security testing

## 🚀 Features

### Core Scanning Capabilities
- **Parameter Discovery**: Automatically detects GET and POST parameters for injection
- **Protocol Fuzzing**: Tests multiple protocols (HTTP, FTP, Gopher, Dict, File, etc.)
- **Filter Evasion**: Advanced bypass techniques including IP encoding and obfuscation
- **Header Injection**: Tests common headers that may be vulnerable to SSRF
- **Multi-threading**: Parallel testing for improved performance

### Advanced Detection Methods
- **Cloud Metadata Access**: Tests for AWS, GCP, Azure metadata services
- **Internal Service Discovery**: Port scanning and service enumeration
- **File System Access**: Tests for local file inclusion via file:// protocol
- **Database Interaction**: Redis, MySQL, PostgreSQL interaction attempts
- **Time-based Detection**: Identifies slow responses indicating successful requests

### Professional Features
- **Collaborator Integration**: Works with external listeners for out-of-band detection
- **Custom Payload Support**: Load custom payloads from external files
- **Proxy Support**: Compatible with Burp Suite and other proxies
- **Comprehensive Reporting**: JSON export with detailed vulnerability information
- **Colored Output**: Easy-to-read terminal output with color coding

## 📦 Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Setup
```bash
# Clone or download the scanner files
git clone <repository> # or download the files

# Install dependencies
pip3 install -r requirements.txt

# Make scripts executable (Linux/Mac)
chmod +x ssrf_scanner.py
chmod +x collaborator_listener.py
```

## 🎯 Usage Examples

### Basic URL Parameter Testing
```bash
# Test a simple URL with parameters
python3 ssrf_scanner.py -u "http://target.com/page?url=http://example.com"

# Test with custom timeout and thread count
python3 ssrf_scanner.py -u "http://target.com/fetch" --timeout 15 --threads 10
```

### POST Data Testing
```bash
# Test JSON POST data
python3 ssrf_scanner.py -u "http://target.com/api/fetch" -m POST -d '{"url":"http://example.com","format":"json"}'

# Test form-encoded POST data
python3 ssrf_scanner.py -u "http://target.com/submit" -m POST -d "url=http://example.com&action=fetch"
```

### Advanced Testing with Collaborator
```bash
# Start the collaborator listener (in separate terminal)
python3 collaborator_listener.py -p 8080

# Use collaborator URL in scan
python3 ssrf_scanner.py -u "http://target.com/page?url=test" -c "your-server.com:8080"
```

### Custom Payloads and Reporting
```bash
# Use custom payload file and save report
python3 ssrf_scanner.py -u "http://target.com/api" --custom-payloads payloads.txt -o report.json

# Test through proxy (Burp Suite)
python3 ssrf_scanner.py -u "http://target.com/page" -p "http://127.0.0.1:8080"
```

## 🔧 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | Target URL to test (required) | `-u "http://target.com/page?url=test"` |
| `-m, --method` | HTTP method (GET/POST) | `-m POST` |
| `-d, --data` | POST data (JSON or form-encoded) | `-d '{"url":"test"}'` |
| `-c, --collaborator` | Collaborator URL for OOB testing | `-c "webhook.site/unique-id"` |
| `-p, --proxy` | Proxy URL | `-p "http://127.0.0.1:8080"` |
| `-t, --timeout` | Request timeout in seconds | `-t 15` |
| `--threads` | Number of concurrent threads | `--threads 10` |
| `-o, --output` | Output report file (JSON) | `-o ssrf_report.json` |
| `--custom-payloads` | Custom payload file | `--custom-payloads my_payloads.txt` |

## 🎛️ Collaborator Listener

The included collaborator listener helps detect out-of-band SSRF interactions:

```bash
# Start listener on port 8080
python3 collaborator_listener.py -p 8080

# Start with custom interface and save interactions
python3 collaborator_listener.py -i 0.0.0.0 -p 9000 -o interactions.json
```

### Collaborator Options
| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port` | Port to listen on | 8080 |
| `-i, --interface` | Interface to bind to | 0.0.0.0 |
| `-o, --output` | Save interactions to file | None |

## 📋 Payload Categories

The scanner includes comprehensive payload sets:

### Basic SSRF Payloads
- Local interfaces (127.0.0.1, localhost, 0.0.0.0)
- Cloud metadata services (AWS, GCP, Azure)
- File system access (Unix/Windows paths)

### Protocol Fuzzing
- Alternative protocols (FTP, Gopher, Dict, LDAP)
- Rare protocols (JAR, Expect, PHP filters)

### Filter Evasion
- IP encoding (decimal, hex, octal)
- IPv6 representations
- Domain confusion techniques
- URL encoding bypasses

### Header-based Testing
- X-Forwarded-For, X-Real-IP
- Host header manipulation
- Custom forwarding headers

## 📊 Understanding Results

### Vulnerability Indicators
The scanner identifies potential SSRF based on:

1. **Connection Errors**: Timeout, connection refused, unreachable
2. **Successful Responses**: Status codes 200, 301, 302, 403, 404
3. **Content Analysis**: Metadata responses, file contents, service banners
4. **Timing Analysis**: Unusually slow response times
5. **Out-of-band Hits**: Collaborator interactions

### Report Format
```json
{
  "scan_summary": {
    "total_tests": 150,
    "scan_time": "2024-01-15 10:30:45",
    "vulnerabilities_found": 3
  },
  "vulnerabilities": [
    {
      "test_type": "parameter_injection",
      "url": "http://target.com/page?url=http://127.0.0.1",
      "payload": "http://127.0.0.1",
      "timestamp": "2024-01-15 10:30:47",
      "response_data": {
        "status_code": 200,
        "content_length": 1234,
        "response_time": 0.5
      }
    }
  ]
}
```

## 🛡️ Defensive Recommendations

If you discover SSRF vulnerabilities:

### Immediate Actions
1. **Input Validation**: Implement strict URL validation
2. **Allowlisting**: Use allowed domains/IPs only
3. **Network Segmentation**: Isolate application servers
4. **Disable Unnecessary Protocols**: Block file://, gopher://, etc.

### Long-term Security
1. **Regular Security Testing**: Automated SSRF scanning
2. **Web Application Firewalls**: Deploy WAF rules
3. **Monitoring**: Log and monitor outbound requests
4. **Security Training**: Educate developers on SSRF risks

## 🔗 References and Further Reading

- [OWASP SSRF Testing Guide](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [SSRFMap Tool](https://github.com/swisskyrepo/SSRFmap)
- [Burp Suite Collaborator](https://portswigger.net/burp/documentation/collaborator)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OWASP community for SSRF research
- Security researchers for bypass techniques
- Python requests library maintainers

---

**Remember: Use responsibly and only on authorized targets!** 🎯