# 🧪 SSRF Scanner Testing & Deployment Guide

This guide provides comprehensive instructions for testing, deploying, and using the Advanced SSRF Vulnerability Scanner.

## 📋 Prerequisites

### System Requirements
- Python 3.7 or higher
- Internet connection for dependency installation
- 2GB+ RAM recommended for large scans
- Linux/macOS/Windows compatible

### Dependencies
```bash
pip install -r requirements.txt
```

Required packages:
- `requests>=2.28.0`
- `urllib3>=1.26.0`
- `typing-extensions>=4.0.0`
- `colorama>=0.4.4`

## 🚀 Quick Setup

### 1. Installation
```bash
# Clone the repository
git clone <repository-url>
cd ssrf-scanner

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x ssrf_scanner.py

# Test installation
python3 ssrf_scanner.py --help
```

### 2. Basic Verification
```bash
# Run example demonstrations
python3 example_usage.py

# Test with safe endpoint
python3 ssrf_scanner.py -u "http://httpbin.org/get?url=test" -t 3 --timeout 5
```

## 🧪 Testing Scenarios

### Safe Testing Endpoints

#### 1. httpbin.org (Echo Service)
```bash
# GET parameter testing
python3 ssrf_scanner.py -u "http://httpbin.org/get?url=test&callback=test"

# POST data testing  
python3 ssrf_scanner.py -u "http://httpbin.org/post" -d "url=test&webhook=test"

# Header testing only
python3 ssrf_scanner.py -u "http://httpbin.org/headers" -t 5
```

#### 2. Local Test Server
```bash
# Start local test server (separate terminal)
python3 -m http.server 8000

# Test against local server
python3 ssrf_scanner.py -u "http://localhost:8000/?url=test" -t 3
```

### Controlled Environment Testing

#### 1. Docker Test Environment
```bash
# Create test environment
docker run -d -p 9090:80 --name ssrf-test nginx

# Test against Docker container
python3 ssrf_scanner.py -u "http://localhost:9090/?test=value" -t 5

# Cleanup
docker stop ssrf-test && docker rm ssrf-test
```

#### 2. Custom Test Application
```python
# simple_test_app.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    return f"Fetching: {url}"

if __name__ == '__main__':
    app.run(port=5000)
```

```bash
# Test custom app
python3 simple_test_app.py &
python3 ssrf_scanner.py -u "http://localhost:5000/fetch?url=test"
```

## 🎯 Advanced Testing

### 1. Collaborator Setup

#### Burp Collaborator
```bash
# Use Burp Suite's collaborator
python3 ssrf_scanner.py -u "http://target.com" -c "xyz123.burpcollaborator.net"
```

#### webhook.site
```bash
# Create webhook at https://webhook.site/
python3 ssrf_scanner.py -u "http://target.com" -c "unique-id.webhook.site"
```

#### Custom Collaborator
```bash
# Set up your own listener
nc -lvnp 80  # In separate terminal

python3 ssrf_scanner.py -u "http://target.com" -c "your-server.com"
```

### 2. Proxy Integration

#### Burp Suite Integration
```bash
# Configure Burp proxy on 127.0.0.1:8080
python3 ssrf_scanner.py -u "http://target.com" --proxy "http://127.0.0.1:8080"
```

#### OWASP ZAP Integration
```bash
# Configure ZAP proxy on 127.0.0.1:8081
python3 ssrf_scanner.py -u "http://target.com" --proxy "http://127.0.0.1:8081"
```

### 3. Performance Testing

#### Large-Scale Scans
```bash
# High-performance scan
python3 ssrf_scanner.py -u "http://target.com" -t 20 --timeout 30

# Memory usage monitoring
python3 -c "
import psutil
import subprocess
import time

proc = subprocess.Popen(['python3', 'ssrf_scanner.py', '-u', 'http://target.com'])
while proc.poll() is None:
    memory = psutil.Process(proc.pid).memory_info().rss / 1024 / 1024
    print(f'Memory usage: {memory:.2f} MB')
    time.sleep(5)
"
```

## 📊 Output Analysis

### 1. Console Output Analysis
- **Green results**: No issues detected
- **Red results**: Potential vulnerabilities found
- **Yellow warnings**: Timeouts or connection issues

### 2. JSON Export Analysis
```bash
# Export results for analysis
python3 ssrf_scanner.py -u "http://target.com" -o results.json

# Analyze results
python3 -c "
import json
with open('results.json') as f:
    results = json.load(f)
    vulnerable = [r for r in results if r['vulnerable']]
    print(f'Total tests: {len(results)}')
    print(f'Vulnerabilities: {len(vulnerable)}')
    for v in vulnerable[:5]:
        print(f'- {v[\"injection_point\"]}: {v[\"payload\"][:50]}...')
"
```

### 3. HTML Report Review
```bash
# Generate detailed HTML report
python3 ssrf_scanner.py -u "http://target.com" -o report.html --format html

# Open in browser (Linux)
xdg-open report.html

# Open in browser (macOS)
open report.html
```

## 🛡️ Security Testing Best Practices

### 1. Authorization & Scope
- ✅ Obtain written permission before testing
- ✅ Define testing scope clearly
- ✅ Document all testing activities
- ✅ Respect rate limits and server resources

### 2. Testing Methodology
```bash
# 1. Reconnaissance
python3 ssrf_scanner.py -u "http://target.com" --no-threading -t 1

# 2. Focused testing
python3 ssrf_scanner.py -u "http://target.com/api?url=test" -t 5

# 3. Deep analysis
python3 ssrf_scanner.py -u "http://target.com" -c "collab.domain.com" -t 10

# 4. Verification
# Manually verify any findings
```

### 3. Result Validation
```bash
# Manual verification script
cat > verify_findings.py << 'EOF'
import requests
import sys

def verify_ssrf(url, payload):
    try:
        response = requests.get(url.replace('test', payload), timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Length: {len(response.text)}")
        if 'metadata' in response.text.lower():
            print("⚠️  Potential AWS metadata access!")
        return response
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python verify_findings.py <url> <payload>")
        sys.exit(1)
    
    url, payload = sys.argv[1], sys.argv[2]
    verify_ssrf(url, payload)
EOF

# Use verification script
python3 verify_findings.py "http://target.com/fetch?url=test" "http://169.254.169.254/latest/meta-data/"
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Connection Errors
```bash
# Issue: "Connection refused" errors
# Solution: Check target availability
curl -I http://target.com

# Issue: SSL certificate errors  
# Solution: Use --insecure flag (add to scanner if needed)
```

#### 2. Memory Issues
```bash
# Issue: High memory usage
# Solution: Reduce thread count
python3 ssrf_scanner.py -u "http://target.com" -t 3

# Issue: Timeout errors
# Solution: Increase timeout
python3 ssrf_scanner.py -u "http://target.com" --timeout 30
```

#### 3. False Positives
```bash
# Issue: Too many false positives
# Solution: Manual verification required
# Review httpbin.org results as example of false positives
```

### Debug Mode
```bash
# Enable verbose output (modify scanner for debug mode)
# Add logging to ssrf_scanner.py:
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📈 Performance Optimization

### 1. Thread Tuning
```bash
# Conservative (low impact)
python3 ssrf_scanner.py -u "http://target.com" -t 3 --timeout 5

# Balanced (recommended)
python3 ssrf_scanner.py -u "http://target.com" -t 10 --timeout 10

# Aggressive (high performance)
python3 ssrf_scanner.py -u "http://target.com" -t 20 --timeout 15
```

### 2. Payload Optimization
```python
# Custom payload selection
from payloads import SSRFPayloadDatabase

# Use specific categories only
cloud_payloads = SSRFPayloadDatabase.get_cloud_payloads()
print(f"Testing {len(cloud_payloads)} cloud-specific payloads")
```

### 3. Resource Monitoring
```bash
# Monitor system resources during scan
htop  # or top

# Network monitoring
netstat -an | grep ESTABLISHED | wc -l
```

## 📝 Reporting & Documentation

### 1. Executive Summary Template
```markdown
# SSRF Assessment Results

## Summary
- Target: http://target.com
- Scan Date: YYYY-MM-DD
- Total Tests: XXX
- Vulnerabilities Found: XXX

## Critical Findings
1. [High] AWS Metadata Access via /api/fetch?url=
2. [Medium] Internal Network Scanning via headers

## Recommendations
1. Implement URL validation and whitelist
2. Use network segmentation
3. Monitor outbound connections
```

### 2. Technical Report
```bash
# Generate comprehensive report
python3 ssrf_scanner.py -u "http://target.com" \
  -c "collab.domain.com" \
  -o technical_report.html \
  --format html \
  -t 10 \
  --timeout 15

# Add custom analysis
echo "## Custom Analysis" >> technical_report.html
echo "- Manual verification required for cloud metadata findings" >> technical_report.html
```

## 🎓 Learning & Development

### 1. Understanding Results
- Study the payload database in `payloads.py`
- Understand detection logic in `_analyze_response()`
- Review real-world SSRF examples

### 2. Extending the Scanner
```python
# Add custom payloads
custom_payloads = [
    "http://internal.company.com",
    "http://admin.local:8080",
    "ftp://backup.company.com"
]

# Add to scanner
scanner.additional_payloads = custom_payloads
```

### 3. Integration Examples
```python
# CI/CD Integration
import subprocess
import json

def run_ssrf_scan(target_url):
    result = subprocess.run([
        'python3', 'ssrf_scanner.py',
        '-u', target_url,
        '-o', 'scan_results.json',
        '--format', 'json'
    ], capture_output=True, text=True)
    
    with open('scan_results.json') as f:
        results = json.load(f)
    
    vulnerable_count = len([r for r in results if r['vulnerable']])
    
    if vulnerable_count > 0:
        print(f"⚠️  {vulnerable_count} potential SSRF vulnerabilities found!")
        return False
    return True

# Usage in CI/CD
if not run_ssrf_scan("http://staging.company.com"):
    exit(1)  # Fail the build
```

## 🏁 Conclusion

This testing guide provides a comprehensive framework for using the SSRF scanner effectively and safely. Remember:

1. **Always get permission** before testing
2. **Start with safe endpoints** to understand the tool
3. **Manually verify** all findings
4. **Use collaborators** for out-of-band detection
5. **Document everything** for proper reporting

For questions or issues, refer to the main README.md or create an issue in the repository.

---

**Happy Security Testing! 🔒🔍**