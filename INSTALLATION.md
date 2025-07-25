# 🚀 Quick Installation Guide

## Prerequisites
- Python 3.6 or higher
- Linux/Unix environment (tested on Ubuntu)
- Internet connection for payload testing

## Installation Steps

### 1. Install System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-requests python3-urllib3

# Or for other systems, use pip
pip3 install requests urllib3
```

### 2. Download the Scanner
```bash
# Clone the repository or download the files
git clone <repository-url>
cd ssrf-scanner

# Or download individual files:
# - ssrf_scanner.py
# - collaborator_listener.py
# - payloads.txt
# - requirements.txt
```

### 3. Make Scripts Executable
```bash
chmod +x ssrf_scanner.py
chmod +x collaborator_listener.py
chmod +x demo.py
```

### 4. Verify Installation
```bash
python3 ssrf_scanner.py --help
python3 collaborator_listener.py --help
```

## Quick Test

### Basic Scan
```bash
python3 ssrf_scanner.py -u "http://httpbin.org/get?url=test"
```

### With Collaborator
```bash
# Terminal 1: Start listener
python3 collaborator_listener.py -p 8080

# Terminal 2: Run scan with collaborator
python3 ssrf_scanner.py -u "http://target.com/page" -c "your-server.com:8080"
```

### Demo Mode
```bash
python3 demo.py run
```

## Troubleshooting

### Permission Errors
```bash
sudo chmod +x *.py
```

### Missing Dependencies
```bash
# Use system packages
sudo apt install python3-requests python3-urllib3

# Or create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Network Issues
- Ensure target URLs are accessible
- Check proxy settings if using `-p` option
- Verify collaborator server is publicly accessible

## Ready to Scan! 🔥

Your SSRF scanner is now ready to use. Remember to only test on authorized targets!