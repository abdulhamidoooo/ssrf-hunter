#!/usr/bin/env python3
"""
SSRF Scanner Demo Script
This demonstrates basic usage of the SSRF vulnerability scanner
"""

import subprocess
import sys
import time

def print_demo_header():
    print("=" * 70)
    print("🔥 SSRF VULNERABILITY SCANNER - DEMO")
    print("=" * 70)
    print("This demo shows how to use the SSRF scanner")
    print("⚠️  Remember: Only test on authorized targets!")
    print("=" * 70)

def run_demo_scan():
    """Run demonstration scans with example URLs"""
    
    demo_commands = [
        {
            "title": "Basic GET Parameter Testing",
            "command": [
                "python3", "ssrf_scanner.py", 
                "-u", "http://httpbin.org/get?url=http://example.com",
                "--timeout", "5",
                "--threads", "3"
            ]
        },
        {
            "title": "POST Data Testing",
            "command": [
                "python3", "ssrf_scanner.py",
                "-u", "http://httpbin.org/post",
                "-m", "POST",
                "-d", '{"url":"http://example.com","test":"ssrf"}',
                "--timeout", "5",
                "--threads", "3"
            ]
        },
        {
            "title": "Custom Payloads Testing",
            "command": [
                "python3", "ssrf_scanner.py",
                "-u", "http://httpbin.org/get?target=test",
                "--custom-payloads", "payloads.txt",
                "--timeout", "5",
                "--threads", "2",
                "-o", "demo_report.json"
            ]
        }
    ]
    
    for i, demo in enumerate(demo_commands, 1):
        print(f"\n🎯 Demo {i}: {demo['title']}")
        print("-" * 50)
        print("Command:", " ".join(demo['command']))
        print("-" * 50)
        
        try:
            # Ask user if they want to run this demo
            response = input("Run this demo? (y/n/q): ").lower().strip()
            
            if response == 'q':
                print("Demo cancelled by user")
                break
            elif response == 'y':
                print("Running scan...")
                result = subprocess.run(demo['command'], capture_output=True, text=True, timeout=60)
                
                print("STDOUT:")
                print(result.stdout)
                
                if result.stderr:
                    print("STDERR:")
                    print(result.stderr)
                
                print(f"Exit code: {result.returncode}")
            else:
                print("Skipping this demo...")
                
        except subprocess.TimeoutExpired:
            print("⏰ Demo timed out - this is normal for some tests")
        except KeyboardInterrupt:
            print("\n❌ Demo interrupted by user")
            break
        except Exception as e:
            print(f"❌ Error running demo: {str(e)}")
        
        if i < len(demo_commands):
            time.sleep(2)

def show_help():
    """Show help information"""
    print("\n📖 HELP INFORMATION")
    print("-" * 50)
    print("Available commands:")
    print("  python3 demo.py run          - Run interactive demo")
    print("  python3 demo.py help         - Show this help")
    print("  python3 demo.py examples     - Show usage examples")
    print("")
    print("Manual scanner usage:")
    print("  python3 ssrf_scanner.py -u 'http://target.com/page?url=test'")
    print("  python3 ssrf_scanner.py -u 'http://target.com' -m POST -d '{\"url\":\"test\"}'")
    print("")
    print("Collaborator listener:")
    print("  python3 collaborator_listener.py -p 8080")

def show_examples():
    """Show usage examples"""
    print("\n📋 USAGE EXAMPLES")
    print("-" * 50)
    
    examples = [
        {
            "description": "Basic URL parameter testing",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/fetch?url=http://example.com'"
        },
        {
            "description": "JSON POST data testing",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/api' -m POST -d '{\"url\":\"test\"}'"
        },
        {
            "description": "Form POST data testing",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/submit' -m POST -d 'url=test&action=fetch'"
        },
        {
            "description": "Using custom payloads",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/page' --custom-payloads payloads.txt"
        },
        {
            "description": "Testing with collaborator",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/page' -c 'your-server.com:8080'"
        },
        {
            "description": "Using proxy (Burp Suite)",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/page' -p 'http://127.0.0.1:8080'"
        },
        {
            "description": "Save results to file",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/page' -o 'results.json'"
        },
        {
            "description": "Advanced configuration",
            "command": "python3 ssrf_scanner.py -u 'http://target.com/page' --timeout 15 --threads 10"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['description']}")
        print(f"   {example['command']}")

def main():
    if len(sys.argv) < 2:
        print_demo_header()
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "run":
        print_demo_header()
        run_demo_scan()
    elif command == "help":
        show_help()
    elif command == "examples":
        show_examples()
    else:
        print(f"Unknown command: {command}")
        show_help()

if __name__ == "__main__":
    main()