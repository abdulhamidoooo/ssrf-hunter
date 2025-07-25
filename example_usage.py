#!/usr/bin/env python3
"""
Example usage of the Advanced SSRF Scanner
Demonstrates various scanning techniques and features
"""

from ssrf_scanner import SSRFScanner
from payloads import SSRFPayloadDatabase, PayloadGenerator
import time

def demo_basic_scan():
    """Demonstrate basic SSRF scanning"""
    print("🔥 Demo 1: Basic SSRF Scan")
    print("=" * 50)
    
    # Example target with GET parameter
    target_url = "http://httpbin.org/get?url=https://google.com"
    
    scanner = SSRFScanner(
        target_url=target_url,
        threads=5,  # Reduced for demo
        timeout=5
    )
    
    print(f"Scanning: {target_url}")
    results = scanner.run_threaded_scan()
    
    scanner.print_results()
    print("\n" + "=" * 50 + "\n")

def demo_post_scan():
    """Demonstrate POST data scanning"""
    print("🔥 Demo 2: POST Data Scan")
    print("=" * 50)
    
    target_url = "http://httpbin.org/post"
    post_data = "url=test&callback=test&redirect=test"
    
    scanner = SSRFScanner(
        target_url=target_url,
        threads=3,
        timeout=5
    )
    
    print(f"Scanning: {target_url}")
    print(f"POST Data: {post_data}")
    results = scanner.run_scan(post_data)
    
    scanner.print_results()
    print("\n" + "=" * 50 + "\n")

def demo_collaborator_scan():
    """Demonstrate collaborator-based scanning"""
    print("🔥 Demo 3: Collaborator-Based Scan")
    print("=" * 50)
    
    target_url = "http://httpbin.org/get?url=test"
    collaborator_url = "webhook.site/unique-id"  # Replace with actual webhook
    
    scanner = SSRFScanner(
        target_url=target_url,
        collaborator_url=collaborator_url,
        threads=3,
        timeout=5
    )
    
    print(f"Scanning: {target_url}")
    print(f"Collaborator: {collaborator_url}")
    results = scanner.run_threaded_scan()
    
    scanner.print_results()
    print("\n💡 Check your collaborator/webhook for out-of-band hits!")
    print("\n" + "=" * 50 + "\n")

def demo_payload_categories():
    """Demonstrate different payload categories"""
    print("🔥 Demo 4: Payload Categories")
    print("=" * 50)
    
    # Show available payload categories
    categories = ['cloud', 'file', 'network', 'encoding', 'bypass']
    
    for category in categories:
        payloads = SSRFPayloadDatabase.get_payloads_by_category(category)
        print(f"\n{category.upper()} PAYLOADS ({len(payloads)}):")
        for i, payload in enumerate(payloads[:5]):  # Show first 5
            print(f"  {i+1}. {payload}")
        if len(payloads) > 5:
            print(f"  ... and {len(payloads) - 5} more")
    
    print("\n" + "=" * 50 + "\n")

def demo_payload_generation():
    """Demonstrate dynamic payload generation"""
    print("🔥 Demo 5: Dynamic Payload Generation")
    print("=" * 50)
    
    # Generate IP variations
    target_ip = "192.168.1.1"
    ip_variations = PayloadGenerator.generate_ip_variations(target_ip)
    
    print(f"IP VARIATIONS for {target_ip}:")
    for variation in ip_variations:
        print(f"  • {variation}")
    
    # Generate URL variations
    url_variations = PayloadGenerator.generate_url_variations("", "127.0.0.1")
    
    print(f"\nURL VARIATIONS (first 10):")
    for i, variation in enumerate(url_variations[:10]):
        print(f"  {i+1}. {variation}")
    
    print("\n" + "=" * 50 + "\n")

def demo_custom_scan():
    """Demonstrate customized scanning"""
    print("🔥 Demo 6: Custom Scan Configuration")
    print("=" * 50)
    
    target_url = "http://httpbin.org/anything?test=value"
    
    # Custom scanner with specific settings
    scanner = SSRFScanner(
        target_url=target_url,
        threads=1,  # Single thread for demonstration
        timeout=3,
        # proxy="http://127.0.0.1:8080"  # Uncomment to use proxy
    )
    
    # Override payload selection for demonstration
    scanner.test_headers = ['X-Forwarded-For', 'Referer']  # Limit headers
    
    print(f"Scanning: {target_url}")
    print("Configuration:")
    print(f"  - Threads: {scanner.threads}")
    print(f"  - Timeout: {scanner.timeout}s")
    print(f"  - Headers: {scanner.test_headers}")
    
    results = scanner.run_scan()
    
    scanner.print_results()
    
    # Export results
    if results:
        scanner.export_results("demo_results.json", "json")
        scanner.export_results("demo_report.html", "html")
        print("\n📁 Results exported to demo_results.json and demo_report.html")
    
    print("\n" + "=" * 50 + "\n")

def demo_safe_testing():
    """Demonstrate safe testing practices"""
    print("🔥 Demo 7: Safe Testing Practices")
    print("=" * 50)
    
    print("🛡️ SAFE TESTING GUIDELINES:")
    print("1. Only test applications you own or have permission to test")
    print("2. Use rate limiting to avoid overwhelming target servers")
    print("3. Test in controlled environments when possible")
    print("4. Monitor network traffic for out-of-band interactions")
    print("5. Document and report findings responsibly")
    
    print("\n📋 TESTING CHECKLIST:")
    checklist = [
        "✅ Permission obtained from application owner",
        "✅ Testing scope clearly defined",
        "✅ Rate limiting configured appropriately",
        "✅ Collaborator/webhook service ready",
        "✅ Network monitoring in place",
        "✅ Results documentation prepared"
    ]
    
    for item in checklist:
        print(f"  {item}")
    
    print("\n⚠️  Remember: Responsible disclosure is key!")
    print("\n" + "=" * 50 + "\n")

def main():
    """Run all demonstrations"""
    print("🔥 Advanced SSRF Scanner - Usage Demonstrations")
    print("=" * 60)
    print("This script demonstrates various features of the SSRF scanner.")
    print("Note: Some demos use httpbin.org for safe testing.")
    print("=" * 60 + "\n")
    
    try:
        # Run demonstrations
        demo_payload_categories()
        demo_payload_generation()
        demo_safe_testing()
        
        # Interactive demos (commented out to avoid actual requests)
        print("🔧 INTERACTIVE DEMOS (Uncomment to run):")
        print("  - demo_basic_scan()")
        print("  - demo_post_scan()")
        print("  - demo_collaborator_scan()")
        print("  - demo_custom_scan()")
        
        # Uncomment the lines below to run interactive demos
        # demo_basic_scan()
        # demo_post_scan()
        # demo_collaborator_scan()
        # demo_custom_scan()
        
        print("\n🎉 All demonstrations completed!")
        print("\n💡 To run interactive demos, uncomment the function calls in main()")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demonstrations interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")

if __name__ == "__main__":
    main()