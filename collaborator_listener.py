#!/usr/bin/env python3
"""
Simple Collaborator Listener for SSRF Testing
This creates a basic HTTP server to receive out-of-band interactions
"""

import http.server
import socketserver
import threading
import time
import json
import argparse
from datetime import datetime

class SSRFCollaboratorHandler(http.server.BaseHTTPRequestHandler):
    interactions = []
    
    def do_GET(self):
        self.log_interaction('GET')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = b"<html><body><h1>SSRF Collaborator Hit!</h1><p>This indicates a potential SSRF vulnerability.</p></body></html>"
        self.wfile.write(response)
    
    def do_POST(self):
        self.log_interaction('POST')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = b"<html><body><h1>SSRF Collaborator Hit (POST)!</h1></body></html>"
        self.wfile.write(response)
    
    def do_HEAD(self):
        self.log_interaction('HEAD')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    
    def log_interaction(self, method):
        interaction = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'client_address': self.client_address[0]
        }
        
        SSRFCollaboratorHandler.interactions.append(interaction)
        
        print(f"\n🔥 SSRF INTERACTION DETECTED!")
        print(f"Time: {interaction['timestamp']}")
        print(f"Method: {method}")
        print(f"Path: {self.path}")
        print(f"Client: {self.client_address[0]}")
        print(f"User-Agent: {self.headers.get('User-Agent', 'Unknown')}")
        print("-" * 50)
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

class SSRFCollaborator:
    def __init__(self, port=8080, interface='0.0.0.0'):
        self.port = port
        self.interface = interface
        self.server = None
        self.server_thread = None
    
    def start(self):
        """Start the collaborator server"""
        try:
            self.server = socketserver.TCPServer((self.interface, self.port), SSRFCollaboratorHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            print(f"🚀 SSRF Collaborator started on {self.interface}:{self.port}")
            print(f"📡 Listening for SSRF interactions...")
            print(f"🔗 Use this URL in your SSRF payloads: http://{self.get_public_ip()}:{self.port}")
            print("=" * 60)
            
            return True
        except Exception as e:
            print(f"❌ Error starting collaborator: {str(e)}")
            return False
    
    def stop(self):
        """Stop the collaborator server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("\n🛑 Collaborator stopped")
    
    def get_public_ip(self):
        """Try to get public IP, fallback to interface"""
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
            return response.strip()
        except:
            return self.interface if self.interface != '0.0.0.0' else 'localhost'
    
    def get_interactions(self):
        """Get all recorded interactions"""
        return SSRFCollaboratorHandler.interactions
    
    def save_interactions(self, filename):
        """Save interactions to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.get_interactions(), f, indent=2)
            print(f"💾 Interactions saved to {filename}")
        except Exception as e:
            print(f"❌ Error saving interactions: {str(e)}")
    
    def print_summary(self):
        """Print summary of interactions"""
        interactions = self.get_interactions()
        if not interactions:
            print("\n📊 No interactions recorded")
            return
        
        print(f"\n📊 INTERACTION SUMMARY")
        print(f"Total interactions: {len(interactions)}")
        
        methods = {}
        clients = {}
        
        for interaction in interactions:
            method = interaction['method']
            client = interaction['client_address']
            
            methods[method] = methods.get(method, 0) + 1
            clients[client] = clients.get(client, 0) + 1
        
        print("\nMethods:")
        for method, count in methods.items():
            print(f"  {method}: {count}")
        
        print("\nClients:")
        for client, count in clients.items():
            print(f"  {client}: {count}")
        
        print("\nRecent interactions:")
        for interaction in interactions[-5:]:  # Show last 5
            print(f"  {interaction['timestamp']} - {interaction['method']} {interaction['path']} from {interaction['client_address']}")

def main():
    parser = argparse.ArgumentParser(description='SSRF Collaborator Listener')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('-i', '--interface', default='0.0.0.0', help='Interface to bind to (default: 0.0.0.0)')
    parser.add_argument('-o', '--output', help='Save interactions to file on exit')
    
    args = parser.parse_args()
    
    collaborator = SSRFCollaborator(port=args.port, interface=args.interface)
    
    if not collaborator.start():
        return 1
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🔄 Shutting down...")
        collaborator.print_summary()
        
        if args.output:
            collaborator.save_interactions(args.output)
        
        collaborator.stop()
        print("👋 Goodbye!")

if __name__ == "__main__":
    main()