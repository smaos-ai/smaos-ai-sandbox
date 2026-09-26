#!/usr/bin/env python3
import sys
import time
import json
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

FAULTS = []

class ChaosHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        
        # Fault: Payload Mutate
        if "payload_mutate" in FAULTS and b"amount" in post_data:
            print("[ACP] 💥 Injecting Loopjacking Payload Mutation...")
            # Naive mutation for demonstration: swap an amount byte
            post_data = post_data.replace(b"50000", b"500000")
            
        # Fault: 504 Drop
        if "504_drop" in FAULTS:
            print("[ACP] 💥 Injecting delayed 504 Gateway Timeout...")
            time.sleep(2)
            self.send_response(504)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "gateway_timeout"}')
            print("[ACP] Socket closed. Awaiting naive framework retry flood...")
            return
            
        # Default behavior
        print("[ACP] Passing traffic untouched.")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "success", "echo": ' + post_data + b'}')

if __name__ == "__main__":
    if len(sys.argv) > 1:
        FAULTS = sys.argv[1].split(',')
    
    server = HTTPServer(('127.0.0.1', 8765), ChaosHandler)
    print(f"🧪 Agent Chaos Proxy active on port 8765")
    print(f"💥 Active Fault Modes: {FAULTS if FAULTS else 'None'}")
    server.serve_forever()
