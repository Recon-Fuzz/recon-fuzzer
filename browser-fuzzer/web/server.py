#!/usr/bin/env python3
"""Simple HTTP server with COOP/COEP headers for SharedArrayBuffer support.

Usage: python3 server.py [port]
Default port: 8080

Serves from the browser-fuzzer root (parent of web/) so that both
web/ files and pkg/ (WASM output) are accessible.
"""
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler


class CORPHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        super().end_headers()

    def log_message(self, format, *args):
        if args and '200' not in str(args[1] if len(args) > 1 else ''):
            super().log_message(format, *args)


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    # Serve from browser-fuzzer root (parent of web/) so pkg/ is accessible
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    os.chdir(root)
    server = HTTPServer(('', port), CORPHandler)
    print(f'Serving on http://localhost:{port}/web/index.html')
    print('Press Ctrl+C to stop')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
