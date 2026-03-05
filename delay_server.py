# delay Python server

import time
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(2)
        body = b"Hello from delayed backend (10s)\n"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.error):
            # Client disconnected before we finished sending.
            pass

httpd = HTTPServer(("", 9000), Handler)
httpd.serve_forever()

