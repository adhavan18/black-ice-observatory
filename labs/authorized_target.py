"""local-only target used by the authorized security test."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404); self.end_headers()

def serve(port: int = 8765):
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()

if __name__ == "__main__": serve()
