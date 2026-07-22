# 0xAmannita
# A lightweight HTTP reverse proxy that forwards requests to a target while rotating spoofed IP headers per request for testing IP-based controls.

from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import random
import sys
import urllib3

# Disable SSL Warnings (untrusted SSL Certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = "https://target.com"

# Random IP Generator
def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

class RotatorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        spoofed_ip = random_ip()
        headers = {
            "X-Forwarded-For": spoofed_ip,
            "X-Real-IP": spoofed_ip,
            "Client-IP": spoofed_ip,
        }

        url = f"{TARGET}{self.path}"

        try:
            resp = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)

            self.send_response(resp.status_code)
            # Only forward safe headers
            for k, v in resp.headers.items():
                if k.lower() not in ("transfer-encoding", "connection", "content-encoding"):
                    try:
                        self.send_header(k, v)
                    except Exception:
                        pass
            self.end_headers()

            try:
                self.wfile.write(resp.content)
                self.wfile.flush()
            except BrokenPipeError:
                pass  # ffuf closed connection early, safe to ignore

        except requests.exceptions.RequestException as e:
            self.send_response(502)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress logs

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"[*] IP Rotator listening on 127.0.0.1:{port}")
    print(f"[*] Forwarding to {TARGET}")
    server = HTTPServer(("127.0.0.1", port), RotatorHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        server.server_close()
