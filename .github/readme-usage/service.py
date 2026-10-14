"""Temporary local HTTP/1.1 service for the README usage recording."""
import http.server
import json
import ssl
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({"path": self.path, "message": "observer usage"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
context.set_alpn_protocols(["http/1.1"])
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(json.dumps({"port": server.server_port, "openssl": ssl.OPENSSL_VERSION}), flush=True)
server.serve_forever()
