# An HTTPS server for the spike's clients: answers every POST with
# "echo:" and the request's body, over HTTP/1.1 keep-alive. Usage:
#   python3 server.py PORT CERT KEY
import http.server, ssl, sys

class Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        out = b"echo:" + body
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a):
        pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Echo)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
