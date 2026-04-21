from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json


class MockVulnerableTarget(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._respond(200, "<html><body>Mock Target</body></html>")
        elif self.path == "/api/users/1":
            self._respond(200, json.dumps({"id": 1, "email": "user@test.com", "name": "Test User"}))
        elif self.path == "/api/users/2":
            self._respond(200, json.dumps({"id": 2, "email": "admin@test.com", "name": "Admin"}))
        elif "/redirect" in self.path:
            url = self.path.split("url=")[-1] if "url=" in self.path else "/"
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
        elif self.path == "/.env":
            self._respond(200, "DB_PASSWORD=secret123\nAPI_KEY=sk-test-abc")
        elif self.path == "/graphql":
            self._respond(200, json.dumps({"data": {"__schema": {"types": []}}}))
        else:
            self._respond(404, "Not found")

    def do_OPTIONS(self):
        self.send_response(200)
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self.end_headers()

    def _respond(self, code: int, body: str):
        self.send_response(code)
        origin = self.headers.get("Origin", "*") if hasattr(self, 'headers') else "*"
        self.send_header("Content-Type", "text/html" if body.startswith("<") else "application/json")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Server", "MockServer/1.0")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


def start_mock_target(port: int = 18080) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), MockVulnerableTarget)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
