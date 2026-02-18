"""Web UI server for the Custom Detection Validator.

Uses only Python stdlib (http.server). Binds to 127.0.0.1 only.
Run with: python -m cdv.web  OR  cdv --web
"""

from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from cdv.output.formatter import format_json
from cdv.validators.engine import ValidationEngine

STATIC_DIR = Path(__file__).parent / "static"


class CDVRequestHandler(BaseHTTPRequestHandler):
    """Handle GET / and POST /api/validate."""

    server_version = "CDV"

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self._serve_index()
        else:
            self._send_error(404, "Not found")

    def do_POST(self) -> None:
        if self.path == "/api/validate":
            self._handle_validate()
        else:
            self._send_error(404, "Not found")

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight (same-origin only)."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _serve_index(self) -> None:
        index_path = STATIC_DIR / "index.html"
        try:
            content = index_path.read_bytes()
        except FileNotFoundError:
            self._send_error(500, "index.html not found")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_validate(self) -> None:
        # Read body
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._send_json_error(400, "Invalid Content-Length")
            return
        if content_length > 1_000_000:  # 1MB limit
            self._send_json_error(400, "Request too large")
            return

        try:
            body = self.rfile.read(content_length)
            data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json_error(400, "Invalid JSON")
            return

        query = data.get("query", "")
        if not isinstance(query, str) or not query.strip():
            self._send_json_error(400, "Empty query")
            return

        # Validate
        try:
            engine = ValidationEngine()
            report = engine.validate(query.strip())
            result_json = format_json(report)
        except Exception as e:
            self._send_json_error(500, f"Validation error: {e}")
            return

        result_bytes = result_json.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(result_bytes)))
        self.end_headers()
        self.wfile.write(result_bytes)

    def _send_error(self, code: int, message: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(message.encode("utf-8"))

    def _send_json_error(self, code: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default request logging to keep terminal clean."""
        pass


def serve(
    host: str = "127.0.0.1",
    port: int = 8471,
    no_browser: bool = False,
) -> None:
    """Start the CDV web server."""

    # Try requested port, then fallback to 8472-8480
    httpd = None
    actual_port = port
    for try_port in range(port, port + 10):
        try:
            httpd = HTTPServer((host, try_port), CDVRequestHandler)
            actual_port = try_port
            break
        except OSError:
            if try_port == port + 9:
                print(
                    f"Error: Could not bind to any port in range {port}-{port + 9}",
                    file=sys.stderr,
                )
                sys.exit(1)
            continue

    assert httpd is not None

    url = f"http://{host}:{actual_port}"
    print(f"\n  Custom Detection Validator - Web UI")
    print(f"  Running at: {url}")
    print(f"  Press Ctrl+C to stop\n")

    if not no_browser:
        threading.Timer(0.5, webbrowser.open, args=[url]).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
