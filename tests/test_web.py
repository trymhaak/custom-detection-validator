"""Tests for the web server."""

from __future__ import annotations

import json
import threading
import time
from http.server import HTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from cdv.web import CDVRequestHandler


def _start_server():
    """Start a test server on a random port and return (server, port)."""
    # Try ports in a test range to find an available one
    for port in range(18471, 18490):
        try:
            httpd = HTTPServer(("127.0.0.1", port), CDVRequestHandler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            return httpd, port
        except OSError:
            continue
    raise RuntimeError("Could not find an available port for test server")


@pytest.fixture(scope="module")
def server():
    """Module-scoped test server."""
    httpd, port = _start_server()
    base_url = f"http://127.0.0.1:{port}"
    yield base_url
    httpd.shutdown()
    httpd.server_close()


class TestGetIndex:
    def test_returns_html(self, server):
        resp = urlopen(f"{server}/")
        assert resp.status == 200
        content_type = resp.headers.get("Content-Type", "")
        assert "text/html" in content_type
        body = resp.read().decode("utf-8")
        assert "Custom Detection Validator" in body

    def test_index_html_path(self, server):
        resp = urlopen(f"{server}/index.html")
        assert resp.status == 200


class TestGet404:
    def test_unknown_path(self, server):
        with pytest.raises(HTTPError) as exc_info:
            urlopen(f"{server}/nonexistent")
        assert exc_info.value.code == 404


class TestPostValidate:
    def test_valid_query(self, server):
        data = json.dumps({"query": "DeviceEvents | where ActionType == 'x'"}).encode()
        req = Request(
            f"{server}/api/validate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        assert resp.status == 200

        result = json.loads(resp.read().decode("utf-8"))
        assert "results" in result
        assert "summary" in result
        assert "version" in result
        assert result["primary_table"] == "DeviceEvents"

    def test_query_with_errors(self, server):
        data = json.dumps({
            "query": "DeviceEvents | project FileName"
        }).encode()
        req = Request(
            f"{server}/api/validate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        result = json.loads(resp.read().decode("utf-8"))
        assert result["summary"]["errors"] > 0

    def test_nrt_eligible_query(self, server):
        data = json.dumps({
            "query": "DeviceProcessEvents | where FileName == 'powershell.exe'"
        }).encode()
        req = Request(
            f"{server}/api/validate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req)
        result = json.loads(resp.read().decode("utf-8"))
        assert result["summary"]["nrt_eligible"] is True

    def test_empty_query_returns_400(self, server):
        data = json.dumps({"query": ""}).encode()
        req = Request(
            f"{server}/api/validate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400
        body = json.loads(exc_info.value.read().decode("utf-8"))
        assert "error" in body

    def test_missing_query_key_returns_400(self, server):
        data = json.dumps({"not_query": "hello"}).encode()
        req = Request(
            f"{server}/api/validate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400

    def test_invalid_json_returns_400(self, server):
        req = Request(
            f"{server}/api/validate",
            data=b"not json at all",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400

    def test_whitespace_only_query_returns_400(self, server):
        data = json.dumps({"query": "   \n  "}).encode()
        req = Request(
            f"{server}/api/validate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 400


class TestPostUnknownPath:
    def test_post_to_unknown_returns_404(self, server):
        req = Request(
            f"{server}/api/unknown",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            urlopen(req)
        assert exc_info.value.code == 404
