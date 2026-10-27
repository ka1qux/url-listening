"""Testes do servidor web local (sem acesso à internet: só endpoints que não analisam sites)."""

from __future__ import annotations

import dataclasses
import json
import threading
import unittest
import urllib.error
import urllib.request

from url_listening import __version__
from url_listening.config import Settings
from url_listening.web import APP_HEADER, create_server


class WebServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_server(dataclasses.replace(Settings(), host="127.0.0.1", port=0))
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _post(self, path: str, payload: bytes) -> tuple[int, dict]:
        req = urllib.request.Request(self.base + path, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_ping_returns_version_and_app_header(self) -> None:
        with urllib.request.urlopen(self.base + "/api/ping", timeout=5) as resp:
            self.assertEqual(resp.headers["X-App"], APP_HEADER)
            self.assertEqual(json.loads(resp.read()), {"ok": True, "version": __version__})

    def test_index_serves_interface_html(self) -> None:
        with urllib.request.urlopen(self.base + "/", timeout=5) as resp:
            body = resp.read().decode("utf-8")
        self.assertIn("<title>URL Listening</title>", body)
        self.assertIn('id="url"', body)

    def test_analyze_with_invalid_scheme_returns_400(self) -> None:
        status, data = self._post("/api/analyze", json.dumps({"url": "ftp://site.com"}).encode())
        self.assertEqual(status, 400)
        self.assertIn("inválida", data["error"])

    def test_analyze_without_url_field_returns_400(self) -> None:
        status, data = self._post("/api/analyze", b'{"nada": 1}')
        self.assertEqual(status, 400)
        self.assertIn("url", data["error"])

    def test_shutdown_sets_stop_flag(self) -> None:
        status, _ = self._post("/api/shutdown", b"")
        self.assertEqual(status, 200)
        self.assertTrue(self.server.stop_requested.is_set())

    def _raw(self, method: str, path: str, headers: dict[str, str], body: bytes = b"") -> int:
        req = urllib.request.Request(self.base + path, data=body or None, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_request_with_foreign_host_returns_403(self) -> None:
        # Simula DNS rebinding: domínio do atacante resolvendo para 127.0.0.1.
        self.assertEqual(self._raw("GET", "/api/ping", {"Host": "evil.example:80"}), 403)

    def test_post_from_other_origin_returns_403_and_keeps_running(self) -> None:
        status = self._raw("POST", "/api/shutdown", {"Origin": "https://evil.example", "Content-Type": "application/json"}, b"{}")
        self.assertEqual(status, 403)
        self.assertFalse(self.server.stop_requested.is_set())

    def test_post_without_json_content_type_returns_415(self) -> None:
        # Formulário/fetch "simples" de outro site (text/plain) não passa por preflight CORS.
        status = self._raw("POST", "/api/shutdown", {"Content-Type": "text/plain"}, b"x")
        self.assertEqual(status, 415)
        self.assertFalse(self.server.stop_requested.is_set())
        status = self._raw("POST", "/api/analyze", {"Content-Type": "text/plain"}, b'{"url": "site.com"}')
        self.assertEqual(status, 415)

    def test_unknown_path_returns_404(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + "/nada", timeout=5)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
