"""Interface web local (http.server da stdlib) com API JSON."""

from __future__ import annotations

import json
import logging
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from . import __version__
from .analyzer import Analyzer
from .config import Settings

log = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 16 * 1024
APP_HEADER = "url-listening"


class AppServer(ThreadingHTTPServer):
    """Servidor que registra a última atividade da interface e pedidos de encerramento."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(address, handler)
        self.last_seen = time.monotonic()
        self.stop_requested = threading.Event()


def _make_handler(analyzer: Analyzer) -> type[BaseHTTPRequestHandler]:
    index_html = resources.files("url_listening").joinpath("static/index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        server_version = "URLListening/1.0"
        server: AppServer

        def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-App", APP_HEADER)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: HTTPStatus, payload: dict) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _origin_ok(self) -> bool:
            """Barra DNS rebinding (Host) e chamadas de outros sites abertos no navegador (Origin)."""
            port = self.server.server_address[1]
            allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
            if self.headers.get("Host", "") not in allowed:
                self._json(HTTPStatus.FORBIDDEN, {"error": "host não permitido"})
                return False
            origin = self.headers.get("Origin")
            if origin and origin.removeprefix("http://") not in allowed:
                self._json(HTTPStatus.FORBIDDEN, {"error": "origem não permitida"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._origin_ok():
                return
            self.server.last_seen = time.monotonic()
            if self.path in ("/", "/index.html"):
                self._send(HTTPStatus.OK, index_html, "text/html; charset=utf-8")
            elif self.path == "/api/ping":
                self._json(HTTPStatus.OK, {"ok": True, "version": __version__})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "não encontrado"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._origin_ok():
                return
            # Exigir JSON obriga o navegador a fazer preflight CORS em chamadas de outros
            # sites; este servidor não responde OPTIONS, então elas nunca chegam aqui.
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "use Content-Type: application/json"})
                return
            self.server.last_seen = time.monotonic()
            if self.path == "/api/shutdown":
                # Marca antes de responder: quem recebe o 200 já pode contar com o encerramento.
                self.server.stop_requested.set()
                self._json(HTTPStatus.OK, {"ok": True})
                return
            if self.path != "/api/analyze":
                self._json(HTTPStatus.NOT_FOUND, {"error": "não encontrado"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if not 0 < length <= MAX_REQUEST_BYTES:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "corpo da requisição inválido"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
                url = str(payload["url"])
                variants = bool(payload.get("variants", True))
            except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "envie JSON com o campo 'url'"})
                return
            try:
                report = analyzer.analyze(url, check_variants=variants)
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._json(HTTPStatus.OK, report.to_dict())

        def log_message(self, fmt: str, *args) -> None:
            log.info("%s - %s", self.address_string(), fmt % args)

    return Handler


def create_server(settings: Settings) -> AppServer:
    """Cria o servidor (porta 0 = porta livre escolhida pelo sistema)."""
    return AppServer((settings.host, settings.port), _make_handler(Analyzer(settings)))


def serve(settings: Settings | None = None) -> None:
    """Sobe a interface em http://HOST:PORT (padrão 127.0.0.1:8765) até Ctrl+C."""
    settings = settings or Settings()
    server = create_server(settings)
    print(f"URL Listening rodando em http://{settings.host}:{server.server_address[1]}  (Ctrl+C para sair)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
