"""Ponto de entrada do aplicativo instalado: sobe o servidor local e abre o navegador.

O processo encerra quando o usuário clica em "Encerrar" na interface ou quando a
aba fica fechada por mais de IDLE_SECONDS (a página envia um ping periódico).
"""

from __future__ import annotations

import dataclasses
import logging
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser

from .config import Settings
from .web import APP_HEADER, AppServer, create_server

log = logging.getLogger(__name__)

# Navegadores reduzem timers de abas em segundo plano para ~1/min; margem folgada.
IDLE_SECONDS = 180
WATCH_INTERVAL = 2.0


def _is_our_app(url: str) -> bool:
    """True se já existe uma instância do aplicativo respondendo nessa URL."""
    try:
        with urllib.request.urlopen(url + "api/ping", timeout=2) as resp:
            return resp.headers.get("X-App") == APP_HEADER
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _start_server(settings: Settings) -> AppServer:
    try:
        return create_server(settings)
    except OSError:
        # Porta padrão ocupada por outro programa: o sistema escolhe uma livre.
        return create_server(dataclasses.replace(settings, port=0))


def _setup_logging() -> None:
    # No Windows o executável não tem console (stdout é None): loga em arquivo.
    path = os.path.join(tempfile.gettempdir(), "url_listening.log")
    logging.basicConfig(filename=path, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main() -> int:
    _setup_logging()
    settings = Settings()
    default_url = f"http://{settings.host}:{settings.port}/"
    if _is_our_app(default_url):
        webbrowser.open(default_url)
        return 0

    server = _start_server(settings)
    url = f"http://{settings.host}:{server.server_address[1]}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("aplicativo iniciado em %s", url)
    webbrowser.open(url)

    try:
        while not server.stop_requested.wait(WATCH_INTERVAL):
            if time.monotonic() - server.last_seen > IDLE_SECONDS:
                log.info("interface fechada há mais de %ss; encerrando", IDLE_SECONDS)
                break
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
