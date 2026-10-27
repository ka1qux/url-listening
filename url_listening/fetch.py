"""Requisição HTTP de um único salto, sem seguir redirecionamentos."""

from __future__ import annotations

import gzip
import http.client
import logging
import socket
import ssl
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from email.message import Message

from .config import Settings

log = logging.getLogger(__name__)


@dataclass
class FetchResult:
    url: str
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    error: str | None = None
    tls_insecure: bool = False

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Impede o urllib de seguir 3xx: queremos registrar cada salto."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _build_opener(verify: bool) -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))


def _decode_body(raw: bytes, encoding: str | None, content_type: str | None) -> str:
    encoding = (encoding or "").lower()
    try:
        if encoding == "gzip":
            raw = gzip.decompress(raw)
        elif encoding == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError) as exc:
        log.debug("falha ao descomprimir corpo: %s", exc)
        return ""
    msg = Message()
    msg["content-type"] = content_type or "text/html"
    charset = msg.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def fetch(url: str, settings: Settings) -> FetchResult:
    """Faz GET em `url` e devolve status, headers e corpo (sem seguir 3xx).

    Se o certificado for inválido, repete sem verificação e marca
    `tls_insecure`, pois sites de espelho costumam ter certificados ruins.
    """
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        },
    )
    result = FetchResult(url=url)
    for verify in (True, False):
        try:
            response = _build_opener(verify).open(request, timeout=settings.timeout)
        except urllib.error.HTTPError as exc:
            # 3xx/4xx/5xx chegam aqui por causa do _NoRedirect; ainda têm headers e corpo.
            response = exc
        except urllib.error.URLError as exc:
            if verify and isinstance(exc.reason, ssl.SSLCertVerificationError):
                result.tls_insecure = True
                continue
            result.error = str(exc.reason)
            return result
        except (socket.timeout, TimeoutError):
            result.error = "timeout"
            return result
        except (http.client.HTTPException, ConnectionError, ssl.SSLError, OSError, ValueError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        try:
            result.status = response.status if hasattr(response, "status") else response.code
            result.headers = list(response.headers.items()) if response.headers else []
            raw = response.read(settings.max_body_bytes)
        except (http.client.HTTPException, ConnectionError, socket.timeout, TimeoutError, OSError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return result
        finally:
            response.close()
        result.body = _decode_body(raw, result.header("content-encoding"), result.header("content-type"))
        return result
    return result
