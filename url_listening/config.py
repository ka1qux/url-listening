"""Configuração via variáveis de ambiente (nada hardcoded no código de negócio)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


# TLDs testadas como "espelho" do domínio (ex.: site.com -> site.net, site.xxx).
DEFAULT_VARIANT_TLDS = [
    "com", "net", "org", "info", "biz", "co", "io", "me", "tv", "cc", "to",
    "xxx", "sex", "porn", "adult", "vip", "club", "online", "site", "live",
    "app", "pro", "ws", "la", "ru", "su", "es", "de", "fr", "it", "nl", "eu",
    "uk", "in", "jp", "mx", "com.br", "net.br", "br",
]

# Prefixos de subdomínio comuns de versões alternativas do mesmo site.
DEFAULT_VARIANT_PREFIXES = ["www", "m", "mobile", "pt", "br", "es", "en"]

# Provedores compartilhados por milhares de sites: bloqueá-los quebra a
# navegação legítima. São listados no relatório, mas nunca sugeridos.
DEFAULT_SHARED_PROVIDERS = [
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
    "googletagmanager.com", "googlesyndication.com", "doubleclick.net",
    "googleusercontent.com", "youtube.com", "ytimg.com", "recaptcha.net",
    "cloudflare.com", "cloudflareinsights.com", "cdnjs.cloudflare.com",
    "jsdelivr.net", "unpkg.com", "jquery.com", "bootstrapcdn.com",
    "fontawesome.com", "fonts.googleapis.com", "facebook.com", "facebook.net",
    "fbcdn.net", "twitter.com", "x.com", "twimg.com", "instagram.com",
    "tiktok.com", "microsoft.com", "bing.com", "apple.com", "amazonaws.com",
    "cloudfront.net", "akamaihd.net", "akamaized.net", "fastly.net",
    "azureedge.net", "hotjar.com", "w3.org", "schema.org", "gravatar.com",
    "wp.com", "wordpress.com", "github.com", "githubusercontent.com",
    "hcaptcha.com", "sentry.io", "newrelic.com", "nr-data.net",
]


@dataclass(frozen=True)
class Settings:
    """Parâmetros de execução do analisador."""

    timeout: int = field(default_factory=lambda: _env_int("URL_LISTENING_TIMEOUT", 10))
    max_hops: int = field(default_factory=lambda: _env_int("URL_LISTENING_MAX_HOPS", 15))
    max_body_bytes: int = field(
        default_factory=lambda: _env_int("URL_LISTENING_MAX_BODY", 3 * 1024 * 1024)
    )
    workers: int = field(default_factory=lambda: _env_int("URL_LISTENING_WORKERS", 16))
    user_agent: str = field(
        default_factory=lambda: os.environ.get(
            "URL_LISTENING_UA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        )
    )
    doh_url: str = field(
        default_factory=lambda: os.environ.get(
            "URL_LISTENING_DOH", "https://dns.google/resolve"
        )
    )
    variant_tlds: list[str] = field(
        default_factory=lambda: _env_list("URL_LISTENING_TLDS", DEFAULT_VARIANT_TLDS)
    )
    variant_prefixes: list[str] = field(
        default_factory=lambda: _env_list("URL_LISTENING_PREFIXES", DEFAULT_VARIANT_PREFIXES)
    )
    shared_providers: list[str] = field(
        default_factory=lambda: _env_list("URL_LISTENING_SHARED", DEFAULT_SHARED_PROVIDERS)
    )
    # Servidor DNS usado para checar ECH quando o DoH estiver bloqueado (padrão: o do sistema).
    dns_server: str | None = field(default_factory=lambda: os.environ.get("URL_LISTENING_DNS_SERVER") or None)
    host: str = field(default_factory=lambda: os.environ.get("URL_LISTENING_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("URL_LISTENING_PORT", 8765))
