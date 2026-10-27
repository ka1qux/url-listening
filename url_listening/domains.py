"""Utilitários de nome de host e domínio registrável."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

# Sufixos de dois níveis mais comuns. Não é a Public Suffix List completa,
# mas cobre os casos que aparecem na prática para filtro web.
MULTI_LEVEL_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp",
    "co.in", "net.in", "co.za", "com.mx", "com.ar", "com.co", "com.pe",
    "com.tr", "com.ru", "com.ua", "com.cn", "com.hk", "com.tw", "com.sg",
    "co.kr", "co.id", "com.my", "com.ph", "com.vn", "com.pl", "com.es",
    "com.pt", "co.il", "com.sa", "com.eg", "com.ng",
}


def host_from_url(url: str) -> str | None:
    """Extrai o host (minúsculo, sem porta e sem ponto final) de uma URL."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return normalize_host(host) if host else None


def normalize_host(host: str) -> str | None:
    """Normaliza um host: minúsculas, sem curinga, sem ponto final, IDNA."""
    host = host.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or " " in host or "/" in host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if is_ip(host):
        return host
    if "." not in host:
        return None
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def registrable_domain(host: str) -> str:
    """Retorna o domínio registrável (ex.: cdn.site.com.br -> site.com.br)."""
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def split_label(domain: str) -> tuple[str, str]:
    """Separa domínio registrável em (rótulo, sufixo): site.com.br -> (site, com.br)."""
    label, _, suffix = registrable_domain(domain).partition(".")
    return label, suffix


def matches_any(host: str, roots: set[str] | list[str]) -> bool:
    """True se o host é igual a algum root ou subdomínio dele."""
    return any(host == root or host.endswith("." + root) for root in roots)
