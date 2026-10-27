"""Extração de hosts referenciados por uma página (HTML, CSS, JS e headers)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

from .domains import host_from_url, normalize_host

URL_ATTRS = {"src", "href", "data-src", "data-href", "data-url", "action", "poster", "data", "data-original", "data-video", "data-poster"}
ABS_URL_RE = re.compile(r"""(?:https?:)?\\?/\\?/([a-z0-9][a-z0-9.\-]*\.[a-z]{2,24})(?=[/:"'\\\s?#)]|$)""", re.I)
CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^'")]+)""", re.I)
JS_REDIRECT_RES = [
    re.compile(r"""(?:window|document|top|self)?\.?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""location\.(?:replace|assign)\(\s*['"]([^'"]+)['"]""", re.I),
]
META_REFRESH_RE = re.compile(r"""\d*\s*;?\s*url\s*=\s*['"]?([^'"\s>]+)""", re.I)


@dataclass
class PageInfo:
    title: str = ""
    meta_refresh: str | None = None
    js_redirect: str | None = None
    identity_urls: list[str] = field(default_factory=list)  # canonical, og:url, hreflang
    resource_hosts: set[str] = field(default_factory=set)


class _Parser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.info = PageInfo()
        self._in_title = False
        self._raw_text: list[str] = []  # conteúdo de <script> e <style>
        self._capture_raw = False

    def _add_url(self, value: str) -> None:
        value = value.strip()
        if not value or value.startswith(("data:", "javascript:", "mailto:", "tel:", "#", "blob:")):
            return
        host = host_from_url(urljoin(self.base_url, value))
        if host:
            self.info.resource_hosts.add(host)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        if tag in ("script", "style"):
            self._capture_raw = True
        if tag == "base" and attr.get("href"):
            self.base_url = urljoin(self.base_url, attr["href"])
        for name in URL_ATTRS & attr.keys():
            self._add_url(attr[name])
        for name in ("srcset", "data-srcset"):
            for candidate in attr.get(name, "").split(","):
                if candidate.strip():
                    self._add_url(candidate.strip().split()[0])
        if attr.get("style"):
            for match in CSS_URL_RE.findall(attr["style"]):
                self._add_url(match)

        if tag == "meta":
            if attr.get("http-equiv", "").lower() == "refresh":
                match = META_REFRESH_RE.search(attr.get("content", ""))
                if match:
                    self.info.meta_refresh = urljoin(self.base_url, match.group(1))
            prop = (attr.get("property") or attr.get("name") or "").lower()
            content = attr.get("content", "")
            if prop in ("og:url", "twitter:url") and content:
                self.info.identity_urls.append(urljoin(self.base_url, content))
            elif content.startswith(("http://", "https://", "//")):
                self._add_url(content)
        if tag == "link":
            rel = attr.get("rel", "").lower()
            if attr.get("href") and ("canonical" in rel or "alternate" in rel or "amphtml" in rel):
                self.info.identity_urls.append(urljoin(self.base_url, attr["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in ("script", "style"):
            self._capture_raw = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.info.title:
            self.info.title = data.strip()[:200]
        if self._capture_raw:
            self._raw_text.append(data)


def parse_page(html: str, base_url: str) -> PageInfo:
    """Analisa o HTML e devolve título, redirecionamentos e hosts referenciados."""
    parser = _Parser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except AssertionError:
        # HTMLParser ainda pode falhar em HTML muito quebrado; usa o que já coletou.
        pass
    info = parser.info
    raw = "\n".join(parser._raw_text)
    for text in (raw, html):
        for host in ABS_URL_RE.findall(text):
            normalized = normalize_host(host)
            if normalized:
                info.resource_hosts.add(normalized)
    for match in CSS_URL_RE.findall(raw):
        parser._add_url(match)

    # Redirecionamento por JS só é considerado em páginas pequenas (páginas
    # intermediárias/encurtadores); em páginas grandes geraria falso positivo.
    if len(html) < 20_000:
        for regex in JS_REDIRECT_RES:
            match = regex.search(raw or html)
            if match:
                info.js_redirect = urljoin(base_url, match.group(1))
                break
    return info


def hosts_from_headers(headers: list[tuple[str, str]], base_url: str) -> set[str]:
    """Hosts citados em CSP, Link, Set-Cookie (domain=) e Access-Control-Allow-Origin."""
    hosts: set[str] = set()
    for key, value in headers:
        key = key.lower()
        if key in ("content-security-policy", "content-security-policy-report-only"):
            for token in re.split(r"[\s;]+", value):
                token = token.strip("'\"")
                if "." in token and not token.startswith(("'", "sha", "nonce")):
                    host = normalize_host(re.sub(r"^[a-z]+://", "", token).split("/")[0].split(":")[0])
                    if host:
                        hosts.add(host)
        elif key == "link":
            for url in re.findall(r"<([^>]+)>", value):
                host = host_from_url(urljoin(base_url, url))
                if host:
                    hosts.add(host)
        elif key == "set-cookie":
            match = re.search(r"domain=\.?([^;\s]+)", value, re.I)
            if match:
                host = normalize_host(match.group(1))
                if host:
                    hosts.add(host)
        elif key == "access-control-allow-origin" and value.strip() != "*":
            host = host_from_url(value.strip())
            if host:
                hosts.add(host)
    return hosts


def supports_quic(headers: list[tuple[str, str]]) -> bool:
    """True se o servidor anuncia HTTP/3 (QUIC) via Alt-Svc: tráfego UDP/443."""
    return any(k.lower() == "alt-svc" and "h3" in v.lower() for k, v in headers)
