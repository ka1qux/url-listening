"""Testes unitários sem acesso à rede (rodar com `python3 -m unittest -v`)."""

from __future__ import annotations

import unittest
from pathlib import Path

from url_listening.analyzer import BLOCK, KEEP, REVIEW, Analyzer, normalize_input_url
from url_listening.config import Settings
from url_listening.domains import normalize_host, registrable_domain, split_label
from url_listening.extract import hosts_from_headers, parse_page, supports_quic
from url_listening.fetch import FetchResult
from url_listening.netinfo import (DnsInfo, EchInfo, ech_public_name, parse_https_text,
                                   parse_svcb_rdata, san_from_der)

FIXTURES = Path(__file__).parent / "fixtures"


class FakeWeb:
    """Simula a internet: mapa URL -> FetchResult e host -> IPs."""

    def __init__(self, pages: dict[str, FetchResult], dns: dict[str, list[str]] | None = None,
                 sans: dict[str, list[str]] | None = None, ech: dict[str, EchInfo] | None = None) -> None:
        self.pages, self.dns, self.san_map, self.ech_map = pages, dns or {}, sans or {}, ech or {}

    def fetch(self, url: str) -> FetchResult:
        return self.pages.get(url, FetchResult(url=url, error="connection refused"))

    def resolve(self, host: str) -> DnsInfo:
        ips = self.dns.get(host, [])
        return DnsInfo(host=host, ips=ips, resolves=bool(ips), source="fake")

    def sans(self, host: str) -> list[str]:
        return self.san_map.get(host, [])

    def ech(self, host: str) -> EchInfo:
        return self.ech_map.get(host, EchInfo(host=host, source="fake"))

    def analyzer(self, **overrides) -> Analyzer:
        settings = Settings(variant_tlds=overrides.get("tlds", ["net", "xxx"]), variant_prefixes=["m"])
        return Analyzer(settings, fetcher=self.fetch, resolver=self.resolve, san_getter=self.sans,
                        ech_checker=self.ech)


def redirect(url: str, location: str, status: int = 301) -> FetchResult:
    return FetchResult(url=url, status=status, headers=[("Location", location)])


def page(url: str, html: str, headers: list[tuple[str, str]] | None = None) -> FetchResult:
    return FetchResult(url=url, status=200, headers=headers or [], body=html)


class DomainsTests(unittest.TestCase):
    def test_registrable_domain_with_simple_tld_returns_two_labels(self) -> None:
        self.assertEqual(registrable_domain("cdn.static.site.com"), "site.com")

    def test_registrable_domain_with_multi_level_suffix_returns_three_labels(self) -> None:
        self.assertEqual(registrable_domain("www.loja.com.br"), "loja.com.br")
        self.assertEqual(split_label("www.loja.com.br"), ("loja", "com.br"))

    def test_normalize_host_with_wildcard_and_uppercase_returns_clean_host(self) -> None:
        self.assertEqual(normalize_host("*.Site.COM."), "site.com")

    def test_normalize_host_without_dot_returns_none(self) -> None:
        self.assertIsNone(normalize_host("localhost"))

    def test_normalize_input_url_without_scheme_adds_https(self) -> None:
        self.assertEqual(normalize_input_url("site.com/x"), "https://site.com/x")

    def test_normalize_input_url_with_ftp_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            normalize_input_url("ftp://site.com")


class ExtractTests(unittest.TestCase):
    def test_parse_page_with_resources_collects_hosts_and_title(self) -> None:
        html = """<html><head><title>Meu Site</title>
            <link rel="canonical" href="https://www.site.com/">
            <script src="https://cdn.site-static.net/app.js"></script>
            <style>body{background:url(//img.sitecdn.com/bg.png)}</style></head>
            <body><img srcset="https://a.site.com/1.jpg 1x, https://b.site.com/2.jpg 2x">
            <script>var api = "https://api.outro.io/v1";</script></body></html>"""
        info = parse_page(html, "https://site.com/")
        self.assertEqual(info.title, "Meu Site")
        self.assertIn("https://www.site.com/", info.identity_urls)
        for host in ("cdn.site-static.net", "img.sitecdn.com", "a.site.com", "b.site.com", "api.outro.io"):
            self.assertIn(host, info.resource_hosts)

    def test_parse_page_with_meta_refresh_returns_target(self) -> None:
        info = parse_page('<meta http-equiv="refresh" content="0; url=https://destino.com/">', "https://a.com/")
        self.assertEqual(info.meta_refresh, "https://destino.com/")

    def test_parse_page_with_js_redirect_in_small_page_returns_target(self) -> None:
        info = parse_page('<script>window.location.href = "https://destino.com/x";</script>', "https://a.com/")
        self.assertEqual(info.js_redirect, "https://destino.com/x")

    def test_parse_page_with_broken_html_does_not_raise(self) -> None:
        info = parse_page("<html><<<script src='https://x.com/a.js'><title>", "https://a.com/")
        self.assertIn("x.com", info.resource_hosts)

    def test_hosts_from_headers_reads_csp_cookie_and_link(self) -> None:
        headers = [
            ("Content-Security-Policy", "default-src 'self' https://*.cdn-site.com media.site.net; script-src 'nonce-abc'"),
            ("Set-Cookie", "sid=1; Domain=.site.com; Path=/"),
            ("Link", "<https://static.site.org/style.css>; rel=preload"),
        ]
        hosts = hosts_from_headers(headers, "https://site.com/")
        self.assertTrue({"cdn-site.com", "media.site.net", "site.com", "static.site.org"} <= hosts)

    def test_supports_quic_with_h3_alt_svc_returns_true(self) -> None:
        self.assertTrue(supports_quic([("alt-svc", 'h3=":443"; ma=86400')]))
        self.assertFalse(supports_quic([("server", "nginx")]))


class CertTests(unittest.TestCase):
    def test_san_from_der_with_real_certificate_returns_dns_names(self) -> None:
        names = san_from_der((FIXTURES / "cert_san.der").read_bytes())
        self.assertEqual(names, ["site-teste.com", "*.site-teste.com", "site-teste-cdn.net"])

    def test_san_from_der_without_extension_returns_empty(self) -> None:
        self.assertEqual(san_from_der(b"\x30\x03\x02\x01\x00"), [])


class ChainTests(unittest.TestCase):
    def test_follow_chain_through_http_meta_and_js_reaches_final(self) -> None:
        web = FakeWeb({
            "https://curto.ly/abc": redirect("https://curto.ly/abc", "https://track.ads.com/r?x=1", 302),
            "https://track.ads.com/r?x=1": page("https://track.ads.com/r?x=1", '<meta http-equiv="refresh" content="0;url=https://ponte.net/">'),
            "https://ponte.net/": page("https://ponte.net/", '<script>location.replace("https://www.site.com/")</script>'),
            "https://www.site.com/": page("https://www.site.com/", "<title>Site</title>"),
        })
        chain = web.analyzer().follow_chain("https://curto.ly/abc")
        self.assertEqual([h.kind for h in chain.hops], ["http", "meta", "js", "final"])
        self.assertEqual(chain.hops[-1].host, "www.site.com")

    def test_follow_chain_with_loop_stops_and_reports_loop(self) -> None:
        web = FakeWeb({
            "https://a.com/": redirect("https://a.com/", "https://b.com/"),
            "https://b.com/": redirect("https://b.com/", "https://a.com/"),
        })
        chain = web.analyzer().follow_chain("https://a.com/")
        self.assertEqual(chain.hops[-1].kind, "loop")

    def test_follow_chain_with_connection_error_reports_error(self) -> None:
        chain = FakeWeb({}).analyzer().follow_chain("https://fora.com/")
        self.assertEqual(chain.hops[-1].kind, "erro")
        self.assertEqual(chain.hops[-1].error, "connection refused")


class AnalyzeTests(unittest.TestCase):
    def setUp(self) -> None:
        html = """<html><head><title>Site Adulto</title>
            <link rel="alternate" hreflang="pt" href="https://pt.siteadulto.org/">
            <script src="https://www.googletagmanager.com/gtm.js"></script>
            <script src="https://cdn.siteadulto-static.com/app.js"></script>
            <img src="https://img.siteadulto.com/a.jpg"><img src="https://ads.parceiro.net/b.gif">
            <script src="https://cdnx.neutro.io/x.js"></script></head></html>"""
        self.web = FakeWeb(
            pages={
                "https://siteadulto.com": redirect("https://siteadulto.com", "https://www.siteadulto.com/"),
                "https://www.siteadulto.com/": page("https://www.siteadulto.com/", html, [("alt-svc", 'h3=":443"')]),
                "https://siteadulto.net/": redirect("https://siteadulto.net/", "https://www.siteadulto.com/"),
                "https://siteadulto.xxx/": page("https://siteadulto.xxx/", "<title>Outro negocio</title>"),
            },
            dns={
                "siteadulto.net": ["1.1.1.10"], "siteadulto.xxx": ["2.2.2.2"], "m.siteadulto.com": ["1.1.1.11"],
                "siteadulto.com": ["1.1.1.1"], "www.siteadulto.com": ["1.1.1.1"], "cdnx.neutro.io": ["3.3.3.3"],
            },
            sans={"www.siteadulto.com": ["siteadulto.com", "*.siteadulto.com", "sa-videos.com"]},
        )
        # CNAME de um recurso "neutro" apontando para o site deve virar bloqueio.
        original = self.web.resolve
        self.web.resolve = lambda host: (
            DnsInfo(host, cnames=["edge.siteadulto.com"], ips=["3.3.3.3"], resolves=True)
            if host == "cdnx.neutro.io" else original(host)
        )
        self.report = self.web.analyzer().analyze("https://siteadulto.com")
        self.verdicts = {d.host: d.verdict for d in self.report.domains}

    def test_analyze_blocks_chain_cert_identity_and_own_cdn(self) -> None:
        for host in ("siteadulto.com", "www.siteadulto.com", "sa-videos.com", "pt.siteadulto.org",
                     "cdn.siteadulto-static.com", "img.siteadulto.com"):
            self.assertEqual(self.verdicts[host], BLOCK, host)

    def test_analyze_never_blocks_shared_providers(self) -> None:
        self.assertEqual(self.verdicts["www.googletagmanager.com"], KEEP)
        self.assertNotIn("googletagmanager.com", self.report.blocklist)

    def test_analyze_marks_unknown_third_party_for_review(self) -> None:
        self.assertEqual(self.verdicts["ads.parceiro.net"], REVIEW)

    def test_analyze_promotes_resource_with_cname_to_site(self) -> None:
        self.assertEqual(self.verdicts["cdnx.neutro.io"], BLOCK)

    def test_analyze_confirms_mirror_and_flags_unconfirmed_variant(self) -> None:
        self.assertEqual(self.verdicts["siteadulto.net"], BLOCK)
        self.assertEqual(self.verdicts["m.siteadulto.com"], BLOCK)
        self.assertEqual(self.verdicts["siteadulto.xxx"], REVIEW)

    def test_analyze_builds_blocklist_and_quic_warning(self) -> None:
        self.assertIn("siteadulto.com", self.report.blocklist)
        self.assertIn("*.siteadulto.net", self.report.blocklist_wildcard)
        self.assertIn("1.1.1.1", self.report.ips)
        self.assertTrue(self.report.quic)
        self.assertTrue(any("QUIC" in w for w in self.report.warnings))

    def test_analyze_with_unreachable_site_warns_about_webfilter(self) -> None:
        report = FakeWeb({}).analyzer().analyze("bloqueado.com", check_variants=False)
        self.assertEqual(report.hops[-1].kind, "erro")
        self.assertTrue(any("webfilter" in w for w in report.warnings))
        self.assertEqual(report.blocklist, ["bloqueado.com"])



# Registro HTTPS real publicado por um site atrás da Cloudflare (out/2026).
REAL_HTTPS_RR = ("1 . alpn=h3,h2 ipv4hint=104.21.11.64,172.67.165.81 "
                 "ech=AEX+DQBBbAAgACAGihtqXvTQKbnrGUBRIhdGB2l7hlwiUXHLKOIjM95McQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA= "
                 "ipv6hint=2606:4700::1")


class EchTests(unittest.TestCase):
    def test_parse_https_text_with_real_record_returns_alpn_and_public_name(self) -> None:
        alpn, ech = parse_https_text(REAL_HTTPS_RR)
        self.assertEqual(alpn, ["h3", "h2"])
        self.assertEqual(ech_public_name(ech), "cloudflare-ech.com")

    def test_parse_https_text_without_ech_returns_none(self) -> None:
        alpn, ech = parse_https_text("1 . alpn=h2 ipv4hint=1.2.3.4")
        self.assertEqual(alpn, ["h2"])
        self.assertIsNone(ech)

    def test_parse_svcb_rdata_binary_matches_text_format(self) -> None:
        _, ech = parse_https_text(REAL_HTTPS_RR)
        alpn_value = b"\x02h3\x02h2"
        rdata = (b"\x00\x01" + b"\x00"
                 + (1).to_bytes(2, "big") + len(alpn_value).to_bytes(2, "big") + alpn_value
                 + (5).to_bytes(2, "big") + len(ech).to_bytes(2, "big") + ech)
        self.assertEqual(parse_svcb_rdata(rdata), (["h3", "h2"], ech))
        generic = "\\# %d %s" % (len(rdata), rdata.hex())
        self.assertEqual(parse_https_text(generic), (["h3", "h2"], ech))

    def test_ech_public_name_with_garbage_returns_none(self) -> None:
        self.assertIsNone(ech_public_name(b"\x00\x10\xfe\x0d\x00\x40\x01"))

    def test_analyze_with_ech_warns_flags_domain_and_keeps_public_name(self) -> None:
        web = FakeWeb(
            pages={"https://adulto.com": page("https://adulto.com", "<title>X</title>")},
            dns={"adulto.com": ["104.21.11.64"]},
            ech={"adulto.com": EchInfo("adulto.com", "cloudflare-ech.com", ["h3", "h2"], "doh")},
        )
        report = web.analyzer().analyze("adulto.com", check_variants=False)
        verdicts = {d.host: d for d in report.domains}
        self.assertEqual(verdicts["adulto.com"].ech, "cloudflare-ech.com")
        self.assertEqual(verdicts["cloudflare-ech.com"].verdict, KEEP)
        self.assertNotIn("cloudflare-ech.com", report.blocklist)
        self.assertEqual(report.ech[0]["public_name"], "cloudflare-ech.com")
        self.assertTrue(report.quic)  # alpn h3 no registro HTTPS
        self.assertTrue(any(w.startswith("ECH ativo em adulto.com") for w in report.warnings))

    def test_analyze_when_ech_lookup_fails_warns_unverified(self) -> None:
        web = FakeWeb(pages={"https://a.com": page("https://a.com", "ok")})
        web.ech = lambda host: EchInfo(host=host, source="")
        report = web.analyzer().analyze("a.com", check_variants=False)
        self.assertFalse(report.ech_checked)
        self.assertTrue(any("Não foi possível verificar ECH" in w for w in report.warnings))


if __name__ == "__main__":
    unittest.main()
