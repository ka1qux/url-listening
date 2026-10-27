"""Orquestra a análise: cadeia de redirecionamento, domínios relacionados e variantes."""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from . import netinfo
from .config import Settings
from .domains import host_from_url, is_ip, matches_any, registrable_domain, split_label
from .extract import PageInfo, hosts_from_headers, parse_page, supports_quic
from .fetch import FetchResult, fetch

log = logging.getLogger(__name__)

BLOCK = "bloquear"
REVIEW = "revisar"
KEEP = "nao_bloquear"

# Certificado com muitos domínios distintos é de hospedagem/CDN compartilhada.
SHARED_CERT_THRESHOLD = 25
MIN_LABEL_TOKEN = 4

Fetcher = Callable[[str], FetchResult]
Resolver = Callable[[str], netinfo.DnsInfo]
SanGetter = Callable[[str], list[str]]
EchChecker = Callable[[str], netinfo.EchInfo]

# Limite de hosts consultados para ECH (cadeia + domínios a bloquear).
MAX_ECH_CHECKS = 40


@dataclass
class Hop:
    url: str
    host: str | None
    status: int | None
    kind: str  # http | meta | js | final | erro | loop
    error: str | None = None


@dataclass
class DomainEntry:
    host: str
    registrable: str
    verdict: str
    sources: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    ech: str | None = None  # nome público do ECH (o que o firewall vê), se ativo


@dataclass
class Report:
    input_url: str
    final_url: str | None
    title: str
    quic: bool
    hops: list[Hop]
    domains: list[DomainEntry]
    blocklist: list[str]
    blocklist_wildcard: list[str]
    blocklist_hosts: list[str]
    ips: list[str]
    warnings: list[str]
    ech: list[dict] = field(default_factory=list)
    ech_checked: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChainResult:
    hops: list[Hop]
    page: PageInfo
    header_hosts: set[str]
    quic: bool


def normalize_input_url(url: str) -> str:
    """Garante esquema http(s); aceita entrada como 'site.com/caminho'."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"URL inválida: {url!r}")
    return url


class Analyzer:
    """Analisa uma URL e monta a lista de domínios para o objeto de bloqueio.

    As funções de rede são injetáveis para permitir testes sem internet.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        fetcher: Fetcher | None = None,
        resolver: Resolver | None = None,
        san_getter: SanGetter | None = None,
        ech_checker: EchChecker | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.fetch = fetcher or (lambda url: fetch(url, self.settings))
        self.resolve = resolver or (lambda host: netinfo.resolve(host, self.settings))
        self.sans = san_getter or (lambda host: netinfo.cert_sans(host, self.settings))
        self.ech_check = ech_checker or (lambda host: netinfo.ech_info(host, self.settings))
        self.shared = set(self.settings.shared_providers)

    # ------------------------------------------------------------------ cadeia
    def follow_chain(self, url: str, max_hops: int | None = None) -> ChainResult:
        """Segue redirecionamentos HTTP 3xx, meta refresh e JS, registrando cada salto."""
        hops: list[Hop] = []
        header_hosts: set[str] = set()
        page = PageInfo()
        quic = False
        seen: set[str] = set()
        current = url
        for _ in range(max_hops or self.settings.max_hops):
            host = host_from_url(current)
            if current in seen:
                hops.append(Hop(current, host, None, "loop", "redirecionamento em loop"))
                break
            seen.add(current)
            res = self.fetch(current)
            if res.error:
                hops.append(Hop(current, host, res.status, "erro", res.error))
                break
            header_hosts |= hosts_from_headers(res.headers, current)
            quic = quic or supports_quic(res.headers)
            location = res.header("location")
            if res.status and 300 <= res.status < 400 and location:
                hops.append(Hop(current, host, res.status, "http"))
                current = urljoin(current, location.strip())
                continue
            page = parse_page(res.body, current)
            next_url = page.meta_refresh or page.js_redirect
            if next_url and next_url != current and host_from_url(next_url):
                kind = "meta" if page.meta_refresh else "js"
                hops.append(Hop(current, host, res.status, kind))
                current = next_url
                continue
            hops.append(Hop(current, host, res.status, "final"))
            break
        else:
            hops.append(Hop(current, host_from_url(current), None, "erro", "limite de saltos atingido"))
        return ChainResult(hops, page, header_hosts, quic)

    # --------------------------------------------------------------- análise
    def analyze(self, url: str, check_variants: bool = True) -> Report:
        url = normalize_input_url(url)
        warnings: list[str] = []
        entries: dict[str, DomainEntry] = {}

        def add(host: str, verdict: str, source: str, reason: str) -> None:
            entry = entries.get(host)
            if entry is None:
                entries[host] = DomainEntry(host, registrable_domain(host), verdict, [source], [reason])
                return
            if source not in entry.sources:
                entry.sources.append(source)
            if reason not in entry.reasons:
                entry.reasons.append(reason)
            # Um veredito mais forte sempre prevalece (bloquear > revisar > manter).
            rank = {KEEP: 0, REVIEW: 1, BLOCK: 2}
            if rank[verdict] > rank[entry.verdict]:
                entry.verdict = verdict

        chain = self.follow_chain(url)
        chain_hosts = [h.host for h in chain.hops if h.host]
        site_roots: set[str] = set()
        for host in chain_hosts:
            if self._is_shared(host):
                add(host, KEEP, "cadeia", "redirecionador/provedor compartilhado")
            else:
                add(host, BLOCK, "cadeia", "faz parte da cadeia de redirecionamento")
                site_roots.add(registrable_domain(host))
        if chain.hops and chain.hops[-1].kind == "erro":
            warnings.append(
                f"Falha em {chain.hops[-1].url}: {chain.hops[-1].error}. Se a análise roda atrás "
                "do webfilter, a página de bloqueio ou o reset de conexão interrompe a cadeia; "
                "rode em uma rede sem filtro ou libere o IP desta máquina."
            )

        # Espelhos (.net, .xxx...) são testados só para o site principal; testar cada
        # domínio do certificado multiplicaria as consultas sem ganho real.
        primary_roots = set(site_roots)
        self._add_cert_names(chain_hosts, site_roots, add, warnings)

        for identity_url in chain.page.identity_urls:
            host = host_from_url(identity_url)
            if host and not self._is_shared(host):
                add(host, BLOCK, "identidade", "canonical/og:url/hreflang do próprio site")
                site_roots.add(registrable_domain(host))

        labels = {split_label(root)[0] for root in site_roots if not is_ip(root)}
        for host in chain.page.resource_hosts | chain.header_hosts:
            verdict, reason = self._classify_resource(host, site_roots, labels)
            add(host, verdict, "recurso", reason)

        if check_variants and primary_roots:
            self._check_variants(primary_roots, site_roots, chain.page.title, entries, add)

        self._enrich_dns(entries, site_roots, add)
        ech_infos = self._check_ech(chain_hosts, entries, add, warnings)
        quic = chain.quic or any("h3" in info.alpn for info in ech_infos)

        if quic:
            warnings.append(
                "O site anuncia HTTP/3 (QUIC, UDP/443). Se o webfilter não inspeciona QUIC, "
                "bloqueie UDP/443 na política para forçar o navegador a usar TCP."
            )

        final = next((h.url for h in reversed(chain.hops) if h.kind == "final"), None)
        report = self._build_report(url, final, chain, entries, warnings)
        report.quic = quic
        report.ech = [
            {"host": i.host, "public_name": i.public_name, "alpn": i.alpn, "source": i.source}
            for i in ech_infos if i.enabled
        ]
        report.ech_checked = any(i.source for i in ech_infos) or not ech_infos
        return report

    # --------------------------------------------------------------- etapas
    def _is_shared(self, host: str) -> bool:
        return matches_any(host, self.shared)

    def _classify_resource(self, host: str, roots: set[str], labels: set[str]) -> tuple[str, str]:
        if matches_any(host, roots):
            return BLOCK, "subdomínio do próprio site"
        if self._is_shared(host):
            return KEEP, "provedor compartilhado (bloquear quebraria outros sites)"
        if any(len(label) >= MIN_LABEL_TOKEN and label in host for label in labels):
            return BLOCK, "contém o nome do site (CDN/infra própria)"
        return REVIEW, "domínio de terceiro carregado pela página"

    def _add_cert_names(self, hosts: list[str], roots: set[str], add, warnings: list[str]) -> None:
        targets = sorted({h for h in hosts if not self._is_shared(h) and not is_ip(h)})
        with ThreadPoolExecutor(self.settings.workers) as pool:
            results = dict(zip(targets, pool.map(self.sans, targets)))
        for host, names in results.items():
            registrables = {registrable_domain(n.lstrip("*.")) for n in names}
            shared_cert = len(registrables) > SHARED_CERT_THRESHOLD
            if shared_cert:
                warnings.append(
                    f"Certificado de {host} cobre {len(registrables)} domínios distintos "
                    "(hospedagem compartilhada): itens marcados como revisar."
                )
            for name in names:
                cert_host = name[2:] if name.startswith("*.") else name
                if not cert_host or "." not in cert_host or self._is_shared(cert_host):
                    continue
                if shared_cert:
                    add(cert_host, REVIEW, "certificado", f"SAN do certificado compartilhado de {host}")
                else:
                    add(cert_host, BLOCK, "certificado", f"nome alternativo no certificado TLS de {host}")
                    roots.add(registrable_domain(cert_host))

    def _check_variants(self, primary: set[str], roots: set[str], title: str, entries, add) -> None:
        candidates: set[str] = set()
        for root in primary:
            label, _ = split_label(root)
            candidates |= {f"{label}.{tld}" for tld in self.settings.variant_tlds}
            candidates |= {f"{prefix}.{root}" for prefix in self.settings.variant_prefixes}
        ordered = sorted(c for c in candidates if c not in entries and not self._is_shared(c))

        with ThreadPoolExecutor(self.settings.workers) as pool:
            dns = dict(zip(ordered, pool.map(self.resolve, ordered)))
        alive = sorted(host for host, info in dns.items() if info.resolves)

        subdomains = [h for h in alive if matches_any(h, roots)]
        for host in subdomains:
            add(host, BLOCK, "variante", "subdomínio comum do site que resolve no DNS")

        mirrors = [h for h in alive if h not in subdomains]
        with ThreadPoolExecutor(self.settings.workers) as pool:
            chains = dict(zip(mirrors, pool.map(lambda h: self.follow_chain(f"https://{h}/", 6), mirrors)))
        for host, chain in chains.items():
            reached = {registrable_domain(h.host) for h in chain.hops if h.host}
            same_title = bool(title) and chain.page.title.strip().lower() == title.strip().lower()
            if reached & roots:
                add(host, BLOCK, "variante", "domínio espelho que redireciona para o site")
            elif same_title:
                add(host, BLOCK, "variante", "domínio espelho com o mesmo título do site")
            else:
                add(host, REVIEW, "variante", "domínio com o mesmo nome existe, sem vínculo confirmado")
            for hop in chain.hops:
                if hop.host and hop.host != host and (reached & roots) and not self._is_shared(hop.host):
                    add(hop.host, BLOCK, "variante", f"cadeia de redirecionamento de {host}")

    def _enrich_dns(self, entries: dict[str, DomainEntry], roots: set[str], add) -> None:
        targets = sorted(h for h, e in entries.items() if e.verdict != KEEP and not is_ip(h))
        with ThreadPoolExecutor(self.settings.workers) as pool:
            infos = dict(zip(targets, pool.map(self.resolve, targets)))
        for host, info in infos.items():
            entry = entries[host]
            entry.ips, entry.cnames = info.ips, info.cnames
            # Recurso de terceiro cujo CNAME aponta para o site é infraestrutura do site.
            if entry.verdict == REVIEW and any(matches_any(c, roots) for c in info.cnames):
                add(host, BLOCK, "dns", "CNAME aponta para o domínio do site")
        for host, entry in entries.items():
            if is_ip(host):
                entry.ips = [host]

    def _check_ech(self, chain_hosts: list[str], entries: dict[str, DomainEntry], add, warnings: list[str]) -> list[netinfo.EchInfo]:
        """Detecta ECH: com ele o webfilter não vê o nome do site, só o nome público da CDN."""
        targets = [h for h in dict.fromkeys(chain_hosts) if not self._is_shared(h) and not is_ip(h)]
        targets += sorted({e.registrable for e in entries.values() if e.verdict == BLOCK and not is_ip(e.host)} - set(targets))
        targets = targets[:MAX_ECH_CHECKS]
        with ThreadPoolExecutor(self.settings.workers) as pool:
            infos = list(pool.map(self.ech_check, targets))

        enabled = [i for i in infos if i.enabled]
        for info in enabled:
            if info.host in entries:
                entries[info.host].ech = info.public_name
        for public in sorted({i.public_name for i in enabled if i.public_name}):
            add(public, KEEP, "ech",
                "nome público do ECH: compartilhado por todos os sites da CDN; bloquear derruba outros sites")
        if enabled:
            hosts = ", ".join(i.host for i in enabled[:5]) + (" ..." if len(enabled) > 5 else "")
            publics = ", ".join(sorted({i.public_name for i in enabled if i.public_name}))
            warnings.append(
                f"ECH ativo em {hosts}: o navegador criptografa o nome do site e o webfilter só vê "
                f"'{publics}', por isso o bloqueio por nome não funciona. Desative o ECH por política "
                "nos navegadores (Chrome/Edge: EncryptedClientHelloEnabled=false; Firefox: "
                "network.dns.echconfig.enabled=false), obrigue o uso do DNS da rede bloqueando DoH e "
                "DoT (TCP/853), bloqueie o domínio também no filtro DNS e bloqueie UDP/443 (QUIC)."
            )
        elif infos and not any(i.source for i in infos):
            warnings.append(
                "Não foi possível verificar ECH: a consulta DNS do registro HTTPS falhou (DoH e DNS "
                "da rede). Defina URL_LISTENING_DNS_SERVER com um DNS acessível e analise de novo."
            )
        return infos

    def _build_report(self, url, final, chain: ChainResult, entries, warnings) -> Report:
        order = {BLOCK: 0, REVIEW: 1, KEEP: 2}
        domains = sorted(entries.values(), key=lambda e: (order[e.verdict], e.registrable, e.host))
        blocked = [e for e in domains if e.verdict == BLOCK]
        registrables = sorted({e.registrable for e in blocked if not is_ip(e.host)})
        return Report(
            input_url=url,
            final_url=final,
            title=chain.page.title,
            quic=chain.quic,
            hops=chain.hops,
            domains=domains,
            blocklist=registrables,
            blocklist_wildcard=[f"*.{d}" for d in registrables],
            blocklist_hosts=sorted({e.host for e in blocked}),
            ips=sorted({ip for e in blocked for ip in e.ips}),
            warnings=warnings,
        )
