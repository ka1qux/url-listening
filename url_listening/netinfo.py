"""Consultas de rede auxiliares: DNS (CNAME/A/AAAA/HTTPS), ECH e SANs do certificado TLS."""

from __future__ import annotations

import base64
import json
import logging
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .config import Settings
from .domains import normalize_host

log = logging.getLogger(__name__)

SAN_OID = bytes.fromhex("0603551d11")  # OID 2.5.29.17 (subjectAltName)


@dataclass
class DnsInfo:
    host: str
    cnames: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    resolves: bool = False
    source: str = ""


def _doh_query(name: str, rtype: str, settings: Settings) -> list[dict]:
    url = f"{settings.doh_url}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=settings.timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("Answer", []) or []


def resolve(host: str, settings: Settings) -> DnsInfo:
    """Resolve CNAMEs e IPs via DoH; se o DoH estiver bloqueado, usa o resolvedor do SO."""
    info = DnsInfo(host=host)
    try:
        for rtype in ("A", "AAAA"):
            for answer in _doh_query(host, rtype, settings):
                data = str(answer.get("data", "")).rstrip(".")
                if answer.get("type") == 5:
                    cname = normalize_host(data)
                    if cname and cname not in info.cnames:
                        info.cnames.append(cname)
                elif answer.get("type") in (1, 28) and data not in info.ips:
                    info.ips.append(data)
        info.source = "doh"
    except (urllib.error.URLError, TimeoutError, socket.timeout, json.JSONDecodeError, OSError) as exc:
        log.debug("DoH falhou para %s (%s); usando resolvedor do sistema", host, exc)
        try:
            for *_, sockaddr in socket.getaddrinfo(host, None):
                if sockaddr[0] not in info.ips:
                    info.ips.append(sockaddr[0])
            info.source = "system"
        except (socket.gaierror, UnicodeError, OSError):
            info.source = "system"
    info.resolves = bool(info.ips)
    return info


def _der_length(data: bytes, pos: int) -> tuple[int, int]:
    """Lê um campo de comprimento DER; devolve (comprimento, posição do conteúdo)."""
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    count = first & 0x7F
    return int.from_bytes(data[pos + 1 : pos + 1 + count], "big"), pos + 1 + count


def san_from_der(der: bytes) -> list[str]:
    """Extrai os dNSName do subjectAltName de um certificado DER, sem libs externas."""
    idx = der.find(SAN_OID)
    if idx < 0:
        return []
    pos = idx + len(SAN_OID)
    if der[pos] == 0x01:  # BOOLEAN "critical" opcional
        length, content = _der_length(der, pos + 1)
        pos = content + length
    if der[pos] != 0x04:  # OCTET STRING
        return []
    _, pos = _der_length(der, pos + 1)
    if der[pos] != 0x30:  # SEQUENCE OF GeneralName
        return []
    seq_len, pos = _der_length(der, pos + 1)
    end = pos + seq_len
    names: list[str] = []
    while pos < end:
        tag = der[pos]
        length, content = _der_length(der, pos + 1)
        if tag == 0x82:  # [2] dNSName
            names.append(der[content : content + length].decode("ascii", errors="replace").lower())
        pos = content + length
    return names


def cert_sans(host: str, settings: Settings, port: int = 443) -> list[str]:
    """Conecta em host:443 e devolve os nomes do certificado (inclui curingas)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # queremos o certificado mesmo se inválido
    try:
        with socket.create_connection((host, port), timeout=settings.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, UnicodeError) as exc:
        log.debug("TLS falhou para %s: %s", host, exc)
        return []
    return san_from_der(der) if der else []


# ---------------------------------------------------------------------------
# ECH (Encrypted Client Hello)
#
# O site publica no DNS um registro HTTPS (tipo 65, formato SVCB) com a chave
# ECH. Com ele o navegador criptografa o nome real e o firewall só enxerga o
# "nome público" da configuração (na Cloudflare, cloudflare-ech.com).
# ---------------------------------------------------------------------------

HTTPS_RR = 65
SVCB_ALPN = 1
SVCB_ECH = 5
ECH_VERSION = 0xFE0D


@dataclass
class EchInfo:
    host: str
    public_name: str | None = None  # nome que o firewall vê no handshake
    alpn: list[str] = field(default_factory=list)
    source: str = ""  # "doh", "dns" ou "" (não foi possível verificar)

    @property
    def enabled(self) -> bool:
        return self.public_name is not None


def ech_public_name(config: bytes) -> str | None:
    """Extrai o public_name do primeiro ECHConfig (versão 0xfe0d) de um ECHConfigList."""
    try:
        end = 2 + int.from_bytes(config[0:2], "big")
        pos = 2
        while pos + 4 <= min(end, len(config)):
            version = int.from_bytes(config[pos : pos + 2], "big")
            length = int.from_bytes(config[pos + 2 : pos + 4], "big")
            body, pos = config[pos + 4 : pos + 4 + length], pos + 4 + length
            if version != ECH_VERSION:
                continue
            # HpkeKeyConfig: config_id(1) kem_id(2) public_key<2> cipher_suites<2>
            i = 3
            i += 2 + int.from_bytes(body[i : i + 2], "big")
            i += 2 + int.from_bytes(body[i : i + 2], "big")
            i += 1  # maximum_name_length
            name_len = body[i]
            name = body[i + 1 : i + 1 + name_len].decode("ascii")
            return normalize_host(name) or name.lower()
    except (IndexError, UnicodeDecodeError):
        log.debug("ECHConfigList malformado")
    return None


def _skip_name(msg: bytes, pos: int) -> int:
    """Avança sobre um nome DNS (com ou sem ponteiro de compressão)."""
    while True:
        length = msg[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += length + 1


def parse_svcb_rdata(rdata: bytes) -> tuple[list[str], bytes | None]:
    """Lê ALPN e ECH do RDATA binário de um registro HTTPS/SVCB."""
    alpn: list[str] = []
    ech: bytes | None = None
    try:
        pos = _skip_name(rdata, 2)  # SvcPriority(2) + TargetName
        while pos + 4 <= len(rdata):
            key = int.from_bytes(rdata[pos : pos + 2], "big")
            length = int.from_bytes(rdata[pos + 2 : pos + 4], "big")
            value, pos = rdata[pos + 4 : pos + 4 + length], pos + 4 + length
            if key == SVCB_ALPN:
                i = 0
                while i < len(value):
                    alpn.append(value[i + 1 : i + 1 + value[i]].decode("ascii", errors="replace"))
                    i += 1 + value[i]
            elif key == SVCB_ECH:
                ech = value
    except IndexError:
        log.debug("RDATA SVCB malformado")
    return alpn, ech


def parse_https_text(data: str) -> tuple[list[str], bytes | None]:
    """Lê ALPN e ECH de um registro HTTPS em texto (DoH JSON) ou no formato genérico '\\# len hex'."""
    data = data.strip()
    if data.startswith("\\#"):
        parts = data.split(maxsplit=2)
        try:
            return parse_svcb_rdata(bytes.fromhex(parts[2].replace(" ", "")))
        except (IndexError, ValueError):
            return [], None
    alpn: list[str] = []
    ech: bytes | None = None
    for token in data.split():
        key, _, value = token.partition("=")
        value = value.strip('"')
        if key == "alpn":
            alpn = [a for a in value.split(",") if a]
        elif key == "ech":
            try:
                ech = base64.b64decode(value + "=" * (-len(value) % 4))
            except ValueError:
                ech = None
    return alpn, ech


def _system_dns_server(settings: Settings) -> str | None:
    if settings.dns_server:
        return settings.dns_server
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        pass
    return None


def _dns_query_udp(name: str, qtype: int, server: str, timeout: float) -> list[bytes]:
    """Consulta DNS mínima por UDP; devolve o RDATA das respostas do tipo pedido."""
    tid = secrets.token_bytes(2)
    qname = b"".join(len(label).to_bytes(1, "big") + label.encode("idna") for label in name.rstrip(".").split("."))
    packet = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        msg = sock.recv(4096)
    if msg[:2] != tid:
        raise OSError("resposta DNS com ID diferente")
    answers = int.from_bytes(msg[6:8], "big")
    pos = _skip_name(msg, 12) + 4
    out: list[bytes] = []
    for _ in range(answers):
        pos = _skip_name(msg, pos)
        rtype = int.from_bytes(msg[pos : pos + 2], "big")
        rdlen = int.from_bytes(msg[pos + 8 : pos + 10], "big")
        rdata = msg[pos + 10 : pos + 10 + rdlen]
        pos += 10 + rdlen
        if rtype == qtype:
            out.append(rdata)
    return out


def ech_info(host: str, settings: Settings) -> EchInfo:
    """Verifica se o host publica ECH. Tenta DoH e, se estiver bloqueado, o DNS da rede."""
    info = EchInfo(host=host)
    records: list[tuple[list[str], bytes | None]] = []
    try:
        records = [parse_https_text(str(a.get("data", ""))) for a in _doh_query(host, "HTTPS", settings) if a.get("type") == HTTPS_RR]
        info.source = "doh"
    except (urllib.error.URLError, TimeoutError, socket.timeout, json.JSONDecodeError, OSError) as exc:
        server = _system_dns_server(settings)
        log.debug("DoH (HTTPS RR) falhou para %s (%s); DNS da rede: %s", host, exc, server)
        if server:
            try:
                records = [parse_svcb_rdata(r) for r in _dns_query_udp(host, HTTPS_RR, server, settings.timeout)]
                info.source = "dns"
            except (OSError, IndexError, UnicodeError) as udp_exc:
                log.debug("consulta HTTPS RR por UDP falhou para %s: %s", host, udp_exc)
    for alpn, ech in records:
        info.alpn = info.alpn or alpn
        if ech and info.public_name is None:
            info.public_name = ech_public_name(ech)
    return info
