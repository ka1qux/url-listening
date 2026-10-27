# URL Listening

Ferramenta para mapear **todos os domínios por trás de um site** e montar o objeto de
bloqueio do webfilter. Informe uma URL e ela devolve a cadeia de redirecionamento até o
site principal, os domínios espelho, as CDNs próprias e os IPs, já classificados.

Usa só a biblioteca padrão do Python 3.10+: não precisa instalar nada.

## Instalação

Os instaladores ficam em `dist/` (gerados por `packaging/build.sh`).

| Sistema | Arquivo | Como instalar |
|---|---|---|
| Windows 10/11 (64 bits) | `URLListening_<versão>_Setup.exe` | Duplo clique. Cria atalho no Menu Iniciar e na Área de Trabalho. Desinstala pelo Painel de Controle. |
| Windows sem instalar | `URLListening_<versão>_windows_portable.zip` | Extraia e abra `Abrir URL Listening.cmd`. |
| Ubuntu / Debian | `url-listening_<versão>_amd64.deb` | `sudo apt install ./url-listening_<versão>_amd64.deb` |
| RHEL / Rocky / Fedora | `url-listening-<versão>-1.x86_64.rpm` | `sudo dnf install ./url-listening-<versão>-1.x86_64.rpm` |
| Outro Linux | `url-listening_<versão>_linux_x86_64.tar.gz` | Extraia e rode `url-listening/url-listening` |

Ao abrir, o aplicativo sobe a interface e abre o navegador padrão. Ele encerra pelo botão
**Encerrar** ou sozinho, 3 minutos depois que a aba é fechada. Abrir de novo com o app já
aberto apenas reabre a aba.

Linha de comando no app instalado:
- Linux: `url-listening analyze site.com -o lista.txt`
- Windows: `"C:\Program Files\URL Listening\url-listening.cmd" analyze site.com -o lista.txt`

### Gerar os instaladores

Requer `podman` (ou `docker`), `dpkg-deb`, `rpmbuild`, `curl`, `unzip` e `zip` em uma máquina Linux:

```bash
packaging/build.sh            # tudo
packaging/build.sh linux      # .deb, .rpm, .tar.gz (PyInstaller em container com glibc 2.31)
packaging/build.sh windows    # Setup.exe e .zip (Python embutido oficial + NSIS)
```

A versão vem de `url_listening/__init__.py`. No Windows o app usa o Python embutido oficial
da python.org em vez de um executável PyInstaller, que costuma ser barrado por antivírus corporativo.

## Uso a partir do código-fonte

```bash
cd url_listening

# Interface web (abre em http://127.0.0.1:8765)
python3 -m url_listening serve

# Linha de comando
python3 -m url_listening analyze site.com
python3 -m url_listening analyze site1.com https://encurtador.ly/abc -o lista.txt
python3 -m url_listening analyze site.com -o relatorio.csv     # ou .json
python3 -m url_listening analyze site.com --no-variants        # mais rápido, sem testar espelhos
```

Na interface: marque/desmarque domínios na tabela, escolha o formato (domínio, `*.domínio`,
host exato ou IP), e use **acumular análises** para juntar vários sites num único objeto.

> **Importante:** rode a análise de uma máquina **liberada no webfilter** (ou fora dele).
> Atrás do filtro, a página de bloqueio interrompe a cadeia e a lista sai incompleta.

## O que a ferramenta verifica

| Fonte | O que encontra |
|---|---|
| Cadeia de redirecionamento | Cada salto HTTP 3xx, `meta refresh` e `location=` em JS (encurtadores, rastreadores, domínios ponte) |
| Certificado TLS (SAN) | Outros domínios do mesmo dono no mesmo certificado |
| HTML da página | `canonical`, `og:url`, `hreflang` (versões por idioma), scripts, imagens, vídeos, CSS |
| Headers HTTP | `Content-Security-Policy`, `Link`, `Set-Cookie domain=`, `Alt-Svc` (QUIC) |
| Espelhos | `nome.net`, `nome.xxx`, `nome.com.br`... e `m.`, `www.`, `pt.`: só confirma os que redirecionam para o site ou têm o mesmo título |
| DNS | CNAMEs e IPs; recurso de terceiro com CNAME para o site vira bloqueio |
| ECH (registro DNS HTTPS) | Se o site usa Encrypted Client Hello e qual nome o firewall realmente vê (ex.: `cloudflare-ech.com`). Consulta via DoH e, se bloqueado, pelo DNS da rede |

### Vereditos

- **bloquear**: comprovadamente do site (cadeia, certificado, CDN própria, espelho confirmado).
- **revisar**: terceiro carregado pela página ou domínio de mesmo nome sem vínculo comprovado.
- **não bloquear**: provedores compartilhados (Google, Cloudflare, jsDelivr...). Bloqueá-los quebra outros sites. Lista editável em `URL_LISTENING_SHARED`.

## Por que o bloqueio pela URL padrão é contornado

1. **Domínios espelho e CDNs**: o vídeo/imagem vem de outro domínio (ex.: `site-cdn.com`). Bloquear só `site.com` deixa o conteúdo passar se o usuário chegar por outro caminho. A ferramenta cobre isso.
2. **QUIC / HTTP3 (UDP 443)**: o navegador fala com o site por UDP e o filtro, que olha TCP, não vê. A ferramenta avisa quando o site anuncia QUIC. **Bloqueie UDP/443** na política.
3. **DNS over HTTPS (DoH)**: Chrome/Firefox resolvem nomes por HTTPS (dns.google, cloudflare-dns.com, mozilla.cloudflare-dns.com) e ignoram o DNS da rede. Bloqueie a categoria de DoH/proxies e o domínio canário `use-application-dns.net`.
4. **ECH (Encrypted Client Hello)**: o navegador criptografa o nome do site e o filtro só vê o nome público da CDN (`cloudflare-ech.com`). Sintoma típico: "só bloqueia se eu bloquear a Cloudflare". A ferramenta detecta e mostra o passo a passo: desativar ECH por política (Chrome/Edge `EncryptedClientHelloEnabled=false`, Firefox `network.dns.echconfig.enabled=false`), forçar o DNS da rede (bloquear DoH/DoT), bloquear o domínio no filtro DNS e bloquear UDP/443. Nunca bloqueie `cloudflare-ech.com` nem IPs da Cloudflare.
5. **Acesso direto por IP / VPN / proxy web**: use a lista de IPs (só se forem dedicados, nunca IPs de CDN) e bloqueie as categorias de anonimizadores e VPN.

## Configuração (variáveis de ambiente)

| Variável | Padrão | Uso |
|---|---|---|
| `URL_LISTENING_PORT` / `URL_LISTENING_HOST` | `8765` / `127.0.0.1` | Endereço da interface web |
| `URL_LISTENING_TIMEOUT` | `10` | Timeout por requisição (s) |
| `URL_LISTENING_MAX_HOPS` | `15` | Máximo de saltos na cadeia |
| `URL_LISTENING_WORKERS` | `16` | Consultas em paralelo |
| `URL_LISTENING_TLDS` | lista em `config.py` | TLDs testadas como espelho (separadas por vírgula) |
| `URL_LISTENING_PREFIXES` | `www,m,mobile,pt,br,es,en` | Subdomínios testados |
| `URL_LISTENING_SHARED` | lista em `config.py` | Provedores que nunca entram na lista |
| `URL_LISTENING_DOH` | `https://dns.google/resolve` | DoH usado na análise (se bloqueado, usa o DNS do sistema) |
| `URL_LISTENING_DNS_SERVER` | DNS do sistema (`/etc/resolv.conf`) | DNS consultado para checar ECH quando o DoH está bloqueado (no Windows, defina para habilitar o fallback) |

## Testes

```bash
python3 -m unittest -v
```

36 testes, sem acesso à internet (rede simulada).
