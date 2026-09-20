#!/usr/bin/env python3
"""
WebHawk — HTTP/HTTPS attack-surface mapper
==========================================
Find ports that speak HTTP or HTTPS on hosts you own or have explicit
permission to test. Conservative defaults (common web ports). Full-range
and large-CIDR sweeps require --authorized.

Requires: Python 3.10+, rich, httpx
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

VERSION = "2.1.0"

THEME = Theme(
    {
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "info": "bold cyan",
        "muted": "dim",
        "brand": "bold bright_magenta",
        "title": "bold magenta",
        "http": "bold bright_blue",
        "https": "bold bright_green",
        "open": "bold green",
        "closed": "dim",
        "redir": "bold yellow",
        "client": "bold cyan",
        "server": "bold red",
        "port": "bold white",
        "tag": "bold bright_yellow",
        "cert": "bold bright_cyan",
    }
)

console = Console(theme=THEME, highlight=False)

COMMON_WEB_PORTS = [
    80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096,
    3000, 3001, 3443, 4000, 4172, 4443, 4567, 5000, 5001,
    5443, 5601, 6000, 6443, 7000, 7001, 7443, 8000, 8001,
    8008, 8010, 8080, 8081, 8088, 8181, 8443, 8484, 8880,
    8888, 9000, 9001, 9090, 9091, 9200, 9443, 10000, 10443,
    12443, 15672, 18080, 28080,
]

USER_AGENTS = [
    "WebHawk/2.1 (+authorized surface mapping)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Opera/9.23 (Nintendo Wii; U; ; 1038-58; Wii Internet Channel/1.0; en)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; PalmSource/hspr-H102; Blazer/4.0) 16;320x320 [ip:127.0.0.1]",
    "Mozilla/1.22 (compatible; MSIE 5.01; PalmOS 3.0) EudoraWeb 2.1",
    "Mozilla/4.0 (PSP (PlayStation Portable); 2.00)",
    "Mozilla/5.0 (X11; GNU/Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/88.0.4324.150 Chrome/88.0.4324.150 Safari/537.36 Tesla/DEV-BUILD-c9db6a2e2678",
    "Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/601.6 (KHTML, like Gecko) NF/4.0.0.8.9 NintendoBrowser/5.1.0.16739",
    "WebHawk/2.1 (coffee-powered; pecks certificates for sport)",
    "NCSA_Mosaic/2.0 (Windows 3.1)",
    "CERN-LineMode/2.15 libwww/2.17",
    "Lynx/2.8.9rel.1 libwww-FM/2.14 SSL-MM/1.4.1",
    "w3m/0.5.3+git20230121",
    "Links (2.29; Linux 6.8.0 x86_64; GNU C 13.2; text)",
    "IBrowse/2.4 (AmigaOS 3.9; 68k)",
    "HotJava/1.0",
    "Mozilla/3.0 (compatible; WebTV/1.2; processed by a satellite and a prayer)",
    "Mozilla/4.0 (compatible; MSN 6.1; MSN 6.2; Windows XP)",
    "Opera/9.80 (Nintendo 3DS; Opera Mini/7.1; U; en) Presto/2.8.119",
    "Mozilla/5.0 (PlayStation 4 5.05) AppleWebKit/537.73 (KHTML, like Gecko)",
    "Mozilla/5.0 (compatible; Nintendobrowser/0.1; Dreamcast VMU)",
    "Wget/1.21.4 (redacted lab box)",
    "curl/7.88.1 (still waiting for the 90s to end)",
    "Mozilla/5.0 (X11; Linux i686) Gecko/20050511 Firefox/1.0.4 (Debian)",
    "BlackBerry8330/4.3.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/105",
    "DoCoMo/2.0 N905i(c100;TB;W24H16) (compatible; Googlebot-Mobile/2.1; lab-only)",
    "Mozilla/4.0 (compatible; Dillo 3.0)",
    "Surf/2.1 (X11; Linux x86_64) WebHawk-edition",
    "Mozilla/5.0 (Macintosh; PPC Mac OS X; U; en) AppleWebKit/125.5 (KHTML, like Gecko) Safari/85",
    "Python-urllib/1.17",
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_BODY_SNIPPET = 180
MAX_CIDR_HOSTS_SOFT = 256
MAX_CIDR_HOSTS_HARD = 1024
HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}

PANEL_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"grafana", re.I), "grafana"),
    (re.compile(r"kibana", re.I), "kibana"),
    (re.compile(r"jenkins", re.I), "jenkins"),
    (re.compile(r"phpmyadmin", re.I), "phpmyadmin"),
    (re.compile(r"tomcat", re.I), "tomcat"),
    (re.compile(r"weblogic", re.I), "weblogic"),
    (re.compile(r"webmin", re.I), "webmin"),
    (re.compile(r"prometheus", re.I), "prometheus"),
    (re.compile(r"portainer", re.I), "portainer"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "apache"),
    (re.compile(r"iis |microsoft-iis|iis windows", re.I), "iis"),
    (re.compile(r"caddy", re.I), "caddy"),
    (re.compile(r"traefik", re.I), "traefik"),
    (re.compile(r"minio", re.I), "minio"),
    (re.compile(r"rabbitmq", re.I), "rabbitmq"),
    (re.compile(r"couchdb", re.I), "couchdb"),
    (re.compile(r"elasticsearch", re.I), "elasticsearch"),
    (re.compile(r"sonarqube", re.I), "sonarqube"),
    (re.compile(r"gitlab", re.I), "gitlab"),
    (re.compile(r"nextcloud", re.I), "nextcloud"),
    (re.compile(r"wordpress", re.I), "wordpress"),
    (re.compile(r"drupal", re.I), "drupal"),
]


@dataclass
class TlsInfo:
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    expired: bool = False
    error: str = ""


@dataclass
class HttpHit:
    scheme: str
    url: str
    final_url: str
    status: int | None
    reason: str
    server: str
    powered_by: str
    content_type: str
    location: str
    title: str
    snippet: str
    bytes_read: int
    sha256: str
    elapsed_ms: float
    tags: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tls: TlsInfo | None = None
    error: str = ""
    body: bytes = field(default=b"", repr=False)


@dataclass
class PortResult:
    port: int
    tcp_open: bool
    hits: list[HttpHit] = field(default_factory=list)
    tcp_error: str = ""


@dataclass
class HostReport:
    target: str
    resolved: list[str]
    results: list[PortResult]
    elapsed: float


def banner() -> None:
    art = Text()
    art.append("  ██╗    ██╗███████╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗\n", style="bright_magenta")
    art.append("  ██║    ██║██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝\n", style="magenta")
    art.append("  ██║ █╗ ██║█████╗  ██████╔╝███████║███████║██║ █╗ ██║█████╔╝ \n", style="bright_cyan")
    art.append("  ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██╗ \n", style="cyan")
    art.append("  ╚███╔███╔╝███████╗██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗\n", style="bright_blue")
    art.append("   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝\n", style="blue")
    art.append(f"   HTTP/HTTPS attack-surface mapper  v{VERSION}\n", style="brand")
    console.print(art)
    console.print(
        Panel.fit(
            "[warn]Authorized use only.[/warn] Scan hosts you own or have written permission to test.\n"
            "[muted]Unauthorized scanning can be illegal. Defaults stay small: common web ports.[/muted]",
            border_style="yellow",
            title="[warn]rules of engagement[/warn]",
        )
    )
    console.print()


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise argparse.ArgumentTypeError("ports must be in 1-65535")
            ports.update(range(start, end + 1))
        else:
            p = int(chunk)
            if p < 1 or p > 65535:
                raise argparse.ArgumentTypeError("ports must be in 1-65535")
            ports.add(p)
    return sorted(ports)


def parse_status_set(spec: str | None) -> set[int] | None:
    if not spec:
        return None
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(chunk))
    return out


def looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_host(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or raw
    host = raw.split("/")[0]
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    return host.split(":")[0]


def normalize_path(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return "/"
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        raw = parsed.path or "/"
        if parsed.query:
            raw = f"{raw}?{parsed.query}"
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def expand_cidr(token: str) -> list[str] | None:
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        hosts = [str(net.network_address)]
    return hosts


def load_list_file(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"list file not found: {path}")
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_target_file(path: Path) -> list[str]:
    return load_list_file(path)


def looks_like_existing_file(value: str) -> bool:
    if not value or any(ch in value for ch in (",", "\n", "\r")):
        return False
    # A single header "X-Foo: bar" is not a file. A UA string usually isn't a path
    # that exists. Only treat it as a file when the path actually exists.
    try:
        return Path(value).expanduser().is_file()
    except OSError:
        return False


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_header_line(line: str) -> tuple[str, str]:
    if ":" not in line:
        raise ValueError(f"header must look like 'Name: value' (got {line!r})")
    name, value = line.split(":", 1)
    name, value = name.strip(), value.strip()
    if not name:
        raise ValueError(f"empty header name in {line!r}")
    return name, value


def merge_headers(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in pairs:
        out[name] = value
    return out


def collect_custom_headers(header_args: list[str], headers_file: str | None) -> dict[str, str]:
    pairs: list[tuple[str, str]] = []
    for item in header_args:
        if looks_like_existing_file(item):
            for line in load_list_file(Path(item).expanduser()):
                pairs.append(parse_header_line(line))
        else:
            pairs.append(parse_header_line(item))
    if headers_file:
        for line in load_list_file(Path(headers_file).expanduser()):
            pairs.append(parse_header_line(line))
    return merge_headers(pairs)


def collect_user_agents(user_agent: str | None, agents_file: str | None, randomize: bool) -> list[str]:
    agents: list[str] = []
    if user_agent:
        if looks_like_existing_file(user_agent):
            agents.extend(load_list_file(Path(user_agent).expanduser()))
        else:
            agents.append(user_agent)
    if agents_file:
        agents.extend(load_list_file(Path(agents_file).expanduser()))
    agents = [a.strip() for a in agents if a.strip()]
    if not agents:
        agents = list(USER_AGENTS) if randomize else [USER_AGENTS[0]]
    elif randomize and len(agents) == 1 and agents[0] == USER_AGENTS[0]:
        agents = list(USER_AGENTS)
    return dedupe(agents)


def collect_paths(paths_arg: str | None, paths_file: str | None) -> list[str]:
    paths: list[str] = []
    if paths_arg:
        if looks_like_existing_file(paths_arg):
            paths.extend(load_list_file(Path(paths_arg).expanduser()))
        else:
            paths.extend(part.strip() for part in paths_arg.split(",") if part.strip())
    if paths_file:
        paths.extend(load_list_file(Path(paths_file).expanduser()))
    normalized = [normalize_path(p) for p in paths]
    return dedupe(normalized) or ["/"]


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addrs: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            addrs.append(addr)
    return addrs


def status_style(code: int | None) -> str:
    if code is None:
        return "muted"
    if 200 <= code < 300:
        return "ok"
    if 300 <= code < 400:
        return "redir"
    if 400 <= code < 500:
        return "client"
    if 500 <= code < 600:
        return "server"
    return "muted"


def extract_title(html: str) -> str:
    m = TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160]


def snippet_of(body: bytes, content_type: str) -> str:
    text = body.decode("utf-8", errors="replace")
    text = re.sub(r"\s+", " ", text).strip()
    if "html" in content_type.lower() or text.lstrip().startswith("<"):
        stripped = re.sub(r"<script[\s\S]*?</script>", " ", text, flags=re.I)
        stripped = re.sub(r"<style[\s\S]*?</style>", " ", stripped, flags=re.I)
        stripped = re.sub(r"<[^>]+>", " ", stripped)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        text = stripped or text
    return text[:MAX_BODY_SNIPPET]


def classify_tags(status: int | None, title: str, server: str, snippet: str, body: bytes) -> list[str]:
    tags: list[str] = []
    blob = f"{title}\n{server}\n{snippet}\n{body[:2000].decode('utf-8', errors='ignore')}"
    if status == 401:
        tags.append("auth-required")
    if status == 403:
        tags.append("forbidden")
    if status is not None and 300 <= status < 400:
        tags.append("redirect")
    if status is not None and 500 <= status < 600:
        tags.append("server-error")
    low = blob.lower()
    if "index of /" in low or "directory listing" in low:
        tags.append("dir-listing")
    if any(s in low for s in ("welcome to nginx", "apache2 ubuntu default", "iis windows server", "it works!")):
        tags.append("default-page")
    for pattern, name in PANEL_SIGNATURES:
        if pattern.search(blob):
            tags.append(name)
            break
    return tags


def header_map(headers: httpx.Headers) -> dict[str, str]:
    interesting = {
        "server",
        "x-powered-by",
        "x-generator",
        "x-aspnet-version",
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "www-authenticate",
        "location",
        "via",
        "x-backend-server",
        "x-drupal-cache",
        "x-served-by",
        "cdn-cache-control",
        "allow",
    }
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in interesting or key.lower().startswith("x-"):
            out[key] = value
    return out


def collect_tls(host: str, port: int, timeout: float) -> TlsInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sni = host if not looks_like_ip(host) else None
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version() or ""
    except Exception as exc:
        return TlsInfo(error=str(exc)[:160])

    def name_from(entries: object) -> str:
        if not entries:
            return ""
        parts: list[str] = []
        try:
            for item in entries:  # type: ignore[not-iterable]
                if isinstance(item, tuple) and item and isinstance(item[0], tuple):
                    for k, v in item:
                        if k in {"commonName", "organizationName"}:
                            parts.append(f"{k}={v}")
        except TypeError:
            return str(entries)
        return ", ".join(parts)

    san: list[str] = []
    for typ, val in cert.get("subjectAltName", ()) or ():
        san.append(f"{typ}:{val}")
    not_after = cert.get("notAfter", "")
    expired = False
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expired = expires < datetime.now(timezone.utc)
        except ValueError:
            expired = False
    return TlsInfo(
        version=version,
        cipher=cipher[0] if cipher else "",
        subject=name_from(cert.get("subject")),
        issuer=name_from(cert.get("issuer")),
        not_before=cert.get("notBefore", ""),
        not_after=not_after,
        san=san[:12],
        expired=expired,
    )


async def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ""
    except asyncio.TimeoutError:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "refused"
    except OSError as exc:
        return False, exc.strerror or str(exc)
    except Exception as exc:
        return False, str(exc)


def speaking(hit: HttpHit | None) -> bool:
    if hit is None:
        return False
    if hit.status is not None:
        return True
    err = hit.error.lower()
    if not err:
        return False
    noise = ("timeout", "connect", "refused", "ssl", "eof", "wrong version", "certificate", "handshake")
    return not any(token in err for token in noise)


def hit_passes_filters(
    hit: HttpHit,
    status_allow: set[int] | None,
    grep: re.Pattern[str] | None,
) -> bool:
    if not speaking(hit):
        return False
    if status_allow is not None and (hit.status is None or hit.status not in status_allow):
        return False
    if grep is not None:
        hay = " ".join([hit.title, hit.snippet, hit.server, hit.powered_by, hit.error])
        if not grep.search(hay):
            return False
    return True


def error_hit(scheme: str, url: str, started: float, error: str) -> HttpHit:
    return HttpHit(
        scheme,
        url,
        url,
        None,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        0,
        "",
        (time.perf_counter() - started) * 1000,
        error=error,
    )


async def http_probe(
    client: httpx.AsyncClient,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    keep_body: bool,
    max_body: int,
    retries: int,
    extra_headers: dict[str, str] | None = None,
) -> HttpHit:
    url = f"{scheme}://{host}:{port}{path}"
    t0 = time.perf_counter()
    last_error = "request failed"
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            resp = await client.request(method, url, headers=extra_headers)
            elapsed = (time.perf_counter() - t0) * 1000
            body = resp.content[:max_body]
            ctype = resp.headers.get("content-type", "")
            decoded = body.decode("utf-8", errors="ignore") if body else ""
            title = extract_title(decoded)
            tags = classify_tags(
                resp.status_code,
                title,
                resp.headers.get("server", ""),
                snippet_of(body, ctype),
                body,
            )
            digest = hashlib.sha256(resp.content).hexdigest()[:16] if resp.content else ""
            allow = resp.headers.get("allow", "")
            if method == "OPTIONS" and allow:
                tags.append(f"allow:{allow.replace(' ', '')}")
            return HttpHit(
                scheme=scheme,
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                reason=resp.reason_phrase or "",
                server=resp.headers.get("server", ""),
                powered_by=resp.headers.get("x-powered-by", ""),
                content_type=ctype.split(";")[0].strip(),
                location=resp.headers.get("location", ""),
                title=title,
                snippet=snippet_of(body, ctype) if body else "",
                bytes_read=len(resp.content),
                sha256=digest,
                elapsed_ms=elapsed,
                tags=tags,
                headers=header_map(resp.headers),
                body=body if keep_body else b"",
            )
        except httpx.TimeoutException:
            last_error = "timeout"
        except ssl.SSLError as exc:
            last_error = f"ssl: {exc}"
            break
        except httpx.ConnectError as exc:
            last_error = f"connect: {exc}"
        except Exception as exc:
            msg = str(exc)
            last_error = (msg[:157] + "...") if len(msg) > 160 else msg
        if attempt + 1 < attempts:
            await asyncio.sleep(0.15 * (attempt + 1))
    return error_hit(scheme, url, t0, last_error)


def safe_name(host: str, port: int, scheme: str, path: str) -> str:
    path_part = path.strip("/") or "root"
    path_part = re.sub(r"[^A-Za-z0-9._-]+", "_", path_part)[:60]
    host_part = re.sub(r"[^A-Za-z0-9._-]+", "_", host)[:80]
    return f"{host_part}_{port}_{scheme}_{path_part}"


def extension_for(content_type: str, body: bytes) -> str:
    ctype = content_type.lower()
    if "json" in ctype or body.lstrip().startswith(b"{"):
        return ".json"
    if "html" in ctype or body.lstrip()[:32].lower().startswith(b"<!doctype") or b"<html" in body[:400].lower():
        return ".html"
    if "xml" in ctype:
        return ".xml"
    if "javascript" in ctype:
        return ".js"
    if "css" in ctype:
        return ".css"
    if "text/" in ctype:
        return ".txt"
    return ".bin"


class ArtifactSink:
    def __init__(
        self,
        urls_path: Path | None,
        source_dir: Path | None,
        header_dir: Path | None,
    ) -> None:
        self.urls_path = urls_path
        self.source_dir = source_dir
        self.header_dir = header_dir
        self._url_fh = None
        self.seen_urls: set[str] = set()
        if urls_path:
            urls_path.parent.mkdir(parents=True, exist_ok=True)
            self._url_fh = urls_path.open("a", encoding="utf-8")
        if source_dir:
            source_dir.mkdir(parents=True, exist_ok=True)
        if header_dir:
            header_dir.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._url_fh:
            self._url_fh.close()
            self._url_fh = None

    def capture(self, host: str, port: int, hit: HttpHit) -> None:
        if not speaking(hit):
            return
        url = hit.final_url or hit.url
        if self._url_fh and url not in self.seen_urls:
            self.seen_urls.add(url)
            self._url_fh.write(url + "\n")
            self._url_fh.flush()
        stem = safe_name(host, port, hit.scheme, urlparse(hit.url).path or "/")
        if self.source_dir and hit.body:
            ext = extension_for(hit.content_type, hit.body)
            (self.source_dir / f"{stem}{ext}").write_bytes(hit.body)
        if self.header_dir:
            lines = [
                f"URL: {hit.url}",
                f"Final-URL: {hit.final_url}",
                f"Status: {hit.status} {hit.reason}".strip(),
                f"SHA256-16: {hit.sha256}",
                "",
            ]
            for k, v in hit.headers.items():
                lines.append(f"{k}: {v}")
            (self.header_dir / f"{stem}.headers.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


async def scan_host(
    target: str,
    ports: list[int],
    connect_timeout: float,
    http_timeout: float,
    concurrency: int,
    paths: list[str],
    follow_redirects: bool,
    try_http: bool,
    try_https: bool,
    verify_tls: bool,
    user_agents: list[str],
    rotate_agent: bool,
    host_header: str | None,
    custom_headers: dict[str, str],
    collect_certs: bool,
    keep_body: bool,
    max_body: int,
    delay: float,
    proxy: str | None,
    sink: ArtifactSink | None,
    status_allow: set[int] | None,
    grep: re.Pattern[str] | None,
    skip_tcp: bool,
    method: str,
    retries: int,
    auth: httpx.Auth | None,
) -> list[PortResult]:
    if skip_tcp:
        tcp_results = [PortResult(port=p, tcp_open=True) for p in ports]
        console.print(f"[warn]skip-tcp[/warn] treating {len(ports)} port(s) as open for HTTP(S) only")
    else:
        sem = asyncio.Semaphore(concurrency)
        with Progress(
            SpinnerColumn(style="info"),
            TextColumn("[info]{task.description}[/info]"),
            BarColumn(bar_width=36, complete_style="bright_green", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            tcp_task = progress.add_task(f"TCP  {target}", total=len(ports))

            async def tcp_one(p: int) -> PortResult:
                async with sem:
                    if delay:
                        await asyncio.sleep(delay)
                    open_, err = await tcp_probe(target, p, connect_timeout)
                progress.advance(tcp_task)
                return PortResult(port=p, tcp_open=open_, tcp_error=err)

            tcp_results = await asyncio.gather(*(tcp_one(p) for p in ports))

    open_ports = [r for r in tcp_results if r.tcp_open]
    by_port = {r.port: r for r in tcp_results}
    if not open_ports:
        return tcp_results

    schemes: list[str] = []
    if try_http:
        schemes.append("http")
    if try_https:
        schemes.append("https")

    jobs = [(r.port, scheme, path) for r in open_ports for scheme in schemes for path in paths]
    http_sem = asyncio.Semaphore(max(4, concurrency // 2))
    limits = httpx.Limits(
        max_connections=max(8, concurrency // 2),
        max_keepalive_connections=max(4, concurrency // 4),
    )
    default_ua = user_agents[0] if user_agents else USER_AGENTS[0]
    headers = {"User-Agent": default_ua, "Accept": "*/*"}
    headers.update(custom_headers)
    if host_header:
        headers["Host"] = host_header

    client_kwargs: dict = {
        "follow_redirects": follow_redirects,
        "verify": verify_tls,
        "timeout": httpx.Timeout(http_timeout, connect=connect_timeout),
        "headers": headers,
        "limits": limits,
        "http2": False,
        "auth": auth,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    with Progress(
        SpinnerColumn(style="http"),
        TextColumn("[http]{task.description}[/http]"),
        BarColumn(bar_width=36, complete_style="bright_cyan", finished_style="cyan"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        http_task = progress.add_task(f"{method}  {target}", total=len(jobs))
        async with httpx.AsyncClient(**client_kwargs) as client:

            async def one(port: int, scheme: str, path: str) -> tuple[int, HttpHit]:
                async with http_sem:
                    if delay:
                        await asyncio.sleep(delay)
                    extra = None
                    if rotate_agent and user_agents:
                        extra = {"User-Agent": random.choice(user_agents)}
                    hit = await http_probe(
                        client,
                        method,
                        scheme,
                        target,
                        port,
                        path,
                        keep_body,
                        max_body,
                        retries,
                        extra,
                    )
                    if scheme == "https" and collect_certs and (hit.status is not None or "ssl" in hit.error.lower()):
                        hit.tls = await asyncio.to_thread(collect_tls, target, port, connect_timeout)
                        if hit.tls and hit.tls.expired:
                            hit.tags.append("expired-cert")
                progress.advance(http_task)
                return port, hit

            pairs = await asyncio.gather(*(one(port, scheme, path) for port, scheme, path in jobs))

    for port, hit in pairs:
        if status_allow or grep:
            if not hit_passes_filters(hit, status_allow, grep) and hit.status is not None:
                hit.tags.append("filtered")
        by_port[port].hits.append(hit)
        if sink and "filtered" not in hit.tags:
            sink.capture(target, port, hit)

    return [by_port[p] for p in ports]


def render_host(report: HostReport, only_live: bool) -> None:
    open_tcp = [r for r in report.results if r.tcp_open]
    live_hits = [h for r in open_tcp for h in r.hits if speaking(h) and "filtered" not in h.tags]
    summary = Table.grid(padding=(0, 2))
    summary.add_row("[info]target[/info]", f"[bold]{report.target}[/bold]")
    summary.add_row("[info]resolved[/info]", ", ".join(report.resolved) or "[muted]n/a[/muted]")
    summary.add_row("[info]ports tested[/info]", str(len(report.results)))
    summary.add_row("[open]tcp open[/open]", str(len(open_tcp)))
    summary.add_row("[http]live http(s)[/http]", str(len(live_hits)))
    summary.add_row("[muted]elapsed[/muted]", f"{report.elapsed:.2f}s")
    console.print(Panel(summary, title=f"[title]{report.target}[/title]", border_style="magenta"))

    if not open_tcp:
        console.print("[err]No TCP-open ports in the selected set.[/err]\n")
        return

    table = Table(
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold white",
        expand=True,
        show_lines=False,
    )
    table.add_column("port", style="port", justify="right", no_wrap=True)
    table.add_column("proto", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("server")
    table.add_column("title / error")
    table.add_column("tags")
    table.add_column("ms", justify="right", no_wrap=True)

    rows = 0
    for r in open_tcp:
        spoken = [h for h in r.hits if speaking(h)]
        if only_live and not spoken:
            continue
        if spoken:
            for hit in spoken:
                status = (
                    Text(f"{hit.status} {hit.reason}".strip(), style=status_style(hit.status))
                    if hit.status is not None
                    else Text(hit.error or "no response", style="err")
                )
                detail = hit.title or hit.location or hit.error or hit.snippet
                tags = " ".join(hit.tags[:5])
                table.add_row(
                    str(r.port),
                    Text(hit.scheme.upper(), style=hit.scheme),
                    status,
                    hit.server or hit.powered_by or Text("—", style="muted"),
                    (detail[:72] + "…") if len(detail) > 72 else detail or Text("—", style="muted"),
                    Text(tags, style="tag") if tags else Text("—", style="muted"),
                    f"{hit.elapsed_ms:.0f}",
                )
                rows += 1
        else:
            why = "; ".join(sorted({h.error for h in r.hits if h.error})) or "no http/https response"
            table.add_row(
                str(r.port),
                Text("TCP", style="muted"),
                Text("open, no HTTP", style="warn"),
                Text("—", style="muted"),
                why[:72],
                Text("—", style="muted"),
                "—",
            )
            rows += 1

    if rows:
        console.print(table)

    for r in open_tcp:
        for hit in r.hits:
            if not speaking(hit) or "filtered" in hit.tags:
                continue
            body = Table.grid(padding=(0, 1))
            body.add_row("[info]url[/info]", f"[{hit.scheme}]{hit.url}[/{hit.scheme}]")
            if hit.final_url != hit.url:
                body.add_row("[info]final[/info]", hit.final_url)
            if hit.status is not None:
                body.add_row("[info]status[/info]", Text(f"{hit.status} {hit.reason}".strip(), style=status_style(hit.status)))
            if hit.server:
                body.add_row("[info]server[/info]", hit.server)
            if hit.powered_by:
                body.add_row("[info]powered-by[/info]", hit.powered_by)
            if hit.content_type:
                body.add_row("[info]type[/info]", hit.content_type)
            if hit.location:
                body.add_row("[info]location[/info]", hit.location)
            if hit.title:
                body.add_row("[info]title[/info]", f"[title]{hit.title}[/title]")
            if hit.tags:
                body.add_row("[info]tags[/info]", Text(", ".join(hit.tags), style="tag"))
            if hit.sha256:
                body.add_row("[muted]hash[/muted]", hit.sha256)
            body.add_row("[muted]bytes[/muted]", str(hit.bytes_read))
            if hit.tls and not hit.tls.error:
                cert_line = f"{hit.tls.version}  {hit.tls.subject or '—'}  exp {hit.tls.not_after or '—'}"
                if hit.tls.expired:
                    cert_line += "  [err]EXPIRED[/err]"
                body.add_row("[cert]tls[/cert]", cert_line)
                if hit.tls.issuer:
                    body.add_row("[cert]issuer[/cert]", hit.tls.issuer)
            if hit.snippet:
                body.add_row("[muted]body[/muted]", Text(hit.snippet, style="muted"))
            border = "green" if hit.status and 200 <= hit.status < 300 else "cyan"
            console.print(
                Panel(
                    body,
                    title=f"[port]:{r.port}[/port] [{hit.scheme}]{hit.scheme.upper()}[/{hit.scheme}]",
                    border_style=border,
                )
            )
    console.print()


def reports_to_json(reports: list[HostReport], elapsed: float) -> dict:
    def tls_dict(t: TlsInfo | None) -> dict | None:
        return asdict(t) if t else None

    def hit_dict(h: HttpHit) -> dict:
        data = asdict(h)
        data.pop("body", None)
        data["tls"] = tls_dict(h.tls)
        return data

    return {
        "tool": "WebHawk",
        "version": VERSION,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 3),
        "hosts": [
            {
                "target": r.target,
                "resolved": r.resolved,
                "elapsed_seconds": round(r.elapsed, 3),
                "ports": [
                    {
                        "port": p.port,
                        "tcp_open": p.tcp_open,
                        "tcp_error": p.tcp_error,
                        "hits": [hit_dict(h) for h in p.hits],
                    }
                    for p in r.results
                    if p.tcp_open
                ],
            }
            for r in reports
        ],
    }


def write_csv(path: Path, reports: list[HostReport]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "target",
                "port",
                "scheme",
                "url",
                "final_url",
                "status",
                "server",
                "title",
                "tags",
                "sha256",
                "bytes",
                "ms",
            ]
        )
        for report in reports:
            for result in report.results:
                for hit in result.hits:
                    if not speaking(hit):
                        continue
                    writer.writerow(
                        [
                            report.target,
                            result.port,
                            hit.scheme,
                            hit.url,
                            hit.final_url,
                            hit.status,
                            hit.server,
                            hit.title,
                            ",".join(hit.tags),
                            hit.sha256,
                            hit.bytes_read,
                            f"{hit.elapsed_ms:.1f}",
                        ]
                    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webhawk",
        description="WebHawk — map HTTP/HTTPS attack surface on authorized hosts.",
        epilog="Examples:\n"
        "  python webhawk.py 127.0.0.1\n"
        "  python webhawk.py 127.0.0.1 --user-agent agents.txt --paths paths.txt -H headers.txt\n"
        "  python webhawk.py -l targets.txt --skip-tcp --ports 80,443 --authorized\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="IPs, hostnames, URLs, or CIDR ranges")
    p.add_argument("-l", "--targets-file", metavar="FILE", help="File of targets, one per line (# comments ok)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--common", action="store_true", help="Common web ports (default)")
    g.add_argument("--ports", metavar="SPEC", help="Ports/ranges, e.g. 80,443,8000-8010")
    g.add_argument("--range", dest="port_range", metavar="START-END", help="Inclusive port range")
    g.add_argument("--all", action="store_true", help="Every TCP port 1-65535 (requires --authorized)")
    p.add_argument("--ports-file", metavar="FILE", help="File of ports / ranges, one spec per line")
    p.add_argument("--exclude-ports", metavar="SPEC", help="Ports to skip, same syntax as --ports")
    p.add_argument(
        "--authorized",
        "--i-own-this",
        dest="authorized",
        action="store_true",
        help="Acknowledge authorization for large sweeps / CIDRs (--i-own-this still works)",
    )
    p.add_argument("--paths", default="/", help="Comma-separated paths, or a file of paths")
    p.add_argument("--paths-file", metavar="FILE", help="File of paths, one per line")
    p.add_argument("--concurrency", type=int, default=256, help="Max parallel TCP connects (default: 256)")
    p.add_argument("--connect-timeout", type=float, default=1.2, help="TCP connect timeout seconds")
    p.add_argument("--http-timeout", type=float, default=4.0, help="HTTP request timeout seconds")
    p.add_argument("--delay", type=float, default=0.0, help="Optional delay (seconds) before each probe")
    p.add_argument("--retries", type=int, default=0, help="Retries per HTTP request on timeout/connect errors")
    p.add_argument("--http-only", action="store_true", help="Skip HTTPS")
    p.add_argument("--https-only", action="store_true", help="Skip HTTP")
    p.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    p.add_argument("--no-cert", action="store_true", help="Do not fetch TLS certificate metadata")
    p.add_argument("--skip-tcp", action="store_true", help="Skip the TCP connect scan; send HTTP(S) to every selected port")
    p.add_argument(
        "--method",
        default="GET",
        choices=sorted(HTTP_METHODS),
        help="HTTP method (default: GET). HEAD is lighter; OPTIONS shows Allow",
    )
    p.add_argument("--host-header", help="Override Host header (vhost on an IP)")
    p.add_argument("-H", "--header", action="append", default=[], metavar="HEADER", help="Custom header 'Name: value' (repeatable) or a headers file")
    p.add_argument("--headers-file", metavar="FILE", help="File of custom headers, one 'Name: value' per line")
    p.add_argument("--auth", metavar="USER:PASS", help="HTTP Basic authentication")
    p.add_argument("--user-agent", default=USER_AGENTS[0], help="User-Agent string, or a file of User-Agents")
    p.add_argument("--user-agents-file", metavar="FILE", help="File of User-Agents, one per line")
    p.add_argument("--random-agent", action="store_true", help="Pick a random User-Agent from the pool for the whole scan")
    p.add_argument("--rotate-agent", action="store_true", help="Pick a random User-Agent from the pool on every request")
    p.add_argument("--proxy", help="HTTP proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--status", help="Only treat these codes as live, e.g. 200,301-302,401")
    p.add_argument("--grep", help="Regex that title/body/server must match to count as live")
    p.add_argument("--only-live", action="store_true", help="Hide TCP-open ports that do not speak HTTP(S)")
    p.add_argument("--save-urls", metavar="FILE", help="Append live URLs (one per line) to FILE")
    p.add_argument("--save-source", metavar="DIR", help="Write response bodies of live URLs into DIR")
    p.add_argument("--save-headers", metavar="DIR", help="Write interesting response headers into DIR")
    p.add_argument("--output-dir", metavar="DIR", help="Shortcut: write live.txt, pages/, headers/, JSON and CSV into DIR")
    p.add_argument("--max-body", type=int, default=262144, help="Max bytes saved per body (default: 256KiB)")
    p.add_argument("--json", metavar="FILE", help="Write a JSON report")
    p.add_argument("--csv", metavar="FILE", help="Write a CSV report of live URLs")
    p.add_argument("--quiet", action="store_true", help="Skip the banner")
    p.add_argument("--version", action="version", version=f"WebHawk {VERSION}")
    return p


def collect_targets(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.targets)
    if args.targets_file:
        raw.extend(load_target_file(Path(args.targets_file)))
    if not raw:
        raise SystemExit("No targets given. Pass hosts or --targets-file.")

    expanded: list[str] = []
    seen: set[str] = set()
    for token in raw:
        cidr = expand_cidr(token) if "/" in token and "://" not in token else None
        pieces = cidr if cidr is not None else [normalize_host(token)]
        if cidr is not None:
            if len(cidr) > MAX_CIDR_HOSTS_HARD:
                raise SystemExit(f"CIDR {token} expands to {len(cidr)} hosts (hard cap {MAX_CIDR_HOSTS_HARD}).")
            if len(cidr) > MAX_CIDR_HOSTS_SOFT and not args.authorized:
                raise SystemExit(
                    f"CIDR {token} expands to {len(cidr)} hosts. Re-run with --authorized only if you own the range."
                )
        for host in pieces:
            host = host.strip()
            if host and host not in seen:
                seen.add(host)
                expanded.append(host)
    return expanded


def choose_ports(args: argparse.Namespace) -> list[int]:
    ports: list[int] = []
    if args.all:
        ports = list(range(1, 65536))
    elif args.ports:
        ports = parse_ports(args.ports)
    elif args.port_range:
        ports = parse_ports(args.port_range)
    else:
        ports = list(COMMON_WEB_PORTS)
    if args.ports_file:
        extra: list[int] = []
        for line in load_list_file(Path(args.ports_file).expanduser()):
            extra.extend(parse_ports(line.replace(" ", "")))
        if args.all or args.ports or args.port_range:
            ports = sorted(set(ports) | set(extra))
        else:
            # A ports file should replace the default common list when it is
            # the only port source besides excludes.
            ports = sorted(set(extra)) or ports
    if args.exclude_ports:
        skip = set(parse_ports(args.exclude_ports))
        ports = [p for p in ports if p not in skip]
    return ports


def apply_output_dir(args: argparse.Namespace) -> None:
    if not args.output_dir:
        return
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if not args.save_urls:
        args.save_urls = str(out / "live.txt")
    if not args.save_source:
        args.save_source = str(out / "pages")
    if not args.save_headers:
        args.save_headers = str(out / "headers")
    if not args.json:
        args.json = str(out / "webhawk.json")
    if not args.csv:
        args.csv = str(out / "webhawk.csv")


def parse_basic_auth(value: str | None) -> httpx.BasicAuth | None:
    if not value:
        return None
    if ":" not in value:
        raise SystemExit("--auth must be USER:PASS")
    user, password = value.split(":", 1)
    return httpx.BasicAuth(user, password)


def describe_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    flags = []
    if parsed.is_loopback:
        flags.append("loopback")
    if parsed.is_private:
        flags.append("private")
    if parsed.is_link_local:
        flags.append("link-local")
    if parsed.is_multicast:
        flags.append("multicast")
    if parsed.is_global:
        flags.append("public")
    label = ",".join(flags) or "other"
    style = "ok" if parsed.is_private or parsed.is_loopback else "warn"
    return f"[{style}]{ip}[/{style}] [muted]({label})[/muted]"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.quiet:
        banner()

    try:
        apply_output_dir(args)
        targets = collect_targets(args)
        ports = choose_ports(args)
        paths = collect_paths(args.paths, args.paths_file)
        agents = collect_user_agents(args.user_agent, args.user_agents_file, args.random_agent or args.rotate_agent)
        custom_headers = collect_custom_headers(args.header, args.headers_file)
        auth = parse_basic_auth(args.auth)
    except (ValueError, argparse.ArgumentTypeError, FileNotFoundError, OSError) as exc:
        console.print(f"[err]{exc}[/err]")
        return 2
    except SystemExit as exc:
        if exc.args:
            console.print(f"[err]{exc.args[0]}[/err]")
        return 2

    if args.all and not args.authorized:
        console.print("[err]--all scans 65535 ports.[/err] Re-run with [warn]--authorized[/warn] only on hosts you own.")
        return 2
    if len(ports) > 4096 and not args.authorized:
        console.print(f"[err]Refusing to scan {len(ports)} ports without [warn]--authorized[/warn].[/err]")
        return 2
    if args.skip_tcp and len(ports) > 1024 and not args.authorized:
        console.print(
            f"[err]--skip-tcp on {len(ports)} ports sends an HTTP(S) request to each one.[/err] "
            "Add [warn]--authorized[/warn] if that is really the plan."
        )
        return 2

    try_http = not args.https_only
    try_https = not args.http_only
    if not try_http and not try_https:
        console.print("[err]Nothing to do: both --http-only and --https-only set.[/err]")
        return 2

    status_allow = parse_status_set(args.status)
    grep = re.compile(args.grep, re.I) if args.grep else None
    if args.random_agent and not args.rotate_agent:
        chosen = random.choice(agents)
        agents = [chosen]
    keep_body = bool(args.save_source)

    sink = ArtifactSink(
        urls_path=Path(args.save_urls) if args.save_urls else None,
        source_dir=Path(args.save_source) if args.save_source else None,
        header_dir=Path(args.save_headers) if args.save_headers else None,
    )

    console.print(
        f"[info]targets[/info] {len(targets)} · [info]ports[/info] {len(ports)} · "
        f"[info]paths[/info] {len(paths)} · [info]concurrency[/info] {args.concurrency}"
    )
    proto = []
    if try_http:
        proto.append("[http]HTTP[/http]")
    if try_https:
        proto.append("[https]HTTPS[/https]")
    console.print("[info]schemes[/info] " + " + ".join(proto) + f"  [info]method[/info] {args.method}")
    if args.skip_tcp:
        console.print("[warn]tcp scan[/warn] skipped — HTTP(S) will be sent to every selected port")
    if custom_headers:
        names = ", ".join(custom_headers)
        console.print(f"[info]headers[/info] {len(custom_headers)} custom ({names})")
    if args.rotate_agent:
        console.print(f"[info]user-agent[/info] rotating across {len(agents)} value(s)")
    else:
        shown = agents[0]
        extra = f" (+{len(agents) - 1} more in pool)" if len(agents) > 1 else ""
        console.print(f"[info]user-agent[/info] {shown}{extra}")
    if args.save_urls:
        console.print(f"[info]live urls[/info] {args.save_urls}")
    if args.save_source:
        console.print(f"[info]sources[/info] {args.save_source}")
    console.print()

    reports: list[HostReport] = []
    t_all = time.perf_counter()
    try:
        for target in targets:
            console.print(f"[brand]▸[/brand] [bold]{target}[/bold]")
            try:
                ip_list = resolve_host(target)
            except socket.gaierror as exc:
                console.print(f"[err]DNS failed:[/err] {exc}\n")
                reports.append(HostReport(target, [], [], 0.0))
                continue
            for ip in ip_list:
                console.print("  " + describe_ip(ip))

            t0 = time.perf_counter()
            try:
                results = asyncio.run(
                    scan_host(
                        target=target,
                        ports=ports,
                        connect_timeout=args.connect_timeout,
                        http_timeout=args.http_timeout,
                        concurrency=max(1, args.concurrency),
                        paths=paths,
                        follow_redirects=args.follow_redirects,
                        try_http=try_http,
                        try_https=try_https,
                        verify_tls=not args.insecure,
                        user_agents=agents,
                        rotate_agent=args.rotate_agent,
                        host_header=args.host_header,
                        custom_headers=custom_headers,
                        collect_certs=try_https and not args.no_cert,
                        keep_body=keep_body,
                        max_body=max(1024, args.max_body),
                        delay=max(0.0, args.delay),
                        proxy=args.proxy,
                        sink=sink,
                        status_allow=status_allow,
                        grep=grep,
                        skip_tcp=args.skip_tcp,
                        method=args.method.upper(),
                        retries=max(0, args.retries),
                        auth=auth,
                    )
                )
            except KeyboardInterrupt:
                raise
            elapsed = time.perf_counter() - t0
            report = HostReport(target, ip_list, results, elapsed)
            reports.append(report)
            console.print()
            render_host(report, only_live=args.only_live)
    except KeyboardInterrupt:
        console.print("\n[warn]Interrupted.[/warn]")
        sink.close()
        return 130
    finally:
        sink.close()

    total = time.perf_counter() - t_all
    live_count = sum(
        1
        for r in reports
        for p in r.results
        for h in p.hits
        if speaking(h) and "filtered" not in h.tags
    )
    console.print(
        Panel.fit(
            f"[ok]{len(reports)}[/ok] host(s)  ·  [http]{live_count}[/http] live URL(s)  ·  [muted]{total:.2f}s[/muted]",
            title="[brand]webhawk done[/brand]",
            border_style="magenta",
        )
    )

    if args.json:
        Path(args.json).write_text(json.dumps(reports_to_json(reports, total), indent=2), encoding="utf-8")
        console.print(f"[ok]wrote[/ok] {args.json}")
    if args.csv:
        write_csv(Path(args.csv), reports)
        console.print(f"[ok]wrote[/ok] {args.csv}")
    if args.save_urls:
        console.print(f"[ok]live urls[/ok] {args.save_urls}  ({len(sink.seen_urls)} unique)")
    if args.save_source:
        console.print(f"[ok]sources[/ok] {args.save_source}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
