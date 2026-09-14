"""Conservative misconfig findings from scanner artifacts. Never invent CVEs."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from covey.catalog import CATALOG as _MAP

HONESTY_LINE = (
    "surface map ≠ honeypot validated ≠ control operating effectiveness"
)
NOT_CLAIMED = (
    "control_failure",
    "control_operating_effectiveness",
    "honeypot_validated",
    "vulnerability",
    "riskready_post",
)

CLAIM_MISCONFIG = "misconfig_observed"
CLAIM_VULN = "vuln_ingested"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_FILE_DROP_MARKERS = (
    "nessusclientdata",
    "<openvas",
    "greenbone",
    "<gmp",
    "omp:",
    "openvas",
)


def map_finding(name: str, asset: str, severity: str) -> dict[str, Any]:
    for row in _MAP:
        if row["match"].search(name or ""):
            return {
                "weakness": row["weakness"],
                "asset": asset,
                "severity": row["severity"],
                "cpg": list(row["cpg"]),
                "csf": list(row["csf"]),
                "action": row["action"],
                "mapped": True,
                "reason": "",
            }
    return {
        "weakness": "UNMAPPED",
        "asset": asset,
        "severity": severity or "info",
        "cpg": [],
        "csf": [],
        "action": "",
        "mapped": False,
        "reason": f"no CPG/CSF map for {name!r}",
    }


def _row(name: str, host: str, severity: str, *, adapter: str) -> dict[str, Any]:
    mapped = map_finding(name, host, severity)
    return {
        "kind": "observation",
        "name": mapped["weakness"] if mapped["mapped"] else name,
        "title": mapped["weakness"] if mapped["mapped"] else name,
        "severity": mapped["severity"] if mapped["mapped"] else severity,
        "claim": CLAIM_MISCONFIG,
        "address": host,
        "adapter": adapter,
        "honesty": HONESTY_LINE,
        "not_claimed": list(NOT_CLAIMED),
        "mapped": mapped["mapped"],
        "weakness": mapped["weakness"],
        "cpg": mapped["cpg"],
        "csf": mapped["csf"],
        "action": mapped["action"],
        "reason": mapped["reason"],
    }


def findings_from_http_blob(blob: str, *, url: str, adapter: str = "httpx") -> list[dict[str, Any]]:
    """Cleartext from the URL scheme. Missing headers only when a status line was sampled."""
    host = urlparse(url).hostname or url
    rows: list[dict[str, Any]] = []
    if url.lower().startswith("http://"):
        rows.append(_row("Cleartext HTTP", host, "medium", adapter=adapter))
    low = (blob or "").lower()
    if "http/" not in low:
        return rows
    if "strict-transport-security:" not in low:
        rows.append(_row("Missing HSTS", host, "medium", adapter=adapter))
    if "x-frame-options:" not in low:
        rows.append(_row("Missing X-Frame-Options", host, "low", adapter=adapter))
    if "content-security-policy:" not in low:
        rows.append(_row("Missing CSP", host, "low", adapter=adapter))
    if re.search(r"(?im)^server:", blob or ""):
        rows.append(_row("Server banner disclosure", host, "low", adapter=adapter))
    for match in re.finditer(r"(?im)^set-cookie:\s*(.+)$", blob or ""):
        cookie = (match.group(1) or "").lower()
        if "secure" not in cookie or "httponly" not in cookie:
            rows.append(_row("Insecure session cookie", host, "medium", adapter=adapter))
            break
    if re.search(r"(?im)^access-control-allow-origin:\s*\*\s*$", blob or ""):
        rows.append(_row("Permissive CORS policy", host, "low", adapter=adapter))
    return rows


def findings_from_sslscan(blob: str, *, host: str, adapter: str = "sslscan") -> list[dict[str, Any]]:
    text = blob or ""
    low = text.lower()
    rows: list[dict[str, Any]] = []
    if re.search(r"(?im)^\s*sslv3\b.*enabled", text) or "sslv3  enabled" in low:
        rows.append(_row("SSLv3 enabled", host, "high", adapter=adapter))
    if re.search(r"(?im)tlsv?1(?:\.0)?\s+enabled", text) or "tlsv1.0  enabled" in low:
        rows.append(_row("TLS 1.0 enabled", host, "medium", adapter=adapter))
    if re.search(r"(?im)tlsv?1\.1\s+enabled", text):
        rows.append(_row("TLS 1.1 enabled", host, "medium", adapter=adapter))
    if "self signed" in low or "self-signed" in low:
        rows.append(_row("Untrusted TLS certificate", host, "medium", adapter=adapter))
    if re.search(r"\baecdh\b|anonymous (dh|ecdh|null)", low):
        rows.append(_row("Anonymous TLS cipher", host, "high", adapter=adapter))
    return rows


def findings_from_httpx_lines(text: str, *, adapter: str = "httpx") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        url = stripped.split()[0]
        if not url.lower().startswith("http://") and not url.lower().startswith("https://"):
            continue
        for row in findings_from_http_blob(line if "HTTP/" in line else "", url=url, adapter=adapter):
            key = (row["address"], row["name"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    return rows


def findings_from_httpx_jsonl(text: str, *, adapter: str = "httpx") -> list[dict[str, Any]]:
    """JSONL from httpx -json. Header map becomes an HTTP status sample."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        url = str(obj.get("url") or "")
        if not url:
            host = str(obj.get("host") or "")
            port = obj.get("port") or ""
            scheme = str(obj.get("scheme") or "http")
            if host:
                url = f"{scheme}://{host}" + (f":{port}" if port else "")
        if not url:
            continue
        header = obj.get("header") or obj.get("headers") or {}
        raw_header = str(
            obj.get("raw_header")
            or obj.get("response_header")
            or obj.get("header_raw")
            or ""
        )
        status = obj.get("status_code") or obj.get("status-code") or ""
        if raw_header and "http/" in raw_header.lower():
            blob = raw_header.replace("\n", "\r\n") if "\r\n" not in raw_header else raw_header
            if not blob.endswith("\r\n"):
                blob += "\r\n"
        else:
            blob = f"HTTP/1.1 {status}\r\n"
            if isinstance(header, dict):
                for key, value in header.items():
                    name = str(key).replace("_", "-")
                    blob += f"{name}: {value}\r\n"
        webserver = str(obj.get("webserver") or "")
        if webserver and "server:" not in blob.lower():
            blob += f"Server: {webserver}\r\n"
        techs = obj.get("tech") or obj.get("technologies") or []
        tech_blob = " ".join(str(item) for item in techs) if isinstance(techs, list) else str(techs)
        host = urlparse(url).hostname or str(obj.get("host") or "")
        for row in findings_from_http_blob(blob, url=url, adapter=adapter):
            key = (row["address"], row["name"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
        extra_names = []
        title = str(obj.get("title") or "")
        body = str(obj.get("body") or obj.get("raw") or "")
        raw_cpe = obj.get("cpe")
        if raw_cpe is None:
            raw_cpe = obj.get("cpes")
        if raw_cpe is None:
            raw_cpe = obj.get("CPE")
        if isinstance(raw_cpe, list):
            cpe_blob = " ".join(str(item) for item in raw_cpe)
        elif raw_cpe:
            cpe_blob = str(raw_cpe)
        else:
            cpe_blob = ""
        haystack = f"{url} {tech_blob} {title} {body} {cpe_blob}"
        if re.search(r"phpmyadmin", haystack, re.I):
            extra_names.append("phpMyAdmin interface exposed")
        if re.search(r"werkzeug|flask", f"{webserver} {tech_blob}", re.I):
            extra_names.append("Werkzeug/Flask development server exposed")
        for name in extra_names:
            row = _row(name, host, "medium", adapter=adapter)
            key = (row["address"], row["name"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    return rows


def findings_from_nmap_services(
    services: list[dict[str, str]], *, adapter: str = "nmap"
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in services:
        service = str(item.get("service") or "").lower()
        port = str(item.get("port") or "")
        host = str(item.get("address") or "")
        if not host:
            continue
        if service == "telnet":
            rows.append(_row("Telnet exposed", host, "high", adapter=adapter))
        elif service == "ftp":
            rows.append(_row("FTP exposed", host, "medium", adapter=adapter))
        elif service in {"redis", "redis_version"}:
            rows.append(_row("Redis exposed", host, "high", adapter=adapter))
        elif service in {"postgresql", "postgres", "pgsql"}:
            rows.append(_row("PostgreSQL exposed", host, "high", adapter=adapter))
        elif service in {"memcache", "memcached"}:
            rows.append(_row("Memcached exposed", host, "high", adapter=adapter))
        elif service == "http":
            rows.append(
                _row("Cleartext HTTP", host, "medium", adapter=adapter)
            )
        product = f"{item.get('product') or ''} {item.get('extrainfo') or ''}".lower()
        blob = f"{service} {product} {item.get('name') or ''}"
        if "phpmyadmin" in blob:
            rows.append(_row("phpMyAdmin interface exposed", host, "high", adapter=adapter))
        if "werkzeug" in blob or "flask" in blob:
            rows.append(
                _row(
                    "Werkzeug/Flask development server exposed",
                    host,
                    "medium",
                    adapter=adapter,
                )
            )
    return rows


def findings_from_whatweb(text: str, *, adapter: str = "whatweb") -> list[dict[str, Any]]:
    """Brief whatweb log. Cleartext from http://; products from plugin/title names."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _keep(row: dict[str, Any]) -> None:
        key = (row["address"], row["name"])
        if key in seen:
            return
        seen.add(key)
        rows.append(row)

    for line in (text or "").splitlines():
        stripped = line.strip()
        match = re.match(
            r"^(https?)://([A-Za-z0-9._-]+)(?::\d+)?\b(.*)$",
            stripped,
            re.I,
        )
        if not match:
            continue
        scheme, host, rest = match.group(1).lower(), match.group(2), match.group(3) or ""
        if not host or host == "*":
            continue
        if scheme == "http":
            _keep(_row("Cleartext HTTP", host, "medium", adapter=adapter))
        if re.search(r"\b(Apache|nginx|IIS|Microsoft-IIS|LiteSpeed)\[", rest, re.I):
            _keep(_row("Server banner disclosure", host, "low", adapter=adapter))
        if re.search(r"phpmyadmin", rest, re.I):
            _keep(_row("phpMyAdmin interface exposed", host, "high", adapter=adapter))
        if re.search(r"werkzeug|flask", rest, re.I):
            _keep(
                _row(
                    "Werkzeug/Flask development server exposed",
                    host,
                    "medium",
                    adapter=adapter,
                )
            )
    return rows


def findings_from_tlsx(text: str, *, adapter: str = "tlsx") -> list[dict[str, Any]]:
    """tlsx host:port lines. Bare ip:port invents nothing."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        match = re.match(
            r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b(.*)$", line.strip()
        )
        if not match:
            continue
        host, rest = match.group(1), (match.group(3) or "").lower()
        if re.search(r"tls\s*1\.0|tlsv?1(?:\.0)?\b|tls10", rest):
            row = _row("TLS 1.0 enabled", host, "medium", adapter=adapter)
            key = (row["address"], row["name"])
            if key not in seen:
                seen.add(key)
                rows.append(row)
        if re.search(r"tls\s*1\.1|tlsv?1\.1|tls11", rest):
            row = _row("TLS 1.1 enabled", host, "medium", adapter=adapter)
            key = (row["address"], row["name"])
            if key not in seen:
                seen.add(key)
                rows.append(row)
        if "self-signed" in rest or "self signed" in rest:
            row = _row("Untrusted TLS certificate", host, "medium", adapter=adapter)
            key = (row["address"], row["name"])
            if key not in seen:
                seen.add(key)
                rows.append(row)
    return rows


def _looks_like_file_drop_vuln(blob: str) -> bool:
    low = (blob or "").lower()
    if "<nmaprun" in low:
        return False
    return any(token in low for token in _FILE_DROP_MARKERS)


def _xml_local(tag: str) -> str:
    if not tag:
        return ""
    return tag.split("}", 1)[-1].lower()


def _cves_on_element(el: ET.Element) -> list[str]:
    tag = _xml_local(el.tag)
    blob = f"{el.text or ''} {el.attrib.get('id') or ''}"
    if tag == "cve":
        return [m.group(0).upper() for m in CVE_RE.finditer(blob)]
    if tag == "ref" and str(el.attrib.get("type") or "").lower() == "cve":
        return [m.group(0).upper() for m in CVE_RE.finditer(blob)]
    return []


def _cves_from_scanner_xml(blob: str) -> list[tuple[str, str]]:
    """(CVE, host) from Nessus ReportHost / OpenVAS result. Empty if not structured."""
    try:
        root = ET.fromstring(blob or "")
    except ET.ParseError:
        return []
    pairs: list[tuple[str, str]] = []
    for host_el in root.iter():
        if _xml_local(host_el.tag) != "reporthost":
            continue
        asset = str(host_el.attrib.get("name") or "").strip()
        for child in host_el.iter():
            for cve in _cves_on_element(child):
                pairs.append((cve, asset))
    for result in root.iter():
        if _xml_local(result.tag) != "result":
            continue
        asset = ""
        for child in list(result):
            if _xml_local(child.tag) == "host":
                asset = (child.text or "").strip()
                break
        if not asset:
            continue
        for child in result.iter():
            for cve in _cves_on_element(child):
                pairs.append((cve, asset))
    return pairs


def _vuln_row(cve: str, address: str, *, adapter: str) -> dict[str, Any]:
    row = _row(cve, address, "high", adapter=adapter)
    row["claim"] = CLAIM_VULN
    row["cve"] = cve
    return row


def findings_from_file_drop(
    blob: str, *, host: str = "", adapter: str = "openvas"
) -> list[dict[str, Any]]:
    """Real CVE/id from OpenVAS/Nessus-class file_drop only. Never from nmap HTTP."""
    if not _looks_like_file_drop_vuln(blob):
        return []
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    hint = (host or "").strip()
    if hint == "file_drop":
        hint = ""
    for cve, asset in _cves_from_scanner_xml(blob):
        address = (asset or hint).strip()
        if not address:
            continue
        key = (cve, address)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_vuln_row(cve, address, adapter=adapter))
    if rows:
        return rows
    if not hint:
        return rows
    for match in CVE_RE.finditer(blob or ""):
        cve = match.group(0).upper()
        key = (cve, hint)
        if key in seen:
            continue
        seen.add(key)
        rows.append(_vuln_row(cve, hint, adapter=adapter))
    return rows
