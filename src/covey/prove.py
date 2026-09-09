"""End-to-end prove: BYO nmap, rustscan, fping, naabu, nping, httpx, sslscan, tlsx, whatweb, or hping3; sharded loopback; multi-pass artifacts."""

from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

from covey.adapters.base import Adapter
from covey.adapters.registry import E2E_PROVEN_ADAPTERS, adapter_for
from covey.errors import CoveyError, RunnerError
from covey.plan import build_plan
from covey.runner import (
    ensure_fping,
    ensure_hping3,
    ensure_httpx,
    ensure_naabu,
    ensure_nmap,
    ensure_nping,
    ensure_rustscan,
    ensure_sslscan,
    ensure_tlsx,
    ensure_whatweb,
    run_plan,
)
from covey.scope import load

LAB_SCOPE = Path("examples/scope.lab.yaml")
RUSTSCAN_LAB_SCOPE = Path("examples/scope.lab.rustscan.yaml")
FPING_LAB_SCOPE = Path("examples/scope.lab.fping.yaml")
NAABU_LAB_SCOPE = Path("examples/scope.lab.naabu.yaml")
NPING_LAB_SCOPE = Path("examples/scope.lab.nping.yaml")
HTTPX_LAB_SCOPE = Path("examples/scope.lab.httpx.yaml")
SSLSCAN_LAB_SCOPE = Path("examples/scope.lab.sslscan.yaml")
TLSX_LAB_SCOPE = Path("examples/scope.lab.tlsx.yaml")
WHATWEB_LAB_SCOPE = Path("examples/scope.lab.whatweb.yaml")
HPING3_LAB_SCOPE = Path("examples/scope.lab.hping3.yaml")
LAB_SCOPES = {
    "nmap": LAB_SCOPE,
    "rustscan": RUSTSCAN_LAB_SCOPE,
    "fping": FPING_LAB_SCOPE,
    "naabu": NAABU_LAB_SCOPE,
    "nping": NPING_LAB_SCOPE,
    "httpx": HTTPX_LAB_SCOPE,
    "sslscan": SSLSCAN_LAB_SCOPE,
    "tlsx": TLSX_LAB_SCOPE,
    "whatweb": WHATWEB_LAB_SCOPE,
    "hping3": HPING3_LAB_SCOPE,
}

# First usable host of each /30 tile of 127.0.0.0/28.
RUSTSCAN_LAB_BIND = ("127.0.0.1", "127.0.0.5", "127.0.0.9", "127.0.0.13")
RUSTSCAN_LAB_PORT = 18080


def _artifact_ok(directory: Path, adapter_name: str) -> bool:
    if adapter_name == "nmap":
        return (directory / "scan.xml").is_file() or (directory / "scan.gnmap").is_file()
    if adapter_name in {
        "rustscan",
        "fping",
        "naabu",
        "nping",
        "httpx",
        "sslscan",
        "tlsx",
        "whatweb",
        "hping3",
    }:
        argv_path = directory / "argv.json"
        stdout_path = directory / "stdout.log"
        if not argv_path.is_file() or not stdout_path.is_file():
            return False
        try:
            argv = json.loads(argv_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        if not isinstance(argv, list) or not argv:
            return False
        return adapter_name in str(argv[0]).lower()
    return False


def assert_report(plan, report, out_root: Path, *, adapter_name: str = "nmap") -> None:
    if len(plan.shards) < 2 and len(plan.pass1_workers) < 2:
        raise RunnerError("prove requires ≥2 shards or ≥2 pass1 workers")
    if not report.pass1:
        raise RunnerError("prove: no pass1 workers ran")
    failed = [r for r in report.pass1 if not r.ok]
    if failed:
        raise RunnerError(
            "prove: pass1 workers failed: "
            + ", ".join(f"{r.id}={r.exit_code}" for r in failed)
        )

    landed = 0
    for result in report.pass1:
        artifact_dir = Path(result.artifact_dir)
        if _artifact_ok(artifact_dir, adapter_name):
            landed += 1
        else:
            kind = "XML/gnmap" if adapter_name == "nmap" else f"{adapter_name} stdout/argv"
            raise RunnerError(f"prove: missing {kind} under {artifact_dir}")

    live = report.all_pass1_hosts()
    if not live:
        raise RunnerError("prove: pass1 found no live hosts on the loopback lab")

    ran_pass2 = [r for r in report.pass2 if not r.skipped]
    if not ran_pass2:
        raise RunnerError("prove: pass2 did not run against any live hosts")

    allowed = set(live)
    for result in ran_pass2:
        if not _artifact_ok(Path(result.artifact_dir), adapter_name):
            raise RunnerError(f"prove: missing pass2 artifacts under {result.artifact_dir}")
        targeted = [h for h in result.target.split(",") if h]
        extra = [h for h in targeted if h not in allowed]
        if extra:
            raise RunnerError(
                f"prove: pass2 {result.id} targeted hosts not in pass1: {extra}"
            )
        if not targeted:
            raise RunnerError(f"prove: pass2 {result.id} had no targets")
        if not result.ok:
            raise RunnerError(f"prove: pass2 {result.id} failed ({result.exit_code})")

    if not (out_root / "run_report.json").is_file():
        raise RunnerError("prove: run_report.json missing")
    if not report.ok:
        raise RunnerError("prove: runner report is not ok")
    if landed < 2:
        raise RunnerError("prove: expected artifacts for at least two shards")


def _lab_port(scope) -> int:
    raw = getattr(getattr(scope, "deepen", None), "ports", None) or str(RUSTSCAN_LAB_PORT)
    token = str(raw).split(",")[0].strip()
    try:
        port = int(token)
    except ValueError as exc:
        raise RunnerError(f"port-scanner lab port is not an integer: {raw!r}") from exc
    if not 1 <= port <= 65535:
        raise RunnerError(f"port-scanner lab port out of range: {port}")
    return port


@contextmanager
def loopback_lab_listeners(
    hosts: tuple[str, ...] = RUSTSCAN_LAB_BIND,
    port: int = RUSTSCAN_LAB_PORT,
) -> Iterator[tuple[str, int]]:
    """Bind a tiny TCP lab on loopback tiles so port scanners can observe opens.

    rustscan, naabu, and nping --tcp-connect are TCP probes (unlike nmap
    ``-sn``, fping, and hping3 ``--icmp``). Without a listener, pass1 finds
    no live hosts and prove fails closed. This is lab fixture, not a
    forged scanner result. httpx and whatweb need ``loopback_http_lab``
    (HTTP 200). sslscan and tlsx need ``loopback_tls_lab`` (a TLS
    handshake). Neither is this bare accept.
    """
    sockets: list[socket.socket] = []
    stop = threading.Event()

    def accept_loop(sock: socket.socket) -> None:
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                conn.close()
            except OSError:
                pass

    try:
        for host in hosts:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError as exc:
                sock.close()
                raise RunnerError(
                    f"port-scanner lab cannot bind {host}:{port}: {exc}"
                ) from exc
            sock.listen(32)
            sock.settimeout(0.25)
            sockets.append(sock)
            threading.Thread(target=accept_loop, args=(sock,), daemon=True).start()
        yield hosts[0], port
    finally:
        stop.set()
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


class _LabHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = b"covey-httpx-lab\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@contextmanager
def loopback_http_lab(
    hosts: tuple[str, ...] = RUSTSCAN_LAB_BIND,
    port: int = RUSTSCAN_LAB_PORT,
) -> Iterator[tuple[str, int]]:
    """Serve HTTP/1.1 200 on loopback tiles so httpx/whatweb can observe live URLs.

    Bare TCP accept is not enough: httpx and whatweb print nothing unless
    the peer speaks HTTP. This is lab fixture, not a forged scanner result.
    """
    servers: list[ThreadingHTTPServer] = []
    try:
        for host in hosts:
            try:
                server = ThreadingHTTPServer((host, port), _LabHTTPHandler)
            except OSError as exc:
                raise RunnerError(
                    f"HTTP lab cannot bind HTTP {host}:{port}: {exc}"
                ) from exc
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        yield hosts[0], port
    finally:
        for server in servers:
            try:
                server.shutdown()
            except OSError:
                pass
            try:
                server.server_close()
            except OSError:
                pass


@contextmanager
def loopback_tls_lab(
    hosts: tuple[str, ...] = RUSTSCAN_LAB_BIND,
    port: int = RUSTSCAN_LAB_PORT,
) -> Iterator[tuple[str, int]]:
    """Serve TLS on loopback tiles so sslscan/tlsx can observe a handshake.

    Bare TCP accept and plain HTTP are not enough: sslscan prints
    ``Connected to`` and tlsx prints ``ip:port`` only after a TLS
    handshake. This is lab fixture, not a forged scanner result. The
    ephemeral cert stays off git.
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RunnerError(
            "TLS lab needs openssl on PATH to mint a throwaway loopback cert"
        )
    servers: list[ThreadingHTTPServer] = []
    with tempfile.TemporaryDirectory(prefix="covey-tls-lab-") as tmp:
        work = Path(tmp)
        cert = work / "cert.pem"
        key = work / "key.pem"
        minted = subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if minted.returncode != 0 or not cert.is_file() or not key.is_file():
            raise RunnerError(
                "TLS lab could not mint a throwaway TLS cert: "
                + (minted.stderr or minted.stdout)[-400:]
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        try:
            for host in hosts:
                try:
                    server = ThreadingHTTPServer((host, port), _LabHTTPHandler)
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                except OSError as exc:
                    raise RunnerError(
                        f"TLS lab cannot bind TLS {host}:{port}: {exc}"
                    ) from exc
                server.daemon_threads = True
                threading.Thread(target=server.serve_forever, daemon=True).start()
                servers.append(server)
            yield hosts[0], port
        finally:
            for server in servers:
                try:
                    server.shutdown()
                except OSError:
                    pass
                try:
                    server.server_close()
                except OSError:
                    pass


def _ensure_binary(adapter: Adapter, *, install_if_missing: bool):
    name = adapter.name
    if name == "nmap":
        return ensure_nmap(install_if_missing=install_if_missing)
    if name == "rustscan":
        return ensure_rustscan(install_if_missing=install_if_missing)
    if name == "fping":
        return ensure_fping(install_if_missing=install_if_missing)
    if name == "naabu":
        return ensure_naabu(install_if_missing=install_if_missing)
    if name == "nping":
        return ensure_nping(install_if_missing=install_if_missing)
    if name == "httpx":
        return ensure_httpx(install_if_missing=install_if_missing)
    if name == "sslscan":
        return ensure_sslscan(install_if_missing=install_if_missing)
    if name == "tlsx":
        return ensure_tlsx(install_if_missing=install_if_missing)
    if name == "whatweb":
        return ensure_whatweb(install_if_missing=install_if_missing)
    if name == "hping3":
        return ensure_hping3(install_if_missing=install_if_missing)
    raise RunnerError(
        f"prove is e2e-live only for {', '.join(E2E_PROVEN_ADAPTERS)}; "
        f"{name} remains argv+unit only"
    )


def run_prove(
    *,
    out_root: Path | str = "out",
    scope_path: Path | str | None = None,
    adapter: str | None = None,
    install_if_missing: bool = True,
) -> dict:
    out = Path(out_root)
    out.mkdir(parents=True, exist_ok=True)
    wanted = (adapter or "").strip().lower() or None
    if scope_path:
        path = Path(scope_path)
    elif wanted:
        path = LAB_SCOPES.get(wanted)
        if path is None:
            raise RunnerError(
                f"prove is e2e-live only for {', '.join(E2E_PROVEN_ADAPTERS)}; "
                f"{wanted} remains argv+unit only"
            )
    else:
        path = LAB_SCOPE
    if not path.is_file():
        raise RunnerError(f"prove SCOPE not found: {path}")

    scope = load(path)
    if wanted and scope.adapter != wanted:
        raise RunnerError(
            f"SCOPE adapter is {scope.adapter!r}, prove --adapter {wanted}"
        )
    if scope.adapter not in E2E_PROVEN_ADAPTERS:
        raise RunnerError(
            f"prove is e2e-live only for {', '.join(E2E_PROVEN_ADAPTERS)}; "
            f"{scope.adapter} remains argv+unit only"
        )

    plugin = adapter_for(scope.adapter, deepen=scope.deepen)
    spec = _ensure_binary(plugin, install_if_missing=install_if_missing)
    plan = build_plan(scope, out_root=out, adapter=plugin)
    plan_path = out / "plan.json"
    plan_path.write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")

    def _execute():
        report = run_plan(plan, out_root=out, spec=spec, adapter=plugin)
        assert_report(plan, report, out, adapter_name=plugin.name)
        return report

    if plugin.name in {"httpx", "whatweb"}:
        with loopback_http_lab(port=_lab_port(scope)):
            report = _execute()
    elif plugin.name in {"sslscan", "tlsx"}:
        with loopback_tls_lab(port=_lab_port(scope)):
            report = _execute()
    elif plugin.name in {"rustscan", "naabu", "nping"}:
        with loopback_lab_listeners(port=_lab_port(scope)):
            report = _execute()
    else:
        report = _execute()

    summary = {
        "ok": True,
        "adapter": plugin.name,
        "exec": spec.display,
        "shards": plan.shards,
        "pass1_workers": len(plan.pass1_workers),
        "pass2_ran": sum(1 for r in report.pass2 if not r.skipped),
        "live_hosts": report.all_pass1_hosts(),
        "out": str(out),
    }
    (out / "prove.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        summary = run_prove()
    except CoveyError as exc:
        print(f"prove failed: {exc}")
        return 1
    print("Evergreen Covey prove: OK")
    print(f"  adapter     {summary.get('adapter', 'nmap')}")
    print(f"  exec        {summary['exec']}")
    print(f"  shards      {len(summary['shards'])} ({', '.join(summary['shards'])})")
    print(f"  pass1       {summary['pass1_workers']} workers")
    print(f"  pass2 ran   {summary['pass2_ran']}")
    print(f"  live hosts  {', '.join(summary['live_hosts'])}")
    print(f"  artifacts   {summary['out']}/shards/")
    return 0
