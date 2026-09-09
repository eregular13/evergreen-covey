# Evergreen Covey

SCOPE-gated Lego for **sharded BYO scanner workers**. Covey plans tiles,
fans out a small worker pool, lands artifacts, and optionally deepens only
the hosts that answered. It does not ship a scanner.

Twenty live BYO adapters (nmap, masscan, rustscan, naabu, fping, arp-scan,
netdiscover, zmap, unicornscan, nping, hping3, ike-scan, nbtscan,
onesixtyone, braa, svmap, sslscan, whatweb, httpx, tlsx). The operator
provides the binary. **Nmap** is the first e2e-proven path (`make prove`).
**rustscan** is the second (`python -m covey prove --adapter rustscan`).
**fping** is the third (`python -m covey prove --adapter fping`).
**naabu** is the fourth (`python -m covey prove --adapter naabu`).
**nping** is the fifth (`python -m covey prove --adapter nping`).
**httpx** is the sixth (`python -m covey prove --adapter httpx`).
**sslscan** is the seventh (`python -m covey prove --adapter sslscan`).
**tlsx** is the eighth (`python -m covey prove --adapter tlsx`).
**whatweb** is the ninth (`python -m covey prove --adapter whatweb`).
**hping3** is the tenth (`python -m covey prove --adapter hping3`).
**onesixtyone** is the eleventh (`python -m covey prove --adapter onesixtyone`).
**nbtscan** is the twelfth (`python -m covey prove --adapter nbtscan`).
**braa** is the thirteenth (`python -m covey prove --adapter braa`).
**ike-scan** is the fourteenth (`python -m covey prove --adapter ike-scan`).
**svmap** is the fifteenth (`python -m covey prove --adapter svmap`).
The other 5 remain argv+unit only — do not claim them live. Source of
truth: `E2E_PROVEN_ADAPTERS` (`nmap`, `rustscan`, `fping`, `naabu`,
`nping`, `httpx`, `sslscan`, `tlsx`, `whatweb`, `hping3`, `onesixtyone`,
`nbtscan`, `braa`, `ike-scan`, `svmap`) in
`src/covey/adapters/registry.py`. See
[ADAPTERS.md](ADAPTERS.md) and [PROVE.md](PROVE.md).

```
discover shards → land XML/gnmap → optional pass2 on live hosts
```

This is orchestration. The scanner stays yours.

## What it is not

- Not an Nmap distribution
- Not a vulnerability farm
- Not a wrapper collection for OpenVAS, Nuclei, Wazuh, osquery, BloodHound,
  PingCastle, or RiskReady — see [LICENSE-LOCK.md](LICENSE-LOCK.md)

OpenVAS-class tools, if added later, are **file_drop only**. Covey will not
spawn them.

## Quick prove

The operator (or the prove VM) must provide Nmap. `make prove` will use
`PATH` / `COVEY_NMAP`, or install Nmap **on this machine only** via apt so
the pipeline can be exercised. Nothing is committed.

```bash
make prove
# or
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m covey prove
.venv/bin/pytest -q
```

On Debian/Ubuntu, `python3.12-venv` is required for the virtualenv. `make prove`
will apt-install that package if `python3 -m venv` fails.

The committed nmap lab SCOPE tiles loopback `127.0.0.0/28` into four `/30`s,
runs pass1 (`nmap -sn`) with `max_workers: 2`, then pass2 (`nmap -sV`)
only against hosts that pass1 marked up. Artifacts land in `out/shards/`.

rustscan uses the same tile honesty (`examples/scope.lab.rustscan.yaml`,
`adapter: rustscan`, SCOPE ports `18080`) plus a loopback lab listener —
rustscan is a port scanner, not a ping sweep. fping uses
`examples/scope.lab.fping.yaml` (`adapter: fping`) and ICMP on loopback
— no listener. naabu uses `examples/scope.lab.naabu.yaml` (`adapter:
naabu`, SCOPE ports `18080`) and the same loopback lab listener; pass1
is a connect scan of those SCOPE ports, not `-top-ports 100`. nping
uses `examples/scope.lab.nping.yaml` (`adapter: nping`, SCOPE ports
`18080`) and the same loopback lab listener; pass1 is unprivileged
`--tcp-connect`, not raw `--icmp`/`--tcp` (those need root). httpx
uses `examples/scope.lab.httpx.yaml` (`adapter: httpx`, SCOPE ports
`18080`) and an HTTP/1.1 200 lab on those same addresses — bare TCP
accept is not enough. sslscan uses `examples/scope.lab.sslscan.yaml`
(`adapter: sslscan`, SCOPE ports `18080`) and a TLS lab on those same
addresses — HTTP 200 is not enough. tlsx uses
`examples/scope.lab.tlsx.yaml` (`adapter: tlsx`, SCOPE ports `18080`)
and the same TLS lab — HTTP 200 is not enough. whatweb uses
`examples/scope.lab.whatweb.yaml` (`adapter: whatweb`, SCOPE ports
`18080`) and the same HTTP/1.1 200 lab httpx uses — bare TCP accept
is not enough. hping3 uses `examples/scope.lab.hping3.yaml`
(`adapter: hping3`) and ICMP on loopback — no listener. Raw sockets
need `CAP_NET_RAW` (or root). onesixtyone uses
`examples/scope.lab.onesixtyone.yaml` (`adapter: onesixtyone`, SCOPE
ports `18080`) and an SNMPv1 GetResponse lab on those same addresses —
a UDP echo is not enough. nbtscan uses
`examples/scope.lab.nbtscan.yaml` (`adapter: nbtscan`) and an NBSTAT
lab on UDP/137 on those same addresses — a UDP echo is not enough.
braa uses `examples/scope.lab.braa.yaml` (`adapter: braa`, SCOPE
ports `18080`) and the same SNMPv1 GetResponse lab onesixtyone uses —
a UDP echo is not enough, and the request-id must be echoed.
ike-scan uses `examples/scope.lab.ike-scan.yaml` (`adapter: ike-scan`,
SCOPE ports `18080`) and an ISAKMP lab on those same addresses — a
UDP echo is not enough (CKY-R=0 is the initiator packet reflected).
svmap uses `examples/scope.lab.svmap.yaml` (`adapter: svmap`, SCOPE
ports `18080`) and a SIP/2.0 200 lab on those same addresses — a
UDP echo is not enough (svmap ignores its own OPTIONS packet).
arp-scan has no L2 on loopback and stays argv+unit.
See [PROVE.md](PROVE.md).

## BYO scanners

SCOPE `adapter:` selects one of the 20 live ids. Resolve order:

1. `COVEY_<TOOL>` — absolute path, binary name, or `docker://<image>`
   (`COVEY_NMAP`, `COVEY_ARP_SCAN`, …)
2. `COVEY_BIN` — same shapes, any adapter
3. the tool name on `PATH`
4. `COVEY_<TOOL>_IMAGE` if set (Docker required)
5. **nmap only**: `COVEY_NMAP_IMAGE` / `docker://instrumentisto/nmap` if Docker is present

```bash
export COVEY_NMAP=/usr/bin/nmap
# or a compose service image that already contains nmap:
export COVEY_NMAP=docker://your-registry/lab-nmap:local
python -m covey run --scope examples/scope.lab.yaml --out out
```

Covey never vendors an Nmap binary and never apt-installs into the git tree.

## SCOPE

Live runs require a **signed** SCOPE document. Unsigned or empty YAML is
refused. Demo documents use HMAC-SHA256 with the well-known key
`evergreen-covey-demo` when `demo: true`. Production-like documents must
set `COVEY_SCOPE_HMAC_KEY`.

```yaml
version: 1
demo: true
consent:
  signed: true
  signer: prove-lab
  purpose: evergreen-covey loopback prove
window:
  start: "2026-01-01T00:00:00Z"
  end: "2029-12-31T23:59:59Z"
adapter: nmap            # one of the 20 live ids; see ADAPTERS.md
max_workers: 2          # cap 1–4; default 2
allow_wide: false
tile:
  default_prefix: 24
  small_prefix: 30      # lab /28 → four /30 tiles
pass2:
  ports: "22"           # SCOPE-owned deepen ports (Palisade P0)
targets:
  - cidr: 127.0.0.0/28
```

`pass2.ports` (alias `deepen.ports`) is the honest deepen surface — not a
silent adapter default. Omit it to keep the adapter's built-in list; set it
to declare the ports the operator actually consented to. Empty or injectable
port strings are refused. Unsigned or empty SCOPE is still refused.

Sign a document in place:

```bash
python -m covey sign --scope path/to/scope.yaml
```

### Fail-closed spray

Refused unless noted:

| Target | Result |
| --- | --- |
| `0.0.0.0/0`, `*`, `any` | always refused |
| `/8`–`/16` | refused unless `allow_wide: true` **and** that parent CIDR is listed verbatim |
| wider than `/8` | always refused |

Default prove uses a tiny loopback `/28`, not a real `/8`. Operators who
need an RFC1918 lab substitute their own listed CIDRs (a `/28` or a
handful of `/30`s) and re-sign.

The consent window is enforced. Outside the window, Covey refuses to plan
or run.

## CLI

```bash
python -m covey plan --scope examples/scope.lab.yaml --out out/plan.json
python -m covey run  --scope examples/scope.lab.yaml --out out
python -m covey prove
python -m covey prove --adapter rustscan
python -m covey prove --adapter fping
python -m covey prove --adapter naabu
python -m covey prove --adapter nping
python -m covey prove --adapter httpx
python -m covey prove --adapter sslscan
python -m covey prove --adapter tlsx
python -m covey prove --adapter whatweb
python -m covey prove --adapter hping3
python -m covey prove --adapter onesixtyone
python -m covey prove --adapter nbtscan
python -m covey prove --adapter braa
python -m covey prove --adapter ike-scan
python -m covey prove --adapter svmap
python -m covey export --out out
# or
make export
```

`plan` writes worker JSON (shard id, target, stage, argv / argv template)
and does **not** invoke a scanner.

`export` reads a prove/run `out/` and writes `out/pack_drop/` for the
assessment MCP / `grc-collector-pack` **file_drop** (assets, conservative
open-port findings, small evidence copies). It does **not** POST anywhere
and does not wrap RiskReady. Honesty baked into `meta.json` and
`README_EXPORT.md`: surface map ≠ honeypot validated ≠ control operating
effectiveness. See [`docs/EVIDENCE_MATRIX.md`](docs/EVIDENCE_MATRIX.md).

## Layout

| Module | Role |
| --- | --- |
| `covey.scope` | load SCOPE, validate consent / window / targets / pass2 ports, HMAC |
| `covey.shard` | expand allowed CIDRs into tiles (pure) |
| `covey.plan` | worker plan JSON, no spawn |
| `covey.runner` | local subprocess or `docker run`; land stdout/stderr/xml |
| `covey.export` | Seen → SoR-ready `pack_drop/` (file_drop only) |
| `covey.adapters` | 20 live BYO argv+parse adapters + OpenVAS file_drop stub |

See [`ADAPTERS.md`](ADAPTERS.md) and
[`src/covey/adapters/README.md`](src/covey/adapters/README.md).

## Tests

```bash
.venv/bin/pytest -q -m "not integration"   # shard math, SCOPE refuse, argv
.venv/bin/pytest -q -m integration         # real nmap through the runner
```
