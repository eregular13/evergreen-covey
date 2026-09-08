# Evergreen Covey

SCOPE-gated Lego for **sharded BYO scanner workers**. Covey plans tiles,
fans out a small worker pool, lands artifacts, and optionally deepens only
the hosts that answered. It does not ship a scanner.

Twenty live BYO adapters (nmap, masscan, rustscan, naabu, fping, arp-scan,
netdiscover, zmap, unicornscan, nping, hping3, ike-scan, nbtscan,
onesixtyone, braa, svmap, sslscan, whatweb, httpx, tlsx). The operator
provides the binary. **Nmap** is the proven end-to-end path (`make prove`).
See [ADAPTERS.md](ADAPTERS.md).

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

The committed lab SCOPE tiles loopback `127.0.0.0/28` into four `/30`s,
runs pass1 (`nmap -sn`) with `max_workers: 2`, then pass2 (`nmap -sV`)
only against hosts that pass1 marked up. Artifacts land in `out/shards/`.

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
targets:
  - cidr: 127.0.0.0/28
```

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
```

`plan` writes worker JSON (shard id, target, stage, argv / argv template)
and does **not** invoke a scanner.

## Layout

| Module | Role |
| --- | --- |
| `covey.scope` | load SCOPE, validate consent / window / targets, HMAC |
| `covey.shard` | expand allowed CIDRs into tiles (pure) |
| `covey.plan` | worker plan JSON, no spawn |
| `covey.runner` | local subprocess or `docker run`; land stdout/stderr/xml |
| `covey.adapters` | 20 live BYO argv+parse adapters + OpenVAS file_drop stub |

See [`ADAPTERS.md`](ADAPTERS.md) and
[`src/covey/adapters/README.md`](src/covey/adapters/README.md).

## Tests

```bash
.venv/bin/pytest -q -m "not integration"   # shard math, SCOPE refuse, argv
.venv/bin/pytest -q -m integration         # real nmap through the runner
```
