# Client-day — operator path

Loopback `prove` is a farm lab. A real engagement is a **signed SCOPE** plus
**BYO scanners on the engagement host**. Covey never vendors Nmap (or
masscan, rustscan, …). See [LICENSE-LOCK.md](../LICENSE-LOCK.md).

Source of truth for which adapters are e2e-proven:
`E2E_PROVEN_ADAPTERS` in `src/covey/adapters/registry.py`.
The other 4 (`masscan`, `arp-scan`, `netdiscover`, `zmap`) stay
**argv+unit only**. Do not claim them live. `python -m covey prove --adapter
masscan` (or any of the 4) **fails closed**.

## One-command SAMPLE dry (DESKTOP / client host)

Same shape as pack `sample_to_sor`: one script, no live client scan.

```bash
./scripts/client_day_dry.sh
# DESKTOP: .\scripts\client_day_dry.ps1
# or: make client-day-dry
# or: python -m covey client-day-dry
```

Uses [`examples/scope.client.example.yaml`](../examples/scope.client.example.yaml)
(copied into `out/client_day_dry/`; the committed template is not mutated):

1. **sign** with the well-known **demo/lab HMAC only** (`demo: true`). Production
   `COVEY_SCOPE_HMAC_KEY` is unset for this SAMPLE.
2. **ready --strict-e2e** — refuse the unproven four. Never install. Never spawn.
3. **plan** — worker JSON only. No scanner subprocess.
4. **export / pack_drop** from committed SAMPLE fixtures when a full `assess`
   would need BYO binaries. Missing BYO prints a clear miss list and fails
   closed (no `apt-get`, no GitHub release).

Prints `elapsed` and the `out/…/pack_drop` path when export is possible.
**SAMPLE ≠ client.** This is not a paying-day PASS and not a live estate.

## Operator sequence

1. Copy [`examples/scope.client.example.yaml`](../examples/scope.client.example.yaml).
   Replace signer, purpose, window, adapter, and **authorized** CIDRs/hosts.
   Do not leave `10.42.0.0/28` in a client document unless that range is
   actually in SCOPE.
2. Set `COVEY_SCOPE_HMAC_KEY` to the engagement secret (not the demo key,
   not git).
3. Sign: `python -m covey sign --scope scope.client.yaml`
   (`demo:` omitted + HMAC key ⇒ `demo: false`. `--demo` is lab-only.)
4. Preflight (no spawn, no install):
   `python -m covey ready --scope scope.client.yaml`
5. Optional dry plan: `python -m covey plan --scope scope.client.yaml --out out/plan.json`
6. Run + leave-behind:
   `python -m covey assess --scope scope.client.yaml --out out --target all`
   or `run` then `export --target all`.
7. Hand `out/pack_drop/` to the collector as **file_drop**. Do not POST to
   RiskReady. Live CISO/Probo stays dual-gated.

`ready` and `assess` never apt-install. Missing BYO is a fail-closed miss,
not a prove-install.

## Sixteen e2e-proven (loopback lab)

`nmap`, `rustscan`, `fping`, `naabu`, `nping`, `httpx`, `sslscan`, `tlsx`,
`whatweb`, `hping3`, `onesixtyone`, `nbtscan`, `braa`, `ike-scan`, `svmap`,
`unicornscan`.

On client-day they still need the operator binary on the **host** (`PATH`,
`COVEY_<TOOL>`, `COVEY_BIN`, or `docker://`). The farm does not ship them.
Targets must speak the protocol the tool probes (HTTP, TLS, SNMP, IKE,
SIP, ICMP, TCP). That is the client's authorized surface, not a lab
listener.

## Fail-closed four (argv+unit only)

| id | Why prove fails closed | Client-day if you still select it |
| --- | --- | --- |
| `masscan` | raw SYN; loopback `found=0` | DESKTOP/host: BYO masscan, non-loopback tile, `CAP_NET_RAW`/root + libpcap |
| `zmap` | raw SYN/pcap; loopback empty | DESKTOP/host: BYO zmap, non-loopback tile, `CAP_NET_RAW`/root + pcap |
| `arp-scan` | no L2 MAC on loopback | DESKTOP/host: BYO arp-scan, Ethernet iface (not `lo`) |
| `netdiscover` | loopback is not Ethernet | DESKTOP/host: BYO netdiscover, Ethernet iface (not `lo`) |

`ready --strict-e2e` refuses a SCOPE that names any of these four.
Without that flag, `plan` / `run` may still build argv if the operator
brought the binary — Covey does not invent a TAP/veth brick and does not
claim a live prove.

## DESKTOP/host BYO that remains even for proven ids

These ran on the loopback farm. A client network still needs host
capabilities Covey will not vendor:

| id | Host need |
| --- | --- |
| `hping3` | `CAP_NET_RAW` or root |
| `nbtscan` | NetBIOS UDP/137 (often privileged) |
| `unicornscan` | correct iface; `max_workers: 1`; readable `modules.conf` |
| every proven id | the BYO binary itself on the engagement host |
| production HMAC | `COVEY_SCOPE_HMAC_KEY` — off git |
| `docker://` | Docker on the host; nmap-only default image fallback |
| OpenVAS/Greenbone/GVM | **file_drop only** — operator-dropped XML, no live spawn |
| CISO / Probo `--live` | dual-gate env + `push/GATE_*` on the host; default is files only |
| Windows | never apt-install; put the binary on `PATH` and use `--no-install` for prove |

## Leave-behind honesty

`export` / `assess --target all` writes `out/pack_drop/`.

Pack ingest expects `schema: covey.pack_drop.v1` and meta `source: evergreen-covey`.

**surface map ≠ honeypot validated ≠ control operating effectiveness.**

| This drop is | This drop is not |
| --- | --- |
| Hosts/services the BYO tool printed | A vulnerability farm or invented CVE |
| `open_port_observed` when artifacts show `open` | Control operating effectiveness |
| `misconfig_observed` when httpx/sslscan/whatweb/nmap evidence supports it | SMBv1-from-HTTP or banner fiction |
| `vuln_ingested` only from OpenVAS/Nessus **file_drop** | A live OpenVAS adapter |
| `e2e_proven` / `unproven` in `meta.json` | A claim that an unproven tool was farm-proven |

Unknown catalog rows stay `UNMAPPED`. No RiskReady POST.

## What `prove` is not

`make prove` / `python -m covey prove` is the signed **loopback** lab. It
may install a missing binary **on that VM only**. It is not a client
engagement. Do not point prove at a client CIDR.
