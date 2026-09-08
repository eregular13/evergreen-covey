# Evergreen Covey — live BYO adapters

Covey is orchestration only. Operators bring binaries (`PATH`, `COVEY_<TOOL>`,
`COVEY_BIN`, or `docker://<image>`). Nothing in this table is vendored.

**E2E-proven live (real BYO binary + signed loopback lab): `nmap` (first),
`rustscan` (second), `fping` (third), `naabu` (fourth), `nping`
(fifth), `httpx` (sixth), `sslscan` (seventh), `tlsx` (eighth),
`whatweb` (ninth).** The other 11 ids are argv+unit only. Source of
truth: `E2E_PROVEN_ADAPTERS` in `src/covey/adapters/registry.py`. See
[PROVE.md](PROVE.md). Do not claim them live.

The prove VM may install nmap (apt; also ships nping), rustscan (GitHub
release / cargo), fping (apt), naabu (GitHub release / go), httpx
(GitHub release / go), sslscan (apt), tlsx (GitHub release / go), or
whatweb (apt) **on that machine only** — never into git.

SCOPE selects the tool with `adapter: <id>`. Unknown ids are refused.
OpenVAS / Greenbone / GVM are **file_drop only** (no live argv). Nuclei,
Wazuh, osquery, BloodHound, PingCastle, and RiskReady are LICENSE-LOCK
forbidden.

| id | binary | pass1 | pass2 | parse notes | BYO env |
| --- | --- | --- | --- | --- | --- |
| `nmap` | `nmap` | `-sn` ping/discover on the tile | `-sV` on pass1-live hosts only; ports from SCOPE `pass2.ports` (else `22`) | XML `status=up` / gnmap `Status: Up` | `COVEY_NMAP` |
| `masscan` | `masscan` | `-p80,443` JSON on the CIDR | extra ports on live hosts | masscan `-oJ` `ip` + open ports | `COVEY_MASSCAN` |
| `rustscan` | `rustscan` | `-a <cidr> -g -p <SCOPE ports>` (no nmap `--`; **2nd e2e-proven**) | `-a <hosts> -p <SCOPE ports>` rustscan-only | `ip -> [ports]` / `Open a.b.c.d:port` | `COVEY_RUSTSCAN` |
| `naabu` | `naabu` | `-host <cidr> -silent -p <SCOPE ports> -scan-type connect` (**4th e2e-proven**) | `-host <hosts> -p <SCOPE ports>` connect | `ip:port` lines | `COVEY_NAABU` |
| `fping` | `fping` | `-aqg <net> <broadcast>` (**3rd e2e-proven**; ICMP) | `-a -c 3` live hosts | alive IPs on stdout | `COVEY_FPING` |
| `arp-scan` | `arp-scan` | CIDR local ARP sweep | retry/timeout deepen on hosts | first-column IPv4 + MAC | `COVEY_ARP_SCAN` |
| `netdiscover` | `netdiscover` | `-P -N -r <cidr>` | `-r host/32` per live host | ARP table IPv4 | `COVEY_NETDISCOVER` |
| `zmap` | `zmap` | `-p 80` on the tile (`-B /dev/null` so RFC1918 labs work) | `-p 443` on `host/32` list | one IPv4 per line | `COVEY_ZMAP` |
| `unicornscan` | `unicornscan` | `-mT <cidr>:80,443` | `-mT host:22,80,443,3389` | `TCP open a.b.c.d:port` | `COVEY_UNICORNSCAN` |
| `nping` | `nping` | `--tcp-connect -p <SCOPE ports>` tile hosts (**5th e2e-proven**) | `--tcp-connect` live hosts | `Handshake with ip:port completed` (not refused `RCVD`) | `COVEY_NPING` |
| `hping3` | `hping3` | `--icmp` to **tile broadcast** (single dest) | `--syn -p 80` first live host | `ip=a.b.c.d` reply lines | `COVEY_HPING3` |
| `ike-scan` | `ike-scan` | IKE Main Mode on the CIDR | `--aggressive --id=vpn` hosts | handshake IPv4 | `COVEY_IKE_SCAN` |
| `nbtscan` | `nbtscan` | `-s :` NetBIOS on the CIDR | `-v` on live hosts | leading IPv4 / name table | `COVEY_NBTSCAN` |
| `onesixtyone` | `onesixtyone` | SNMP `public/private` over tile hosts file | extra communities on live hosts | `ip [community] …` | `COVEY_ONESIXTYONE` |
| `braa` | `braa` | `public@first-last:sysDescr` | sysDescr + sysName per host | `ip:oid:value` | `COVEY_BRAA` |
| `svmap` | `svmap` | SIP sweep of the CIDR (`sipvicious`) | `--fp` fingerprint live hosts | SIP device IPv4 | `COVEY_SVMAP` |
| `sslscan` | `sslscan` | TLS probe of the **first usable tile host** as `host:<SCOPE port>` (**7th e2e-proven**) | `--show-certificate` first live host | `Connected to` / XML host (not refused `ERROR`) | `COVEY_SSLSCAN` |
| `whatweb` | `whatweb` | `-a 1` `http://host:<SCOPE port>` tile hosts (**9th e2e-proven**) | `-a 3` on live host URLs | `http://ip` brief log (not banner `IP[]`) | `COVEY_WHATWEB` |
| `httpx` | `httpx` | `-silent -l` tile hosts file `-p <SCOPE ports>` (**6th e2e-proven**) | title/status/tech on live hosts | `http(s)://ip` lines | `COVEY_HTTPX` |
| `tlsx` | `tlsx` | `-silent -l` tile hosts file `-p <SCOPE ports>` (**8th e2e-proven**) | `-san -cn` on live hosts | `ip:port` TLS lines | `COVEY_TLSX` |

## Limits (honest)

- **hping3** / **ping**: one destination per process. pass1 uses the tile
  broadcast (`ping -b`) so replies can name hosts; pass2 deepens the first
  live host.
- **sslscan**: one target per process. pass1 is the first usable host of the
  already-tiled CIDR (Covey tiles; a `/30` is two hosts) as
  `host:<SCOPE port>` (default `443`). Seventh e2e-proven adapter
  (`python -m covey prove --adapter sslscan` / `make prove-sslscan`).
  Prove serves TLS on the same loopback addresses rustscan / naabu /
  nping / httpx / tlsx bind. Bare TCP accept and plain HTTP are not enough:
  sslscan prints `Connected to` only after a TLS handshake. Parse
  requires `Connected to` / XML `ssltest host`; connection-refused
  `ERROR` lines name the IP but are not live hosts. Pass1 uses SCOPE
  `pass2.ports` (lab default `18080`).
- **onesixtyone** / **httpx** / **tlsx**: the runner writes `{out_prefix}.hosts`
  (and `.comm` for onesixtyone) next to artifacts before spawn. argv still
  invokes only that tool.
- **zmap**: `-B /dev/null` turns off the default public blocklist so a
  SCOPE-approved RFC1918 tile is reachable. SCOPE spray rules are unchanged.
- **rustscan**: never appends `--` nmap flags. Deepen stays rustscan-only.
  Second e2e-proven adapter (`python -m covey prove --adapter rustscan`).
  Pass1 uses SCOPE `pass2.ports` (lab default `18080`) so the loopback
  prove is a tiny port list, not a 65535-port spray.
- **fping**: ICMP host discovery, not a port scanner. Third e2e-proven
  adapter (`python -m covey prove --adapter fping` / `make prove-fping`).
  Loopback answers; no TCP lab listener. Lab SCOPE omits `pass2.ports`.
- **naabu**: connect-scan port discover, not a ping sweep. Fourth
  e2e-proven adapter (`python -m covey prove --adapter naabu` /
  `make prove-naabu`). Pass1 uses SCOPE `pass2.ports` (lab default
  `18080`) so the loopback prove is a tiny port list, not `-top-ports
  100`. masscan was preferred first; it cannot observe loopback SYN
  replies, so it stays argv+unit only.
- **nping**: unprivileged `--tcp-connect` against SCOPE ports, not raw
  `--icmp`/`--tcp` (those need root). Fifth e2e-proven adapter
  (`python -m covey prove --adapter nping` / `make prove-nping`).
  Prove binds the same loopback lab listener as rustscan/naabu.
  Parse requires `Handshake with ip:port completed`; Connection
  refused `RCVD` lines are not live hosts.
- **httpx**: HTTP probe, not a TCP connect scan. Sixth e2e-proven
  adapter (`python -m covey prove --adapter httpx` / `make prove-httpx`).
  Prove serves HTTP/1.1 200 on the same loopback addresses rustscan /
  naabu / nping bind. Bare TCP accept is not enough: httpx prints
  nothing unless the peer speaks HTTP. Pass1 uses SCOPE `pass2.ports`
  (lab default `18080`). Parse requires `http(s)://ip` lines.
- **tlsx**: TLS handshake probe, not HTTP or a TCP connect scan. Eighth
  e2e-proven adapter (`python -m covey prove --adapter tlsx` /
  `make prove-tlsx`). Prove serves TLS on the same loopback addresses
  rustscan / naabu / nping / httpx / sslscan bind. Bare TCP accept and
  plain HTTP are not enough: tlsx prints `ip:port` only after a TLS
  handshake. Pass1 uses SCOPE `pass2.ports` (lab default `18080`).
  Parse requires leading `ip:port` lines; banner/SAN IPs are ignored.
- **whatweb**: HTTP fingerprint, not a TCP connect scan. Ninth e2e-proven
  adapter (`python -m covey prove --adapter whatweb` /
  `make prove-whatweb`). Prove serves HTTP/1.1 200 on the same loopback
  addresses rustscan / naabu / nping / httpx bind. Bare TCP accept is
  not enough: whatweb prints `http://ip` only after an HTTP reply.
  Pass1 uses SCOPE `pass2.ports` (lab default `18080`) as
  `http://host:<port>`. Parse requires leading `http(s)://ip` brief-log
  lines; plugin/banner IPs are ignored.
- **SCOPE `pass2.ports` / `deepen.ports`**: deepen port lists are
  operator-declared. Adapters keep their built-in default when the field is
  omitted. Empty or injectable strings are refused. Single-port tools
  (zmap, nping, hping3, sslscan, whatweb) use the first listed port.

## Resolution

1. `COVEY_<ID>` with hyphens → underscores (`COVEY_ARP_SCAN`)
2. `COVEY_BIN` (path, name, or `docker://image`)
3. binary name on `PATH` (`svmap` also tries `sipvicious_svmap`)
4. `COVEY_<ID>_IMAGE` if set (docker required)
5. **nmap only**: `COVEY_NMAP_IMAGE` or `docker://instrumentisto/nmap` when
   Docker is present

Docker entrypoint defaults to the adapter id. Override with
`COVEY_<ID>_ENTRYPOINT` or `COVEY_ENTRYPOINT`.

## Not live adapters

| id | behavior |
| --- | --- |
| `openvas`, `greenbone`, `gvm` | `file_drop_only`; `adapter_for()` raises; argv methods raise |
| `nuclei`, `wazuh`, `osquery`, `bloodhound`, `pingcastle`, `riskready` | LICENSE-LOCK refuse |
