# Evergreen Covey — live BYO adapters

Covey is orchestration only. Operators bring binaries (`PATH`, `COVEY_<TOOL>`,
`COVEY_BIN`, or `docker://<image>`). Nothing in this table is vendored.

**E2E-proven live (real BYO binary + signed loopback lab): `nmap` (first),
`rustscan` (second).** The other 18 ids are argv+unit only. See
[PROVE.md](PROVE.md). Do not claim them live.

The prove VM may install nmap (apt) or rustscan (GitHub release / cargo)
**on that machine only** — never into git.

SCOPE selects the tool with `adapter: <id>`. Unknown ids are refused.
OpenVAS / Greenbone / GVM are **file_drop only** (no live argv). Nuclei,
Wazuh, osquery, BloodHound, PingCastle, and RiskReady are LICENSE-LOCK
forbidden.

| id | binary | pass1 | pass2 | parse notes | BYO env |
| --- | --- | --- | --- | --- | --- |
| `nmap` | `nmap` | `-sn` ping/discover on the tile | `-sV` on pass1-live hosts only; ports from SCOPE `pass2.ports` (else `22`) | XML `status=up` / gnmap `Status: Up` | `COVEY_NMAP` |
| `masscan` | `masscan` | `-p80,443` JSON on the CIDR | extra ports on live hosts | masscan `-oJ` `ip` + open ports | `COVEY_MASSCAN` |
| `rustscan` | `rustscan` | `-a <cidr> -g -p <SCOPE ports>` (no nmap `--`; **2nd e2e-proven**) | `-a <hosts> -p <SCOPE ports>` rustscan-only | `ip -> [ports]` / `Open a.b.c.d:port` | `COVEY_RUSTSCAN` |
| `naabu` | `naabu` | `-host <cidr> -top-ports 100` | `-host <hosts> -p 22,80,443,…` | `ip:port` lines | `COVEY_NAABU` |
| `fping` | `fping` | `-aqg <net> <broadcast>` | `-a -c 3` live hosts | alive IPs on stdout | `COVEY_FPING` |
| `arp-scan` | `arp-scan` | CIDR local ARP sweep | retry/timeout deepen on hosts | first-column IPv4 + MAC | `COVEY_ARP_SCAN` |
| `netdiscover` | `netdiscover` | `-P -N -r <cidr>` | `-r host/32` per live host | ARP table IPv4 | `COVEY_NETDISCOVER` |
| `zmap` | `zmap` | `-p 80` on the tile (`-B /dev/null` so RFC1918 labs work) | `-p 443` on `host/32` list | one IPv4 per line | `COVEY_ZMAP` |
| `unicornscan` | `unicornscan` | `-mT <cidr>:80,443` | `-mT host:22,80,443,3389` | `TCP open a.b.c.d:port` | `COVEY_UNICORNSCAN` |
| `nping` | `nping` | `--icmp` against tile hosts (Python expand) | `--tcp -p 80` live hosts | `RCVD` / Echo reply IPv4 | `COVEY_NPING` |
| `hping3` | `hping3` | `--icmp` to **tile broadcast** (single dest) | `--syn -p 80` first live host | `ip=a.b.c.d` reply lines | `COVEY_HPING3` |
| `ike-scan` | `ike-scan` | IKE Main Mode on the CIDR | `--aggressive --id=vpn` hosts | handshake IPv4 | `COVEY_IKE_SCAN` |
| `nbtscan` | `nbtscan` | `-s :` NetBIOS on the CIDR | `-v` on live hosts | leading IPv4 / name table | `COVEY_NBTSCAN` |
| `onesixtyone` | `onesixtyone` | SNMP `public/private` over tile hosts file | extra communities on live hosts | `ip [community] …` | `COVEY_ONESIXTYONE` |
| `braa` | `braa` | `public@first-last:sysDescr` | sysDescr + sysName per host | `ip:oid:value` | `COVEY_BRAA` |
| `svmap` | `svmap` | SIP sweep of the CIDR (`sipvicious`) | `--fp` fingerprint live hosts | SIP device IPv4 | `COVEY_SVMAP` |
| `sslscan` | `sslscan` | TLS probe of the **first usable tile host** | `--show-certificate` first live host | `Connected to` / XML host | `COVEY_SSLSCAN` |
| `whatweb` | `whatweb` | `-a 1` against expanded tile hosts | `-a 3` on live hosts | `http://ip` brief log | `COVEY_WHATWEB` |
| `httpx` | `httpx` | `-silent -l` tile hosts file | title/status/tech on live hosts | `https://ip` lines | `COVEY_HTTPX` |
| `tlsx` | `tlsx` | `-silent -l` tile hosts file | `-san -cn -so` on live hosts | `ip:443` TLS lines | `COVEY_TLSX` |

## Limits (honest)

- **hping3** / **ping**: one destination per process. pass1 uses the tile
  broadcast (`ping -b`) so replies can name hosts; pass2 deepens the first
  live host.
- **sslscan**: one target per process. pass1 is the first usable host of the
  already-tiled CIDR (Covey tiles; a `/30` is two hosts).
- **onesixtyone** / **httpx** / **tlsx**: the runner writes `{out_prefix}.hosts`
  (and `.comm` for onesixtyone) next to artifacts before spawn. argv still
  invokes only that tool.
- **zmap**: `-B /dev/null` turns off the default public blocklist so a
  SCOPE-approved RFC1918 tile is reachable. SCOPE spray rules are unchanged.
- **rustscan**: never appends `--` nmap flags. Deepen stays rustscan-only.
  Second e2e-proven adapter (`python -m covey prove --adapter rustscan`).
  Pass1 uses SCOPE `pass2.ports` (lab default `18080`) so the loopback
  prove is a tiny port list, not a 65535-port spray.
- **SCOPE `pass2.ports` / `deepen.ports`**: deepen port lists are
  operator-declared. Adapters keep their built-in default when the field is
  omitted. Empty or injectable strings are refused. Single-port tools
  (zmap, nping, hping3) use the first listed port.

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
