# Evergreen Covey — prove honesty

Covey has **20** live adapter ids (argv + unit parse). Only **eleven** have
been run end-to-end through the runner with a real operator-provided
binary against a signed loopback lab.

| # | adapter | command | artifacts |
| --- | --- | --- | --- |
| 1 | `nmap` | `make prove` / `python -m covey prove` | `out/shards/*/scan.xml` (or `.gnmap`) |
| 2 | `rustscan` | `python -m covey prove --adapter rustscan` / `make prove-rustscan` | `out/shards/*/stdout.log` + `argv.json` |
| 3 | `fping` | `python -m covey prove --adapter fping` / `make prove-fping` | `out/shards/*/stdout.log` + `argv.json` |
| 4 | `naabu` | `python -m covey prove --adapter naabu` / `make prove-naabu` | `out/shards/*/stdout.log` + `argv.json` |
| 5 | `nping` | `python -m covey prove --adapter nping` / `make prove-nping` | `out/shards/*/stdout.log` + `argv.json` |
| 6 | `httpx` | `python -m covey prove --adapter httpx` / `make prove-httpx` | `out/shards/*/stdout.log` + `argv.json` |
| 7 | `sslscan` | `python -m covey prove --adapter sslscan` / `make prove-sslscan` | `out/shards/*/stdout.log` + `argv.json` |
| 8 | `tlsx` | `python -m covey prove --adapter tlsx` / `make prove-tlsx` | `out/shards/*/stdout.log` + `argv.json` |
| 9 | `whatweb` | `python -m covey prove --adapter whatweb` / `make prove-whatweb` | `out/shards/*/stdout.log` + `argv.json` |
| 10 | `hping3` | `python -m covey prove --adapter hping3` / `make prove-hping3` | `out/shards/*/stdout.log` + `argv.json` |
| 11 | `onesixtyone` | `python -m covey prove --adapter onesixtyone` / `make prove-onesixtyone` | `out/shards/*/stdout.log` + `argv.json` |

The other **9** (`masscan`, `arp-scan`, `netdiscover`,
`zmap`, `unicornscan`, `ike-scan`, `nbtscan`,
`braa`, `svmap`)
remain **argv+unit only**. Do not claim they are live on Covey.

Source of truth: `E2E_PROVEN_ADAPTERS` in `src/covey/adapters/registry.py`
(`nmap`, `rustscan`, `fping`, `naabu`, `nping`, `httpx`, `sslscan`, `tlsx`, `whatweb`, `hping3`, `onesixtyone`). `UNPROVEN_ADAPTERS` is the derived remainder.
Adding a twelfth live e2e requires a real BYO prove — not a docs edit.

`python -m covey prove --adapter masscan` (or any of the 9, with or
without `--no-install`) **fails closed**.

masscan was preferred earlier. `apt-get install masscan` resolves
`/usr/bin/masscan` 1.3.2, but masscan is a raw SYN scanner: it needs
libpcap + `CAP_NET_RAW`, and even then it reports `found=0` on loopback
`127.0.0.0/28` (including `-e lo` with adapter MAC overrides). That is
not a live prove. Covey does not invent a fake masscan brick.

nping raw `--icmp` / `--tcp` need root. The fifth brick is unprivileged
`--tcp-connect` against the same loopback lab listener rustscan and
naabu use. The sixth brick is **httpx**: it needs an HTTP 200, not a
bare TCP accept. Prove serves HTTP/1.1 200 on the loopback tiles. The
seventh brick is **sslscan**: it needs a TLS handshake, not HTTP or a
bare TCP accept. Prove serves TLS on the loopback tiles. The eighth
brick is **tlsx**: same TLS handshake requirement as sslscan. Prove
reuses that TLS lab. The ninth brick is **whatweb**: it needs an HTTP
200, not a bare TCP accept. Prove reuses the httpx HTTP lab.
The tenth brick is **hping3**: raw `--icmp` / `--syn` need
`CAP_NET_RAW` (or root). Prove may `apt-get install hping3` and
`setcap` on this VM only. pass1 is ICMP to the first usable host of
each loopback tile — loopback answers; no TCP listener. The HPING
banner is not a live host; parse requires `ip=` reply lines.
The eleventh brick is **onesixtyone**: SNMP community sweep. Prove
serves SNMPv1 GetResponse on the loopback tiles. A UDP echo is not
enough — onesixtyone prints the source IP on any datagram; parse
requires `ip [community] sysDescr`. Decode-error lines and the hosts
sidecar are not live hosts. nbtscan / braa / arp-scan were not
selected: onesixtyone was first in the try order and produced honest
loopback output. arp-scan stays argv+unit (no L2 / loopback ARP).
masscan stays argv+unit until a non-loopback raw-SYN prove.

## Lab SCOPE

All eleven proven paths tile loopback `127.0.0.0/28` into four `/30`s with
`max_workers: 2`. Not a `/8`. Not `0.0.0.0/0`.

| adapter | SCOPE | pass1 | pass2 |
| --- | --- | --- | --- |
| nmap | `examples/scope.lab.yaml` | `nmap -sn` (host discovery; localhost answers) | `nmap -sV` on pass1-live hosts only |
| rustscan | `examples/scope.lab.rustscan.yaml` | `rustscan -a <tile> -g -p 18080` (no nmap `--`) | rustscan-only on pass1-live hosts |
| fping | `examples/scope.lab.fping.yaml` | `fping -aqg <net> <broadcast>` (ICMP; loopback answers) | `fping -a -c 3` on pass1-live hosts |
| naabu | `examples/scope.lab.naabu.yaml` | `naabu -host <tile> -silent -p 18080 -scan-type connect` | naabu-only on pass1-live hosts |
| nping | `examples/scope.lab.nping.yaml` | `nping --tcp-connect -p 18080` on expanded tile hosts | nping-only on pass1-live hosts |
| httpx | `examples/scope.lab.httpx.yaml` | `httpx -silent -l` tile hosts file `-p 18080` | title/status/tech on pass1-live hosts |
| sslscan | `examples/scope.lab.sslscan.yaml` | `sslscan --xml --no-colour` first tile host `:18080` | `--show-certificate` on first pass1-live host |
| tlsx | `examples/scope.lab.tlsx.yaml` | `tlsx -silent -l` tile hosts file `-p 18080` | `-san -cn` on pass1-live hosts |
| whatweb | `examples/scope.lab.whatweb.yaml` | `whatweb -a 1` `http://host:18080` tile hosts | `-a 3` on pass1-live host URLs |
| hping3 | `examples/scope.lab.hping3.yaml` | `hping3 --icmp` first usable tile host | `--syn` first pass1-live host |
| onesixtyone | `examples/scope.lab.onesixtyone.yaml` | `onesixtyone -c/-i` tile hosts `-p 18080` | extra communities on pass1-live hosts |

rustscan, naabu, and nping `--tcp-connect` are **TCP probes**. Unlike
nmap `-sn` or fping ICMP, an empty loopback tile has no live hosts
unless a TCP port is open. The prove binds a lab listener on
`127.0.0.1`, `.5`, `.9`, `.13` port `18080` (first usable host of each
`/30`) for the duration of the run. That is a lab fixture, not a forged
scanner result. rustscan itself must still connect and print greppable
`ip -> [18080]` lines. naabu must still connect-scan and print
`ip:18080` lines. nping must still complete `Handshake with ip:18080`
lines. Connection-refused `RCVD` lines are not live hosts.

httpx is an **HTTP probe**. Bare TCP accept is not enough: httpx prints
nothing unless the peer speaks HTTP. Prove serves HTTP/1.1 200 on the
same loopback addresses. httpx itself must still request and print
`http://ip:18080` lines.

sslscan is a **TLS probe**. HTTP 200 is not enough: sslscan prints
`Connected to` only after a TLS handshake. Prove serves TLS on the
same loopback addresses (ephemeral cert, off git). sslscan itself must
still connect and print `Connected to` (or XML `ssltest host`).
Connection-refused `ERROR` lines name the IP but are not live hosts.
sslscan takes one target per process; pass1 is the first usable host
of each `/30`.

tlsx is a **TLS probe**. HTTP 200 is not enough: tlsx prints `ip:port`
only after a TLS handshake. Prove reuses the sslscan TLS lab on the
same loopback addresses. tlsx itself must still handshake and print
leading `ip:18080` lines. Banner or SAN IPs are not live hosts.

whatweb is an **HTTP fingerprint**. Bare TCP accept is not enough:
whatweb prints `http://ip` only after an HTTP reply. Prove reuses the
httpx HTTP/1.1 200 lab on the same loopback addresses. whatweb itself
must still request and print leading `http://ip:18080` brief-log
lines. Plugin or banner IPs are not live hosts. whatweb has no `-p`;
pass1 embeds SCOPE `pass2.ports` (lab default `18080`) in each URL.

fping is ICMP host discovery. Loopback answers; no TCP listener is
required. The committed fping SCOPE omits `pass2.ports` — there is no
port surface.

hping3 is ICMP host discovery on pass1 (single destination). Loopback
answers; no TCP listener is required. The committed hping3 SCOPE omits
`pass2.ports` — pass2 SYN uses the adapter default (`80`). hping3
itself must still send ICMP and print `ip=` reply lines. The HPING
banner names the destination even on 100% loss; that is not a live
host. SYN RST still prints `ip=` because a reply arrived.

onesixtyone is an **SNMP community sweeper**. A UDP echo is not enough:
onesixtyone prints the source IP on any datagram. Prove serves SNMPv1
GetResponse on the same loopback addresses rustscan / naabu / nping /
httpx bind. onesixtyone itself must still send a GET and print
`ip [community] sysDescr` lines. Decode-error lines name the IP but
are not live hosts. The hosts sidecar IPs are not live hosts. Pass1
uses SCOPE `pass2.ports` (lab default `18080`) via `-p`.

## BYO binaries

Scanner binaries stay **off git**. LICENSE-LOCK is unchanged.

- **nmap**: `PATH` / `COVEY_NMAP` / optional `apt-get install nmap` on this VM only
- **rustscan**: `PATH` / `COVEY_RUSTSCAN` / optional GitHub release download
  into `~/.local/bin` (or `cargo install`) on this VM only
- **fping**: `PATH` / `COVEY_FPING` / optional `apt-get install fping` on this VM only
- **naabu**: `PATH` / `COVEY_NAABU` / optional GitHub release download
  into `~/.local/bin` (or `go install`) on this VM only
- **nping**: `PATH` / `COVEY_NPING` / optional `apt-get install nmap` on this
  VM only (the nmap package ships `/usr/bin/nping`)
- **httpx**: `PATH` / `COVEY_HTTPX` / optional GitHub release download
  into `~/.local/bin` (or `go install`) on this VM only
- **sslscan**: `PATH` / `COVEY_SSLSCAN` / optional `apt-get install sslscan`
  on this VM only
- **tlsx**: `PATH` / `COVEY_TLSX` / optional GitHub release download
  into `~/.local/bin` (or `go install`) on this VM only
- **whatweb**: `PATH` / `COVEY_WHATWEB` / optional `apt-get install whatweb`
  on this VM only
- **hping3**: `PATH` / `COVEY_HPING3` / optional `apt-get install hping3`
  on this VM only, plus `setcap cap_net_raw,cap_net_admin+ep` when the
  binary cannot open a raw socket unprivileged
- **onesixtyone**: `PATH` / `COVEY_ONESIXTYONE` / optional
  `apt-get install onesixtyone` on this VM only

`--no-install` fails closed if the binary is missing.

## Fail closed

Prove exits non-zero when:

- the adapter is not nmap, rustscan, fping, naabu, nping, httpx, sslscan, tlsx, whatweb, hping3, or onesixtyone
- SCOPE is unsigned, expired, or a wide spray
- the BYO binary cannot be resolved or will not run
- pass1 workers fail, artifacts are missing, no live hosts, or pass2
  targets a host that pass1 did not mark live
