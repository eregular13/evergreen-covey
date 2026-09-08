# Evergreen Covey — prove honesty

Covey has **20** live adapter ids (argv + unit parse). Only **six** have
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

The other **14** (`masscan`, `arp-scan`, `netdiscover`,
`zmap`, `unicornscan`, `hping3`, `ike-scan`, `nbtscan`,
`onesixtyone`, `braa`, `svmap`, `sslscan`, `whatweb`, `tlsx`)
remain **argv+unit only**. Do not claim they are live on Covey.

Source of truth: `E2E_PROVEN_ADAPTERS` in `src/covey/adapters/registry.py`
(`nmap`, `rustscan`, `fping`, `naabu`, `nping`, `httpx`). `UNPROVEN_ADAPTERS` is the derived remainder.
Adding a seventh live e2e requires a real BYO prove — not a docs edit.

`python -m covey prove --adapter masscan` (or any of the 14, with or
without `--no-install`) **fails closed**.

masscan was preferred earlier. `apt-get install masscan` resolves
`/usr/bin/masscan` 1.3.2, but masscan is a raw SYN scanner: it needs
libpcap + `CAP_NET_RAW`, and even then it reports `found=0` on loopback
`127.0.0.0/28` (including `-e lo` with adapter MAC overrides). That is
not a live prove. Covey does not invent a fake masscan brick.

nping raw `--icmp` / `--tcp` need root. The fifth brick is unprivileged
`--tcp-connect` against the same loopback lab listener rustscan and
naabu use. The sixth brick is **httpx**: it needs an HTTP 200, not a
bare TCP accept. Prove serves HTTP/1.1 200 on the loopback tiles.

## Lab SCOPE

All six proven paths tile loopback `127.0.0.0/28` into four `/30`s with
`max_workers: 2`. Not a `/8`. Not `0.0.0.0/0`.

| adapter | SCOPE | pass1 | pass2 |
| --- | --- | --- | --- |
| nmap | `examples/scope.lab.yaml` | `nmap -sn` (host discovery; localhost answers) | `nmap -sV` on pass1-live hosts only |
| rustscan | `examples/scope.lab.rustscan.yaml` | `rustscan -a <tile> -g -p 18080` (no nmap `--`) | rustscan-only on pass1-live hosts |
| fping | `examples/scope.lab.fping.yaml` | `fping -aqg <net> <broadcast>` (ICMP; loopback answers) | `fping -a -c 3` on pass1-live hosts |
| naabu | `examples/scope.lab.naabu.yaml` | `naabu -host <tile> -silent -p 18080 -scan-type connect` | naabu-only on pass1-live hosts |
| nping | `examples/scope.lab.nping.yaml` | `nping --tcp-connect -p 18080` on expanded tile hosts | nping-only on pass1-live hosts |
| httpx | `examples/scope.lab.httpx.yaml` | `httpx -silent -l` tile hosts file `-p 18080` | title/status/tech on pass1-live hosts |

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

fping is ICMP host discovery. Loopback answers; no TCP listener is
required. The committed fping SCOPE omits `pass2.ports` — there is no
port surface.

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

`--no-install` fails closed if the binary is missing.

## Fail closed

Prove exits non-zero when:

- the adapter is not nmap, rustscan, fping, naabu, nping, or httpx
- SCOPE is unsigned, expired, or a wide spray
- the BYO binary cannot be resolved or will not run
- pass1 workers fail, artifacts are missing, no live hosts, or pass2
  targets a host that pass1 did not mark live
