# Evergreen Covey — prove honesty

Covey has **20** live adapter ids (argv + unit parse). Only **four** have
been run end-to-end through the runner with a real operator-provided
binary against a signed loopback lab.

| # | adapter | command | artifacts |
| --- | --- | --- | --- |
| 1 | `nmap` | `make prove` / `python -m covey prove` | `out/shards/*/scan.xml` (or `.gnmap`) |
| 2 | `rustscan` | `python -m covey prove --adapter rustscan` / `make prove-rustscan` | `out/shards/*/stdout.log` + `argv.json` |
| 3 | `fping` | `python -m covey prove --adapter fping` / `make prove-fping` | `out/shards/*/stdout.log` + `argv.json` |
| 4 | `naabu` | `python -m covey prove --adapter naabu` / `make prove-naabu` | `out/shards/*/stdout.log` + `argv.json` |

The other **16** (`masscan`, `arp-scan`, `netdiscover`,
`zmap`, `unicornscan`, `nping`, `hping3`, `ike-scan`, `nbtscan`,
`onesixtyone`, `braa`, `svmap`, `sslscan`, `whatweb`, `httpx`, `tlsx`)
remain **argv+unit only**. Do not claim they are live on Covey.

Source of truth: `E2E_PROVEN_ADAPTERS` in `src/covey/adapters/registry.py`
(`nmap`, `rustscan`, `fping`, `naabu`). `UNPROVEN_ADAPTERS` is the derived remainder.
Adding a fifth live e2e requires a real BYO prove — not a docs edit.

`python -m covey prove --adapter masscan` (or any of the 16, with or
without `--no-install`) **fails closed**.

masscan was preferred for this fourth brick. `apt-get install masscan`
resolves `/usr/bin/masscan` 1.3.2, but masscan is a raw SYN scanner: it
needs libpcap + `CAP_NET_RAW`, and even then it reports `found=0` on
loopback `127.0.0.0/28` (including `-e lo` with adapter MAC overrides).
That is not a live prove. Covey does not invent a fake masscan brick.

## Lab SCOPE

All four proven paths tile loopback `127.0.0.0/28` into four `/30`s with
`max_workers: 2`. Not a `/8`. Not `0.0.0.0/0`.

| adapter | SCOPE | pass1 | pass2 |
| --- | --- | --- | --- |
| nmap | `examples/scope.lab.yaml` | `nmap -sn` (host discovery; localhost answers) | `nmap -sV` on pass1-live hosts only |
| rustscan | `examples/scope.lab.rustscan.yaml` | `rustscan -a <tile> -g -p 18080` (no nmap `--`) | rustscan-only on pass1-live hosts |
| fping | `examples/scope.lab.fping.yaml` | `fping -aqg <net> <broadcast>` (ICMP; loopback answers) | `fping -a -c 3` on pass1-live hosts |
| naabu | `examples/scope.lab.naabu.yaml` | `naabu -host <tile> -silent -p 18080 -scan-type connect` | naabu-only on pass1-live hosts |

rustscan and naabu are **port scanners**. Unlike nmap `-sn` or fping ICMP,
an empty loopback tile has no live hosts unless a TCP port is open. The
prove binds a lab listener on `127.0.0.1`, `.5`, `.9`, `.13` port `18080`
(first usable host of each `/30`) for the duration of the run. That is a
lab fixture, not a forged scanner result. rustscan itself must still
connect and print greppable `ip -> [18080]` lines. naabu must still
connect-scan and print `ip:18080` lines.

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

`--no-install` fails closed if the binary is missing.

## Fail closed

Prove exits non-zero when:

- the adapter is not nmap, rustscan, fping, or naabu
- SCOPE is unsigned, expired, or a wide spray
- the BYO binary cannot be resolved or will not run
- pass1 workers fail, artifacts are missing, no live hosts, or pass2
  targets a host that pass1 did not mark live
