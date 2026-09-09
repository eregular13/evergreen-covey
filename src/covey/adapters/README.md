# Covey adapters

An adapter is a **pure argv + artifact parser**. Covey owns SCOPE, shards,
plans, and the runner. The adapter never downloads a scanner and never
apt-installs into the repository.

Live ids (SCOPE `adapter:` field) are listed in [`ADAPTERS.md`](../../../ADAPTERS.md).

## Live adapter protocol

Implement `covey.adapters.base.Adapter`:

| Method | Role |
| --- | --- |
| `pass1_argv(target, out_prefix)` | Discover one shard. No spawn. |
| `pass2_argv_template(out_prefix)` | Deepen template; include a `{hosts}` token when the CLI takes hosts on argv. |
| `pass2_argv(hosts, out_prefix)` | Concrete deepen argv for pass1-live hosts only. |
| `parse_live_hosts(artifact_dir)` | Read XML/JSON/stdout the runner already landed. |

Optional `stage_files(stage, target, out_prefix)` may return relative
path → text sidecars (host lists, community files). The runner writes them
under the artifact root immediately before spawn. Plan-time argv builders
must not mkdir in the repo.

Set `file_drop_only = False` for tools the operator actually execs.

Register in `covey.adapters.registry` (`adapter_for()`, `LIVE_ADAPTER_IDS`).
Keep the same shard id / stage / `out/shards/<id>/` layout.

## Nmap (first e2e-proven)

BYO only. Resolve from `PATH`, `COVEY_NMAP`, or a user image
(`docker://your-nmap-image`). The operator provides the binary.

- pass1: `-sn` ping/discover on one tile
- pass2: `-sV` **only** against hosts parsed live from that shard’s pass1 artifacts
- pass2 ports come from SCOPE `pass2.ports` / `deepen.ports` (Palisade P0).
  The adapter default (`22`) is used only when SCOPE omits the field.

`make prove` still exercises this path.

## rustscan (second e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_RUSTSCAN`, or the prove path may
download the official GitHub release onto **this VM only**.

- pass1: `-a <tile> -g -p <SCOPE ports>` — greppable, no nmap `--`
- pass2: rustscan-only against pass1-live hosts
- prove binds a loopback lab listener (port scanner ≠ ping sweep)

`python -m covey prove --adapter rustscan`

## fping (third e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_FPING`, or the prove path may
`apt-get install fping` onto **this VM only**.

- pass1: `-a -q -g <net> <broadcast>` — alive IPs on stdout
- pass2: `-a -c 3` against pass1-live hosts
- ICMP host discovery; loopback answers; no TCP lab listener

`python -m covey prove --adapter fping`

## naabu (fourth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_NAABU`, or the prove path may
download the official GitHub release onto **this VM only**.

- pass1: `-host <tile> -silent -p <SCOPE ports> -scan-type connect`
- pass2: naabu-only against pass1-live hosts
- prove binds a loopback lab listener (port scanner ≠ ping sweep)

`python -m covey prove --adapter naabu`

## nping (fifth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_NPING`, or the prove path may
`apt-get install nmap` onto **this VM only** (the nmap package ships
nping).

- pass1: `--tcp-connect -p <SCOPE ports>` against expanded tile hosts
- pass2: nping-only against pass1-live hosts
- prove binds a loopback lab listener (TCP handshake ≠ ICMP; raw
  `--icmp`/`--tcp` need root)

`python -m covey prove --adapter nping`

## httpx (sixth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_HTTPX`, or the prove path may
download the official GitHub release onto **this VM only**.

- pass1: `-silent -l` tile hosts file `-p <SCOPE ports>`
- pass2: title/status/tech against pass1-live hosts
- prove serves HTTP/1.1 200 (HTTP probe ≠ bare TCP accept)

`python -m covey prove --adapter httpx`

## sslscan (seventh e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_SSLSCAN`, or the prove path may
`apt-get install sslscan` onto **this VM only**.

- pass1: `--xml --no-colour` first usable tile host as `host:<SCOPE port>`
- pass2: `--show-certificate` first pass1-live host
- prove serves TLS (TLS handshake ≠ HTTP 200 ≠ bare TCP accept)

`python -m covey prove --adapter sslscan`

## tlsx (eighth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_TLSX`, or the prove path may
download the official GitHub release onto **this VM only**.

- pass1: `-silent -l` tile hosts file `-p <SCOPE ports>`
- pass2: `-san -cn` against pass1-live hosts (tlsx 1.4+ refuses `-so` with those)
- prove serves TLS (TLS handshake ≠ HTTP 200 ≠ bare TCP accept)

`python -m covey prove --adapter tlsx`

## whatweb (ninth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_WHATWEB`, or the prove path may
`apt-get install whatweb` onto **this VM only**.

- pass1: `-a 1` against `http://host:<SCOPE port>` for each usable tile host
- pass2: `-a 3` against pass1-live host URLs
- prove serves HTTP/1.1 200 (HTTP fingerprint ≠ bare TCP accept)

`python -m covey prove --adapter whatweb`

## hping3 (tenth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_HPING3`, or the prove path may
`apt-get install hping3` and `setcap` onto **this VM only**.

- pass1: `--icmp` against the first usable tile host
- pass2: `--syn` against the first pass1-live host
- ICMP host discovery; loopback answers; no TCP lab listener
- raw sockets need `CAP_NET_RAW` / root; parse requires `ip=` reply lines

`python -m covey prove --adapter hping3`

## onesixtyone (eleventh e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_ONESIXTYONE`, or the prove path
may `apt-get install onesixtyone` onto **this VM only**.

- pass1: `-c` communities `-i` tile hosts `-p <SCOPE port>`
- pass2: extra communities against pass1-live hosts
- prove serves SNMPv1 GetResponse (SNMP probe ≠ UDP echo)
- parse requires `ip [community] sysDescr`; decode-error IPs are ignored

`python -m covey prove --adapter onesixtyone`

## nbtscan (twelfth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_NBTSCAN`, or the prove path
may `apt-get install nbtscan` onto **this VM only**.

- pass1: `-s :` NetBIOS name sweep of the tile CIDR
- pass2: `-v -s :` against pass1-live hosts
- prove serves NBSTAT on UDP/137 (NetBIOS probe ≠ UDP echo)
- parse requires a real name-table entry; `ip:<unknown>` and MAC lines
  are ignored. UDP/137 is privileged; prove may lower
  `ip_unprivileged_port_start` on this VM only.

`python -m covey prove --adapter nbtscan`

## braa (thirteenth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_BRAA`, or the prove path
may `apt-get install braa` onto **this VM only**.

- pass1: one `public@host:<SCOPE port>:sysDescr` query per usable tile host
- pass2: sysDescr + sysName against pass1-live hosts
- prove serves SNMPv1 GetResponse and echoes the request-id
  (SNMP probe ≠ UDP echo; mismatched request-id is not live)
- parse requires `ip:oid:value` / `ip:rtt:id:value`

`python -m covey prove --adapter braa`

## ike-scan (fourteenth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_IKE_SCAN`, or the prove path
may `apt-get install ike-scan` onto **this VM only**.

- pass1: `--sport=0 --dport <SCOPE port>` Main Mode on the tile CIDR
- pass2: `--aggressive --id=vpn` against pass1-live hosts
- prove serves ISAKMP and sets a nonzero responder cookie
  (IKE probe ≠ UDP echo; CKY-R=0 is the initiator packet reflected)
- parse requires `Handshake returned` with a nonzero CKY-R

`python -m covey prove --adapter ike-scan`

## svmap (fifteenth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_SVMAP`, or the prove path
may `apt-get install sipvicious` onto **this VM only**.

- pass1: `-p <SCOPE port> -P 0` OPTIONS sweep of the tile CIDR
- pass2: OPTIONS against pass1-live hosts
- prove serves SIP/2.0 200 and sets User-Agent `covey-sip-lab`
  (SIP probe ≠ UDP echo; UA `unknown` is not live)
- parse requires an `ip:port` SIP Device table cell with a real
  User-Agent. sipvicious 0.3.3 has no `-o` and no `--fp`.

`python -m covey prove --adapter svmap`

## unicornscan (sixteenth e2e-proven)

BYO only. Resolve from `PATH` / `COVEY_UNICORNSCAN`, or the prove
path may install a GitHub release `.deb` onto **this VM only**.

- pass1: `-mT <tile>:<SCOPE ports>`; loopback adds `-i lo -s 127.0.0.254`
- pass2: unicornscan-only against pass1-live hosts
- prove binds a loopback lab listener (TCP SYN ≠ ping sweep)
- parse requires `TCP open`; `TCP closed` IPs are ignored
- Ubuntu noble has no apt unicornscan. Package `modules.conf` is
  `0640`; prove may `chmod 644` on this VM only.

`python -m covey prove --adapter unicornscan`

## Other live BYO adapters (argv+unit only)

masscan, arp-scan, netdiscover, zmap
— same shard/stage kit, same fail-closed SCOPE,
**not** e2e-proven. See `ADAPTERS.md` / `PROVE.md`.
arp-scan / netdiscover have no L2 on loopback.
zmap cannot observe loopback SYN replies.

The runner is tool-generic: `COVEY_<TOOL>`, `COVEY_BIN`, or `docker://`
with a configurable entrypoint.

## OpenVAS-class (file_drop only)

OpenVAS, Greenbone, and GVM **must not** gain a live spawn adapter.
`covey.adapters.openvas.OpenVASFileDrop` sets `file_drop_only=True` and
raises on every argv method. `adapter_for("openvas")` refuses a live plan.

A later ingest adapter may hang operator-dropped artifacts on the same
shard/stage kit. That is the only allowed path.

## Forbidden wrappers

Do not add Nuclei, Wazuh, osquery, BloodHound, PingCastle, or RiskReady
wrappers. See `LICENSE-LOCK.md`.
