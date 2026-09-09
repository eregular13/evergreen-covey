# LICENSE-LOCK — Evergreen Covey

Evergreen Covey is **orchestration only**. This file is a hard product lock,
not a suggestion.

## Do not ship

This repository must **never** vendor, wrap as a bundled binary, apt-install
into the tree, or commit:

- Nmap (or Npcap, zenmap)
- OpenVAS / Greenbone
- Nuclei
- Wazuh
- osquery
- BloodHound
- PingCastle
- RiskReady wrappers

Operators bring their own scanner. Covey resolves the selected adapter
binary from `PATH`, `COVEY_<TOOL>`, `COVEY_BIN`, or a user-supplied
`docker://` image. The prove path may install Nmap (which ships nping),
fping, sslscan, whatweb, hping3, onesixtyone, nbtscan, braa, ike-scan, or
sipvicious (svmap) **on the local prove VM only**, or download a rustscan/naabu/httpx/tlsx GitHub
release into `~/.local/bin` on that machine; those binaries are not part
of git. Other live adapters are argv+parser only — never vendored, never
apt-installed into the tree.

## OpenVAS-class tools

OpenVAS, Greenbone, and similar heavy scanners are **`file_drop` only**.
Covey must never grow a live spawn adapter for them. A later ingest adapter
may hang operator-dropped artifacts on the same shard/stage kit. That is the
only allowed path.

## Fail-closed spray

Covey refuses `0.0.0.0/0`, `*`, and automatic expansion of `/8`–`/16`
unless SCOPE sets `allow_wide: true` **and** lists that parent CIDR
verbatim. The committed prove lab is a tiny loopback `/28`, not a real `/8`.
