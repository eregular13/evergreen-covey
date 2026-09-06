# Covey adapters

An adapter is a **pure argv + artifact parser**. Covey owns SCOPE, shards,
plans, and the runner. The adapter never downloads a scanner and never
apt-installs into the repository.

## Live adapter protocol

Implement `covey.adapters.base.Adapter`:

| Method | Role |
| --- | --- |
| `pass1_argv(target, out_prefix)` | Discover one shard. No spawn. |
| `pass2_argv_template(out_prefix)` | Deepen template; include a `{hosts}` token. |
| `pass2_argv(hosts, out_prefix)` | Concrete deepen argv for pass1-live hosts only. |
| `parse_live_hosts(artifact_dir)` | Read XML/gnmap/etc. that the runner already landed. |

Set `file_drop_only = False` for tools the operator actually execs (Nmap).

Register by adding a module next to `nmap.py` and wiring it in
`covey.plan.adapter_for()`. Keep the same shard id / stage / `out/shards/<id>/`
layout so the runner stays unchanged.

## Nmap (proven)

BYO only. Resolve from `PATH`, `COVEY_NMAP`, or a user image
(`docker://your-nmap-image`). The operator provides the binary.

- pass1: `-sn` ping/discover on one tile
- pass2: `-sV` **only** against hosts parsed live from that shard’s pass1 artifacts

## OpenVAS-class (file_drop only)

OpenVAS, Greenbone, and anything in that weight class **must not** gain a
live spawn adapter. If you add them later:

1. Accept operator-dropped XML/reports already written to disk.
2. Parse and hang those files on the existing shard/stage kit.
3. Raise if anyone asks for `pass1_argv` / `pass2_argv`.

There is no OpenVAS live implementation in this repo. That is intentional.

## Forbidden wrappers

Do not add Nuclei, Wazuh, osquery, BloodHound, PingCastle, or RiskReady
wrappers. See `LICENSE-LOCK.md`.
