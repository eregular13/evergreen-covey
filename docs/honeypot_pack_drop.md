# Honeypot pack_drop contract

Fleet-sensor P1 and Hermes lab write this layout. Covey city agrees on the
schema so a collector pack can `file_drop` decoy evidence next to a Covey
surface drop. Covey **does not** emit these files from `covey export`.

```
pack_drop/
  in/honeypot/
    events.jsonl      # one honeypot_event.v1 per line
    sessions.jsonl    # one session_summary.v1 per line
```

JSON Schema stubs: [`schemas/honeypot_event.v1.json`](../schemas/honeypot_event.v1.json),
[`schemas/session_summary.v1.json`](../schemas/session_summary.v1.json).

## Honesty

A decoy session is **honeypot validated**. That is not a surface map and it
is not control operating effectiveness. Do not file “MFA works” or “EDR
failed” from `in/honeypot/` alone.

Ingest is **file_drop only**. No RiskReady POST. No Hermes lab code is
vendored here.

## `honeypot_event.v1`

| field | required | notes |
| --- | --- | --- |
| `schema` | yes | literal `honeypot_event.v1` |
| `event_id` | yes | stable id (UUID) |
| `observed_at` | yes | ISO-8601 UTC |
| `sensor_id` | yes | fleet-sensor / decoy id |
| `src_ip` | yes | client |
| `src_port` | no | 1–65535 |
| `dst_ip` | yes | decoy |
| `dst_port` | yes | 1–65535 |
| `protocol` | yes | `tcp` / `udp` / `icmp` |
| `action` | yes | `connect` / `banner` / `auth_attempt` / `payload` / `close` |
| `session_id` | no | join key to `session_summary.v1` |
| `service` | no | `ssh`, `http`, … |
| `payload_sha256` | no | hash only — do not dump malware bytes by default |
| `labels` | no | string map |

## `session_summary.v1`

| field | required | notes |
| --- | --- | --- |
| `schema` | yes | literal `session_summary.v1` |
| `session_id` | yes | join key |
| `sensor_id` | yes | |
| `started_at` / `ended_at` | yes | ISO-8601 UTC |
| `src_ip` | yes | |
| `dst_port` | yes | |
| `protocol` | yes | |
| `event_count` | yes | ≥ 1 |
| `first_action` / `last_action` | no | |
| `outcome` | no | `closed` / `timeout` / `reset` |

## SoR mapping

| file | object |
| --- | --- |
| `events.jsonl` | evidence (+ optional finding `decoy_session_observed`) |
| `sessions.jsonl` | asset `decoy_service` + session rollup |
| sensor id | asset `sensor` |

Keep payloads small. Pointer + sha256 beats a megabyte pcap in the default drop.
