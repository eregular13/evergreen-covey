# Evidence matrix — Said / Seen / Shown → GRC

Machine-readable twin: [`evidence_matrix.yaml`](evidence_matrix.yaml).
This is the product contract Hermes and `grc-collector-pack` share.

**Honesty:** surface map ≠ honeypot validated ≠ control operating effectiveness.
Ingest is **file_drop only**. No RiskReady POST.

| Lane | Said | Seen | Shown | Example collectors | SoR objects | Honesty limits |
| --- | --- | --- | --- | --- | --- | --- |
| Identity / IdP | IdP named; MFA "required" | Tenant export, MFA counts, admin roles | Live MFA challenge; leaver timestamp | Entra / Google / Okta export | asset: idp_tenant, sso_app, admin_role · finding: mfa_gap_observed · evidence: idp_export · poam: mfa_coverage | Config dump ≠ Shown MFA |
| MDM / endpoint | Fleet enrolled; encryption + EDR on | Inventory + policy assignment | One device proves encryption + EDR check-in | Jamf / Intune / Kandji; osquery file_drop | asset: device · finding: unenrolled_device · evidence: inventory · poam: mdm_coverage | Assigned ≠ healthy |
| Cloud / SaaS config | CSPM on; public storage off | Account list, public-bucket probe, SSO flags | Remediation ticket; SSO on a sampled app | Prowler/Scout file_drop; SaaS admin export | asset: cloud_account, bucket · finding: public_storage_observed · evidence: cis_json · poam: public_exposure | Scanner finding is Seen, not OE |
| Email / DNS | SPF/DKIM/DMARC "set" | Published DNS records | DMARC reject + sampled aggregate | dig / checkdmarc export | asset: domain · finding: dmarc_missing · evidence: dns_txt · poam: dmarc | TXT record ≠ mailbox proof |
| Covey surface | Signed SCOPE ranges | pass1 hosts + pass2 open ports | *Not this lane* | `covey prove` / `covey export` | asset: host, service · finding: open_port_observed · evidence: scan.xml · poam: *(none from nmap)* | Open port ≠ vuln ≠ control failure |
| VM file_drop | Heavy scanner used | Operator-dropped OpenVAS XML | Human-accepted true positive | OpenVAS/Greenbone **file_drop only** | asset: host · finding: scanner_finding_ingested · evidence: openvas.xml · poam: after accept | No live OpenVAS adapter |
| Honeypot / fleet-sensor | Decoys + sensors enrolled | `honeypot_event.v1` / `session_summary.v1` | Real decoy session | fleet-sensor / Hermes lab | asset: sensor, decoy · finding: decoy_session_observed · evidence: in/honeypot/ · poam: *(none)* | Honeypot validated ≠ control OE |
| Interview / docs | Policies, SOC2, "we do that" | File received + hash | Live walkthrough | Notes, policy PDF | asset: policy_doc · evidence: notes.md · poam: doc_gap | Said is not Seen |
| Logging / backup / IR Shown | SIEM; daily backups; IR plan | Retention + job inventory + plan PDF | In-window query; restore ticket; IR exercise | SIEM / backup catalog / ticket | asset: log_source, backup_job · finding: no_restore_test · evidence: restore_ticket · poam: backup_restore | Plan PDF ≠ Shown |

## How Covey uses this

`python -m covey export --out <run>` writes a `pack_drop/` that fills the
**Covey surface** row only. Other lanes arrive as separate file_drops.
See [`honeypot_pack_drop.md`](honeypot_pack_drop.md) for the decoy contract.
