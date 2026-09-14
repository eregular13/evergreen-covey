from __future__ import annotations

from covey.findings import (
    findings_from_file_drop,
    findings_from_http_blob,
    findings_from_sslscan,
    findings_from_tlsx,
    findings_from_whatweb,
    map_finding,
)


def test_http_url_without_headers_is_cleartext_only():
    rows = findings_from_http_blob("http://10.9.8.7:80\n", url="http://10.9.8.7:80")
    names = {row["name"] for row in rows}
    assert "Cleartext HTTP" in names
    assert "Missing HSTS" not in names


def test_empty_reply_does_not_invent_missing_hsts():
    rows = findings_from_http_blob("", url="https://10.9.8.7")
    assert all(row["name"] != "Missing HSTS" for row in rows)


def test_header_sample_missing_hsts():
    blob = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
    rows = findings_from_http_blob(blob, url="https://10.9.8.7")
    names = {row["name"] for row in rows}
    assert "Missing HSTS" in names
    assert "Server banner disclosure" in names
    assert "Cleartext HTTP" not in names


def test_http_does_not_invent_smbv1():
    blob = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    rows = findings_from_http_blob(blob, url="http://10.9.8.7/")
    names = {row["name"] for row in rows}
    assert "Cleartext HTTP" in names
    assert not any("SMB" in name for name in names)


def test_sslscan_tls10_and_self_signed():
    blob = """
Connected to 10.9.8.7
Testing SSL server 10.9.8.7 on port 443
SSLv3  enabled
TLSv1.0  enabled
TLSv1.2  enabled
Subject: /CN=localhost
Issuer: /CN=localhost
Verify return code: 18 (self signed certificate)
"""
    rows = findings_from_sslscan(blob, host="10.9.8.7")
    names = {row["name"] for row in rows}
    assert "TLS 1.0 enabled" in names
    assert "SSLv3 enabled" in names
    assert "Untrusted TLS certificate" in names


def test_sslscan_anonymous_ecdh_cipher():
    blob = """
Connected to 172.26.0.4
Testing SSL server 172.26.0.4 on port 443
TLSv1.2  enabled
Accepted  TLSv1.2  256 bits  AECDH-AES256-SHA              Curve 25519 DHE 253
"""
    rows = findings_from_sslscan(blob, host="172.26.0.4")
    names = {row["name"] for row in rows}
    assert "Anonymous TLS cipher" in names
    mapped = map_finding("Anonymous TLS cipher", "172.26.0.4", "high")
    assert mapped["mapped"] is True
    assert mapped["severity"] == "high"


def test_unknown_finding_stays_unmapped():
    mapped = map_finding("quantum flux capacitor", "10.9.8.7", "low")
    assert mapped["weakness"] == "UNMAPPED"
    assert mapped["reason"]


def test_whatweb_cleartext_and_banner():
    blob = "http://10.9.8.7:80 [200 OK] Apache[2.4.41]"
    rows = findings_from_whatweb(blob)
    names = {row["name"] for row in rows}
    assert "Cleartext HTTP" in names
    assert "Server banner disclosure" in names
    assert not any("SMB" in name for name in names)


def test_whatweb_dns_phpmyadmin_and_flask_independent():
    blob = (
        "http://honeypot:8081 [200 OK] PHPMyAdmin[5.2.1], Flask[3.1.8], "
        "Title[phpMyAdmin], nginx"
    )
    rows = findings_from_whatweb(blob)
    names = {row["name"] for row in rows}
    assert "phpMyAdmin interface exposed" in names
    assert "Werkzeug/Flask development server exposed" in names
    assert {row["address"] for row in rows} == {"honeypot"}
    assert "Cleartext HTTP" in names
    assert not any("SMB" in name for name in names)


def test_tlsx_bare_host_invents_nothing():
    rows = findings_from_tlsx("10.9.8.7:443")
    assert rows == []


def test_tlsx_self_signed_when_present():
    rows = findings_from_tlsx("10.9.8.7:443 self-signed tls1.0")
    names = {row["name"] for row in rows}
    assert "Untrusted TLS certificate" in names
    assert "TLS 1.0 enabled" in names


def test_file_drop_cve_not_from_nmap():
    nmap = '<?xml version="1.0"?><nmaprun><host></host></nmaprun> CVE-2024-1234'
    assert findings_from_file_drop(nmap) == []
    openvas = "<openvas><result>CVE-2024-9999 in OpenVAS</result></openvas>"
    rows = findings_from_file_drop(openvas, host="10.9.8.7")
    assert rows and rows[0]["cve"] == "CVE-2024-9999"
    assert rows[0]["claim"] == "vuln_ingested"


def test_file_drop_nessus_cve_uses_reporthost_not_placeholder():
    nessus = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="lab">
    <ReportHost name="10.9.8.7">
      <ReportItem port="443" svc_name="www" pluginID="1" pluginName="OpenSSL">
        <cve>CVE-2024-9999</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""
    rows = findings_from_file_drop(nessus)
    assert len(rows) == 1
    assert rows[0]["cve"] == "CVE-2024-9999"
    assert rows[0]["claim"] == "vuln_ingested"
    assert rows[0]["address"] == "10.9.8.7"


def test_file_drop_openvas_cve_uses_result_host_not_placeholder():
    openvas = """<openvas>
  <result>
    <host>10.9.8.7</host>
    <nvt>
      <ref type="cve" id="CVE-2024-8888"/>
    </nvt>
  </result>
</openvas>
"""
    rows = findings_from_file_drop(openvas)
    assert len(rows) == 1
    assert rows[0]["cve"] == "CVE-2024-8888"
    assert rows[0]["claim"] == "vuln_ingested"
    assert rows[0]["address"] == "10.9.8.7"


def test_file_drop_nessus_pairs_cve_to_each_reporthost():
    nessus = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="lab">
    <ReportHost name="10.9.8.7">
      <ReportItem port="443" pluginID="1" pluginName="a">
        <cve>CVE-2024-1111</cve>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.9.8.8">
      <ReportItem port="80" pluginID="2" pluginName="b">
        <cve>CVE-2024-2222</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""
    rows = findings_from_file_drop(nessus)
    by_cve = {row["cve"]: row["address"] for row in rows}
    assert by_cve == {"CVE-2024-1111": "10.9.8.7", "CVE-2024-2222": "10.9.8.8"}


def test_file_drop_unstructured_cve_without_host_is_not_an_asset():
    openvas = "<openvas><result>CVE-2024-9999 in OpenVAS</result></openvas>"
    rows = findings_from_file_drop(openvas)
    assert rows == []
    assert all(row.get("address") != "file_drop" for row in rows)
