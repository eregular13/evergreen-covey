from covey.findings import findings_from_nmap_services, map_finding


def test_redis_service_maps_high():
    rows = findings_from_nmap_services(
        [
            {
                "address": "172.26.0.4",
                "port": "6379",
                "protocol": "tcp",
                "service": "redis",
            }
        ]
    )
    names = {row["name"] for row in rows}
    assert "Redis exposed" in names
    mapped = map_finding("Redis exposed", "172.26.0.4", "high")
    assert mapped["mapped"] is True
    assert mapped["severity"] == "high"


def test_postgres_service_maps_high():
    rows = findings_from_nmap_services(
        [
            {
                "address": "172.26.0.8",
                "port": "5432",
                "protocol": "tcp",
                "service": "postgresql",
            }
        ]
    )
    names = {row["name"] for row in rows}
    assert "PostgreSQL exposed" in names
    mapped = map_finding("PostgreSQL exposed", "172.26.0.8", "high")
    assert mapped["mapped"] is True
    assert mapped["severity"] == "high"


def test_memcache_service_maps_high():
    rows = findings_from_nmap_services(
        [
            {
                "address": "172.26.0.9",
                "port": "11211",
                "protocol": "tcp",
                "service": "memcache",
            }
        ]
    )
    names = {row["name"] for row in rows}
    assert "Memcached exposed" in names
    mapped = map_finding("Memcached exposed", "172.26.0.9", "high")
    assert mapped["mapped"] is True
    assert mapped["severity"] == "high"


def test_memcached_service_alias_maps_high():
    rows = findings_from_nmap_services(
        [
            {
                "address": "172.26.0.7",
                "port": "11211",
                "protocol": "tcp",
                "service": "memcached",
            }
        ]
    )
    assert "Memcached exposed" in {row["name"] for row in rows}


def test_port_11211_without_service_name_is_not_memcached():
    rows = findings_from_nmap_services(
        [
            {
                "address": "172.26.0.9",
                "port": "11211",
                "protocol": "tcp",
                "service": "",
            }
        ]
    )
    assert "Memcached exposed" not in {row["name"] for row in rows}


def test_nmap_phpmyadmin_and_flask_both_fire_on_one_service():
    rows = findings_from_nmap_services(
        [
            {
                "address": "172.26.0.2",
                "port": "8081",
                "protocol": "tcp",
                "service": "http",
                "product": "Werkzeug httpd",
                "extrainfo": "phpMyAdmin",
            }
        ]
    )
    names = {row["name"] for row in rows}
    assert "phpMyAdmin interface exposed" in names
    assert "Werkzeug/Flask development server exposed" in names
    assert "Cleartext HTTP" in names
