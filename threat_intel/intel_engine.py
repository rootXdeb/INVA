import os
import json
import socket
import struct
import time
import requests
import ipaddress

FEEDS_DIR = os.path.join(os.path.dirname(__file__), "feeds")
CACHE_FILE = os.path.join(FEEDS_DIR, "ip_blacklist.json")
CACHE_TTL = 86400  # 24 hours

THREAT_FEEDS = [
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
]

DANGEROUS_OPEN_PORTS = {
    23:    ("Telnet", "CRITICAL", "Plaintext remote access — easy to intercept"),
    445:   ("SMB", "CRITICAL", "EternalBlue target — commonly exploited for ransomware"),
    3389:  ("RDP", "HIGH",     "Remote Desktop — top brute-force target"),
    4444:  ("Metasploit", "CRITICAL", "Default Metasploit listener port"),
    31337: ("Back Orifice", "CRITICAL", "Classic backdoor port"),
    6379:  ("Redis", "CRITICAL", "Redis often runs without auth — full data access"),
    27017: ("MongoDB", "CRITICAL", "MongoDB often runs without auth"),
    9200:  ("Elasticsearch", "CRITICAL", "Elasticsearch often runs without auth"),
    11211: ("Memcached", "HIGH", "Can be abused for DDoS amplification"),
    2375:  ("Docker", "CRITICAL", "Unauthenticated Docker API — full host compromise"),
    5900:  ("VNC", "HIGH", "Remote desktop — brute-force target"),
    1433:  ("MSSQL", "HIGH", "Database exposed to internet"),
    3306:  ("MySQL", "HIGH", "Database exposed to internet"),
    5432:  ("PostgreSQL", "HIGH", "Database exposed to internet"),
    135:   ("RPC", "HIGH", "Used in several Windows worm propagations"),
    139:   ("NetBIOS", "HIGH", "Information leakage and lateral movement"),
    512:   ("rexec", "HIGH", "Plaintext remote execution"),
    513:   ("rlogin", "HIGH", "Plaintext remote login"),
    514:   ("rsh", "HIGH", "Plaintext remote shell"),
    69:    ("TFTP", "MEDIUM", "Unauthenticated file transfer"),
    161:   ("SNMP", "MEDIUM", "Can leak system info with default community strings"),
    873:   ("rsync", "MEDIUM", "Can expose filesystem without auth"),
    2049:  ("NFS", "MEDIUM", "Can expose filesystems to unauthorized access"),
}


def _load_feeds():
    os.makedirs(FEEDS_DIR, exist_ok=True)

    if os.path.exists(CACHE_FILE):
        age = time.time() - os.path.getmtime(CACHE_FILE)
        if age < CACHE_TTL:
            with open(CACHE_FILE) as f:
                return set(json.load(f))

    blacklist = set()
    for url in THREAT_FEEDS:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ip = line.split()[0]
                    try:
                        ipaddress.ip_address(ip)
                        blacklist.add(ip)
                    except ValueError:
                        pass
        except Exception:
            pass

    with open(CACHE_FILE, "w") as f:
        json.dump(list(blacklist), f)

    return blacklist


def _geo_lookup(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as,hosting",
                            timeout=5)
        if resp.status_code == 200:
            d = resp.json()
            return {
                "country": d.get("country", "Unknown"),
                "city": d.get("city", "Unknown"),
                "isp": d.get("isp", "Unknown"),
                "org": d.get("org", "Unknown"),
                "asn": d.get("as", "Unknown"),
                "hosting": d.get("hosting", False),
            }
    except Exception:
        pass
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown",
            "org": "Unknown", "asn": "Unknown", "hosting": False}


def _is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def analyze_ip(ip: str, open_ports: list) -> dict:
    indicators = []
    threat_score = 0
    blacklist_hits = []

    if _is_private_ip(ip):
        geo = {"country": "Private Network", "city": "N/A", "isp": "Internal",
               "org": "Internal", "asn": "N/A", "hosting": False}
    else:
        geo = _geo_lookup(ip)
        if geo.get("hosting"):
            indicators.append("Hosted on datacenter/VPS infrastructure")
            threat_score += 10

        try:
            blacklist = _load_feeds()
            for feed_ip in blacklist:
                if ip == feed_ip:
                    blacklist_hits.append("Public IP Blacklist")
                    threat_score += 40
                    break
        except Exception:
            pass

    # Port-based threat analysis
    port_threats = []
    for port in open_ports:
        if port in DANGEROUS_OPEN_PORTS:
            name, severity, desc = DANGEROUS_OPEN_PORTS[port]
            port_threats.append({"port": port, "service": name, "severity": severity, "detail": desc})
            if severity == "CRITICAL":
                threat_score += 25
                indicators.append(f"CRITICAL port {port} ({name}) exposed")
            elif severity == "HIGH":
                threat_score += 15
                indicators.append(f"HIGH-risk port {port} ({name}) exposed")
            elif severity == "MEDIUM":
                threat_score += 8

    # Pattern analysis
    if len(open_ports) > 20:
        indicators.append("Excessive open ports — possible misconfigured server")
        threat_score += 10

    db_ports = {1433, 3306, 5432, 27017, 6379, 9200}
    if db_ports.intersection(set(open_ports)):
        indicators.append("Database port(s) exposed to internet")
        threat_score += 15

    legacy_ports = {21, 23, 69, 79, 512, 513, 514}
    if legacy_ports.intersection(set(open_ports)):
        indicators.append("Legacy/insecure protocols detected")
        threat_score += 10

    threat_score = min(threat_score, 100)

    if threat_score >= 70:
        reputation = "MALICIOUS"
    elif threat_score >= 40:
        reputation = "SUSPICIOUS"
    elif threat_score >= 15:
        reputation = "MODERATE"
    else:
        reputation = "CLEAN"

    return {
        "ip": ip,
        "threat_score": threat_score,
        "reputation": reputation,
        "blacklist_hits": blacklist_hits,
        "indicators": indicators,
        "port_threats": port_threats,
        "geolocation": geo,
    }
