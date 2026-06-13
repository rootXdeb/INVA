OWASP = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Maps port or service → list of (owasp_id, description)
PORT_COMPLIANCE = {
    21:    [("A02", "FTP transmits credentials and data in plaintext"),
            ("A07", "FTP supports weak or anonymous authentication")],
    23:    [("A02", "Telnet transmits all data in plaintext"),
            ("A07", "No modern authentication mechanisms"),
            ("A05", "Telnet should be disabled in all modern environments")],
    25:    [("A05", "Open SMTP relay enables spam and phishing abuse")],
    53:    [("A05", "DNS misconfiguration can enable cache poisoning or zone transfer")],
    69:    [("A07", "TFTP has no authentication — allows unauthenticated file transfer"),
            ("A02", "TFTP transfers data in plaintext")],
    80:    [("A02", "HTTP transmits data without encryption"),
            ("A05", "Serving content over HTTP instead of HTTPS is a misconfiguration")],
    110:   [("A02", "POP3 transmits email and credentials in plaintext")],
    135:   [("A05", "RPC/DCOM exposed — misconfiguration enabling lateral movement")],
    139:   [("A05", "NetBIOS exposure leaks system information"),
            ("A01", "NetBIOS can expose shared resources without proper access control")],
    143:   [("A02", "IMAP without TLS transmits email in plaintext")],
    161:   [("A07", "SNMP v1/v2 uses plain-text community strings"),
            ("A05", "Default SNMP community strings allow system info leakage")],
    445:   [("A05", "SMB exposed — common vector for ransomware (EternalBlue)"),
            ("A06", "Unpatched SMB is highly susceptible to known exploits")],
    512:   [("A02", "rexec transmits credentials in plaintext"),
            ("A07", "rexec lacks modern authentication")],
    513:   [("A02", "rlogin is a plaintext legacy protocol"),
            ("A07", "rlogin uses host-based authentication — easily spoofed")],
    514:   [("A02", "rsh executes commands over unencrypted channel"),
            ("A01", "rsh can allow command execution without proper authorization")],
    873:   [("A01", "rsync without auth allows unauthenticated filesystem access")],
    1433:  [("A05", "MSSQL exposed to internet — should be behind firewall"),
            ("A07", "Database ports exposed enable brute-force attacks")],
    2049:  [("A01", "NFS without proper exports can expose filesystem to all hosts")],
    2375:  [("A05", "Docker daemon API exposed — allows full host compromise"),
            ("A01", "Unauthenticated Docker API grants root-level access")],
    3306:  [("A05", "MySQL exposed to internet — should be behind firewall"),
            ("A07", "Database ports exposed enable brute-force attacks")],
    3389:  [("A07", "RDP is a top target for brute-force and credential stuffing"),
            ("A05", "RDP exposed to internet — major attack surface")],
    4444:  [("A05", "Metasploit default port open — possible active compromise")],
    5432:  [("A05", "PostgreSQL exposed to internet — should be behind firewall"),
            ("A07", "Database ports exposed enable brute-force attacks")],
    5900:  [("A07", "VNC often lacks strong authentication"),
            ("A05", "Remote desktop exposed without VPN")],
    6379:  [("A07", "Redis has no authentication by default"),
            ("A05", "Redis exposed to internet allows full data access")],
    8080:  [("A02", "HTTP alternate port — unencrypted traffic"),
            ("A05", "Development/proxy port exposed to internet")],
    9200:  [("A07", "Elasticsearch has no authentication by default"),
            ("A01", "Unauthenticated Elasticsearch allows full data read/write")],
    11211: [("A05", "Memcached exposed enables DDoS amplification attacks")],
    27017: [("A07", "MongoDB has no authentication by default in older versions"),
            ("A01", "Unauthenticated MongoDB allows full database access")],
    31337: [("A05", "Known backdoor port — indicates active compromise")],
}

SERVICE_COMPLIANCE = {
    "HTTP":  [("A02", "Unencrypted HTTP protocol in use")],
    "FTP":   [("A02", "Plaintext FTP in use — upgrade to SFTP or FTPS")],
    "TELNET":[("A02", "Plaintext Telnet in use — replace with SSH")],
}


def map_findings(results: list) -> dict:
    violations = {}
    port_mapping = {}

    for finding in results:
        port = finding.get("port")
        service = finding.get("service", "").upper()
        cve_found = "CVE" in str(finding.get("issue", ""))
        risk = finding.get("risk", "LOW")

        mappings_for_port = []

        if port in PORT_COMPLIANCE:
            for owasp_id, desc in PORT_COMPLIANCE[port]:
                mappings_for_port.append((owasp_id, desc))
                violations.setdefault(owasp_id, []).append(
                    {"port": port, "service": service, "detail": desc}
                )

        for svc_key, entries in SERVICE_COMPLIANCE.items():
            if svc_key in service:
                for owasp_id, desc in entries:
                    if (owasp_id, desc) not in mappings_for_port:
                        mappings_for_port.append((owasp_id, desc))
                        violations.setdefault(owasp_id, []).append(
                            {"port": port, "service": service, "detail": desc}
                        )

        if cve_found:
            owasp_id = "A06"
            desc = f"Known CVE found on port {port}/{service} — component is outdated or unpatched"
            violations.setdefault(owasp_id, []).append(
                {"port": port, "service": service, "detail": desc}
            )
            mappings_for_port.append((owasp_id, desc))

        if risk in ("HIGH", "CRITICAL") and not mappings_for_port:
            owasp_id = "A05"
            desc = f"High-risk service on port {port} indicates security misconfiguration"
            violations.setdefault(owasp_id, []).append(
                {"port": port, "service": service, "detail": desc}
            )
            mappings_for_port.append((owasp_id, desc))

        if mappings_for_port:
            port_mapping[port] = [{"owasp_id": oid, "detail": d} for oid, d in mappings_for_port]

    compliant = [k for k in OWASP if k not in violations]
    score = round((len(compliant) / len(OWASP)) * 100)

    return {
        "violations": {k: {"title": OWASP[k], "findings": v} for k, v in violations.items()},
        "compliant_controls": compliant,
        "compliance_score": score,
        "port_mapping": port_mapping,
        "owasp_labels": OWASP,
    }
