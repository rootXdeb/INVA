import socket

PORT_SERVICES = {
    21:    "FTP",
    22:    "SSH",
    23:    "TELNET",
    25:    "SMTP",
    53:    "DNS",
    69:    "TFTP",
    79:    "FINGER",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPC",
    135:   "RPC",
    139:   "NETBIOS",
    143:   "IMAP",
    161:   "SNMP",
    443:   "HTTPS",
    445:   "SMB",
    512:   "REXEC",
    513:   "RLOGIN",
    514:   "RSH",
    587:   "SMTP-TLS",
    636:   "LDAPS",
    873:   "RSYNC",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "ORACLE",
    2049:  "NFS",
    2375:  "DOCKER",
    3306:  "MYSQL",
    3389:  "RDP",
    4444:  "METASPLOIT",
    5432:  "POSTGRESQL",
    5900:  "VNC",
    6379:  "REDIS",
    8080:  "HTTP-ALT",
    8443:  "HTTPS-ALT",
    9200:  "ELASTICSEARCH",
    11211: "MEMCACHED",
    27017: "MONGODB",
    31337: "BACKDOOR",
}

BANNER_PORTS = {21, 22, 25, 110, 143, 220, 443, 6379}


def detect_service(ip, port):
    service = PORT_SERVICES.get(port, "UNKNOWN")
    banner = None

    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        if port in (80, 8080):
            s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            service = "HTTP"

        elif port == 443:
            service = "HTTPS"

        elif port in BANNER_PORTS:
            banner = s.recv(1024).decode(errors="ignore").strip()

        s.close()
    except Exception:
        pass

    return service, banner
