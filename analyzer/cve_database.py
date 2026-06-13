CVE_DB = {
    # Apache
    "Apache/2.4.49":  ("HIGH",     "CVE-2021-41773 Path Traversal",  "Upgrade Apache to 2.4.51+"),
    "Apache/2.4.50":  ("HIGH",     "CVE-2021-42013 Path Traversal",  "Upgrade Apache to 2.4.51+"),
    "Apache/2.2":     ("HIGH",     "CVE-2017-7679 Buffer Overflow",  "Upgrade Apache to 2.4.x"),

    # OpenSSH
    "OpenSSH_7.2":    ("MEDIUM",   "CVE-2016-6210 User Enumeration", "Upgrade OpenSSH to 8.x+"),
    "OpenSSH_7.4":    ("MEDIUM",   "CVE-2018-15473 User Enumeration","Upgrade OpenSSH to 8.x+"),
    "OpenSSH_6":      ("HIGH",     "CVE-2016-0778 Buffer Overflow",  "Upgrade OpenSSH immediately"),

    # ProFTPD
    "ProFTPD/1.3.5":  ("HIGH",     "CVE-2015-3306 Remote Code Exec", "Upgrade ProFTPD to 1.3.6+"),

    # OpenSSL
    "OpenSSL/1.0.1":  ("CRITICAL", "CVE-2014-0160 Heartbleed",       "Upgrade OpenSSL to 1.0.2+"),
    "OpenSSL/1.0.2":  ("HIGH",     "CVE-2016-2107 DROWN Attack",     "Upgrade OpenSSL to 1.1.0+"),

    # Nginx
    "nginx/1.14":     ("MEDIUM",   "CVE-2019-9511 HTTP/2 DoS",       "Upgrade Nginx to 1.17.3+"),
    "nginx/1.10":     ("HIGH",     "CVE-2017-7529 Integer Overflow",  "Upgrade Nginx to 1.13.3+"),

    # IIS
    "Microsoft-IIS/7.5": ("HIGH",  "CVE-2017-7269 Buffer Overflow",  "Apply MS15-034 patch"),
    "Microsoft-IIS/6.0": ("CRITICAL","CVE-2017-7269 RCE WebDAV",     "Upgrade IIS immediately"),

    # Samba/SMB
    "Samba 3":        ("CRITICAL", "CVE-2017-7494 SambaCry RCE",     "Upgrade Samba to 4.6.4+"),
    "Samba 4.1":      ("HIGH",     "CVE-2018-1050 Denial of Service", "Upgrade Samba to 4.7.6+"),

    # vsftpd
    "vsftpd 2.3.4":   ("CRITICAL", "CVE-2011-2523 Backdoor RCE",     "Remove and reinstall vsftpd 3.x"),
}
