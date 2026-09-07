import re
from typing import Dict, List

# Local CVE database mapping service patterns to known vulnerabilities.
# Each entry contains a regex pattern matching the banner and a list
# of associated CVEs with severity and description.
CVE_DATABASE = [
    {
        "pattern": r"OpenSSH[_\s]7\.([0-4])",
        "service": "OpenSSH 7.0-7.4",
        "cves": [
            {"id": "CVE-2017-15906", "severity": "Medium", "description": "Read-only bypass in sftp-server"},
            {"id": "CVE-2016-10009", "severity": "High",   "description": "Remote code execution via agent forwarding"},
            {"id": "CVE-2016-10012", "severity": "High",   "description": "Privilege escalation via shared memory"},
        ]
    },
    {
        "pattern": r"OpenSSH[_\s]8\.[0-3]",
        "service": "OpenSSH 8.0-8.3",
        "cves": [
            {"id": "CVE-2021-28041", "severity": "Medium", "description": "Double free in ssh-agent"},
            {"id": "CVE-2020-15778", "severity": "Medium", "description": "Command injection via scp"},
        ]
    },
    {
        "pattern": r"OpenSSH[_\s]8\.[4-9]|OpenSSH[_\s]9\.[0-3]",
        "service": "OpenSSH 8.4-9.3",
        "cves": [
            {"id": "CVE-2023-38408", "severity": "Critical", "description": "Remote code execution via PKCS#11 provider"},
        ]
    },
    {
        "pattern": r"Apache/2\.4\.([0-9]|[1-3][0-9]|4[0-9])[^0-9]",
        "service": "Apache 2.4.0-2.4.49",
        "cves": [
            {"id": "CVE-2021-41773", "severity": "Critical", "description": "Path traversal and RCE"},
            {"id": "CVE-2021-42013", "severity": "Critical", "description": "Path traversal bypass"},
        ]
    },
    {
        "pattern": r"Apache/2\.4\.(50|51)[^0-9]",
        "service": "Apache 2.4.50-2.4.51",
        "cves": [
            {"id": "CVE-2022-22720", "severity": "High", "description": "HTTP request smuggling"},
        ]
    },
    {
        "pattern": r"nginx/1\.(1[0-7]|[0-9])\.",
        "service": "Nginx 1.0-1.17",
        "cves": [
            {"id": "CVE-2019-9511",  "severity": "High",   "description": "HTTP/2 Data Dribble DoS"},
            {"id": "CVE-2019-9513",  "severity": "High",   "description": "HTTP/2 Resource Loop DoS"},
            {"id": "CVE-2018-16843", "severity": "Medium",  "description": "Excessive memory consumption"},
        ]
    },
    {
        "pattern": r"nginx/1\.(1[89]|2[0-2])\.",
        "service": "Nginx 1.18-1.22",
        "cves": [
            {"id": "CVE-2021-23017", "severity": "Critical", "description": "DNS resolver off-by-one heap write"},
            {"id": "CVE-2022-41741", "severity": "High",     "description": "MP4 module memory corruption"},
        ]
    },
    {
        "pattern": r"Microsoft-IIS/([5-7]\.)",
        "service": "IIS 5.x-7.x",
        "cves": [
            {"id": "CVE-2017-7269", "severity": "Critical", "description": "WebDAV buffer overflow RCE"},
        ]
    },
    {
        "pattern": r"vsftpd\s+2\.",
        "service": "vsftpd 2.x",
        "cves": [
            {"id": "CVE-2011-2523", "severity": "Critical", "description": "Backdoor command execution (v2.3.4)"},
        ]
    },
    {
        "pattern": r"ProFTPD\s+1\.[23]\.",
        "service": "ProFTPD 1.2-1.3",
        "cves": [
            {"id": "CVE-2015-3306", "severity": "Critical", "description": "mod_copy unauthenticated file copy"},
            {"id": "CVE-2019-12815", "severity": "Critical", "description": "Arbitrary file copy without auth"},
        ]
    },
    {
        "pattern": r"MySQL.*5\.[0-6]\.",
        "service": "MySQL 5.0-5.6",
        "cves": [
            {"id": "CVE-2016-6662", "severity": "Critical", "description": "Remote root code execution"},
            {"id": "CVE-2012-2122", "severity": "High",     "description": "Authentication bypass"},
        ]
    },
    {
        "pattern": r"VMware\s+Authentication\s+Daemon",
        "service": "VMware Auth Daemon",
        "cves": [
            {"id": "CVE-2017-4901", "severity": "Medium", "description": "DnD function out-of-bounds access"},
        ]
    },
    {
        "pattern": r"Exim\s+4\.([0-8]|9[0-3])",
        "service": "Exim 4.0-4.93",
        "cves": [
            {"id": "CVE-2019-10149", "severity": "Critical", "description": "The Return of the WIZard RCE"},
        ]
    },
    {
        "pattern": r"Postfix",
        "service": "Postfix",
        "cves": [
            {"id": "CVE-2023-51764", "severity": "Medium", "description": "SMTP smuggling vulnerability"},
        ]
    },
]


class CVEMatcher:
    """Match service banners against a local vulnerability database.

    Parses banners obtained from banner grabbing, extracts the service
    name and version, and matches them against known CVE entries stored
    in a built-in dictionary.
    """

    def __init__(self):
        self.database = CVE_DATABASE

    def match_banner(self, banner: str) -> List[Dict]:
        """
        Match a single banner against the CVE database.

        :param banner: The service banner string.
        :return: List of matched CVE entries.
        """
        matches = []
        if not banner or banner == "Unknown Service":
            return matches

        for entry in self.database:
            if re.search(entry["pattern"], banner, re.IGNORECASE):
                matches.append({
                    "service": entry["service"],
                    "cves": entry["cves"]
                })

        return matches

    def analyze_all(self, service_results: Dict[int, str]) -> Dict[int, List[Dict]]:
        """
        Match all discovered service banners against the CVE database.

        :param service_results: Dictionary mapping port numbers to banners.
        :return: Dictionary mapping port numbers to lists of CVE matches.
        """
        results = {}
        for port, banner in service_results.items():
            matches = self.match_banner(banner)
            if matches:
                results[port] = matches
        return results
