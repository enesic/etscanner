import asyncio
import http.client
import re
import socket
import ssl
from typing import Dict, List, Optional

# Known technology fingerprints: (header_or_body_pattern, technology_name)
TECH_SIGNATURES = [
    # Web servers
    (r"apache",             "Apache"),
    (r"nginx",              "Nginx"),
    (r"microsoft-iis",      "Microsoft IIS"),
    (r"lighttpd",           "Lighttpd"),
    (r"caddy",              "Caddy"),
    (r"gunicorn",           "Gunicorn"),
    (r"jetty",              "Jetty"),
    (r"tomcat",             "Apache Tomcat"),

    # App frameworks / CMS (body patterns)
    (r"wp-content|wp-login|wordpress",  "WordPress"),
    (r"joomla",                         "Joomla"),
    (r"drupal",                         "Drupal"),
    (r"django",                         "Django"),
    (r"laravel",                        "Laravel"),
    (r"flask",                          "Flask"),
    (r"express",                        "Express.js"),
    (r"ruby on rails",                  "Ruby on Rails"),

    # Monitoring / DevOps tools
    (r"grafana",            "Grafana"),
    (r"kibana",             "Kibana"),
    (r"jenkins",            "Jenkins"),
    (r"gitlab",             "GitLab"),
    (r"prometheus",         "Prometheus"),
    (r"portainer",          "Portainer"),
    (r"phpmyadmin",         "phpMyAdmin"),
    (r"adminer",            "Adminer"),
]

# Security headers that should be present on any hardened web server
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class HTTPFingerprinter:
    """Fingerprint web services running on open HTTP/HTTPS ports.

    Uses Python's built-in ``http.client`` — no external dependencies.
    Sends an HTTP HEAD (and optionally GET) request to gather:
      - Page title
      - Server and technology headers
      - Security header audit
      - Technology stack detection
    """

    # Ports likely running HTTPS
    HTTPS_PORTS = {443, 8443, 9443, 4443, 10443}
    # Ports likely running HTTP
    HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 7070, 9090, 1080, 3001, 4000}

    def __init__(self, target_host: str, timeout: float = 3.0):
        """
        Initialize the HTTPFingerprinter.

        :param target_host: Target hostname or IP address.
        :param timeout: Request timeout in seconds.
        """
        self.target_host = target_host
        self.timeout = timeout

    def _is_web_port(self, port: int) -> bool:
        """Heuristic: is this port likely serving HTTP/HTTPS?"""
        return port in self.HTTPS_PORTS or port in self.HTTP_PORTS

    async def fingerprint_port(self, port: int) -> Optional[Dict]:
        """
        Fingerprint a single port.

        :param port: Port number to probe.
        :return: Dictionary of HTTP info, or None if not HTTP.
        """
        loop = asyncio.get_event_loop()
        use_ssl = port in self.HTTPS_PORTS

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._do_request, port, use_ssl),
                timeout=self.timeout + 2
            )
            if result is None and not use_ssl:
                # Retry with HTTPS in case the port serves it anyway
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._do_request, port, True),
                    timeout=self.timeout + 2
                )
            return result
        except (asyncio.TimeoutError, Exception):
            return None

    def _do_request(self, port: int, use_ssl: bool) -> Optional[Dict]:
        """Synchronous HTTP request run in a thread pool."""
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    self.target_host, port, timeout=self.timeout, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(
                    self.target_host, port, timeout=self.timeout
                )

            # HEAD request first (lightweight)
            conn.request("HEAD", "/", headers={"User-Agent": "etscanner/1.0", "Host": self.target_host})
            resp = conn.getresponse()
            headers = dict(resp.getheaders())

            result = {
                "status_code": resp.status,
                "protocol": "HTTPS" if use_ssl else "HTTP",
                "headers": headers,
                "server": headers.get("Server", headers.get("server", "")),
                "powered_by": headers.get("X-Powered-By", headers.get("x-powered-by", "")),
                "technologies": [],
                "security_headers": {},
                "title": "",
                "warnings": [],
            }

            # Security header audit
            headers_lower = {k.lower(): v for k, v in headers.items()}
            for sh in SECURITY_HEADERS:
                result["security_headers"][sh] = sh.lower() in headers_lower

            missing = [sh for sh, present in result["security_headers"].items() if not present]
            if missing:
                result["warnings"].append(f"Missing security headers: {', '.join(missing)}")

            # Detect technologies from Server / X-Powered-By headers
            header_blob = " ".join([
                result["server"], result["powered_by"],
                headers.get("X-Generator", ""),
                headers.get("x-generator", ""),
            ]).lower()
            for pattern, tech in TECH_SIGNATURES:
                if re.search(pattern, header_blob, re.IGNORECASE):
                    if tech not in result["technologies"]:
                        result["technologies"].append(tech)

            # GET request to grab title and body fingerprint
            try:
                conn2 = http.client.HTTPSConnection(
                    self.target_host, port, timeout=self.timeout, context=ctx if use_ssl else None
                ) if use_ssl else http.client.HTTPConnection(
                    self.target_host, port, timeout=self.timeout
                )
                conn2.request("GET", "/", headers={"User-Agent": "etscanner/1.0", "Host": self.target_host})
                resp2 = conn2.getresponse()
                body = resp2.read(4096).decode("utf-8", errors="ignore")

                # Extract <title>
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:80]

                # Detect technologies from body
                for pattern, tech in TECH_SIGNATURES:
                    if re.search(pattern, body, re.IGNORECASE):
                        if tech not in result["technologies"]:
                            result["technologies"].append(tech)

                conn2.close()
            except Exception:
                pass

            conn.close()
            return result

        except (ConnectionRefusedError, OSError, socket.timeout, http.client.HTTPException):
            return None
        except Exception:
            return None

    async def fingerprint_all(self, open_ports: List[int]) -> Dict[int, Dict]:
        """
        Fingerprint all web-likely ports.

        :param open_ports: List of open port numbers.
        :return: Dictionary of port → HTTP fingerprint for web ports only.
        """
        web_ports = [p for p in open_ports if self._is_web_port(p)]
        # Also probe any unknown port to check if it serves HTTP
        other_ports = [p for p in open_ports if not self._is_web_port(p)]

        tasks = {}
        for port in web_ports + other_ports[:5]:  # Cap extra ports to 5
            tasks[port] = asyncio.create_task(self.fingerprint_port(port))

        results = {}
        for port, task in tasks.items():
            info = await task
            if info is not None:
                results[port] = info

        return results
