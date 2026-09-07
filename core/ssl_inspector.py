import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional


# Cipher suites known to be weak or deprecated
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "RC2", "IDEA", "SEED",
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class SSLInspector:
    """Inspect SSL/TLS certificates and configuration on open ports.

    Uses Python's built-in ``ssl`` module — no external dependencies.
    Connects to each SSL-capable port, performs a handshake, and
    extracts certificate metadata and security posture information.
    """

    def __init__(self, target_host: str, timeout: float = 3.0):
        """
        Initialize the SSLInspector.

        :param target_host: Target hostname or IP address.
        :param timeout: Connection timeout in seconds.
        """
        self.target_host = target_host
        self.timeout = timeout

    async def inspect_port(self, port: int) -> Optional[Dict]:
        """
        Attempt an SSL handshake on the given port and return cert info.

        :param port: Port number to inspect.
        :return: Dictionary of SSL info, or None if not SSL.
        """
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self._do_handshake, port),
                timeout=self.timeout + 1
            )
            return result
        except (asyncio.TimeoutError, Exception):
            return None

    def _do_handshake(self, port: int) -> Optional[Dict]:
        """Synchronous SSL handshake run in a thread pool."""
        # Try with SNI first (hostname-based)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want info even for self-signed

        try:
            with socket.create_connection((self.target_host, port), timeout=self.timeout) as sock:
                # Use SNI only when connecting to a hostname (not an IP)
                server_hostname = self.target_host if not self._is_ip(self.target_host) else None
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    return self._parse_cert(cert, cipher, tls_version)
        except ssl.SSLError:
            return None
        except (ConnectionRefusedError, OSError, socket.timeout):
            return None
        except Exception:
            return None

    def _parse_cert(self, cert: dict, cipher: tuple, tls_version: str) -> Dict:
        """Extract and annotate relevant certificate fields."""
        result = {
            "tls_version": tls_version or "Unknown",
            "cipher": cipher[0] if cipher else "Unknown",
            "warnings": [],
        }

        # TLS version check
        if tls_version in WEAK_PROTOCOLS:
            result["warnings"].append(f"Deprecated protocol: {tls_version}")

        # Cipher strength check
        cipher_name = (cipher[0] or "").upper()
        for weak in WEAK_CIPHERS:
            if weak in cipher_name:
                result["warnings"].append(f"Weak cipher: {cipher[0]}")
                break

        if not cert:
            result["warnings"].append("No certificate / self-signed")
            return result

        # Subject / issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["common_name"] = subject.get("commonName", "N/A")
        result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

        # Self-signed check
        if subject == issuer:
            result["warnings"].append("Self-signed certificate")

        # Expiry
        not_after_str = cert.get("notAfter")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days
                result["expires"] = not_after.strftime("%Y-%m-%d")
                result["days_remaining"] = days_remaining
                if days_remaining < 0:
                    result["warnings"].append("Certificate EXPIRED")
                elif days_remaining < 30:
                    result["warnings"].append(f"Expires in {days_remaining} days!")
            except ValueError:
                pass

        # Subject Alternative Names (SAN) — great for domain discovery
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_list.append(san_value)
        if san_list:
            result["sans"] = san_list

        return result

    async def inspect_all(self, open_ports: List[int]) -> Dict[int, Dict]:
        """
        Inspect all given ports for SSL/TLS.

        :param open_ports: List of open port numbers.
        :return: Dictionary of port → SSL info for SSL-capable ports only.
        """
        tasks = {port: asyncio.create_task(self.inspect_port(port)) for port in open_ports}
        results = {}
        for port, task in tasks.items():
            info = await task
            if info is not None:
                results[port] = info
        return results

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if the string is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
