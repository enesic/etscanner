import ipaddress
import socket
from typing import List


def parse_targets(target_string: str) -> List[str]:
    """
    Parse a flexible target string into a list of IP address strings.

    Supported formats:
        - Single IP      : "192.168.1.1"
        - Hostname       : "scanme.nmap.org"
        - CIDR block     : "192.168.1.0/24"
        - Dash range     : "192.168.1.1-50"
        - Comma list     : "192.168.1.1,192.168.1.5,10.0.0.1"
        - Mixed          : "192.168.1.0/24,10.0.0.1"

    :param target_string: The raw target input from the CLI.
    :return: Sorted, deduplicated list of IP address strings.
    """
    targets = set()
    parts = [p.strip() for p in target_string.split(',') if p.strip()]

    for part in parts:
        # CIDR notation
        if '/' in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                for host in network.hosts():
                    targets.add(str(host))
                continue
            except ValueError:
                pass

        # Dash range: "192.168.1.1-50" or "192.168.1.1-192.168.1.50"
        if '-' in part:
            try:
                left, right = part.rsplit('-', 1)
                # Check if right side is a full IP or just the last octet
                if '.' in right:
                    # Full IP range: 10.0.0.1-10.0.0.50
                    start_int = int(ipaddress.ip_address(left))
                    end_int = int(ipaddress.ip_address(right))
                    for ip_int in range(start_int, end_int + 1):
                        targets.add(str(ipaddress.ip_address(ip_int)))
                else:
                    # Short range: 192.168.1.1-50 (last octet only)
                    base = '.'.join(left.split('.')[:3])
                    start_octet = int(left.split('.')[-1])
                    end_octet = int(right)
                    for octet in range(start_octet, end_octet + 1):
                        targets.add(f"{base}.{octet}")
                continue
            except (ValueError, IndexError):
                pass

        # Hostname — resolve to IP
        if not _is_ip(part):
            try:
                resolved = socket.gethostbyname(part)
                targets.add(resolved)
                continue
            except socket.gaierror:
                pass

        # Plain IP address
        try:
            ipaddress.ip_address(part)
            targets.add(part)
        except ValueError:
            pass

    return sorted(targets, key=lambda ip: ipaddress.ip_address(ip))


def _is_ip(value: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
