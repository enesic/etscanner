import asyncio
import socket
from typing import List, Optional


class HostDiscoverer:
    """Discover live hosts on a network using lightweight TCP SYN pings.

    Before scanning ports on an entire subnet, quickly identify which
    hosts are actually up by attempting a TCP connection to a fast-
    responding port (default: 80). Hosts that respond are classified
    as *live*; those that time out are skipped.

    This avoids wasting time scanning thousands of ports on dead hosts.
    """

    # Common ports likely to be open on any live host
    PROBE_PORTS = [80, 443, 22, 445, 8080]

    def __init__(self, timeout: float = 1.0, max_concurrent: int = 200):
        """
        Initialize the HostDiscoverer.

        :param timeout: Seconds to wait per probe.
        :param max_concurrent: Maximum concurrent probes.
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def _probe_host(self, ip: str) -> Optional[str]:
        """Probe a single host across several common ports.

        Returns the IP if any probe succeeds, None otherwise.
        """
        async with self._semaphore:
            for port in self.PROBE_PORTS:
                try:
                    fut = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                    writer.close()
                    await writer.wait_closed()
                    return ip  # Host is alive
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    continue
                except Exception:
                    continue
        return None

    async def discover(self, hosts: List[str]) -> List[str]:
        """
        Discover which hosts in the list are live.

        :param hosts: List of IP address strings to probe.
        :return: Sorted list of live IP addresses.
        """
        tasks = [asyncio.create_task(self._probe_host(ip)) for ip in hosts]
        results = await asyncio.gather(*tasks)
        live = sorted(
            [r for r in results if r is not None],
            key=lambda ip: tuple(int(o) for o in ip.split('.'))
        )
        return live
