import asyncio
import socket
from typing import List

class AsyncUDPScanner:
    """Asynchronous UDP port scanner.

    Sends empty UDP datagrams and checks for ICMP 'port unreachable'
    responses. If no response is received within the timeout, the port
    is classified as open|filtered.

    Note: UDP scanning is inherently less reliable than TCP scanning.
    On Windows, raw ICMP reception may require administrator privileges.
    """

    def __init__(self, target_host: str, max_concurrent: int = 100, timeout: float = 2.0):
        """
        Initialize the AsyncUDPScanner.

        :param target_host: The IP address or hostname to scan.
        :param max_concurrent: Maximum number of concurrent probes.
        :param timeout: Seconds to wait for an ICMP unreachable response.
        """
        self.target_host = target_host
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.open_filtered_ports: List[int] = []
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def check_port(self, port: int):
        """Send a UDP datagram and classify the port based on the response."""
        async with self._semaphore:
            loop = asyncio.get_event_loop()
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._probe_port, port),
                    timeout=self.timeout + 1
                )
                if result:
                    self.open_filtered_ports.append(port)
            except asyncio.TimeoutError:
                # No response — port is likely open or filtered
                self.open_filtered_ports.append(port)
            except Exception:
                pass

    def _probe_port(self, port: int) -> bool:
        """
        Synchronous UDP probe executed in a thread pool.

        Returns True if the port appears open|filtered (no ICMP unreachable),
        False if an ICMP unreachable error was received (port closed).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(b'\x00', (self.target_host, port))
            try:
                sock.recvfrom(1024)
                # If we receive data, the port is open
                return True
            except socket.timeout:
                # No response — likely open|filtered
                return True
            except ConnectionResetError:
                # ICMP port unreachable received — port is closed
                return False
            except OSError as e:
                # Error code 10054 on Windows means ICMP unreachable
                if getattr(e, 'winerror', None) == 10054 or e.errno == 10054:
                    return False
                return True
        except Exception:
            return False
        finally:
            sock.close()

    async def scan_ports(self, ports: List[int]) -> List[int]:
        """
        Scan a list of UDP ports concurrently.

        :param ports: List of port numbers to scan.
        :return: A sorted list of open|filtered ports.
        """
        self.open_filtered_ports = []
        tasks = [asyncio.create_task(self.check_port(port)) for port in ports]
        await asyncio.gather(*tasks)
        return sorted(self.open_filtered_ports)
