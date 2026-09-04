import asyncio
import socket
from typing import List

class AsyncPortScanner:
    def __init__(self, target_host: str, max_concurrent: int = 100, timeout: float = 1.0):
        """
        Initialize the AsyncPortScanner.
        
        :param target_host: The IP address or hostname to scan.
        :param max_concurrent: Maximum number of concurrent connections.
        :param timeout: Connection timeout in seconds.
        """
        self.target_host = target_host
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.open_ports = []
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def check_port(self, port: int):
        """
        Attempt to connect to a single port and record it if open.
        """
        async with self._semaphore:
            try:
                fut = asyncio.open_connection(self.target_host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                
                # Connection successful
                self.open_ports.append(port)
                
                # Clean up the connection
                writer.close()
                await writer.wait_closed()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is likely closed or filtered
                pass
            except Exception:
                # Catch any other unexpected exceptions during connection
                pass

    async def scan_ports(self, ports: List[int]) -> List[int]:
        """
        Scan a list of ports concurrently using asyncio.
        
        :param ports: List of port numbers to scan.
        :return: A sorted list of open ports.
        """
        self.open_ports = []
        tasks = [asyncio.create_task(self.check_port(port)) for port in ports]
        await asyncio.gather(*tasks)
        
        return sorted(self.open_ports)
