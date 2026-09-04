import asyncio
from typing import Dict, List

class ServiceAnalyzer:
    def __init__(self, target_host: str, timeout: float = 2.0):
        """
        Initialize the ServiceAnalyzer.
        
        :param target_host: The IP address or hostname of the target.
        :param timeout: Timeout in seconds for connection and reading data.
        """
        self.target_host = target_host
        self.timeout = timeout

    async def grab_banner(self, port: int) -> str:
        """
        Connect to a specific port and read the initial banner response.
        If the server expects the client to speak first, it might time out.
        In that case, we send a basic HTTP HEAD request as a generic probe.
        """
        try:
            # Establish the connection
            fut = asyncio.open_connection(self.target_host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            
            try:
                # Wait for the server to send a banner
                data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                banner = data.decode('utf-8', errors='ignore').strip()
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                # If no banner is sent automatically, attempt a basic HTTP probe
                try:
                    probe = f"HEAD / HTTP/1.0\r\nHost: {self.target_host}\r\n\r\n".encode('utf-8')
                    writer.write(probe)
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    banner = ""
            
            # Clean up the connection
            writer.close()
            await writer.wait_closed()
            
            # Return the first line or truncated banner for readability
            return banner.split('\n')[0].strip() if banner else ""
            
        except Exception:
            return ""

    async def analyze_services(self, open_ports: List[int]) -> Dict[int, str]:
        """
        Perform banner grabbing concurrently on all discovered open ports.
        
        :param open_ports: List of open port numbers.
        :return: A dictionary mapping port numbers to their grabbed banners.
        """
        results = {}
        
        async def analyze_port(port: int):
            banner = await self.grab_banner(port)
            if banner:
                results[port] = banner
            else:
                results[port] = "Unknown Service"

        tasks = [asyncio.create_task(analyze_port(port)) for port in open_ports]
        if tasks:
            await asyncio.gather(*tasks)
            
        return dict(sorted(results.items()))
