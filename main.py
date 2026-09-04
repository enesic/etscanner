import argparse
import asyncio
import sys
import time

from core.scanner import AsyncPortScanner
from core.analyzer import ServiceAnalyzer
from utils.display import (
    print_banner,
    print_info,
    print_success,
    print_error,
    print_port_result
)

def parse_ports(port_string: str) -> list[int]:
    """Parse port string like '80,443,1000-2000' into a list of integers."""
    ports = set()
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            except ValueError:
                print_error(f"Invalid port range: {part}")
                sys.exit(1)
        elif part:
            try:
                ports.add(int(part))
            except ValueError:
                print_error(f"Invalid port: {part}")
                sys.exit(1)
    
    valid_ports = [p for p in ports if 1 <= p <= 65535]
    return sorted(valid_ports)

async def main():
    parser = argparse.ArgumentParser(description="e'tscanner - Asynchronous TCP Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g., '80,443,1-1024')")
    parser.add_argument("-c", "--concurrent", type=int, default=500, help="Maximum concurrent connections")
    
    args = parser.parse_args()
    
    print_banner()
    
    ports_to_scan = parse_ports(args.ports)
    if not ports_to_scan:
        print_error("No valid ports specified.")
        sys.exit(1)
        
    print_info(f"Target: {args.target}")
    print_info(f"Ports to scan: {len(ports_to_scan)}")
    print_info("Starting port scan...\n")
    
    start_time = time.time()
    
    # Initialize and run the port scanner
    scanner = AsyncPortScanner(target_host=args.target, max_concurrent=args.concurrent, timeout=1.5)
    open_ports = await scanner.scan_ports(ports_to_scan)
    
    scan_duration = time.time() - start_time
    
    if not open_ports:
        print_error(f"No open ports found on {args.target}.")
        print_info(f"Scan completed in {scan_duration:.2f} seconds.")
        return
        
    print_success(f"Found {len(open_ports)} open ports. Grabbing banners...\n")
    
    # Initialize and run the service analyzer (banner grabbing)
    analyzer = ServiceAnalyzer(target_host=args.target, timeout=2.0)
    service_results = await analyzer.analyze_services(open_ports)
    
    # Display the final report
    print_success(f"Scan Report for {args.target}:")
    for port in open_ports:
        service_banner = service_results.get(port, "")
        # Clean up very long banners for display
        if len(service_banner) > 50:
            service_banner = service_banner[:47] + "..."
        print_port_result(port, service_banner)
        
    total_duration = time.time() - start_time
    print("")
    print_info(f"Total scan time: {total_duration:.2f} seconds.")

if __name__ == "__main__":
    try:
        # For Windows, use the SelectorEventLoop to avoid issues with many connections/subprocess errors
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n")
        print_error("Scan interrupted by user. Exiting...")
        sys.exit(0)
