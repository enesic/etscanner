import argparse
import asyncio
import sys
import time

from core.scanner import AsyncPortScanner
from core.udp_scanner import AsyncUDPScanner
from core.analyzer import ServiceAnalyzer
from core.fingerprint import OSFingerprinter
from core.cve_matcher import CVEMatcher
from core.discovery import SubdomainDiscoverer
from utils.display import (
    Colors,
    print_banner,
    print_info,
    print_success,
    print_warning,
    print_error,
    print_port_result,
)
from utils.progress import ProgressBar
from utils.exporter import ResultExporter


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


async def run_subdomain_discovery(args):
    """Run subdomain discovery mode."""
    print_info(f"Starting subdomain discovery for: {args.discover}")
    print_info("Using built-in wordlist with common subdomain prefixes...\n")

    discoverer = SubdomainDiscoverer(
        domain=args.discover,
        max_concurrent=args.concurrent,
        timeout=args.timeout,
    )

    start_time = time.time()
    results = await discoverer.discover()
    duration = time.time() - start_time

    if not results:
        print_error(f"No subdomains found for {args.discover}.")
    else:
        print_success(f"Found {len(results)} subdomain(s):\n")
        for entry in results:
            print(f"    {Colors.GREEN}{entry['subdomain']}{Colors.RESET}"
                  f"  ->  {Colors.CYAN}{entry['ip']}{Colors.RESET}")
        print("")

    print_info(f"Discovery completed in {duration:.2f} seconds.")


async def run_port_scan(args):
    """Run port scanning mode with all features."""
    ports_to_scan = parse_ports(args.ports)
    if not ports_to_scan:
        print_error("No valid ports specified.")
        sys.exit(1)

    scan_mode = "UDP" if args.udp else "TCP"

    print_info(f"Target     : {args.target}")
    print_info(f"Ports      : {len(ports_to_scan)}")
    print_info(f"Mode       : {scan_mode}")
    print_info(f"Timeout    : {args.timeout}s")
    print_info(f"Retries    : {args.retry}")
    print_info(f"Concurrent : {args.concurrent}")
    print_info("Starting port scan...\n")

    start_time = time.time()

    # --- Progress bar setup ---
    progress = ProgressBar(total=len(ports_to_scan), prefix="  Scanning: ")

    def on_progress():
        progress.update()

    # --- Port scanning ---
    if args.udp:
        scanner = AsyncUDPScanner(
            target_host=args.target,
            max_concurrent=args.concurrent,
            timeout=args.timeout,
        )
        open_ports = await scanner.scan_ports(ports_to_scan)
        progress.finish()
    else:
        scanner = AsyncPortScanner(
            target_host=args.target,
            max_concurrent=args.concurrent,
            timeout=args.timeout,
            retries=args.retry,
            on_progress=on_progress,
        )
        open_ports = await scanner.scan_ports(ports_to_scan)
        progress.finish()

    scan_duration = time.time() - start_time

    if not open_ports:
        port_label = "open|filtered" if args.udp else "open"
        print_error(f"No {port_label} ports found on {args.target}.")
        print_info(f"Scan completed in {scan_duration:.2f} seconds.")
        return

    port_label = "open|filtered" if args.udp else "open"
    print_success(f"Found {len(open_ports)} {port_label} port(s).")

    # --- Banner grabbing (TCP only) ---
    service_results = {}
    if not args.udp:
        print_info("Grabbing banners...\n")
        analyzer = ServiceAnalyzer(target_host=args.target, timeout=args.timeout)
        service_results = await analyzer.analyze_services(open_ports)
    else:
        print("")
        for port in open_ports:
            service_results[port] = "open|filtered (UDP)"

    # --- OS Fingerprinting ---
    os_info = {}
    if not args.udp:
        print_info("Running OS fingerprinting...")
        fingerprinter = OSFingerprinter(target_host=args.target, timeout=args.timeout)
        os_info = await fingerprinter.fingerprint(open_ports)

        os_guess = os_info.get("os_guess", "Unknown")
        confidence = os_info.get("confidence", "N/A")
        details = os_info.get("details", "")
        print_success(f"OS Guess: {Colors.BOLD}{os_guess}{Colors.RESET}"
                      f"  (Confidence: {confidence}, {details})\n")

    # --- CVE matching ---
    cve_results = {}
    if not args.udp and service_results:
        matcher = CVEMatcher()
        cve_results = matcher.analyze_all(service_results)

    # --- Display results ---
    print_success(f"Scan Report for {args.target}:")
    for port in open_ports:
        service_banner = service_results.get(port, "")
        if len(service_banner) > 60:
            service_banner = service_banner[:57] + "..."
        print_port_result(port, service_banner)

        # Show CVEs for this port
        if port in cve_results:
            for match in cve_results[port]:
                for cve in match.get("cves", []):
                    severity = cve["severity"]
                    if severity == "Critical":
                        color = Colors.RED + Colors.BOLD
                    elif severity == "High":
                        color = Colors.RED
                    elif severity == "Medium":
                        color = Colors.YELLOW
                    else:
                        color = Colors.WHITE
                    print(f"         {color}[{severity:>8}]{Colors.RESET}"
                          f" {cve['id']} — {cve['description']}")

    total_duration = time.time() - start_time
    print("")
    print_info(f"Total scan time: {total_duration:.2f} seconds.")

    # --- Export results ---
    if args.output:
        exporter = ResultExporter(
            target_host=args.target,
            open_ports=open_ports,
            service_results=service_results,
            cve_results=cve_results,
            os_info=os_info,
            scan_duration=total_duration,
        )
        try:
            exporter.export(args.output)
            print_success(f"Results saved to: {args.output}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")


async def main():
    parser = argparse.ArgumentParser(
        description="e'tscanner — Asynchronous TCP/UDP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py -t 192.168.1.1 -p 80,443
  python main.py -t 192.168.1.1 -p 1-1024 --udp
  python main.py -t 192.168.1.1 -p 1-65535 -c 1000 -T 2 --retry 2
  python main.py -t 192.168.1.1 -p 1-1024 -o results.json
  python main.py -d example.com
""",
    )

    # Target options
    parser.add_argument("-t", "--target", help="Target IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan (e.g., '80,443,1-1024')")

    # Scan options
    parser.add_argument("--udp", action="store_true", help="Perform UDP scan instead of TCP")
    parser.add_argument("-c", "--concurrent", type=int, default=500,
                        help="Maximum concurrent connections (default: 500)")
    parser.add_argument("-T", "--timeout", type=float, default=1.5,
                        help="Connection timeout in seconds (default: 1.5)")
    parser.add_argument("--retry", type=int, default=0,
                        help="Number of retries for failed connections (default: 0)")

    # Output options
    parser.add_argument("-o", "--output",
                        help="Save results to file (auto-detects format: .json, .csv, .txt)")

    # Discovery mode
    parser.add_argument("-d", "--discover",
                        help="Run subdomain discovery for a domain (e.g., -d example.com)")

    args = parser.parse_args()

    print_banner()

    # Determine which mode to run
    if args.discover:
        await run_subdomain_discovery(args)
    elif args.target:
        await run_port_scan(args)
    else:
        print_error("Please specify a target (-t) or a domain for discovery (-d).")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    try:
        # For Windows, use the SelectorEventLoop to avoid issues with many connections
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n")
        print_error("Scan interrupted by user. Exiting...")
        sys.exit(0)
