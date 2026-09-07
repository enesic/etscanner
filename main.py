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
from core.ssl_inspector import SSLInspector
from core.http_fingerprint import HTTPFingerprinter
from core.host_discovery import HostDiscoverer
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
from utils.target_parser import parse_targets


# ---------------------------------------------------------------------------
# Timing profiles
# ---------------------------------------------------------------------------
TIMING_PROFILES = {
    "paranoid":   {"concurrent": 10,   "timeout": 5.0, "delay": 1.0},
    "sneaky":     {"concurrent": 50,   "timeout": 3.0, "delay": 0.2},
    "normal":     {"concurrent": 500,  "timeout": 1.5, "delay": 0.0},
    "aggressive": {"concurrent": 1000, "timeout": 0.8, "delay": 0.0},
    "insane":     {"concurrent": 5000, "timeout": 0.3, "delay": 0.0},
}

# ---------------------------------------------------------------------------
# Port profiles
# ---------------------------------------------------------------------------
PORT_PROFILES = {
    "web":    [80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 4000, 5000, 9090],
    "db":     [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 7474, 8086],
    "mail":   [25, 110, 143, 465, 587, 993, 995],
    "ssh":    [22, 2222, 22222],
    "ftp":    [20, 21, 2121],
    "smb":    [135, 137, 138, 139, 445],
    "dns":    [53, 5353],
    "rdp":    [3389, 3388],
    "vnc":    [5900, 5901, 5902, 5903],
    "docker": [2375, 2376, 4243],
    "k8s":    [6443, 8080, 10250, 10255, 2379, 2380],
}

# Nmap's top ports (condensed top-100 list)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080,
    8, 20, 37, 69, 79, 88, 106, 109, 113, 119, 123, 137, 138,
    144, 179, 199, 389, 427, 444, 465, 513, 514, 515, 543, 544,
    548, 554, 587, 631, 646, 873, 990, 993, 995, 1080, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
    5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9100, 9999, 49152, 49153,
]

TOP_1000_PORTS = list(range(1, 1001))


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
    return sorted(p for p in ports if 1 <= p <= 65535)


def resolve_ports(args) -> list[int]:
    """Resolve final port list from --profile, --top, or -p flags."""
    if args.profile:
        profile = args.profile.lower()
        if profile not in PORT_PROFILES:
            print_error(f"Unknown profile '{profile}'. Available: {', '.join(PORT_PROFILES)}")
            sys.exit(1)
        return sorted(PORT_PROFILES[profile])

    if args.top:
        if args.top == 100:
            return sorted(set(TOP_100_PORTS))
        elif args.top == 1000:
            return sorted(set(TOP_1000_PORTS))
        else:
            return sorted(range(1, min(args.top + 1, 65536)))

    return parse_ports(args.ports)


def apply_timing(args) -> dict:
    """Return timing parameters, applying --timing profile then CLI overrides."""
    profile = TIMING_PROFILES.get(args.timing, TIMING_PROFILES["normal"])
    params = dict(profile)
    # CLI flags always override the profile
    if args.concurrent != 500:   # 500 is the default, so only override if changed
        params["concurrent"] = args.concurrent
    if args.timeout != 1.5:
        params["timeout"] = args.timeout
    return params


# ---------------------------------------------------------------------------
# Print helpers for new features
# ---------------------------------------------------------------------------
def print_ssl_result(port: int, info: dict):
    tls = info.get("tls_version", "?")
    issuer = info.get("issuer", "?")
    cn = info.get("common_name", "")
    expires = info.get("expires", "")
    days = info.get("days_remaining", None)
    sans = info.get("sans", [])
    warnings = info.get("warnings", [])

    days_str = ""
    if days is not None:
        color = Colors.RED if days < 30 else Colors.GREEN
        days_str = f"  {color}({days}d remaining){Colors.RESET}"

    print(f"    {Colors.CYAN}[SSL]{Colors.RESET} Port {port} — {Colors.BOLD}{tls}{Colors.RESET}")
    if cn:
        print(f"         CN      : {cn}")
    print(f"         Issuer  : {issuer}")
    if expires:
        print(f"         Expires : {expires}{days_str}")
    if sans:
        print(f"         SANs    : {', '.join(sans[:5])}" + (" ..." if len(sans) > 5 else ""))
    for w in warnings:
        print(f"         {Colors.YELLOW}⚠ {w}{Colors.RESET}")


def print_http_result(port: int, info: dict):
    title = info.get("title", "")
    server = info.get("server", "")
    powered = info.get("powered_by", "")
    techs = info.get("technologies", [])
    proto = info.get("protocol", "HTTP")
    code = info.get("status_code", "")
    sec = info.get("security_headers", {})
    warnings = info.get("warnings", [])

    present = sum(1 for v in sec.values() if v)
    total = len(sec)
    sec_score_color = Colors.GREEN if present == total else (Colors.YELLOW if present >= total // 2 else Colors.RED)

    print(f"    {Colors.MAGENTA}[HTTP]{Colors.RESET} Port {port} — {Colors.BOLD}{proto} {code}{Colors.RESET}")
    if title:
        print(f"          Title   : {title}")
    if server:
        print(f"          Server  : {server}")
    if powered:
        print(f"          Powered : {powered}")
    if techs:
        print(f"          Tech    : {Colors.CYAN}{', '.join(techs)}{Colors.RESET}")
    print(f"          SecHdrs : {sec_score_color}{present}/{total} present{Colors.RESET}")
    for w in warnings:
        if "Missing" in w:
            print(f"          {Colors.YELLOW}⚠ {w}{Colors.RESET}")


# ---------------------------------------------------------------------------
# Scan a single host
# ---------------------------------------------------------------------------
async def scan_single_host(host: str, ports_to_scan: list[int], timing: dict,
                            args, host_label: str = None) -> dict:
    """Run the full scan pipeline on one host. Returns a result dict."""
    label = host_label or host

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print_info(f"Scanning: {Colors.BOLD}{label}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'─' * 60}{Colors.RESET}")

    start_time = time.time()
    progress = ProgressBar(total=len(ports_to_scan), prefix="  Scanning: ")

    def on_progress():
        progress.update()

    # --- Port scan ---
    if args.udp:
        scanner = AsyncUDPScanner(
            target_host=host,
            max_concurrent=timing["concurrent"],
            timeout=timing["timeout"],
        )
        open_ports = await scanner.scan_ports(ports_to_scan)
        progress.finish()
    else:
        scanner = AsyncPortScanner(
            target_host=host,
            max_concurrent=timing["concurrent"],
            timeout=timing["timeout"],
            retries=args.retry,
            on_progress=on_progress,
            delay=timing.get("delay", 0.0),
        )
        open_ports = await scanner.scan_ports(ports_to_scan)
        progress.finish()

    scan_duration = time.time() - start_time

    if not open_ports:
        label_type = "open|filtered" if args.udp else "open"
        print_error(f"No {label_type} ports found. ({scan_duration:.2f}s)")
        return {"host": host, "open_ports": [], "scan_duration": scan_duration}

    label_type = "open|filtered" if args.udp else "open"
    print_success(f"Found {len(open_ports)} {label_type} port(s) in {scan_duration:.2f}s")

    service_results = {}
    ssl_results = {}
    http_results = {}
    os_info = {}
    cve_results = {}

    if not args.udp:
        # Banner grabbing
        print_info("Grabbing banners...")
        analyzer = ServiceAnalyzer(target_host=host, timeout=timing["timeout"])
        service_results = await analyzer.analyze_services(open_ports)

        # OS fingerprinting
        print_info("Running OS fingerprinting...")
        fingerprinter = OSFingerprinter(target_host=host, timeout=timing["timeout"])
        os_info = await fingerprinter.fingerprint(open_ports)
        os_guess = os_info.get("os_guess", "Unknown")
        confidence = os_info.get("confidence", "N/A")
        details = os_info.get("details", "")
        print_success(f"OS Guess: {Colors.BOLD}{os_guess}{Colors.RESET}  "
                      f"(Confidence: {confidence}, {details})")

        # SSL inspection
        print_info("Inspecting SSL/TLS...")
        ssl_inspector = SSLInspector(target_host=host, timeout=timing["timeout"])
        ssl_results = await ssl_inspector.inspect_all(open_ports)

        # HTTP fingerprinting
        print_info("Fingerprinting HTTP services...")
        http_fp = HTTPFingerprinter(target_host=host, timeout=timing["timeout"])
        http_results = await http_fp.fingerprint_all(open_ports)

        # CVE matching
        cve_matcher = CVEMatcher()
        cve_results = cve_matcher.analyze_all(service_results)
    else:
        for port in open_ports:
            service_results[port] = "open|filtered (UDP)"

    # --- Display report ---
    total_duration = time.time() - start_time
    print(f"\n{Colors.BOLD}[+] Scan Report — {host}{Colors.RESET}")

    for port in open_ports:
        service_banner = service_results.get(port, "")
        if len(service_banner) > 60:
            service_banner = service_banner[:57] + "..."
        print_port_result(port, service_banner)

        # CVEs
        if port in cve_results:
            for match in cve_results[port]:
                for cve in match.get("cves", []):
                    severity = cve["severity"]
                    col = (Colors.RED + Colors.BOLD if severity == "Critical"
                           else Colors.RED if severity == "High"
                           else Colors.YELLOW if severity == "Medium"
                           else Colors.WHITE)
                    print(f"         {col}[{severity:>8}]{Colors.RESET}"
                          f" {cve['id']} — {cve['description']}")

        # SSL
        if port in ssl_results:
            print_ssl_result(port, ssl_results[port])

        # HTTP
        if port in http_results:
            print_http_result(port, http_results[port])

    print_info(f"Total scan time: {total_duration:.2f}s")

    return {
        "host": host,
        "open_ports": open_ports,
        "service_results": service_results,
        "ssl_results": ssl_results,
        "http_results": http_results,
        "os_info": os_info,
        "cve_results": cve_results,
        "scan_duration": total_duration,
    }


# ---------------------------------------------------------------------------
# Main modes
# ---------------------------------------------------------------------------
async def run_subdomain_discovery(args):
    print_info(f"Subdomain discovery for: {Colors.BOLD}{args.discover}{Colors.RESET}")
    print_info("Using built-in wordlist...\n")
    discoverer = SubdomainDiscoverer(domain=args.discover, max_concurrent=100, timeout=2.0)
    start = time.time()
    results = await discoverer.discover()
    if not results:
        print_error(f"No subdomains found for {args.discover}.")
    else:
        print_success(f"Found {len(results)} subdomain(s):\n")
        for entry in results:
            print(f"    {Colors.GREEN}{entry['subdomain']}{Colors.RESET}"
                  f"  →  {Colors.CYAN}{entry['ip']}{Colors.RESET}")
    print_info(f"\nCompleted in {time.time() - start:.2f}s.")


async def run_port_scan(args):
    targets = parse_targets(args.target)
    ports_to_scan = resolve_ports(args)
    timing = apply_timing(args)

    if not ports_to_scan:
        print_error("No valid ports specified.")
        sys.exit(1)

    scan_mode = "UDP" if args.udp else "TCP"
    print_info(f"Targets    : {len(targets)} host(s)")
    print_info(f"Ports      : {len(ports_to_scan)}")
    print_info(f"Mode       : {scan_mode}  |  Timing: {Colors.BOLD}{args.timing}{Colors.RESET}"
               f"  (concurrent={timing['concurrent']}, timeout={timing['timeout']}s, "
               f"delay={timing['delay']}s)")
    print_info(f"Retries    : {args.retry}")

    # Host discovery for multiple targets
    live_hosts = targets
    if len(targets) > 1 and not args.skip_discovery:
        print_info(f"\nRunning host discovery on {len(targets)} hosts...")
        discoverer = HostDiscoverer(timeout=1.0, max_concurrent=200)
        disc_progress = ProgressBar(total=len(targets), prefix="  Discovery: ")
        # Wrap with progress (patch discover to update)
        live_hosts = await discoverer.discover(targets)
        disc_progress.current = len(targets)
        disc_progress.finish()
        print_success(f"{len(live_hosts)}/{len(targets)} host(s) are live.\n")
        if not live_hosts:
            print_error("No live hosts found.")
            return
    elif len(targets) > 1 and args.skip_discovery:
        print_warning("Host discovery skipped.")

    all_results = []
    for host in live_hosts:
        result = await scan_single_host(host, ports_to_scan, timing, args)
        all_results.append(result)

    # Export
    if args.output and all_results:
        # Use the first (or only) host result for single exports;
        # for multi-host, export all merged into one JSON
        primary = all_results[0]
        exporter = ResultExporter(
            target_host=", ".join([r["host"] for r in all_results]),
            open_ports=primary.get("open_ports", []),
            service_results=primary.get("service_results", {}),
            cve_results=primary.get("cve_results", {}),
            os_info=primary.get("os_info", {}),
            scan_duration=sum(r.get("scan_duration", 0) for r in all_results),
        )
        try:
            exporter.export(args.output)
            print_success(f"\nResults saved to: {Colors.BOLD}{args.output}{Colors.RESET}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main():
    parser = argparse.ArgumentParser(
        description="e'tscanner — Async TCP/UDP Port Scanner & Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""timing profiles:
  paranoid  — 10 concurrent, 5.0s timeout, 1.0s delay  (stealth)
  sneaky    — 50 concurrent, 3.0s timeout, 0.2s delay
  normal    — 500 concurrent, 1.5s timeout, no delay    (default)
  aggressive— 1000 concurrent, 0.8s timeout, no delay
  insane    — 5000 concurrent, 0.3s timeout, no delay   (max speed)

port profiles:
  web, db, mail, ssh, ftp, smb, dns, rdp, vnc, docker, k8s

examples:
  python main.py -t 192.168.1.1 -p 1-1024
  python main.py -t 192.168.1.0/24 --profile web --timing aggressive
  python main.py -t 10.0.0.1-20 --top 100
  python main.py -t 192.168.1.1 --profile web -o report.html
  python main.py -t scanme.nmap.org -p 80,443 --timing sneaky
  python main.py -d example.com
""",
    )

    # Target
    parser.add_argument("-t", "--target",
                        help="Target IP, hostname, CIDR (192.168.1.0/24), or range (10.0.0.1-50)")

    # Port selection
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports", default="1-1024",
                            help="Ports to scan (e.g. '80,443,1-1024')")
    port_group.add_argument("--profile",
                            metavar="PROFILE",
                            help=f"Port profile: {', '.join(PORT_PROFILES)}")
    port_group.add_argument("--top", type=int, metavar="N",
                            help="Scan top N ports (e.g. --top 100 or --top 1000)")

    # Scan mode
    parser.add_argument("--udp", action="store_true",
                        help="UDP scan mode instead of TCP")

    # Timing
    parser.add_argument("--timing", default="normal",
                        choices=TIMING_PROFILES.keys(),
                        help="Timing profile (default: normal)")

    # CLI overrides (override timing profile)
    parser.add_argument("-c", "--concurrent", type=int, default=500,
                        help="Override concurrent connections")
    parser.add_argument("-T", "--timeout", type=float, default=1.5,
                        help="Override connection timeout (seconds)")
    parser.add_argument("--retry", type=int, default=0,
                        help="Retries for failed connections (default: 0)")

    # Host discovery
    parser.add_argument("--skip-discovery", action="store_true",
                        help="Skip host discovery when scanning multiple hosts")

    # Output
    parser.add_argument("-o", "--output",
                        help="Save results to file (.json, .csv, .txt)")

    # Discovery mode
    parser.add_argument("-d", "--discover",
                        help="Subdomain discovery for a domain (e.g. -d example.com)")

    args = parser.parse_args()
    print_banner()

    if args.discover:
        await run_subdomain_discovery(args)
    elif args.target:
        await run_port_scan(args)
    else:
        print_error("Please specify a target (-t) or domain (-d).")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n")
        print_error("Scan interrupted by user. Exiting...")
        sys.exit(0)
