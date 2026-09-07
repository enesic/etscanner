import csv
import json
import os
from typing import Dict, List

class ResultExporter:
    """Export scan results to JSON, CSV, or TXT formats."""

    def __init__(self, target_host: str, open_ports: List[int],
                 service_results: Dict[int, str],
                 cve_results: Dict[int, List[Dict]] = None,
                 os_info: Dict[str, str] = None,
                 scan_duration: float = 0.0):
        """
        Initialize the ResultExporter.

        :param target_host: Scanned target host.
        :param open_ports: List of discovered open ports.
        :param service_results: Mapping of port to service banner.
        :param cve_results: Mapping of port to CVE matches.
        :param os_info: OS fingerprinting results.
        :param scan_duration: Total scan duration in seconds.
        """
        self.target_host = target_host
        self.open_ports = open_ports
        self.service_results = service_results
        self.cve_results = cve_results or {}
        self.os_info = os_info or {}
        self.scan_duration = scan_duration

    def _build_data(self) -> dict:
        """Build a structured dictionary of all scan results."""
        ports_data = []
        for port in self.open_ports:
            entry = {
                "port": port,
                "state": "open",
                "service": self.service_results.get(port, "Unknown"),
            }
            if port in self.cve_results:
                entry["vulnerabilities"] = []
                for match in self.cve_results[port]:
                    for cve in match.get("cves", []):
                        entry["vulnerabilities"].append({
                            "cve_id": cve["id"],
                            "severity": cve["severity"],
                            "description": cve["description"]
                        })
            ports_data.append(entry)

        return {
            "target": self.target_host,
            "scan_duration_seconds": round(self.scan_duration, 2),
            "os_fingerprint": self.os_info,
            "total_open_ports": len(self.open_ports),
            "ports": ports_data
        }

    def export_json(self, filepath: str):
        """Export results as a JSON file."""
        data = self._build_data()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_csv(self, filepath: str):
        """Export results as a CSV file."""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "State", "Service", "CVE ID", "Severity", "Description"])
            for port in self.open_ports:
                service = self.service_results.get(port, "Unknown")
                if port in self.cve_results:
                    for match in self.cve_results[port]:
                        for cve in match.get("cves", []):
                            writer.writerow([
                                port, "open", service,
                                cve["id"], cve["severity"], cve["description"]
                            ])
                else:
                    writer.writerow([port, "open", service, "", "", ""])

    def export_txt(self, filepath: str):
        """Export results as a human-readable TXT report."""
        lines = []
        lines.append("=" * 60)
        lines.append("  e'tscanner — Scan Report")
        lines.append("=" * 60)
        lines.append(f"  Target      : {self.target_host}")
        lines.append(f"  Duration    : {self.scan_duration:.2f}s")
        lines.append(f"  Open Ports  : {len(self.open_ports)}")

        if self.os_info:
            lines.append(f"  OS Guess    : {self.os_info.get('os_guess', 'N/A')}")
            lines.append(f"  Confidence  : {self.os_info.get('confidence', 'N/A')}")

        lines.append("-" * 60)

        for port in self.open_ports:
            service = self.service_results.get(port, "Unknown")
            lines.append(f"  Port {port:>5} | open | {service}")
            if port in self.cve_results:
                for match in self.cve_results[port]:
                    for cve in match.get("cves", []):
                        lines.append(f"      [{cve['severity']:>8}] {cve['id']} — {cve['description']}")

        lines.append("-" * 60)
        lines.append("")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def export(self, filepath: str):
        """
        Auto-detect format from file extension and export.

        :param filepath: Output file path (.json, .csv, or .txt).
        """
        ext = os.path.splitext(filepath)[1].lower()
        if ext == '.json':
            self.export_json(filepath)
        elif ext == '.csv':
            self.export_csv(filepath)
        elif ext == '.txt':
            self.export_txt(filepath)
        else:
            # Default to JSON if unrecognised
            self.export_json(filepath)
