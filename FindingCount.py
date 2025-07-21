import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

def parse_nessus(file_path):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading Nessus file: {e}")
        return

    severity_names = {
        "0": "Info",
        "1": "Low",
        "2": "Medium",
        "3": "High",
        "4": "Critical"
    }

    live_hosts = set()
    unique_findings = defaultdict(set)
    total_findings = defaultdict(int)

    for report in root.findall(".//Report"):
        for host in report.findall("ReportHost"):
            host_ip = host.attrib.get("name")
            live_hosts.add(host_ip)

            for item in host.findall("ReportItem"):
                severity = item.attrib.get("severity", "0")
                plugin_id = item.attrib.get("pluginID", "unknown")
                key = f"{plugin_id}"

                # Track total and unique
                total_findings[severity] += 1
                unique_findings[severity].add(key)

    print(f"\nSummary for: {file_path}")
    print(f"Total Live Hosts: {len(live_hosts)}")

    total_unique = sum(len(v) for v in unique_findings.values())
    total_total = sum(total_findings.values())

    print("\nUnique Findings per Severity:")
    for sev in sorted(severity_names.keys(), key=int, reverse=True):
        print(f"  {severity_names[sev]}: {len(unique_findings[sev])}")

    print(f"  TOTAL: {total_unique}")

    print("\nTotal Findings per Severity:")
    for sev in sorted(severity_names.keys(), key=int, reverse=True):
        print(f"  {severity_names[sev]}: {total_findings[sev]}")

    print(f"  TOTAL: {total_total}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nessus_summary.py <file.nessus>")
        sys.exit(1)

    nessus_file = sys.argv[1]
    parse_nessus(nessus_file)
