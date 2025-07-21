import os
import sys
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from tabulate import tabulate

def parse_nessus(file_path):
    live_hosts = set()
    unique_findings = defaultdict(set)
    total_findings = defaultdict(int)

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

    for report in root.findall(".//Report"):
        for host in report.findall("ReportHost"):
            host_ip = host.attrib.get("name")
            live_hosts.add(host_ip)

            for item in host.findall("ReportItem"):
                severity = item.attrib.get("severity", "0")
                plugin_id = item.attrib.get("pluginID", "unknown")
                total_findings[severity] += 1
                unique_findings[severity].add(plugin_id)

    result = {
        "File": os.path.basename(file_path),
        "👥Hosts": len(live_hosts),
        "🔴Uni": len(unique_findings["4"]),
        "🟠Uni": len(unique_findings["3"]),
        "🟡Uni": len(unique_findings["2"]),
        "🔵Uni": len(unique_findings["1"]),
        "⚪Uni": len(unique_findings["0"]),
        "📌UniTot": sum(len(v) for v in unique_findings.values()),
        "🔴Tot": total_findings["4"],
        "🟠Tot": total_findings["3"],
        "🟡Tot": total_findings["2"],
        "🔵Tot": total_findings["1"],
        "⚪Tot": total_findings["0"],
        "🧮Tot": sum(total_findings.values())
    }

    return result

def process_directory(directory_path):
    summaries = []
    for filename in os.listdir(directory_path):
        if filename.endswith(".nessus"):
            full_path = os.path.join(directory_path, filename)
            result = parse_nessus(full_path)
            if result:
                summaries.append(result)

    if not summaries:
        print("No valid .nessus files found in directory.")
        return

    headers = summaries[0].keys()
    table = [list(summary.values()) for summary in summaries]
    print(tabulate(table, headers=headers, tablefmt="grid"))

def main():
    parser = argparse.ArgumentParser(description="Summarize Nessus .nessus files.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a single .nessus file")
    group.add_argument("-d", "--directory", help="Path to directory containing .nessus files")
    args = parser.parse_args()

    if args.directory:
        process_directory(args.directory)
    elif args.file:
        result = parse_nessus(args.file)
        if result:
            print(f"\nSummary for: {args.file}")
            for k, v in result.items():
                print(f"{k}: {v}")

if __name__ == "__main__":
    main()
