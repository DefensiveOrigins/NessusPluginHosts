import os
import sys
import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from tabulate import tabulate
import csv

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

    return {
        "File": os.path.basename(file_path),
        "👥 Hosts": len(live_hosts),
        "Critical 🔴 Uni": len(unique_findings["4"]),
        "High 🟠 Uni": len(unique_findings["3"]),
        "Medium 🟡 Uni": len(unique_findings["2"]),
        "Low 🔵 Uni": len(unique_findings["1"]),
        "Info ⚪ Uni": len(unique_findings["0"]),
        "📌 Unique Total": sum(len(v) for v in unique_findings.values()),
        "Critical 🔴 Tot": total_findings["4"],
        "High 🟠 Tot": total_findings["3"],
        "Medium 🟡 Tot": total_findings["2"],
        "Low 🔵 Tot": total_findings["1"],
        "Info ⚪ Tot": total_findings["0"],
        "🧮 Total Findings": sum(total_findings.values())
    }

def format_output(results, include_unique=True, include_total=True):
    output_rows = []

    for res in results:
        if include_unique:
            output_rows.append({
                "File": res["File"],
                "👥 Hosts": res["👥 Hosts"],
                "Type": "Unique",
                "Critical 🔴": res["Critical 🔴 Uni"],
                "High 🟠": res["High 🟠 Uni"],
                "Medium 🟡": res["Medium 🟡 Uni"],
                "Low 🔵": res["Low 🔵 Uni"],
                "Info ⚪": res["Info ⚪ Uni"],
                "📌 Total": res["📌 Unique Total"]
            })
        if include_total:
            output_rows.append({
                "File": res["File"],
                "👥 Hosts": res["👥 Hosts"],
                "Type": "Total",
                "Critical 🔴": res["Critical 🔴 Tot"],
                "High 🟠": res["High 🟠 Tot"],
                "Medium 🟡": res["Medium 🟡 Tot"],
                "Low 🔵": res["Low 🔵 Tot"],
                "Info ⚪": res["Info ⚪ Tot"],
                "📌 Total": res["🧮 Total Findings"]
            })

    if output_rows:
        headers = output_rows[0].keys()
        table = [list(row.values()) for row in output_rows]
        print(tabulate(table, headers=headers, tablefmt="grid"))

def process_directory(directory_path, include_unique=True, include_total=True, csv_output=None):
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

    format_output(summaries, include_unique=include_unique, include_total=include_total)

    if csv_output:
        try:
            with open(csv_output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=summaries[0].keys())
                writer.writeheader()
                for summary in summaries:
                    writer.writerow(summary)
            print(f"\n✅ CSV exported to: {csv_output}")
        except Exception as e:
            print(f"❌ Error writing CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description="Summarize Nessus .nessus files.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a single .nessus file")
    group.add_argument("-d", "--directory", help="Path to directory containing .nessus files")
    parser.add_argument("--csv", help="Path to export CSV (only used with -d)")

    # Output filters
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--unique", action="store_true", help="Only show unique findings")
    output_group.add_argument("--total", action="store_true", help="Only show total findings")

    args = parser.parse_args()

    include_unique = not args.total
    include_total = not args.unique

    if args.directory:
        process_directory(args.directory, include_unique=include_unique, include_total=include_total, csv_output=args.csv)
    elif args.file:
        result = parse_nessus(args.file)
        if result:
            format_output([result], include_unique=include_unique, include_total=include_total)

if __name__ == "__main__":
    main()
