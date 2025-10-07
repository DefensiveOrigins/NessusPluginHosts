#!/usr/bin/env python3
"""
Remove a specified host from a Nessus XML file.

Usage:
    python RemoveHost.py -f input.nessus -o output.nessus -n target-hostname
"""

import argparse
import xml.etree.ElementTree as ET
import sys

def remove_host_from_nessus(input_file, output_file, hostname):
    """
    Remove all results for the specified host from a Nessus XML file.
    """
    try:
        tree = ET.parse(input_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] Failed to parse '{input_file}': {e}")
        sys.exit(1)

    removed = False
    # Nessus structure: <NessusClientData_v2><Report><ReportHost name="hostname">...</ReportHost>
    for report in root.findall(".//Report"):
        for host in list(report.findall("ReportHost")):
            if host.get("name") == hostname:
                report.remove(host)
                removed = True
                print(f"[+] Removed host: {hostname}")

    if not removed:
        print(f"[-] Host '{hostname}' not found in file.")
    else:
        tree.write(output_file, encoding="utf-8", xml_declaration=True)
        print(f"[+] Output written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Remove a specified host from a Nessus (.nessus) file."
    )
    parser.add_argument("-f", "--file", required=True, help="Input .nessus file path")
    parser.add_argument("-o", "--output", required=True, help="Output .nessus file path")
    parser.add_argument("-n", "--name", required=True, help="Hostname or IP to remove")

    args = parser.parse_args()

    remove_host_from_nessus(args.file, args.output, args.name)


if __name__ == "__main__":
    main()
