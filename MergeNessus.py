#!/usr/bin/env python3
"""
MergeNessus.py
Merge multiple .nessus files into a single .nessus file.

Features:
- Uses argparse for CLI options.
- -d / --directory: directory containing .nessus files (default: current directory).
- -o / --output: output path for merged .nessus (default: ./Merged.nessus).
- -t / --title: title for the merged <Report> (default: "Merged Scan").
- Prints a startup message with the number of identified .nessus files.
- Shows a live progress bar (alive-progress) with files/hosts/findings counters.
- Deduplicates per host by (pluginID, port, svc_name).
- Tracks total unique findings across all hosts (global dedup by the same key).
- Attempts to compute overall scan window from HOST_START / HOST_END and records it in <MergeMeta>.
- Carries over <Policy> and <ServerPreferences>/<Preferences> from the first file that has them.

Requires:
    pip install alive-progress
"""

import argparse
import glob
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

try:
    from alive_progress import alive_bar
except ImportError:
    print("[!] Missing dependency: alive-progress. Install with: pip install alive-progress", file=sys.stderr)
    sys.exit(1)

HOST_START_TAG = "HOST_START"
HOST_END_TAG = "HOST_END"

# Common Nessus time formats
TIME_FORMATS = [
    "%a %b %d %H:%M:%S %Y",  # e.g., Tue Jun 27 16:22:00 2023
    "%Y-%m-%d %H:%M:%S",     # fallback
]

def parse_time(s: str):
    if not s:
        return None
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

def get_hostprops_tag(host_elem, tag_name):
    """Return text for <tag name="..."> within <HostProperties>."""
    hp = host_elem.find("HostProperties")
    if hp is None:
        return None
    for tag in hp.findall("tag"):
        if tag.get("name") == tag_name:
            return tag.text
    return None

def ensure_hostproperties(host_elem):
    hp = host_elem.find("HostProperties")
    if hp is None:
        hp = ET.SubElement(host_elem, "HostProperties")
    return hp

def add_or_update_tag(host_elem, name, value):
    hp = ensure_hostproperties(host_elem)
    for tag in hp.findall("tag"):
        if tag.get("name") == name:
            tag.text = value
            return
    t = ET.SubElement(hp, "tag")
    t.set("name", name)
    t.text = value

def clone_element(elem: ET.Element) -> ET.Element:
    """Deep clone for ET Elements."""
    new = ET.Element(elem.tag, attrib=dict(elem.attrib))
    if elem.text:
        new.text = elem.text
    if elem.tail:
        new.tail = elem.tail
    for child in list(elem):
        new.append(clone_element(child))
    return new

def indent(elem, level=0):
    """Pretty-print XML in-place for readability."""
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in list(elem):
            indent(child, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def main():
    parser = argparse.ArgumentParser(
        description="Merge .nessus files into a single .nessus file."
    )
    parser.add_argument(
        "-d", "--directory",
        default=".",
        help="Directory containing .nessus files (default: current directory)."
    )
    parser.add_argument(
        "-o", "--output",
        default=os.path.join(".", "Merged.nessus"),
        help="Output merged .nessus file path (default: ./Merged.nessus)."
    )
    parser.add_argument(
        "-t", "--title",
        default="Merged Scan",
        help='Title for the merged Nessus <Report name="..."> (default: "Merged Scan").'
    )
    args = parser.parse_args()

    search_dir = os.path.abspath(args.directory)
    files = sorted(glob.glob(os.path.join(search_dir, "*.nessus")))
    if not files:
        print(f"[!] No .nessus files found in: {search_dir}", file=sys.stderr)
        sys.exit(1)

    # Initial script start message
    plural = "file" if len(files) == 1 else "files"
    print(f"[+] Starting merge process...")
    print(f"[+] Found {len(files)} .nessus {plural} in: {search_dir}")

    # Prepare merged XML structure
    merged_root = ET.Element("NessusClientData_v2")
    merged_policy = None
    merged_prefs = None
    merged_report = ET.SubElement(merged_root, "Report")
    merged_report.set("name", args.title)

    # Dedup structures
    hosts_map = {}  # host name -> ReportHost element in merged
    host_item_keys = defaultdict(set)  # host name -> set of (pluginID, port, svc_name)
    global_finding_keys = set()  # across all hosts: (pluginID, port, svc_name)

    # Counters and scan window
    total_findings = 0  # deduped per host
    earliest_start = None
    latest_end = None

    with alive_bar(len(files), title="Merging Nessus files") as bar:
        for idx, fpath in enumerate(files, start=1):
            try:
                tree = ET.parse(fpath)
                root = tree.getroot()
            except Exception as e:
                print(f"[!] Error parsing {fpath}: {e}", file=sys.stderr)
                bar()
                continue

            # Copy Policy/Preferences once from first file that has them
            if merged_policy is None:
                policy = root.find("Policy")
                if policy is not None:
                    merged_policy = clone_element(policy)
                    merged_root.insert(0, merged_policy)

            if merged_prefs is None:
                prefs = root.find("ServerPreferences")
                if prefs is None:
                    prefs = root.find("Preferences")
                if prefs is not None:
                    merged_prefs = clone_element(prefs)
                    insert_index = 1 if merged_policy is not None else 0
                    merged_root.insert(insert_index, merged_prefs)

            # Merge ReportHosts
            for report in root.findall("Report"):
                for host in report.findall("ReportHost"):
                    name = host.get("name")
                    if not name:
                        continue

                    # Track host time window
                    h_start = get_hostprops_tag(host, HOST_START_TAG)
                    h_end = get_hostprops_tag(host, HOST_END_TAG)
                    dt_start = parse_time(h_start) if h_start else None
                    dt_end = parse_time(h_end) if h_end else None
                    if dt_start and (earliest_start is None or dt_start < earliest_start):
                        earliest_start = dt_start
                    if dt_end and (latest_end is None or dt_end > latest_end):
                        latest_end = dt_end

                    # Merge items for this host
                    if name in hosts_map:
                        existing_host = hosts_map[name]
                        existing_keys = host_item_keys[name]
                        for item in host.findall("ReportItem"):
                            plugin_id = item.get("pluginID", "")
                            port = item.get("port", "")
                            svc = item.get("svc_name", "")
                            key = (plugin_id, port, svc)
                            if key not in existing_keys:
                                existing_host.append(clone_element(item))
                                existing_keys.add(key)
                                total_findings += 1
                                global_finding_keys.add(key)
                    else:
                        # New host
                        new_host = ET.Element("ReportHost", attrib=dict(host.attrib))
                        # Clone HostProperties
                        hp = host.find("HostProperties")
                        if hp is not None:
                            new_host.append(clone_element(hp))
                        # Clone unique items
                        keys = set()
                        for item in host.findall("ReportItem"):
                            plugin_id = item.get("pluginID", "")
                            port = item.get("port", "")
                            svc = item.get("svc_name", "")
                            key = (plugin_id, port, svc)
                            if key not in keys:
                                new_host.append(clone_element(item))
                                keys.add(key)
                                total_findings += 1
                                global_finding_keys.add(key)
                        hosts_map[name] = new_host
                        host_item_keys[name] = keys
                        merged_report.append(new_host)

            bar.text = f"[files:{idx}/{len(files)}] hosts:{len(hosts_map)} findings:{total_findings}"
            bar()

    # Add MergeMeta with overall scan window, if available
    if earliest_start or latest_end:
        meta = ET.SubElement(merged_report, "MergeMeta")
        if earliest_start:
            ET.SubElement(meta, "EarliestHostStart").text = earliest_start.strftime("%a %b %d %H:%M:%S %Y")
        if latest_end:
            ET.SubElement(meta, "LatestHostEnd").text = latest_end.strftime("%a %b %d %H:%M:%S %Y")

    # Pretty-print XML
    indent(merged_root)

    # Ensure output dir exists and write file
    out_path = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    ET.ElementTree(merged_root).write(out_path, encoding="utf-8", xml_declaration=True)

    # Summary
    print(f"\nMerged {len(files)} file(s) -> {out_path}")
    print(f"Unique hosts: {len(hosts_map)}")
    print(f"Total findings (deduped per host): {total_findings}")
    print(f"Total unique findings across all hosts: {len(global_finding_keys)}")
    if earliest_start or latest_end:
        print("Overall scan window:")
        if earliest_start:
            print(f"  Earliest host start: {earliest_start}")
        if latest_end:
            print(f"  Latest host end:    {latest_end}")

if __name__ == "__main__":
    main()
