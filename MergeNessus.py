#!/usr/bin/env python3
"""
Merge multiple .nessus files into a single .nessus file.

- Uses argparse for CLI options.
- -o / --output sets the output path (default: ./Merged.nessus).
- -t / --title sets the merged Report title (default: "Merged Scan").
- -d / --directory optionally points to a directory to scan for .nessus files
  (default is current directory).
- Shows a live progress bar with alive-progress, updating files/hosts/findings.
- Attempts to compute overall scan window from HOST_START / HOST_END tags and
  writes it into a <MergeMeta> node (non-standard, informational).
- Deduplicates hosts by name and ReportItems by (pluginID, port, svc_name).

Tested with NessusClientData_v2 format.
"""

import argparse
import glob
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from alive_progress import alive_bar

# Nessus host time tags we try to read
HOST_START_TAG = "HOST_START"
HOST_END_TAG = "HOST_END"

# Known Nessus host time format example: "Tue Jun 27 16:22:00 2023"
# Nessus can vary a bit; we try a couple of common patterns.
TIME_FORMATS = [
    "%a %b %d %H:%M:%S %Y",
    "%Y-%m-%d %H:%M:%S",  # fallback
]

def parse_time(s: str):
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

def get_hostprops_tag(host_elem, tag_name):
    """Return text for a <tag name="..."> under <HostProperties>."""
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
    """Deep-ish clone for ET Elements."""
    new = ET.Element(elem.tag, attrib=dict(elem.attrib))
    if elem.text:
        new.text = elem.text
    if elem.tail:
        new.tail = elem.tail
    for child in list(elem):
        new.append(clone_element(child))
    return new

def main():
    parser = argparse.ArgumentParser(description="Merge .nessus files into a single .nessus file.")
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

    # Collect .nessus files
    search_dir = os.path.abspath(args.directory)
    files = sorted(glob.glob(os.path.join(search_dir, "*.nessus")))
    if not files:
        print(f"No .nessus files found in: {search_dir}", file=sys.stderr)
        sys.exit(1)

    # Prepare merged XML structure
    merged_root = ET.Element("NessusClientData_v2")
    merged_policy = None  # take from first file encountered that has one
    merged_prefs = None   # carry over ServerPreferences/Preferences if useful
    merged_report = ET.SubElement(merged_root, "Report")
    merged_report.set("name", args.title)

    # Deduplication structures
    hosts_map = {}  # name -> ReportHost element
    host_item_keys = defaultdict(set)  # name -> set of (pluginID, port, svc_name)

    # Counters + scan window
    total_hosts_seen = 0
    total_findings = 0
    earliest_start = None
    latest_end = None

    with alive_bar(len(files), title="Merging Nessus files") as bar:
        for idx, fpath in enumerate(files, start=1):
            try:
                tree = ET.parse(fpath)
                root = tree.getroot()
            except Exception as e:
                print(f"[!] Error parsing {fpath}: {e}", file=sys.stderr)
                bar()  # still advance bar
                continue

            # Copy Policy/Preferences once (from the first file that has them)
            if merged_policy is None:
                policy = root.find("Policy")
                if policy is not None:
                    merged_policy = clone_element(policy)
                    merged_root.insert(0, merged_policy)  # keep near top

            if merged_prefs is None:
                # Nessus exports sometimes have <ServerPreferences> or <Preferences>
                prefs = root.find("ServerPreferences")
                if prefs is None:
                    prefs = root.find("Preferences")
                if prefs is not None:
                    merged_prefs = clone_element(prefs)
                    # Put after Policy if present, else at top
                    insert_index = 1 if merged_policy is not None else 0
                    merged_root.insert(insert_index, merged_prefs)

            # Merge ReportHosts
            for report in root.findall("Report"):
                for host in report.findall("ReportHost"):
                    name = host.get("name")
                    if not name:
                        # Skip hosts without a name
                        continue

                    total_hosts_seen += 1

                    # Track host time window for overall scan window
                    h_start = get_hostprops_tag(host, HOST_START_TAG)
                    h_end = get_hostprops_tag(host, HOST_END_TAG)

                    if h_start:
                        dt = parse_time(h_start)
                        if dt and (earliest_start is None or dt < earliest_start):
                            earliest_start = dt
                    if h_end:
                        dt = parse_time(h_end)
                        if dt and (latest_end is None or dt > latest_end):
                            latest_end = dt

                    # If this host already exists, merge its ReportItems with dedup
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
                            else:
                                # Duplicate finding for same host: ignore
                                pass
                    else:
                        # New host: clone and index all its items
                        new_host = ET.Element("ReportHost", attrib=dict(host.attrib))
                        # Clone HostProperties
                        hp = host.find("HostProperties")
                        if hp is not None:
                            new_host.append(clone_element(hp))
                        # Clone items and record keys
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
                        hosts_map[name] = new_host
                        host_item_keys[name] = keys
                        merged_report.append(new_host)

            bar.text = f"[files:{idx}/{len(files)}] hosts:{len(hosts_map)} findings:{total_findings}"
            bar()

    # Add a small merge meta node with overall scan window if discovered
    if earliest_start or latest_end:
        meta = ET.SubElement(merged_report, "MergeMeta")
        if earliest_start:
            ET.SubElement(meta, "EarliestHostStart").text = earliest_start.strftime("%a %b %d %H:%M:%S %Y")
        if latest_end:
            ET.SubElement(meta, "LatestHostEnd").text = latest_end.strftime("%a %b %d %H:%M:%S %Y")

    # Pretty-print output (ElementTree doesn't pretty by default; we do a simple indent)
    def indent(elem, level=0):
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

    indent(merged_root)

    # Ensure directory exists
    out_path = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    # Write the merged .nessus file
    ET.ElementTree(merged_root).write(out_path, encoding="utf-8", xml_declaration=True)

    print(f"\nMerged {len(files)} files -> {out_path}")
    print(f"Unique hosts: {len(hosts_map)}")
    print(f"Total findings (deduped per host by pluginID/port/svc_name): {total_findings}")
    if earliest_start or latest_end:
        print("Overall scan window:")
        if earliest_start:
            print(f"  Earliest host start: {earliest_start}")
        if latest_end:
            print(f"  Latest host end:    {latest_end}")

if __name__ == "__main__":
    main()
