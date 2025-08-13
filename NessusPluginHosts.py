import sys
import os
import xml.etree.ElementTree as ET
import ipaddress
import argparse
from pathlib import Path
from collections import defaultdict

SEV_LABELS = ("Info", "Low", "Medium", "High", "Critical")

def is_ip(entry):
    try:
        ipaddress.ip_address(entry.split(":")[0])
        return True
    except ValueError:
        return False

def sort_key_ip(entry):
    ip_part, port_part = (entry.split(":") + ["0"])[:2]
    return (ipaddress.ip_address(ip_part), int(port_part))

def severity_label_from_int(sev_int):
    if 0 <= sev_int < len(SEV_LABELS):
        return SEV_LABELS[sev_int]
    return "Unknown"

def cvss3_to_sev(cvss3):
    """
    Map CVSS v3 base score to severity buckets:
      0.0                -> 0 Info
      0.1 - 3.9          -> 1 Low
      4.0 - 6.9          -> 2 Medium
      7.0 - 8.9          -> 3 High
      9.0 - 10.0         -> 4 Critical
    """
    try:
        s = float(cvss3)
    except (TypeError, ValueError):
        return 0  # Default to Info if score missing or unparsable
    if s == 0.0:
        return 0
    if 0.0 < s <= 3.9:
        return 1
    if 4.0 <= s <= 6.9:
        return 2
    if 7.0 <= s <= 8.9:
        return 3
    # Clamp any value >= 9.0 to Critical (handles 10.0 and any oddities)
    return 4

def sanitize_filename(name: str, max_len: int = 80) -> str:
    safe = "".join(c if (c.isalnum() or c in "-_ .") else "_" for c in (name or "").strip())
    safe = "_".join(safe.split())
    if not safe:
        safe = "plugin"
    if len(safe) > max_len:
        safe = safe[:max_len].rstrip("_")
    return safe

def parse_nessus_file(filename, plugin_id, omit_ports=False):
    """Original single-plugin host listing (kept for backward compatibility)."""
    ip_results = set()
    host_results = set()
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
        for report in root.findall(".//Report"):
            for host in report.findall("ReportHost"):
                name = host.attrib.get("name", "")
                for item in host.findall("ReportItem"):
                    if item.attrib.get("pluginID") == plugin_id:
                        port = item.attrib.get("port", "0")
                        entry = name if (omit_ports or port == "0") else f"{name}:{port}"
                        (ip_results if is_ip(entry) else host_results).add(entry)
        sorted_ips = sorted(ip_results, key=sort_key_ip)
        sorted_hosts = sorted(host_results)
        return sorted_ips + sorted_hosts
    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        return []
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return []

def build_index_stream(filename, include_ports=True):
    """
    Single-pass streaming index:
      - plugins: pid -> {name, severity_int, severity_label}
      - plugin_hosts: pid -> set(host entries)
    Severity is derived EXCLUSIVELY from <cvss3_base_score>.
    """
    plugins = {}
    plugin_hosts = defaultdict(set)
    current_host = ""

    try:
        for event, elem in ET.iterparse(filename, events=("start", "end")):
            tag = elem.tag

            if event == "start" and tag == "ReportHost":
                current_host = elem.attrib.get("name", "")

            elif event == "end" and tag == "ReportItem":
                pid = elem.attrib.get("pluginID")
                if not pid:
                    elem.clear(); continue

                # Severity derived ONLY from CVSS v3 base score
                cvss3 = elem.findtext("cvss3_base_score")
                sev_int = cvss3_to_sev(cvss3)

                # Plugin name & highest severity
                pname = (elem.attrib.get("pluginName") or "").strip()
                existing = plugins.get(pid)
                if (existing is None) or (sev_int > existing["severity_int"]):
                    plugins[pid] = {
                        "name": pname,
                        "severity_int": sev_int,
                        "severity_label": severity_label_from_int(sev_int),
                    }
                elif existing and not existing["name"] and pname:
                    existing["name"] = pname  # fill name if previously blank

                # Host entry
                port = elem.attrib.get("port", "0")
                entry = current_host if (not include_ports or port == "0") else f"{current_host}:{port}"
                plugin_hosts[pid].add(entry)

                elem.clear()

            elif event == "end" and tag == "ReportHost":
                elem.clear()
                current_host = ""

        return plugins, plugin_hosts

    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        return {}, defaultdict(set)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return {}, defaultdict(set)

def write_lines(path: Path, lines, space=False, comma=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not lines:
        return False
    # Respect delimiter flags; default is one per line
    if space:
        text = " ".join(lines) + "\n"
        path.write_text(text, encoding="utf-8")
    elif comma:
        text = ",".join(lines) + "\n"
        path.write_text(text, encoding="utf-8")
    else:
        with path.open("w", encoding="utf-8") as fh:
            fh.writelines(l + "\n" for l in lines)
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Parse .nessus file(s) for a specific plugin ID, list distinct plugins with severities, or export plugin hostlists."
    )
    parser.add_argument("plugin_id", nargs="?", help="Plugin ID to search for (omit when using --list-plugins / --export-plugin-hosts)")
    parser.add_argument("-f", "--file", help="Path to a single .nessus file")
    parser.add_argument("-d", "--directory", help="Path to a directory of .nessus files")
    parser.add_argument("--no-port", action="store_true", help="Omit port from results / exports")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--space-delim", action="store_true", help="Output space-delimited (host results mode / exports)")
    group.add_argument("--comma-delim", action="store_true", help="Output comma-delimited (host results mode / exports)")
    parser.add_argument(
        "--list-plugins",
        nargs="?", type=int, const=-1, metavar="SEVERITY",
        help="List distinct plugin IDs (optionally filter by SEVERITY 0..4)."
    )
    parser.add_argument(
        "--export-plugin-hosts",
        metavar="OUTDIR",
        help="When used with --list-plugins (optional SEVERITY), exports a host list per plugin to OUTDIR/<scan>/<Severity>/PID_[PluginName].txt"
    )
    args = parser.parse_args()

    if not args.file and not args.directory:
        parser.error("Either --file or --directory must be specified.")

    if args.list_plugins is not None and args.list_plugins != -1:
        if args.list_plugins not in (0, 1, 2, 3, 4):
            parser.error("--list-plugins SEVERITY must be one of 0,1,2,3,4.")

    in_list_mode = args.list_plugins is not None
    in_export_mode = args.export_plugin_hosts is not None

    if not in_list_mode and not in_export_mode and not args.plugin_id:
        parser.error("Provide a plugin_id, or use --list-plugins, or --export-plugin-hosts with --list-plugins.")

    # Build list of files
    file_list = []
    if args.directory:
        with os.scandir(args.directory) as it:
            for entry in it:
                if entry.is_file() and entry.name.endswith(".nessus"):
                    file_list.append(entry.path)
        if not file_list:
            print(f"No .nessus files found in directory {args.directory}.")
            sys.exit(1)
    elif args.file:
        file_list = [args.file]

    # List-plugins mode (with or without export) -> single-pass stream per file
    if in_list_mode:
        target_sev = None if args.list_plugins == -1 else args.list_plugins
        for file in file_list:
            plugins, plugin_hosts = build_index_stream(file, include_ports=(not args.no_port))

            if args.directory and not in_export_mode:
                print(f"\n===== Plugins in {os.path.basename(file)} =====")

            if not plugins:
                if not in_export_mode:
                    print("No plugins with findings found.")
                continue

            # sort: severity desc, then numeric plugin id asc
            def sort_key(item):
                pid, meta = item
                try:
                    pid_int = int(pid)
                except ValueError:
                    pid_int = float("inf")
                return (-meta["severity_int"], pid_int)

            # If exporting, prepare base path
            if in_export_mode:
                base = Path(args.export_plugin_hosts)
                scan_name = Path(file).stem
                base_scan = base / sanitize_filename(scan_name)

            for pid, meta in sorted(plugins.items(), key=sort_key):
                if target_sev is not None and meta["severity_int"] != target_sev:
                    continue

                if in_export_mode:
                    sev_dir = base_scan / f"{meta['severity_int']}_{meta['severity_label']}"
                    fname = f"{pid}_{sanitize_filename(meta['name'])}.txt"
                    out_path = sev_dir / fname

                    # Use pre-built host set; sort for stable output
                    hosts = plugin_hosts.get(pid, set())
                    ip_list = [h for h in hosts if is_ip(h)]
                    host_list = [h for h in hosts if not is_ip(h)]
                    ip_list_sorted = sorted(ip_list, key=sort_key_ip)
                    host_list_sorted = sorted(host_list)
                    ordered = ip_list_sorted + host_list_sorted

                    written = write_lines(out_path, ordered, space=args.space_delim, comma=args.comma_delim)
                    if written:
                        print(f"Wrote {out_path}")
                else:
                    name = meta["name"].replace("\n", " ").replace("\r", " ").strip()
                    print(f"{pid},{meta['severity_int']},{meta['severity_label']},{name}")
        return

    # Export mode alone is not allowed; require --list-plugins
    if in_export_mode and not in_list_mode:
        parser.error("--export-plugin-hosts must be used with --list-plugins.")

    # Original single-plugin host/port results mode
    for file in file_list:
        matches = parse_nessus_file(file, args.plugin_id, args.no_port)

        if args.directory:
            print(f"\n===== Results from {os.path.basename(file)} =====")

        if matches:
            if args.space_delim:
                print(" ".join(matches))
            elif args.comma_delim:
                print(",".join(matches))
            else:
                print("\n".join(matches))
        else:
            print(f"No matches found for plugin ID {args.plugin_id}.")

if __name__ == "__main__":
    main()
