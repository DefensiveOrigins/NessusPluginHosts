import sys
import os
import xml.etree.ElementTree as ET
import ipaddress
import argparse
from pathlib import Path

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
    mapping = {
        0: "Info",
        1: "Low",
        2: "Medium",
        3: "High",
        4: "Critical",
    }
    return mapping.get(sev_int, "Unknown")

def severity_int_from_risk_factor(risk_text):
    if not risk_text:
        return None
    t = risk_text.strip().lower()
    mapping = {
        "none": 0, "informational": 0, "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return mapping.get(t)

def sanitize_filename(name: str, max_len: int = 80) -> str:
    safe = "".join(c if (c.isalnum() or c in "-_ .") else "_" for c in (name or "").strip())
    safe = "_".join(safe.split())
    if not safe:
        safe = "plugin"
    if len(safe) > max_len:
        safe = safe[:max_len].rstrip("_")
    return safe

def parse_nessus_file(filename, plugin_id, omit_ports=False):
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
                        if omit_ports or port == "0":
                            entry = name
                        else:
                            entry = f"{name}:{port}"
                        if is_ip(entry):
                            ip_results.add(entry)
                        else:
                            host_results.add(entry)
        sorted_ips = sorted(ip_results, key=sort_key_ip)
        sorted_hosts = sorted(host_results)
        return sorted_ips + sorted_hosts
    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        return []
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return []

def collect_plugins_from_nessus(filename):
    plugins = {}
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
        for report in root.findall(".//Report"):
            for host in report.findall("ReportHost"):
                for item in host.findall("ReportItem"):
                    pid = item.attrib.get("pluginID")
                    if not pid:
                        continue
                    sev_attr = item.attrib.get("severity")
                    sev_int = int(sev_attr) if (sev_attr and sev_attr.isdigit()) else None
                    if sev_int is None:
                        rf_elem = item.find("risk_factor")
                        sev_int = severity_int_from_risk_factor(rf_elem.text if rf_elem is not None else None)
                    if sev_int is None:
                        sev_int = 0
                    pname = (item.attrib.get("pluginName") or "").strip()
                    current = plugins.get(pid)
                    if current is None:
                        plugins[pid] = {
                            "name": pname,
                            "severity_int": sev_int,
                            "severity_label": severity_label_from_int(sev_int),
                        }
                    else:
                        if sev_int > current["severity_int"]:
                            current["severity_int"] = sev_int
                            current["severity_label"] = severity_label_from_int(sev_int)
                        if not current["name"] and pname:
                            current["name"] = pname
        return plugins
    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        return {}
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return {}

def write_lines(path: Path, lines, space=False, comma=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not lines:
        return False
    if space:
        text = " ".join(lines) + "\n"
    elif comma:
        text = ",".join(lines) + "\n"
    else:
        text = "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Parse .nessus file(s) for a specific plugin ID, list distinct plugins with severities, or export plugin hostlists."
    )
    parser.add_argument("plugin_id", nargs="?", help="Plugin ID to search for (omit when using --list-plugins / --export-plugin-hosts)")
    parser.add_argument("-f", "--file", help="Path to a single .nessus file")
    parser.add_argument("-d", "--directory", help="Path to a directory of .nessus files")
    parser.add_argument("--no-port", action="store_true", help="Omit port from results / exports")
    parser.add_argument("--space-delim", action="store_true", help="Output space-delimited (host results mode / exports)")
    parser.add_argument("--comma-delim", action="store_true", help="Output comma-delimited (host results mode / exports)")
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

    file_list = []
    if args.directory:
        for fname in os.listdir(args.directory):
            if fname.endswith(".nessus"):
                file_list.append(os.path.join(args.directory, fname))
        if not file_list:
            print(f"No .nessus files found in directory {args.directory}.")
            sys.exit(1)
    elif args.file:
        file_list = [args.file]

    if in_list_mode:
        target_sev = None if args.list_plugins == -1 else args.list_plugins
        for file in file_list:
            plugins = collect_plugins_from_nessus(file)
            if args.directory and not in_export_mode:
                print(f"\n===== Plugins in {os.path.basename(file)} =====")
            if not plugins:
                if not in_export_mode:
                    print("No plugins with findings found.")
                continue
            def sort_key(item):
                pid, meta = item
                try:
                    pid_int = int(pid)
                except ValueError:
                    pid_int = float("inf")
                return (-meta["severity_int"], pid_int)
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
                    matches = parse_nessus_file(file, pid, args.no_port)
                    written = write_lines(out_path, matches, space=args.space_delim, comma=args.comma_delim)
                    if written:
                        print(f"Wrote {out_path}")
                else:
                    name = meta["name"].replace("\n", " ").replace("\r", " ").strip()
                    print(f"{pid},{meta['severity_int']},{meta['severity_label']},{name}")
        return

    if in_export_mode and not in_list_mode:
        parser.error("--export-plugin-hosts must be used with --list-plugins.")

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
