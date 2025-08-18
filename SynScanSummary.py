#!/usr/bin/env python3
import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

PLUGIN_ID = "11219"  # Nessus SYN Scanner

def parse_port_list(spec: str):
    """
    Parse a comma-separated list of ports and ranges (e.g., '22,80,8000-8100')
    into a set of ints.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid range: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}")
    return ports

def get_host_display(report_host_elem):
    """
    Build a user-friendly host display (IP and/or FQDN).
    """
    name_attr = report_host_elem.get("name", "").strip()
    ip = None
    fqdn = None

    # HostProperties -> tag/name/value entries
    hp = report_host_elem.find("./HostProperties")
    if hp is not None:
        for tag in hp.findall("./tag"):
            if tag.get("name") == "host-ip":
                ip = (tag.text or "").strip()
            elif tag.get("name") == "host-fqdn":
                fqdn = (tag.text or "").strip()

    # Prefer FQDN then IP, fall back to ReportHost name
    if fqdn and ip:
        return f"{fqdn} ({ip})"
    if fqdn:
        return fqdn
    if ip:
        return ip
    return name_attr or "UNKNOWN_HOST"

def load_syn_results(nessus_path, include_ports=None):
    """
    Parse the .nessus XML and collect open ports (plugin 11219).
    Returns:
        ports_by_host: dict[str, set[int]]
        hosts_by_port: dict[int, set[str]]
    """
    ports_by_host = defaultdict(set)
    hosts_by_port = defaultdict(set)

    # iterparse for memory efficiency
    context = ET.iterparse(nessus_path, events=("start", "end"))
    _, root = next(context)  # get root element

    current_host_elem = None
    current_host_display = None

    for event, elem in context:
        # Track when we enter/leave a ReportHost to capture HostProperties
        if event == "start" and elem.tag == "ReportHost":
            current_host_elem = elem
            current_host_display = None

        if event == "end":
            if elem.tag == "ReportHost":
                # free memory
                elem.clear()
                root.clear()
                current_host_elem = None
                current_host_display = None

            elif elem.tag == "ReportItem":
                # Only pick SYN Scanner plugin results
                if elem.get("pluginID") == PLUGIN_ID:
                    # Determine host display if not already
                    if current_host_display is None and current_host_elem is not None:
                        current_host_display = get_host_display(current_host_elem)
                    host = current_host_display or "UNKNOWN_HOST"

                    # Extract port (int) and protocol (should be tcp for SYN)
                    port_s = elem.get("port", "").strip()
                    proto = (elem.get("protocol") or "").strip().lower()
                    if not port_s.isdigit():
                        elem.clear()
                        continue
                    port = int(port_s)

                    # Include only requested ports if provided
                    if include_ports is not None and port not in include_ports:
                        elem.clear()
                        continue

                    # SYN scan is TCP; still accept if Nessus labels properly
                    if proto and proto != "tcp":
                        elem.clear()
                        continue

                    ports_by_host[host].add(port)
                    hosts_by_port[port].add(host)

                # clear processed ReportItem
                elem.clear()
                root.clear()

    return ports_by_host, hosts_by_port

def write_stdout_ports_per_host(ports_by_host, limit=None):
    for host in sorted(ports_by_host):
        ports = sorted(ports_by_host[host])
        shown = ports if limit is None else ports[:limit]
        extra = "" if (limit is None or len(ports) <= limit) else f" (+{len(ports)-limit} more)"
        print(f"{host}: {', '.join(map(str, shown))}{extra}")

def write_stdout_hosts_per_port(hosts_by_port, limit=None):
    for port in sorted(hosts_by_port):
        hosts = sorted(hosts_by_port[port])
        shown = hosts if limit is None else hosts[:limit]
        extra = "" if (limit is None or len(hosts) <= limit) else f" (+{len(hosts)-limit} more)"
        print(f"{port}: {', '.join(shown)}{extra}")

def write_csv_ports_per_host(csv_path, ports_by_host, limit=None):
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port"])
        for host in sorted(ports_by_host):
            ports = sorted(ports_by_host[host])
            ports = ports if limit is None else ports[:limit]
            for p in ports:
                w.writerow([host, p])

def write_csv_hosts_per_port(csv_path, hosts_by_port, limit=None):
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["port", "host"])
        for port in sorted(hosts_by_port):
            hosts = sorted(hosts_by_port[port])
            hosts = hosts if limit is None else hosts[:limit]
            for h in hosts:
                w.writerow([port, h])

def main():
    parser = argparse.ArgumentParser(
        description="Summarize open ports from Nessus SYN Scanner (plugin 11219)."
    )
    parser.add_argument("nessus_file", help="Path to .nessus file")
    parser.add_argument(
        "--analysis",
        choices=["ports-per-host", "hosts-per-port", "both"],
        default="both",
        help="Which summary to produce (default: both)",
    )
    parser.add_argument(
        "--include-ports",
        type=parse_port_list,
        default=None,
        help="Comma/range list of ports to include (e.g., '22,80,443,8000-8100'). Default: all reported ports.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit count per host/port in output (e.g., top N ports per host or top N hosts per port).",
    )
    parser.add_argument(
        "--csv",
        metavar="CSV_PATH",
        help="If provided, write CSV to this path. If omitted, print to stdout.",
    )
    parser.add_argument(
        "--no-stdout",
        action="store_true",
        help="If set with --csv, suppress stdout printing.",
    )

    args = parser.parse_args()

    try:
        ports_by_host, hosts_by_port = load_syn_results(
            args.nessus_file, include_ports=args.include_ports
        )
    except ET.ParseError as e:
        print(f"ERROR: Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print("ERROR: Nessus file not found.", file=sys.stderr)
        sys.exit(2)

    if args.analysis in ("ports-per-host", "both"):
        if args.csv:
            write_csv_ports_per_host(args.csv if args.analysis != "both" else args.csv.replace(".csv","_ports_per_host.csv"),
                                     ports_by_host, limit=args.limit)
        if not args.csv or (args.csv and not args.no-stdout):
            print("# Ports listening per host")
            write_stdout_ports_per_host(ports_by_host, limit=args.limit)
            print()

    if args.analysis in ("hosts-per-port", "both"):
        if args.csv:
            write_csv_hosts_per_port(args.csv if args.analysis != "both" else args.csv.replace(".csv","_hosts_per_port.csv"),
                                     hosts_by_port, limit=args.limit)
        if not args.csv or (args.csv and not args.no-stdout):
            print("# Hosts listening per port")
            write_stdout_hosts_per_port(hosts_by_port, limit=args.limit)

if __name__ == "__main__":
    main()
