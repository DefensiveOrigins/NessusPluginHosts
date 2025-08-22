#!/usr/bin/env python3
import argparse
import csv
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Nessus plugin IDs of interest
PLUGIN_LDAP_SERVICE = "20870"
PLUGIN_LDAP_INFO = "25701"

# ---------------------------
# Helpers for .nessus parsing
# ---------------------------

def read_nessus(file_path: Path) -> Optional[ET.ElementTree]:
    try:
        return ET.parse(file_path)
    except Exception as e:
        print(f"[!] Failed to parse {file_path}: {e}", file=sys.stderr)
        return None

def iter_report_items(tree: ET.ElementTree):
    root = tree.getroot()
    for report in root.findall(".//Report"):
        for host in report.findall("./ReportHost"):
            host_name = host.get("name") or host.findtext("./HostName") or "UNKNOWN"
            for item in host.findall("./ReportItem"):
                yield host_name, item

# ---------------------------
# Extractors for 25701 output
# ---------------------------

def dn_to_domain(dn: str) -> Optional[str]:
    """Convert a DN containing DC= components to dotted domain."""
    if not dn:
        return None
    dcs = re.findall(r"DC=([^,/\s]+)", dn, flags=re.I)
    if dcs:
        return ".".join(d.strip() for d in dcs if d.strip())
    return None

def extract_domain_from_25701(output: str) -> Optional[str]:
    """
    Prefer [+]-namingContexts block, e.g.:
      [+]-namingContexts:
      | DC=domain,DC=local
    Fallback to default/root naming contexts or any DN with DC=... in the blob.
    """
    if not output:
        return None

    # Primary: [+]-namingContexts:
    m = re.search(r"\[\+\]-namingContexts:\s*(?:\r?\n\|\s*)?([^\r\n]+)", output, flags=re.I)
    if m:
        dom = dn_to_domain(m.group(1))
        if dom:
            return dom

    # Fallbacks: defaultNamingContext or rootDomainNamingContext
    for attr in ("defaultNamingContext", "rootDomainNamingContext"):
        m2 = re.search(rf"{attr}\s*[:=]\s*([^\r\n]+)", output, flags=re.I)
        if m2:
            dom = dn_to_domain(m2.group(1))
            if dom:
                return dom

    # Last resort: first DN-like sequence with DC=... in the blob
    m3 = re.search(r"(DC=[^,\r\n]+(?:\s*,\s*DC=[^,\r\n]+)+)", output, flags=re.I)
    if m3:
        dom = dn_to_domain(m3.group(0))
        if dom:
            return dom

    return None

def extract_server_from_25701(output: str) -> Optional[str]:
    """
    Prefer [+]-serverName block, e.g.:
      [+]-serverName:
      | CN=DomainDC01,CN=Servers,....
    Return the first CN value ('DomainDC01'). Fall back to serverName: lines
    or dNSHostName if present.
    """
    if not output:
        return None

    # Primary: [+]-serverName:
    m = re.search(r"\[\+\]-serverName:\s*(?:\r?\n\|\s*)?([^\r\n]+)", output, flags=re.I)
    if m:
        dn = m.group(1).strip()
        cn = re.search(r"CN=([^,]+)", dn, flags=re.I)
        return cn.group(1).strip() if cn else dn

    # Fallback: serverName: <dn>
    m2 = re.search(r"serverName\s*[:=]\s*([^\r\n]+)", output, flags=re.I)
    if m2:
        dn = m2.group(1).strip()
        cn = re.search(r"CN=([^,]+)", dn, flags=re.I)
        return cn.group(1).strip() if cn else dn

    # Fallback: dNSHostName: fqdn
    m3 = re.search(r"dNSHostName\s*[:=]\s*([^\r\n]+)", output, flags=re.I)
    if m3:
        return m3.group(1).strip()

    return None

# ---------------------------
# File-level processing
# ---------------------------

def parse_file(file_path: Path) -> Tuple[List[Dict], List[Dict]]:
    """
    Returns:
      services_20870: list of {host, port, protocol, svc_name, plugin_output_present, source_file}
      info_25701: list of {host, port, domain, server, source_file}
    """
    services_20870: List[Dict] = []
    info_25701: List[Dict] = []

    tree = read_nessus(file_path)
    if not tree:
        return services_20870, info_25701

    for host_name, item in iter_report_items(tree):
        plugin_id = item.get("pluginID", "")
        port = item.get("port", "") or item.get("portnum", "")
        protocol = item.get("protocol", "") or item.get("svc_name", "")
        svc_name = item.get("svc_name", "")
        plugin_output = item.findtext("plugin_output") or ""

        if plugin_id == PLUGIN_LDAP_SERVICE:
            services_20870.append({
                "host": host_name,
                "port": port,
                "protocol": protocol,
                "svc_name": svc_name,
                "plugin_output_present": bool(plugin_output.strip()),
                "source_file": str(file_path),
            })

        elif plugin_id == PLUGIN_LDAP_INFO:
            domain = extract_domain_from_25701(plugin_output) or ""
            server = extract_server_from_25701(plugin_output) or ""

            # Fallback heuristics if nothing parsed
            if not domain and "." in host_name:
                # If ReportHost name is an FQDN, derive domain from it
                parts = host_name.split(".")
                if len(parts) > 1:
                    domain = ".".join(parts[1:])
            info_25701.append({
                "host": host_name,
                "port": port,
                "domain": domain,
                "server": server,
                "source_file": str(file_path),
            })

    return services_20870, info_25701

def gather_inputs(f: Optional[str], d: Optional[str]) -> List[Path]:
    paths: List[Path] = []
    if f:
        p = Path(f)
        if not p.exists() or not p.is_file():
            sys.exit(f"[!] File not found or not a file: {f}")
        if p.suffix.lower() != ".nessus":
            sys.exit("[!] File must have a .nessus extension.")
        paths.append(p)
    elif d:
        base = Path(d)
        if not base.exists() or not base.is_dir():
            sys.exit(f"[!] Directory not found or not a directory: {d}")
        paths = sorted(base.glob("*.nessus"))
        if not paths:
            sys.exit("[!] No .nessus files found in the directory.")
    else:
        sys.exit("[!] One of -f or -d is required.")
    return paths

# ---------------------------
# Output
# ---------------------------

def print_services(services: List[Dict]):
    if not services:
        print("\n[LDAP Services Identified] (plugin 20870): none found")
        return
    print("\n[LDAP Services Identified] (plugin 20870)")
    print("-" * 72)
    print(f"{'Host':<30} {'Port':<6} {'Proto':<6} {'Service':<10} Source")
    print("-" * 72)
    for s in services:
        source_name = Path(s['source_file']).name
        print(f"{s['host']:<30} {s['port']:<6} {s['protocol']:<6} {s['svc_name']:<10} {source_name}")
    print("-" * 72)

def print_table(rows: List[Dict]):
    if not rows:
        print("\n[LDAP Information Disclosure] (plugin 25701): none found")
        return
    print("\n[LDAP Information Disclosure] (plugin 25701)")
    print("-" * 110)
    print(f"{'Host':<30} {'Port':<6} {'Domain':<30} {'Server':<30}")
    print("-" * 110)
    for r in rows:
        print(f"{r['host']:<30} {r['port']:<6} {r['domain']:<30} {r['server']:<30}")
    print("-" * 110)

def write_csv(rows: List[Dict], out_path: Path):
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "port", "domain", "server", "source_file"])
        writer.writeheader()
        if rows:
            writer.writerows(rows)
    print(f"[+] Wrote CSV: {out_path}")

# ---------------------------
# Main
# ---------------------------

def safe_int(s: str) -> int:
    try:
        return int(s)
    except Exception:
        return 0

def main():
    ap = argparse.ArgumentParser(
        description="Extract LDAP service (20870) and LDAP info disclosure (25701) from Nessus .nessus files."
    )
    mx = ap.add_mutually_exclusive_group(required=True)
    mx.add_argument("-f", "--file", help="Single .nessus file")
    mx.add_argument("-d", "--directory", help="Directory containing .nessus files")
    ap.add_argument("--csv", help="Output CSV path for 25701 table (default: ./ldap_info.csv)", default="ldap_info.csv")
    args = ap.parse_args()

    inputs = gather_inputs(args.file, args.directory)

    all_services: List[Dict] = []
    all_info: List[Dict] = []

    for p in inputs:
        services, info = parse_file(p)
        all_services.extend(services)
        all_info.extend(info)

    # Sort for consistent output
    all_services.sort(key=lambda x: (x["host"], safe_int(x["port"])))
    all_info.sort(key=lambda x: (x["host"], safe_int(x["port"])))

    print_services(all_services)
    print_table(all_info)

    out_csv = Path(args.csv).resolve()
    write_csv(all_info, out_csv)

if __name__ == "__main__":
    main()
