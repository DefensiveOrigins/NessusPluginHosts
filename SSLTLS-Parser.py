#!/usr/bin/env python3
"""
parse_nessus_tls.py

Parse a .nessus XML file and produce a CSV of hosts running SSLv3, TLS 1.0,
TLS 1.1, or TLS 1.2 (i.e. where TLS 1.3 is not exclusively enforced).

Output columns:
  host:port | Offending Protocol(s) | Web Server | Device Type

Usage:
  python parse_nessus_tls.py <file.nessus> [-o output.csv]
"""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

# ---------------------------------------------------------------------------
# Plugin definitions
# ---------------------------------------------------------------------------

# Plugins that directly flag a weak protocol being *enabled*
PROTOCOL_PLUGINS = {
    # SSLv3
    "20007": "SSLv3",   # SSL Version 2 and 3 Protocol Detection
    "35291": "SSLv3",   # SSL Version 2 and 3 Protocol Detection (older)
    "83875": "SSLv3",   # Deprecated SSLv3 Enabled

    # TLS 1.0
    "104743": "TLS 1.0",  # TLS Version 1.0 Protocol Deprecated
    "15901":  "TLS 1.0",  # SSL / TLS Versions Supported (parsed below)

    # TLS 1.1
    "157288": "TLS 1.1",  # TLS Version 1.1 Protocol Deprecated

    # TLS 1.2 (present but TLS 1.3 not enforced)
    "121010": "TLS 1.2",  # TLS Version 1.2 Protocol Detection (no 1.3)
}

# Plugin 15901 reports ALL versions supported; we parse its output text
SUPPORTED_VERSIONS_PLUGIN = "15901"

# ---------------------------------------------------------------------------
# Web server identification — plugin IDs → server family
# Each entry: plugin_id -> (server_family, parse_from_output)
# parse_from_output=True means we also scan the plugin output text
# ---------------------------------------------------------------------------
WEBSERVER_PLUGINS = {
    # HTTP banner / server header
    "10107": ("HTTP", True),   # HTTP Server Type and Version
    "11213": ("HTTP", True),   # HTTP Server Type (SSL)
    "22964": ("HTTP", True),   # Service Detection (banner grab)
    "10386": ("HTTP", True),   # Web server version
    "43111": ("HTTP", True),   # HTTP methods
    "24260": ("HTTP", True),   # HyperText Transfer Protocol (HTTP) Information
}

WEBSERVER_KEYWORDS = {
    "iis":        "IIS",
    "microsoft-iis": "IIS",
    "apache":     "Apache",
    "nginx":      "nginx",
    "lighttpd":   "lighttpd",
    "tomcat":     "Apache Tomcat",
    "jetty":      "Jetty",
    "weblogic":   "WebLogic",
    "websphere":  "WebSphere",
    "jboss":      "JBoss",
    "openssl":    None,    # Not a web server by itself; skip
}

# ---------------------------------------------------------------------------
# Device type identification — plugin IDs and keywords
# ---------------------------------------------------------------------------
DEVICE_PLUGINS = {
    # OS / device identification
    "11936": True,   # OS Identification
    "45590": True,   # Common Platform Enumeration (CPE)
    "54615": True,   # Device Type
    "25220": True,   # TCP/IP Fingerprint
}

PRINTER_KEYWORDS = [
    "printer", "jetdirect", "hp laserjet", "hp officejet", "xerox",
    "ricoh", "konica", "minolta", "lexmark", "brother mfc",
    "canon imagerunner", "sharp mx", "kyocera", "epson",
    "zebra", "dell laser",
]

DEVICE_TYPE_MAP = {
    "router": "Network Device (Router)",
    "switch": "Network Device (Switch)",
    "firewall": "Network Device (Firewall)",
    "load balancer": "Network Device (Load Balancer)",
    "voip": "VoIP Device",
    "phone": "VoIP Device",
    "camera": "IoT (Camera)",
    "scada": "ICS/SCADA",
    "plc": "ICS/SCADA",
    "nas": "NAS/Storage",
    "storage": "NAS/Storage",
    "hypervisor": "Hypervisor",
    "vmware": "Hypervisor (VMware)",
    "windows": None,   # generic; skip unless more specific
    "linux":   None,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalise_protocol_text(text: str) -> list[str]:
    """
    Given free-text plugin output for plugin 15901, return list of weak
    protocols found (SSLv3 / TLS 1.0 / TLS 1.1 / TLS 1.2).
    """
    found = []
    tl = text.lower()
    if "sslv3" in tl or "ssl 3" in tl or "ssl version 3" in tl:
        found.append("SSLv3")
    if "tlsv1.0" in tl or "tls 1.0" in tl or "tlsv1\n" in tl or "tls version 1.0" in tl:
        found.append("TLS 1.0")
    if "tlsv1.1" in tl or "tls 1.1" in tl or "tls version 1.1" in tl:
        found.append("TLS 1.1")
    if "tlsv1.2" in tl or "tls 1.2" in tl or "tls version 1.2" in tl:
        found.append("TLS 1.2")
    return found


def detect_webserver(text: str) -> str | None:
    """Scan plugin output text for web server hints."""
    tl = text.lower()
    for kw, label in WEBSERVER_KEYWORDS.items():
        if kw in tl and label:
            return label
    return None


def detect_device_type(text: str) -> str | None:
    """Scan plugin output text for device type hints."""
    tl = text.lower()
    # Printers first (most specific)
    for kw in PRINTER_KEYWORDS:
        if kw in tl:
            return "Printer"
    for kw, label in DEVICE_TYPE_MAP.items():
        if kw in tl and label:
            return label
    return None


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_nessus(filepath: str) -> list[dict]:
    """
    Parse the .nessus file.

    Returns a list of dicts:
      {
        "host": str,
        "port": str,
        "protocols": set[str],
        "webserver": str | None,
        "device_type": str | None,
      }
    """
    try:
        tree = ET.parse(filepath)
    except ET.ParseError as exc:
        sys.exit(f"ERROR: Could not parse XML — {exc}")

    root = tree.getroot()

    # Keyed by (host, port)
    records: dict[tuple, dict] = defaultdict(lambda: {
        "protocols": set(),
        "webserver": None,
        "device_type": None,
    })

    for report_host in root.iter("ReportHost"):
        host_name = report_host.get("name", "")

        # Prefer the resolved IP or FQDN from HostProperties
        host_ip = host_name
        for tag in report_host.iter("tag"):
            if tag.get("name") == "host-ip":
                host_ip = tag.text or host_name
                break

        for item in report_host.iter("ReportItem"):
            plugin_id = item.get("pluginID", "")
            port      = item.get("port", "")
            svc_name  = item.get("svc_name", "")
            plugin_out = (item.findtext("plugin_output") or "").strip()
            plugin_name = item.get("pluginName", "")

            key = (host_ip, port)

            # --- Protocol detection ---
            if plugin_id in PROTOCOL_PLUGINS:
                proto = PROTOCOL_PLUGINS[plugin_id]
                records[key]["protocols"].add(proto)

            if plugin_id == SUPPORTED_VERSIONS_PLUGIN:
                for p in normalise_protocol_text(plugin_out):
                    records[key]["protocols"].add(p)

            # Also scan any SSL/TLS plugin output text for protocol strings
            # (some Nessus versions embed version lists in generic SSL plugins)
            if svc_name in ("https", "ssl", "tls") or "ssl" in plugin_name.lower() or "tls" in plugin_name.lower():
                for p in normalise_protocol_text(plugin_out):
                    records[key]["protocols"].add(p)

            # --- Web server detection ---
            if plugin_id in WEBSERVER_PLUGINS:
                _, do_parse = WEBSERVER_PLUGINS[plugin_id]
                if do_parse and plugin_out:
                    ws = detect_webserver(plugin_out)
                    if ws and not records[key]["webserver"]:
                        records[key]["webserver"] = ws

            # Also check plugin_name / svc_name for web server hints
            if not records[key]["webserver"]:
                ws = detect_webserver(plugin_out + " " + plugin_name)
                if ws:
                    records[key]["webserver"] = ws

            # --- Device type detection ---
            if plugin_id in DEVICE_PLUGINS and plugin_out:
                dt = detect_device_type(plugin_out)
                if dt and not records[key]["device_type"]:
                    records[key]["device_type"] = dt

    # Build result rows — only include hosts where weak protocols were found
    results = []
    for (host, port), data in records.items():
        protos = data["protocols"]
        if not protos:
            continue
        results.append({
            "host_port": f"{host}:{port}",
            "protocols": ", ".join(sorted(protos, key=lambda x: (
                # Sort: SSLv3, TLS 1.0, TLS 1.1, TLS 1.2
                {"SSLv3": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3}.get(x, 99)
            ))),
            "webserver":   data["webserver"] or "",
            "device_type": data["device_type"] or "",
        })

    # Sort by host:port for readability
    results.sort(key=lambda r: r["host_port"])
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract weak TLS/SSL hosts from a .nessus file into CSV."
    )
    parser.add_argument("nessus_file", help="Path to the .nessus input file")
    parser.add_argument(
        "-o", "--output",
        default="tls_findings.csv",
        help="Output CSV filename (default: tls_findings.csv)",
    )
    args = parser.parse_args()

    print(f"[*] Parsing: {args.nessus_file}")
    rows = parse_nessus(args.nessus_file)

    if not rows:
        print("[!] No weak TLS/SSL findings detected in this scan file.")
        sys.exit(0)

    fieldnames = ["Host:Port", "Offending Protocol(s)", "Web Server", "Device Type"]

    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "Host:Port":              row["host_port"],
                "Offending Protocol(s)":  row["protocols"],
                "Web Server":             row["webserver"],
                "Device Type":            row["device_type"],
            })

    print(f"[+] Done. {len(rows)} unique host:port entries written to: {args.output}")


if __name__ == "__main__":
    main()
