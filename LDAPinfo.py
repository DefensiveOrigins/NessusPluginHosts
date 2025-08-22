#!/usr/bin/env python3
import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

PLUGIN_PRINTERS = "11933"
PLUGIN_SYN_SCANNER = "11219"  # Nessus SYN Scanner

# ---------------------------
# .nessus parsing helpers
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
# Notes extraction (11933)
# ---------------------------

NOTE_LINE_PATS = [

    r"[^\r\n]+",

]

def extract_notes(text: str) -> List[str]:
    if not text:
        return []
    hits: List[str] = []
    for pat in NOTE_LINE_PATS:
        for m in re.finditer(pat, text):
            s = m.group(0).strip()
            if s and s not in hits:
                hits.append(s)
    return hits

# ---------------------------
# File-level processing
# ---------------------------

def parse_file(file_path: Path) -> Tuple[List[Dict], Dict[str, Set[int]]]:
    """
    Returns:
      rows: [{host, notes, source_file}, ...]   from plugin 11933
      ports_by_host: {host: set(int ports)}     from plugin 11219
    """
    rows: List[Dict] = []
    ports_by_host: Dict[str, Set[int]] = {}

    tree = read_nessus(file_path)
    if not tree:
        return rows, ports_by_host

    for host_name, item in iter_report_items(tree):
        plugin_id = item.get("pluginID", "")

        # Collect SYN scanner ports (11219)
        if plugin_id == PLUGIN_SYN_SCANNER:
            port_str = item.get("port", "") or item.get("portnum", "")
            proto = (item.get("protocol", "") or "").lower()
            if proto in ("", "tcp"):  # SYN scanner is TCP; be tolerant
                try:
                    port = int(port_str)
                    if port > 0:
                        ports_by_host.setdefault(host_name, set()).add(port)
                except Exception:
                    pass  # ignore unparsable ports

        # Collect printer notes (11933)
        if plugin_id == PLUGIN_PRINTERS:
            plugin_output = item.findtext("plugin_output") or ""
            notes = extract_notes(plugin_output)
            if not notes:
                notes = ["Printer detected (11933)"]
            for note in notes:
                rows.append({
                    "host": host_name,
                    "notes": note,
                    "source_file": str(file_path),
                })

    return rows, ports_by_host

# ---------------------------
# Deduplication
# ---------------------------

def dedup_rows(rows: List[Dict]) -> List[Dict]:
    """
    Deduplicate by (host, notes). Merge source_file names (semicolon-separated).
    """
    bucket: Dict[Tuple[str, str], Dict] = {}
    for r in rows:
        host = (r.get("host") or "").strip()
        note = (r.get("notes") or "").strip()
        key = (host, note)
        sf = Path(r.get("source_file", "")).name
        if key not in bucket:
            bucket[key] = {"host": host, "notes": note, "source_files": set()}
        if sf:
            bucket[key]["source_files"].add(sf)

    out: List[Dict] = []
    for v in bucket.values():
        out.append({
            "host": v["host"],
            "notes": v["notes"],
            "source_file": ";".join(sorted(v["source_files"])) if v["source_files"] else "",
        })
    return out

# ---------------------------
# Output
# ---------------------------

def ports_to_string(ports: Set[int], max_len: int = 40) -> str:
    if not ports:
        return ""
    s = ",".join(str(p) for p in sorted(ports))
    if len(s) > max_len:
        return s[: max_len - 1] + "…"
    return s

def print_table(rows: List[Dict], ports_by_host: Dict[str, Set[int]]):
    if not rows:
        print("\n[Printers Identified] (plugin 11933): none found")
        return
    print("\n[Printers Identified] (plugin 11933)")
    print("-" * 132)
    print(f"{'Host':<28} {'OpenTCP':<20} {'Notes':<80}")
    print("-" * 132)
    for r in rows:
        open_tcp = ports_to_string(ports_by_host.get(r["host"], set()), max_len=20)
        notes = r["notes"]
        # Fit notes to remaining width
        if len(notes) > 80:
            notes = notes[:78] + "…"
        print(f"{r['host']:<28} {open_tcp:<20} {notes:<80}")
    print("-" * 132)

def write_csv(rows: List[Dict], ports_by_host: Dict[str, Set[int]], out_path: Path):
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["host","open_tcp","notes","source_file"]
        )
        writer.writeheader()
        if rows:
            for r in rows:
                open_tcp = ",".join(str(p) for p in sorted(ports_by_host.get(r["host"], set())))
                writer.writerow({
                    "host": r["host"],
                    "open_tcp": open_tcp,
                    "notes": r["notes"],
                    "source_file": r["source_file"],
                })
    print(f"[+] Wrote CSV: {out_path}")

# ---------------------------
# Main
# ---------------------------

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

def main():
    ap = argparse.ArgumentParser(
        description="Extract identified printers (plugin 11933) and SYN scanner open TCP ports (plugin 11219) from Nessus .nessus files."
    )
    mx = ap.add_mutually_exclusive_group(required=True)
    mx.add_argument("-f", "--file", help="Single .nessus file")
    mx.add_argument("-d", "--directory", help="Directory containing .nessus files")
    ap.add_argument("--csv", help="Output CSV path (default: ./printers.csv)", default="printers.csv")
    args = ap.parse_args()

    inputs = gather_inputs(args.file, args.directory)

    all_rows_raw: List[Dict] = []
    all_ports: Dict[str, Set[int]] = {}

    for p in inputs:
        rows, ports_by_host = parse_file(p)
        all_rows_raw.extend(rows)
        # merge ports per host across files
        for h, s in ports_by_host.items():
            all_ports.setdefault(h, set()).update(s)

    rows = dedup_rows(all_rows_raw)

    # Sort for consistent output
    rows.sort(key=lambda x: (x["host"].lower(), x["notes"].lower()))

    print_table(rows, all_ports)
    write_csv(rows, all_ports, Path(args.csv).resolve())

if __name__ == "__main__":
    main()
