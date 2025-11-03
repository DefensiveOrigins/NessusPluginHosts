#!/usr/bin/env python3
"""
nessus_host_summary.py

Usage examples:
  python nessus_host_summary.py -f path/to/scan.nessus -n 10.0.0.5
  python nessus_host_summary.py -d ./nessus_outputs -n host.example.com

The script prints:
  - A short host summary (scan start/end times if present, host-ip, fqdn, and other host properties)
  - A section listing plugins seen for that host and the ports associated with each plugin

Notes:
 - The script parses Tenable Nessus XML (.nessus) files (NessusClientData_v2 format).
 - It attempts to be flexible with HostProperties tag names (HOST_START / HOST_END / host-fqdn / host-ip / netbios / dns, etc.)
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from typing import Dict, Tuple, List, Set, Optional


def find_nessus_files_in_dir(d: str) -> List[str]:
    files = []
    for root, _, filenames in os.walk(d):
        for fn in filenames:
            if fn.lower().endswith('.nessus'):
                files.append(os.path.join(root, fn))
    return sorted(files)


def parse_host_properties(report_host_elem: ET.Element) -> Dict[str, str]:
    """
    Collects <HostProperties><tag name="...">value</tag></HostProperties> into dict.
    """
    props = {}
    hp = report_host_elem.find('HostProperties')
    if hp is None:
        # Older/alternate layout might nest tags differently. Try to find tags under ReportHost anywhere.
        for tag in report_host_elem.findall('.//tag'):
            name = tag.attrib.get('name') or tag.attrib.get('Name') or ''
            if name:
                props[name] = (tag.text or '').strip()
        return props

    for tag in hp.findall('tag'):
        name = tag.attrib.get('name') or tag.attrib.get('Name') or ''
        if not name:
            continue
        props[name] = (tag.text or '').strip()
    return props


def get_scan_times_from_props(props: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Look for likely keys in props indicating scan start/end. Return raw strings if found.
    Common keys: 'HOST_START', 'HOST_END', 'host_start', 'host_end', 'SCAN_START', 'SCAN_END'
    """
    candidates_start = ['HOST_START', 'host_start', 'HostStart', 'SCAN_START', 'scan_start', 'Host start']
    candidates_end = ['HOST_END', 'host_end', 'HostEnd', 'SCAN_END', 'scan_end', 'Host end']

    start = None
    end = None
    for k in candidates_start:
        if k in props and props[k]:
            start = props[k]
            break
    for k in candidates_end:
        if k in props and props[k]:
            end = props[k]
            break

    # If not found, sometimes ReportHost has attributes or parent Report has start/end. We will return None if unknown.
    return start, end


def normalize_port_repr(port: str, protocol: Optional[str]) -> str:
    if not port or port in ('0', '-1'):
        return 'n/a'
    proto = protocol or ''
    # often protocol is 'tcp' or 'udp'
    return f'{proto}/{port}' if proto else str(port)


def inspect_nessus_file_for_host(path: str, target_name: str) -> Optional[Dict]:
    """
    Parse a .nessus file, look for a ReportHost whose 'name' attribute or HostProperties contain target_name,
    or whose reportitems reference that host. Return None if not found.

    Returned structure:
    {
      'file': path,
      'report_name': ...,
      'host_name': report_host_name,
      'host_props': {...},
      'scan_start': ...,
      'scan_end': ...,
      'plugins': { pluginid: {'name': pluginName, 'ports': set([...]), 'severity': set([...]) } }
    }
    """
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f'[!] Failed to parse "{path}": {e}', file=sys.stderr)
        return None

    root = tree.getroot()
    # Usually structure: NessusClientData_v2 -> Report -> ReportHost*
    report = root.find('Report')
    report_name = report.attrib.get('name') if report is not None and 'name' in report.attrib else None

    # We'll examine every ReportHost
    for rh in root.findall('.//ReportHost'):
        rh_name = rh.attrib.get('name', '').strip()
        # Quick match against the ReportHost name
        matched = False
        if rh_name and rh_name.lower() == target_name.lower():
            matched = True
        else:
            # collect host properties and check common host tags
            props = parse_host_properties(rh)
            # check obvious fields for match
            host_identifiers = set()
            for k, v in props.items():
                if not v:
                    continue
                host_identifiers.add(v.lower())
            if target_name.lower() in host_identifiers:
                matched = True
            else:
                # Sometimes hostnames/ips appear in ReportItems' host attribute - check those quickly
                for ri in rh.findall('ReportItem'):
                    host_attr = ri.attrib.get('host') or ''
                    if host_attr and host_attr.lower() == target_name.lower():
                        matched = True
                        break

        if not matched:
            continue

        # If matched, extract summary + plugins
        props = parse_host_properties(rh)
        start, end = get_scan_times_from_props(props)

        plugins = {}
        for ri in rh.findall('ReportItem'):
            plugin_id = ri.attrib.get('pluginID') or ri.attrib.get('pluginID') or ri.attrib.get('pluginId') or ri.attrib.get('pluginID')
            plugin_name = ri.attrib.get('pluginName') or ri.attrib.get('plugin_name') or ri.attrib.get('pluginName') or (ri.findtext('pluginName') or '').strip()
            port = ri.attrib.get('port') or ri.attrib.get('port') or ''
            protocol = ri.attrib.get('protocol') or ri.attrib.get('protocol') or ri.attrib.get('svc_name') or ri.attrib.get('protocol')
            severity = ri.attrib.get('severity') or ri.attrib.get('severity')  # numeric 0-4 usually
            if not plugin_id:
                # As fallback, try to find pluginID tag inside
                pid_tag = ri.find('pluginID')
                if pid_tag is not None:
                    plugin_id = (pid_tag.text or '').strip()
            if not plugin_name:
                pn_tag = ri.find('pluginName')
                if pn_tag is not None:
                    plugin_name = (pn_tag.text or '').strip()

            if not plugin_id:
                # Skip items without plugin id (should be rare)
                continue

            plugin_entry = plugins.setdefault(plugin_id, {'name': plugin_name or '<unknown>', 'ports': set(), 'severities': set()})
            plugin_entry['ports'].add(normalize_port_repr(port, protocol))
            if severity is not None:
                plugin_entry['severities'].add(severity)

        return {
            'file': path,
            'report_name': report_name,
            'host_name': rh_name or target_name,
            'host_props': props,
            'scan_start': start,
            'scan_end': end,
            'plugins': plugins
        }

    # Not found in any ReportHost
    return None


def pretty_print_result(res: Dict):
    print('=' * 72)
    print(f'File: {res["file"]}')
    if res.get('report_name'):
        print(f'Report: {res["report_name"]}')
    print('-' * 72)
    print('Host summary:')
    print(f'  ReportHost name: {res.get("host_name")}')
    # Try to show host-ip and fqdn and any other useful props
    props = res.get('host_props', {})
    # Common keys to highlight in a specific order
    highlight_keys = ['host-ip', 'host-ipv4', 'host-ipv6', 'host-fqdn', 'host-fqdn.', 'host-fqdn', 'HOST_START', 'HOST_END', 'host-fqdn', 'netbios-name', 'netbios']
    # dedup and print important ones first
    printed = set()

    for k in ['host-ip', 'host-ipv4', 'host-ipv6', 'host-fqdn', 'host-fqdn.', 'netbios-name', 'netbios']:
        if k in props:
            print(f'  {k}: {props[k]}')
            printed.add(k)
    # scan start/end
    if res.get('scan_start'):
        print(f'  scan start: {res["scan_start"]}')
    if res.get('scan_end'):
        print(f'  scan end: {res["scan_end"]}')

    # print any remaining host props (short list)
    other_keys = [k for k in props.keys() if k not in printed]
    if other_keys:
        print()
        print('  Other Host Properties:')
        for k in sorted(other_keys):
            v = props[k]
            if not v:
                continue
            print(f'    {k}: {v}')

    # Plugins section
    print('\n' + '-' * 72)
    print('Plugins found for host (pluginID - name):')
    if not res['plugins']:
        print('  (no plugins found for host in this file)')
        return

    # Sort plugins by severity if available then pluginID - but we only stored severities as set of strings.
    # We'll sort by plugin id numeric if possible.
    def plugin_sort_key(item):
        pid = item[0]
        try:
            return int(pid)
        except Exception:
            return pid

    for pid, info in sorted(res['plugins'].items(), key=plugin_sort_key):
        ports = sorted(info['ports'])
        sev = ','.join(sorted(info['severities'])) if info['severities'] else 'n/a'
        name = info['name']
        ports_display = ', '.join(ports) if ports else 'n/a'
        print(f'  {pid} - {name}  [ports: {ports_display}] [severity: {sev}]')

    print('=' * 72 + '\n')


def main():
    parser = argparse.ArgumentParser(description='Summarize a host from Nessus (.nessus) file(s).')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Single .nessus file to parse')
    group.add_argument('-d', '--dir', help='Directory to scan recursively for .nessus files')
    parser.add_argument('-n', '--name', required=True, help='Target hostname or IP to lookup')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - only print findings without extra notes')
    args = parser.parse_args()

    files_to_check = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f'[!] File not found: {args.file}', file=sys.stderr)
            sys.exit(2)
        files_to_check = [args.file]
    else:
        if not os.path.isdir(args.dir):
            print(f'[!] Directory not found: {args.dir}', file=sys.stderr)
            sys.exit(2)
        files_to_check = find_nessus_files_in_dir(args.dir)
        if not files_to_check:
            print(f'[!] No .nessus files found in directory {args.dir}', file=sys.stderr)
            sys.exit(2)

    found_any = False
    for f in files_to_check:
        res = inspect_nessus_file_for_host(f, args.name)
        if res:
            found_any = True
            pretty_print_result(res)

    if not found_any:
        print(f'[!] No results found for host "{args.name}" in the checked .nessus files.', file=sys.stderr)
        sys.exit(3)


if __name__ == '__main__':
    main()
