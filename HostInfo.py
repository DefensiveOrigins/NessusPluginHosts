#!/usr/bin/env python3
import argparse
import os
import sys
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Dict, Tuple, List, Set, Optional

URL_RE = re.compile(r'(https?://[^\s"\'<>]+|(?:^|[\s])/(?:[^\s"\'<>]+))', re.IGNORECASE | re.MULTILINE)
SSL_LINE_RE = re.compile(r'^\s*(Subject|Issuer|Not\s*(?:Before|After)|Validity|Serial\s*Number|Public\s*Key\s*Algorithm|Key\s*Size|Signature\s*Algorithm|Signature\s*Algorithm\s*OID|MD5|SHA1|SHA-1|SHA256|SANs?|DNS\s*Names?)\s*:\s*(.+?)\s*$', re.IGNORECASE)

SEV_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

def find_nessus_files_in_dir(d: str) -> List[str]:
    out = []
    for root, _, files in os.walk(d):
        for fn in files:
            if fn.lower().endswith(".nessus"):
                out.append(os.path.join(root, fn))
    return sorted(out)

def parse_host_properties(report_host_elem: ET.Element) -> Dict[str, str]:
    props = {}
    hp = report_host_elem.find('HostProperties')
    if hp is None:
        for tag in report_host_elem.findall('.//tag'):
            name = tag.attrib.get('name') or tag.attrib.get('Name') or ''
            if name:
                props[name] = (tag.text or '').strip()
        return props
    for tag in hp.findall('tag'):
        name = tag.attrib.get('name') or tag.attrib.get('Name') or ''
        if name:
            props[name] = (tag.text or '').strip()
    return props

def get_scan_times_from_props(props: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    start_keys = ['HOST_START', 'host_start', 'HostStart', 'SCAN_START', 'scan_start', 'Host start']
    end_keys   = ['HOST_END', 'host_end', 'HostEnd', 'SCAN_END', 'scan_end', 'Host end']
    start = next((props[k] for k in start_keys if k in props and props[k]), None)
    end   = next((props[k] for k in end_keys   if k in props and props[k]), None)
    return start, end

def normalize_port_repr(port: str, protocol: Optional[str]) -> str:
    if not port or port in ('0', '-1'):
        return 'n/a'
    proto = (protocol or '').strip()
    return f'{proto}/{port}' if proto else str(port)

def likely_http_plugin(plugin_name: str) -> bool:
    if not plugin_name:
        return False
    pn = plugin_name.lower()
    return any(s in pn for s in [
        'http', 'web application', 'cgi', 'apache', 'iis', 'nginx', 'tomcat', 'jetty',
        'wordpress', 'drupal', 'joomla', 'servlet', 'web server', 'x-powered-by'
    ])

def extract_urls_from_output(text: str) -> List[str]:
    if not text:
        return []
    urls = []
    for m in URL_RE.finditer(text):
        raw = m.group(1).strip()
        # clean leading whitespace before a leading slash case
        if raw.startswith('/'):
            urls.append(raw)
        else:
            # ensure scheme urls are reasonable
            urls.append(raw.rstrip(').,;]\"\''))
    # dedupe while preserving order
    seen = set()
    uniq = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq

def parse_ssl_info_from_output(text: str) -> Dict[str, str]:
    """Heuristic parse of common SSL Certificate info lines."""
    info = {}
    if not text:
        return info
    for line in text.splitlines():
        m = SSL_LINE_RE.match(line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            # Normalize a few keys
            key_norm = key.lower().replace(' ', '_').replace('-', '')
            # Map a couple of common variants
            if key_norm in ('sha1', 'sha_1'):
                key_norm = 'sha1_fingerprint'
            elif key_norm == 'sha256':
                key_norm = 'sha256_fingerprint'
            elif key_norm.startswith('dns_names') or key_norm.startswith('sans'):
                key_norm = 'subject_alt_names'
            elif key_norm.startswith('notbefore'):
                key_norm = 'not_before'
            elif key_norm.startswith('notafter'):
                key_norm = 'not_after'
            elif key_norm == 'validity':
                key_norm = 'validity'
            elif key_norm == 'md5':
                key_norm = 'md5_fingerprint'
            elif key_norm == 'serialnumber':
                key_norm = 'serial_number'
            elif key_norm == 'public_key_algorithm':
                key_norm = 'public_key_algorithm'
            elif key_norm == 'keysize':
                key_norm = 'key_size'
            elif key_norm == 'signaturealgorithm':
                key_norm = 'signature_algorithm'
            info[key_norm] = val
    return info

def inspect_nessus_file_for_host(path: str, target_name: str, want_sitemap: bool, want_sslinfo: bool) -> Optional[Dict]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f'[!] Failed to parse "{path}": {e}', file=sys.stderr)
        return None
    root = tree.getroot()
    report = root.find('Report')
    report_name = report.attrib.get('name') if report is not None and 'name' in report.attrib else None

    for rh in root.findall('.//ReportHost'):
        rh_name = rh.attrib.get('name', '').strip()
        props = parse_host_properties(rh)

        # match by ReportHost name or any HostProperties value or ReportItem host attr
        target_l = target_name.lower()
        matched = (rh_name and rh_name.lower() == target_l) or any((v or '').lower() == target_l for v in props.values())
        if not matched:
            for ri in rh.findall('ReportItem'):
                host_attr = (ri.attrib.get('host') or '').lower()
                if host_attr and host_attr == target_l:
                    matched = True
                    break
        if not matched:
            continue

        start, end = get_scan_times_from_props(props)

        # Aggregates
        plugins: Dict[str, Dict] = {}
        listening_ports: Dict[str, Set[str]] = defaultdict(set)  # key: proto/port -> set(services)
        sitemap_urls: Set[str] = set()
        ssl_certs: List[Dict[str, str]] = []

        for ri in rh.findall('ReportItem'):
            plugin_id = (ri.attrib.get('pluginID') or ri.findtext('pluginID') or '').strip()
            plugin_name = (ri.attrib.get('pluginName') or ri.findtext('pluginName') or '').strip()
            port = (ri.attrib.get('port') or '').strip()
            protocol = (ri.attrib.get('protocol') or ri.attrib.get('svc_name') or '').strip()
            svc_name = (ri.attrib.get('svc_name') or '').strip()
            severity_raw = ri.attrib.get('severity')
            try:
                severity = int(severity_raw) if severity_raw is not None else None
            except Exception:
                severity = None

            plugin_output = (ri.findtext('plugin_output') or '').strip()

            # Build plugin map
            if plugin_id:
                p = plugins.setdefault(plugin_id, {
                    'name': plugin_name or '<unknown>',
                    'ports': set(),
                    'severities': set(),
                    'max_sev': -1
                })
                p['ports'].add(normalize_port_repr(port, protocol))
                if severity is not None:
                    p['severities'].add(severity)
                    if severity > p['max_sev']:
                        p['max_sev'] = severity

            # Listening ports/services
            if port and port not in ('0', '-1'):
                pp = normalize_port_repr(port, protocol)
                if svc_name:
                    listening_ports[pp].add(svc_name)
                else:
                    # Heuristic: derive service name from plugin_name when obvious (e.g., "SSH", "RDP", "SMB", "HTTP")
                    guess = None
                    pn = plugin_name.lower()
                    for s, label in (('ssh', 'ssh'), ('rdp', 'rdp'), ('smb', 'smb'), ('http', 'http'),
                                     ('https', 'https'), ('smtp', 'smtp'), ('imap', 'imap'),
                                     ('pop3', 'pop3'), ('ftp', 'ftp'), ('telnet', 'telnet'),
                                     ('mssql', 'mssql'), ('mysql', 'mysql'), ('postgres', 'postgres'),
                                     ('oracle', 'oracle'), ('winrm', 'winrm')):
                        if s in pn:
                            guess = label
                            break
                    if guess:
                        listening_ports[pp].add(guess)

            # Optional sitemap
            if want_sitemap and (likely_http_plugin(plugin_name) or protocol.lower() in ('http', 'https')):
                for u in extract_urls_from_output(plugin_output):
                    sitemap_urls.add(u)

            # Optional SSL info
            if want_sslinfo and ('ssl' in (plugin_name or '').lower() and 'certificate' in (plugin_name or '').lower()):
                info = parse_ssl_info_from_output(plugin_output)
                if info:
                    # Attach port for context
                    info['_port'] = normalize_port_repr(port, protocol)
                    ssl_certs.append(info)

        return {
            'file': path,
            'report_name': report_name,
            'host_name': rh_name or target_name,
            'host_props': props,
            'scan_start': start,
            'scan_end': end,
            'plugins': plugins,
            'listening_ports': listening_ports,
            'sitemap_urls': sorted(sitemap_urls),
            'ssl_certs': ssl_certs
        }
    return None

def print_host_summary(res: Dict):
    print('=' * 72)
    print(f'File: {res["file"]}')
    if res.get('report_name'):
        print(f'Report: {res["report_name"]}')
    print('-' * 72)
    print('Host summary:')
    print(f'  ReportHost name: {res.get("host_name")}')
    props = res.get('host_props', {})
    for k in ['host-ip', 'host-ipv4', 'host-ipv6', 'host-fqdn', 'netbios-name', 'netbios']:
        if k in props and props[k]:
            print(f'  {k}: {props[k]}')
    if res.get('scan_start'):
        print(f'  scan start: {res["scan_start"]}')
    if res.get('scan_end'):
        print(f'  scan end: {res["scan_end"]}')
    other_keys = [k for k in sorted(props.keys()) if k not in {'host-ip','host-ipv4','host-ipv6','host-fqdn','netbios-name','netbios'}]
    if other_keys:
        print('\n  Other Host Properties:')
        for k in other_keys:
            v = props[k]
            if v:
                print(f'    {k}: {v}')

def print_plugins(res: Dict):
    print('\n' + '-' * 72)
    print('Plugins for host (sorted by severity desc, then pluginID):')
    plugins = res['plugins']
    if not plugins:
        print('  (none)')
        return

    def key_fn(item):
        pid, info = item
        try:
            pid_num = int(pid)
        except Exception:
            pid_num = float('inf')
        # severity desc
        max_sev = info.get('max_sev', -1)
        return (-max_sev, pid_num)

    for pid, info in sorted(plugins.items(), key=key_fn):
        name = info['name']
        ports = ', '.join(sorted(info['ports']))
        max_sev = info.get('max_sev', -1)
        sev_label = SEV_NAMES.get(max_sev, 'n/a') if max_sev >= 0 else 'n/a'
        print(f'  {pid} [{sev_label}] - {name}  (ports: {ports})')

def print_listening_ports(res: Dict):
    print('\n' + '-' * 72)
    print('Listening ports & identified services:')
    lp = res.get('listening_ports', {})
    if not lp:
        print('  (none)')
        return
    # sort by protocol then numeric port
    def sort_key(pp: str):
        # pp like tcp/80
        if '/' in pp:
            proto, port = pp.split('/', 1)
            try:
                return (proto, int(port))
            except Exception:
                return (proto, port)
        return ('', pp)
    for pp in sorted(lp.keys(), key=sort_key):
        svcs = sorted(s for s in lp[pp] if s)
        services = ', '.join(svcs) if svcs else 'unknown'
        print(f'  {pp:<12}  {services}')

def print_sitemap(res: Dict):
    urls = res.get('sitemap_urls') or []
    if not urls:
        print('\n' + '-' * 72)
        print('Website map (requested) :')
        print('  (no web application URLs/paths found in plugin output)')
        return
    print('\n' + '-' * 72)
    print('Website map (requested) :')
    for u in urls:
        print(f'  {u}')

def print_sslinfo(res: Dict):
    certs = res.get('ssl_certs') or []
    print('\n' + '-' * 72)
    print('SSL certificate information (requested) :')
    if not certs:
        print('  (no SSL certificate details found in plugin output)')
        return
    for idx, info in enumerate(certs, 1):
        print(f'  #{idx} (on {info.get("_port","n/a")})')
        for key in ('subject', 'issuer', 'not_before', 'not_after', 'subject_alt_names',
                    'serial_number', 'public_key_algorithm', 'key_size', 'signature_algorithm',
                    'sha1_fingerprint', 'sha256_fingerprint', 'md5_fingerprint', 'validity'):
            if key in info:
                print(f'    {key}: {info[key]}')

def main():
    parser = argparse.ArgumentParser(description='Summarize host context from Tenable Nessus (.nessus) file(s).')
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('-f', '--file', help='Single .nessus file')
    src.add_argument('-d', '--dir',  help='Directory (recursive) of .nessus files')
    parser.add_argument('-n', '--name', required=True, help='Target hostname or IP to lookup')
    parser.add_argument('--sitemap', action='store_true', help='Extract a simple website map from HTTP/HTTPS plugin outputs')
    parser.add_argument('--SSLInfo', action='store_true', help='Summarize SSL certificate info from relevant plugins')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal chatter')
    args = parser.parse_args()

    files = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f'[!] File not found: {args.file}', file=sys.stderr)
            sys.exit(2)
        files = [args.file]
    else:
        if not os.path.isdir(args.dir):
            print(f'[!] Directory not found: {args.dir}', file=sys.stderr)
            sys.exit(2)
        files = find_nessus_files_in_dir(args.dir)
        if not files:
            print(f'[!] No .nessus files found under: {args.dir}', file=sys.stderr)
            sys.exit(2)

    found = False
    for path in files:
        res = inspect_nessus_file_for_host(path, args.name, args.sitemap, args.SSLInfo)
        if not res:
            continue
        found = True
        print_host_summary(res)
        print_plugins(res)
        print_listening_ports(res)
        if args.sitemap:
            print_sitemap(res)
        if args.SSLInfo:
            print_sslinfo(res)
        print('=' * 72 + '\n')

    if not found:
        print(f'[!] No results found for host "{args.name}" in the provided .nessus file(s).', file=sys.stderr)
        sys.exit(3)

if __name__ == '__main__':
    main()
