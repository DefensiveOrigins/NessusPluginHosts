import sys
import xml.etree.ElementTree as ET
import ipaddress

def sort_key(entry):
    """Sort by IP, then port if available."""
    if ":" in entry:
        ip, port = entry.split(":")
        return (ipaddress.ip_address(ip), int(port))
    else:
        return (ipaddress.ip_address(entry), 0)

def parse_nessus_file(filename, plugin_id, omit_ports=False):
    results = set()

    try:
        tree = ET.parse(filename)
        root = tree.getroot()

        for report in root.findall(".//Report"):
            for host in report.findall("ReportHost"):
                ip = host.attrib.get("name", "")
                for item in host.findall("ReportItem"):
                    if item.attrib.get("pluginID") == plugin_id:
                        port = item.attrib.get("port", "0")
                        if omit_ports or port == "0":
                            results.add(ip)
                        else:
                            results.add(f"{ip}:{port}")

        return sorted(results, key=sort_key)

    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: python nessus_plugin_hosts.py <filename.nessus> <plugin_id> [--no-port]")
        sys.exit(1)

    filename = sys.argv[1]
    plugin_id = sys.argv[2]
    omit_ports = "--no-port" in sys.argv

    matches = parse_nessus_file(filename, plugin_id, omit_ports)

    if matches:
        print("\n".join(matches))
    else:
        print(f"No matches found for plugin ID {plugin_id}.")

if __name__ == "__main__":
    main()
