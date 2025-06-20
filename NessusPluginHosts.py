import sys
import xml.etree.ElementTree as ET
import ipaddress

def is_ip(entry):
    try:
        ipaddress.ip_address(entry.split(":")[0])
        return True
    except ValueError:
        return False

def sort_key_ip(entry):
    ip_part, port_part = (entry.split(":") + ["0"])[:2]
    return (ipaddress.ip_address(ip_part), int(port_part))

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
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: python nessus_plugin_hosts.py <filename.nessus> <plugin_id> [--no-port] [--space-delim | --comma-delim]")
        sys.exit(1)

    filename = sys.argv[1]
    plugin_id = sys.argv[2]

    omit_ports = "--no-port" in sys.argv
    space_delim = "--space-delim" in sys.argv
    comma_delim = "--comma-delim" in sys.argv

    matches = parse_nessus_file(filename, plugin_id, omit_ports)

    if matches:
        if space_delim:
            print(" ".join(matches))
        elif comma_delim:
            print(",".join(matches))
        else:
            print("\n".join(matches))
    else:
        print(f"No matches found for plugin ID {plugin_id}.")

if __name__ == "__main__":
    main()
