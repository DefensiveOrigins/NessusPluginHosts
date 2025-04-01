import sys
import xml.etree.ElementTree as ET
import ipaddress
from collections import defaultdict

SERVICE_DETECTION_PLUGIN_ID = "22964"

def sort_key(entry):
    if ":" in entry:
        ip, port = entry.split(":")
        return (ipaddress.ip_address(ip), int(port))
    else:
        return (ipaddress.ip_address(entry), 0)

def parse_service_detection(filename, omit_ports=False):
    services = defaultdict(set)

    try:
        tree = ET.parse(filename)
        root = tree.getroot()

        for report in root.findall(".//Report"):
            for host in report.findall("ReportHost"):
                ip = host.attrib.get("name", "")
                for item in host.findall("ReportItem"):
                    if item.attrib.get("pluginID") == SERVICE_DETECTION_PLUGIN_ID:
                        port = item.attrib.get("port", "0")
                        svc_name = item.attrib.get("svc_name", "unknown")

                        if omit_ports or port == "0":
                            services[svc_name].add(ip)
                        else:
                            services[svc_name].add(f"{ip}:{port}")

        # Sort each list
        for svc in services:
            services[svc] = sorted(services[svc], key=sort_key)

        return services

    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        sys.exit(1)

def print_services(services, delim="\n"):
    for svc, hosts in sorted(services.items()):
        print(svc)
        print(delim.join(hosts))

def main():
    if len(sys.argv) < 2:
        print("Usage: python nessus_services_by_plugin.py <filename.nessus> [--no-port] [--space-delim | --comma-delim]")
        sys.exit(1)

    filename = sys.argv[1]

    omit_ports = "--no-port" in sys.argv
    space_delim = "--space-delim" in sys.argv
    comma_delim = "--comma-delim" in sys.argv

    # Set delimiter
    if space_delim:
        delim = " "
    elif comma_delim:
        delim = ","
    else:
        delim = "\n"

    services = parse_service_detection(filename, omit_ports)

    if services:
        print_services(services, delim)
    else:
        print("No services detected using plugin ID 22964.")

if __name__ == "__main__":
    main()
