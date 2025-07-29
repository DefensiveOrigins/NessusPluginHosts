import sys
import os
import xml.etree.ElementTree as ET
import ipaddress
import argparse

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
        return []
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return []

def main():
    parser = argparse.ArgumentParser(description="Parse .nessus file(s) for a specific plugin ID.")
    parser.add_argument("plugin_id", help="Plugin ID to search for")
    parser.add_argument("-f", "--file", help="Path to a single .nessus file")
    parser.add_argument("-d", "--directory", help="Path to a directory of .nessus files")
    parser.add_argument("--no-port", action="store_true", help="Omit port from results")
    parser.add_argument("--space-delim", action="store_true", help="Output space-delimited")
    parser.add_argument("--comma-delim", action="store_true", help="Output comma-delimited")

    args = parser.parse_args()

    if not args.file and not args.directory:
        parser.error("Either --file or --directory must be specified.")

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
