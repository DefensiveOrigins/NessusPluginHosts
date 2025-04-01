import sys
import xml.etree.ElementTree as ET

def parse_nessus_file(filename, plugin_id):
    results = set()  # Use set to avoid duplicate IP:port entries

    try:
        tree = ET.parse(filename)
        root = tree.getroot()

        for report in root.findall(".//Report"):
            for host in report.findall("ReportHost"):
                ip = host.attrib.get("name", "")
                for item in host.findall("ReportItem"):
                    if item.attrib.get("pluginID") == plugin_id:
                        port = item.attrib.get("port", "0")
                        results.add(f"{ip}:{port}")

        return sorted(results)

    except ET.ParseError:
        print(f"Error: Could not parse {filename} as XML.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print("Usage: python nessus_plugin_hosts.py <filename.nessus> <plugin_id>")
        sys.exit(1)

    filename = sys.argv[1]
    plugin_id = sys.argv[2]

    matches = parse_nessus_file(filename, plugin_id)

    if matches:
        print("\n".join(matches))
    else:
        print(f"No matches found for plugin ID {plugin_id}.")

if __name__ == "__main__":
    main()
