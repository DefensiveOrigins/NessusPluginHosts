# Nessus Plugin Host Extractor

This is a Python script that parses a `.nessus` file (XML format from Tenable Nessus) and extracts all hosts and ports where a specified plugin ID was detected.

## 🧰 Requirements

- Python 3.x
- No external dependencies (uses built-in `xml.etree.ElementTree`)

## 📦 Usage

```bash
python NessusPluginHosts.py <filename.nessus> <plugin_id>
```

also have option to not include port ```--no-port```

## useage examples 
```
# Default line-delimited
python nessus_plugin_hosts.py scan.nessus 19506

# Default line-delimited, no port
python nessus_plugin_hosts.py scan.nessus 19506 --no-port

# Space-delimited
python nessus_plugin_hosts.py scan.nessus 19506 --space-delim

# Comma-delimited
python nessus_plugin_hosts.py scan.nessus 19506 --comma-delim

# Comma-delimited, no port
python nessus_plugin_hosts.py scan.nessus 19506 --comma-delim --no-port
```
