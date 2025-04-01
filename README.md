# Nessus Plugin Host Extractor

This is a Python script that parses a `.nessus` file (XML format from Tenable Nessus) and extracts all hosts and ports where a specified plugin ID was detected.

## 🧰 Requirements

- Python 3.x
- No external dependencies (uses built-in `xml.etree.ElementTree`)

## 📦 Usage

```bash
python NessusPluginHosts.py <filename.nessus> <plugin_id>
```

## Example

### Commandline 
```
python NessusPluginHosts.py internal_scan.nessus 19506
```

### Output
```
10.0.0.5:22
10.0.0.10:0
192.168.1.25:80
```
