# Nessus Plugin Host Extractor

This is a Python script that parses a `.nessus` file (XML format from Tenable Nessus) and extracts all hosts and ports where a specified plugin ID was detected.

## 🧰 Requirements

- Python 3.x
- No external dependencies (uses built-in `xml.etree.ElementTree`)

## 📦 Usage

```bash
python NessusPluginHosts.py <filename.nessus> <plugin_id>

python IdentifiedServices <filename.nessus>

python FindingCount.py -f <filename.nessus>
python FindingCount.py -d <directory of nessus files>
python FindingCount.py -d <directory of nessus files> --csv summary.csv
python FindingCount.py -f <filename.nessus> --unique/--total/--both

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


# Space-delimited, no-port -- Specfication for metasploit "rhosts"
python nessus_plugin_hosts.py scan.nessus 19506 --space-delim --no-port

# Comma-delimited
python nessus_plugin_hosts.py scan.nessus 19506 --comma-delim

# Comma-delimited, no port
python nessus_plugin_hosts.py scan.nessus 19506 --comma-delim --no-port
```
# List Identified Services
Looks at the Nessus plugin 22964 and outputs the services by service type.
```
python IdentifiedServices.py scan.nessus --no-port --comma-delim
```

# Count Unqiue/Total Findngs 
Looks at the Nessus file and counts both unique and total findings 
```
# database selection
python FindingCount.py -f <filename.nessus>
python FindingCount.py -d <directory of nessus files>

# Option to return unique findings, total findings, or both
python FindingCount.py -f <filename.nessus> --unique
python FindingCount.py -f <filename.nessus> --total
python FindingCount.py -f <filename.nessus> --both

#export to CSV
python FindingCount.py -d <directory of nessus files> --csv summary.csv

```

