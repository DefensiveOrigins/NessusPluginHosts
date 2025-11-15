# Nessus Plugin Scripts:

This repo is a collection of Python scripts designed to work with Nessus scan results. The scripts utilize the built-in `xml.etree.ElementTree` library to parse `.nessus` files and provide various functionalities such as counting findings, listing hosts/services for specific plugins, identifying services, merging Nessus files, and summarizing Scanner results.

## istallation

With pip: 

```bash
pip install nessus-plugin-hosts
```


With Git: 

```bash
git clone https://github.com/DefensiveOrigins/NessusPluginHosts
cd NessusPluginHosts
```

## Tools Included

 | PyPI Command                     | Python Script           | Description                                                                                                                                                                |
| -------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`nessus-finding-count`**       | `FindingCount.py`       | Counts findings from a Nessus file. Supports unique or total counts. Can analyze a single file or all `.nessus` files within a directory.                                  |
| **`nessus-plugin-hosts`**        | `NessusPluginHosts.py`  | Lists hosts/services for a specific Nessus plugin. Supports multiple delimiter formats, can search a single file or many in a directory, and can export `host:port` lists. |
| **`nessus-identified-services`** | `IdentifiedServices.py` | Lists services identified within a Nessus file (e.g., plugin 22964).                                                                                                       |
| **`nessus-merge`**               | `MergeNessus.py`        | Merges multiple Nessus files from a directory into a single `.nessus` file. Adjusts scan start/end times and allows changing the report title.                             |
| **`nessus-synscan-summary`**     | `SynScanSummary.py`     | Summarizes SYN Scanner results from plugin 11219. Outputs both hosts-per-port and ports-per-host analyses, with optional CSV output.                                       |
| **`nessus-ldap-info`**           | `LDAPinfo.py`           | Parses LDAP-related information from plugins 20870 and 25701. Extracts LDAP services, info disclosure, domain names, and server names.                                     |
| **`nessus-printer-info`**        | `PrinterInfo.py`        | Extracts printer information, including vendor/model (when identifiable) and open TCP ports.                                                                               |
| **`nessus-remove-host`**         | `RemoveHost.py`         | Removes a specified host from a `.nessus` file.                                                                                                                            |
| **`nessus-host-info`**           | `HostInfo.py`           | Provides detailed information about a specific host, including scan timing, alternate hostnames, FQDNs, plugins triggered, and detected services.                          |


## 🧰 Requirements

- Python 3.x
- No external dependencies (uses built-in `xml.etree.ElementTree`)

## 📦 Usage

### FindingCount.py / nessus-finding-count (Count Findings)

```bash
python NessusPluginHosts.py -f <filename.nessus> <plugin_id>

python IdentifiedServices -f <filename.nessus>

python FindingCount.py -f <filename.nessus>
python FindingCount.py -d <directory of nessus files>
python FindingCount.py -d <directory of nessus files> --csv summary.csv
python FindingCount.py -f <filename.nessus> --unique/--total/--both

```


### NessusPluginHosts.py / nessus-plugin-hosts (List Hosts/Services per Plugin)

 
```bash
# Default line-delimited
python NessusPluginHosts.py -f scan.nessus 19506

# Default line-delimited, no port
python NessusPluginHosts.pyy -f scan.nessus 19506 --no-port

# Space-delimited
python NessusPluginHosts.py -f scan.nessus 19506 --space-delim

# Space-delimited, no-port -- Specfication for metasploit "rhosts"
python NessusPluginHosts.py -f scan.nessus 19506 --space-delim --no-port

# Comma-delimited
python NessusPluginHosts.py -f scan.nessus 19506 --comma-delim

# Comma-delimited, no port
python NessusPluginHosts.py -f scan.nessus 19506 --comma-delim --no-port

# List High severity (0 = Info, 1 = Low, 2 = Med, 3 = High, 4 = Critical) finding names in terminal
python NessusPluginHosts.py -f scan.nessus --list-plugins 3

# List ALL severity finding names in terminal
python NessusPluginHosts.py -f scan.nessus --list-plugins

# Export ALL findings to nessus_plugin_hosts directory, create file for each finding with an ordered host:port list
python NessusPluginHosts.py -f scan.nessus --list-plugins --export-plugin-hosts ./nessus_plugin_hosts
```

### IdentifiedServices.py / nessus-identified-services (List Identified Services)
Looks at the Nessus plugin 22964 and outputs the services by service type.

```
python IdentifiedServices.py scan.nessus --no-port --comma-delim
```

### MergeNessus.py /nessus-merge (Merge Nessus Files)

```bash
# Merges all nessus files in current folder, outputs to "Merged.Nesssus"
python3 MergeNessus.py

# Merge all nessus files in specific directory
python3 MergeNessus.py -d /path/to/nessus/files

# Merge and set custom filename
python3 MergeNessus.py -o /path/to/output/Combined_Scan.nessus

# Merge and give the merged scan a custom title:
python3 MergeNessus.py -t "Quarterly Security Scan"

# Merge from a directory, set both custom title and output file:
python3 MergeNessus.py -d /scans/q1 -o ./Merged_Q1.nessus -t "Q1 Combined Scan"
```

### HostInfo.py / nessus-host-info (Provide Host Details)

Provides details about a host, alternate hostnames, scanning times, etc.

```bash
python3 HostInfo.py -f input.nessus -n 192.168.1.1

python3 HostInfo.py -d ./nessusDirectory/ -n 192.168.1.1
```

### RemoveHost.py / nessus-remove-host (Remove Host from Nessus File)
```bash
python3 RemoveHost.py -f input.nessus -o output.nessus -n target-hostname
```

## SynScanSummary.py / nessus-synscan-summarySummary

Reads Nessus results from Nessus' Plugin 11219 (SYN Scanner) and creates an output summarizing the scan results. 

### Usage 

```bash
# Show both summaries to stdout
python .\SynScanSummary.py .\scan.nessus

# Only ports per host, showing at most 15 ports per host
python .\SynScanSummary.py .\scan.nessus --analysis ports-per-host --limit 15

# Only hosts per port, for a specific port set, to stdout
python .\SynScanSummary.py .\scan.nessus --analysis hosts-per-port --include-ports 22,80,443,8000-8100

# Write CSV (and also print to stdout)
python .\SynScanSummary.py .\scan.nessus --csv .\syn_summary.csv

# Write CSVs only (no stdout), both analyses -> creates syn_summary_ports_per_host.csv and syn_summary_hosts_per_port.csv
python .\SynScanSummary.py .\scan.nessus --analysis both --csv .\syn_summary.csv --no-stdout
```
### Example

```bash
SynScanSummary.py Merged.nessus --analysis hosts-per-port
```

| ![Syn Scan1](images/synScan1.png) |
|------------------------------------|

```bash
SynScanSummary.py Merged.nessus --analysis ports-per-host
```

| ![Syn Scan2](images/synScan2.png) |
|------------------------------------|



## LDAPinfo.py / nessus-ldap-info (LDAP Information Gathering)

This script parses the details from plugins 20870 and 25701 and returns the information in a easy to read format.  No more hunting the Nessus file when you just quickly need the LDAP information.

### Usage
```bash
# Parse a single Nessus file 
python3 LDAPinfo.py -f scan.nessus

# Parse all Nessus files in a directory
python3 LDAPinfo.py -d /path/to/nessus/files

# Output to a specific CSV file (for paste into Excel/word)
python3 LDAPinfo.py -f scan.nessus --csv /tmp/ldap_info.csv
```

### Example Output
```
# $ python3 LDAPinfo.py -d /path/to/nessus/files

[LDAP Services Identified] (plugin 20870)
------------------------------------------------------------------------
Host                           Port   Proto  Service    Source
------------------------------------------------------------------------
192.168.1.10                   389    tcp    ldap       corp_scan1.nessus
192.168.1.11                   636    tcp    ldaps      corp_scan2.nessus
------------------------------------------------------------------------

[LDAP Information Disclosure] (plugin 25701)
--------------------------------------------------------------------------------------------------------------
Host                           Port   Domain                        Server
--------------------------------------------------------------------------------------------------------------
192.168.1.10                   389    domain.local                  DomainDC01
192.168.1.11                   636    domain.local                  DomainDC02
--------------------------------------------------------------------------------------------------------------

[+] Wrote CSV: /current/dir/ldap_info.csv
```
