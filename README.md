# Nessus Plugin Scripts:

This reposity is a collection of Python scripts designed to work with Nessus scan results. The scripts utilize the built-in `xml.etree.ElementTree` library to parse `.nessus` files and provide various functionalities such as counting findings, listing hosts/services for specific plugins, identifying services, merging Nessus files, and summarizing Scanner results.

## Tools Included
- FindingCount.py - Counts findings from a nessus file.  Will count unique/total.  Can count fron one Nessus file, or many in a directory.
- NessusPluginHosts.py - Provides a list of hosts/services for a specific Nessus Plugin.  Multiple delimit options and search one Nessus file, or many in a directory.
- IdentififedServices.py - Lists the services identified in a Nessus file.
- MergeNessus.py -- Merges Nessus files from a given directory. Corrects overall start/end time & accepts change in Title.
- SynScanSummary.py -- Summarizes SYN Scanner results from Nessus Plugin 11219. Outputs both hosts-per-port and ports-per-host analyses, with options for CSV output.

## 🧰 Requirements

- Python 3.x
- No external dependencies (uses built-in `xml.etree.ElementTree`)

## 📦 Usage

### FindingCount.py (Count Findings)

```bash
python NessusPluginHosts.py -f <filename.nessus> <plugin_id>

python IdentifiedServices -f <filename.nessus>

python FindingCount.py -f <filename.nessus>
python FindingCount.py -d <directory of nessus files>
python FindingCount.py -d <directory of nessus files> --csv summary.csv
python FindingCount.py -f <filename.nessus> --unique/--total/--both

```


### NessusPluginHosts.py (List Hosts/Services per Plugin)

 
```
# Default line-delimited
python NessusPluginHosts.py scan.nessus 19506

# Default line-delimited, no port
python NessusPluginHosts.pyy scan.nessus 19506 --no-port

# Space-delimited
python NessusPluginHosts.py scan.nessus 19506 --space-delim


# Space-delimited, no-port -- Specfication for metasploit "rhosts"
python NessusPluginHosts.py scan.nessus 19506 --space-delim --no-port

# Comma-delimited
python NessusPluginHosts.py scan.nessus 19506 --comma-delim

# Comma-delimited, no port
python NessusPluginHosts.py scan.nessus 19506 --comma-delim --no-port
```

### IdentifiedServices.py (List Identified Services)
Looks at the Nessus plugin 22964 and outputs the services by service type.

```
python IdentifiedServices.py scan.nessus --no-port --comma-delim
```

### MergeNessus.py (Merge Nessus Files)

```
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

## Syn Scanner

Reads Nessus results from Nessus' Plugn 11219 (SYN Scanner) and creates an output summarizing the scan results. 

```
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


```



