# Acunetix CSV 2 Rootshell

Parser for creating output tables from Acunetix Vulnerability Report CSV.

Filters on the "Name" field and extracts relevant data.
## Usage
```
usage: AcunetixCsv2Rootshell.py [-h] --inputfile INPUTFILE [--outputfolder OUTPUTFOLDER] [--cookiehttp] [--cookiesecure] [--cookieinconsistent] [--XSS] [--unique]
```

Process security issues from Acunetix CSV files.

```
options:
  -h, --help            show this help message and exit
  --inputfile, -i INPUTFILE
                        Path to the input CSV file.
  --outputfolder, -o OUTPUTFOLDER
                        Directory to save the output CSV file.
  --cookiehttp          Filter for 'Cookies Not Marked as HttpOnly'.
  --cookiesecure        Filter for 'Cookies Not Marked as Secure'.
  --cookieinconsistent  Filter for 'Cookies with missing, inconsistent or contradictory properties'.
  --XSS, -x             Filter for 'Cross-site Scripting'.
  --unique, -u          Remove duplicate entries from the output file.
```