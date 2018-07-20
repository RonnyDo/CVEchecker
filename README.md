# CVEchecker
A simple but powerful offline checker to lookup CVEs for software packages.

## Dependencies


## Examples
~# python CVEchecker.py
Take all packages from the ./packages.txt file and check if they match with entries from in nvdcve-1.0-<year>.json files.

~# python CVEchecker.py --download-cve-dbs --create-packages-file --no-check
Download all CVE database files and create a file with all installed packages. Don't run the check afterwards.

~# python CVEchecker.py --download-cve-dbs --packages-file /some/folder/mypackage_file.txt
Download the current CVE database. Run the check afterwards against packages from the file /some/folder/mypackage_file.txt


## Missing Features
- Show CVE Score
- Show only --criticality findigs (LOW,MEDIUM,HIGH,...)
- color output depending on CVE score
- disable fuzzy search to ignore false positives