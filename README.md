# CVEchecker
A simple but powerful offline checker to lookup CVEs for software packages.

## Description 
This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. It gets feed with two files, the package list file and a cve database file(s). These can be obtained manually or by using the paramaters --download-cve-dbs and --create-packages-file.

## Dependencies
    ```Python 3.4```

## Quickstart
1. Download CVE databases and create a packages.txt file (just work packages installed using APT). Don't run the check afterwards.
    ```~# python CVEchecker.py --download-cve-dbs --create-packages-file --no-check```

2.1 Run CVEchecker against all packages in the "package.txt" file. Use all CVE DB files matching the schema "nvdcve-1.0-YYYY.json".
    ```~# python CVEchecker.py```

2.2 Use custom paths for package and CVE db files.
    ```~# python CVEchecker.py --packages-file /my/folder/all_packages.txt --cve-dbs /foo1/bar1.json,/foo2/bar2.json```
    


## Missing Features
- Show CVE Score
- Show only --criticality findigs (LOW,MEDIUM,HIGH,...)
- color output depending on CVE score
- disable fuzzy search to avoid false positives
- show exact reason for matching (name + version, fuzzy/exact,...)