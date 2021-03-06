# CVEchecker
A simple but powerful offline checker to lookup CVEs for software packages.

## Description 
This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. It gets feed with two files, the package list file and a cve database file(s). These can be obtained manually or by using the paramaters --download-cve-dbs and --create-packages-file.

## Features
* Download CVE databases
* Create list of installed applications
* Lookup corresponding CVEs to applications+version
* CVE lookup works offline
* CSV output

## Dependencies
   ```Python 3.4```

## Quickstart
1. Download CVE databases and create a packages.txt file (just work packages installed using APT). Don't run the check afterwards.

   ``` ~# python CVEchecker.py --download-cve-dbs --create-packages-file --no-check ```

2. Run CVEchecker against all packages in the "package.txt" file. Use all CVE DB files matching the schema "nvdcve-1.0-YYYY.json".

   ``` ~# python CVEchecker.py```

3. Use custom paths for package and CVE db files.

   ``` ~# python CVEchecker.py --packages-file /my/folder/all_packages.txt --cve-dbs /foo1/bar1.json,/foo2/bar2.json ```
   
4. Like nr. 2 but exclude some CVEs from the result.

   ``` ~# python CVEchecker.py  --whitelist-file /some/whitelist.txt ```
    

## Missing Features
* Show only --criticality findigs (LOW,MEDIUM,HIGH,...)
* disable fuzzy search to avoid false positives
* show exact reason for matching (name + version, fuzzy/exact,...)