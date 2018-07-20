import json
from pprint import pprint
import argparse
import os
import zipfile
import io
import datetime
import requests


def download_cve_dbs():
    current_year=datetime.datetime.now().year
    years=range(2002, current_year + 1)
    print ("\n[*] download CVEs from {0}-{1}".format("2002", current_year))
    for year in years:
        zip_file_url = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{0}.json.zip".format(year)
        print ("[*] download and extract {0}".format(zip_file_url))
        r = requests.get("" + zip_file_url)
        if r.ok:
            z = zipfile.ZipFile(io.BytesIO(r.content))
            z.extractall()
        else:
            print ("[!] download failed")

    
def create_packages_file():
    print ("[!] \"--create-packages-file\" isn't yet implemented")

    
def get_installed_packages(f):
    p = []
    with open(f, encoding='utf-8') as p_file:
        for line in p_file:
            p.append(line)
    return p

    
def get_cve_db_paths():
    cve_db_paths = []
    for f in os.listdir("./"):
        if f.startswith('nvdcve-1.0-') and f.endswith('.json'):
            cve_db_paths.append(f)
    return cve_db_paths

    
def check_package (package, cve_dbs):
    name = package.split()[0]
    version = package.split()[1]
    print ("\n[*] lookup package {0} version {1}".format(name, version))

    for cve_db in cve_dbs:
        for cve in cve_db["CVE_Items"]:
            for vendor in cve['cve']['affects']['vendor']['vendor_data']:
                for product_data in vendor['product']['product_data']:
                    if name in product_data['product_name']:
                        for version_data in product_data['version']['version_data']:
                            if version == version_data['version_value']:
                                print ("[+] {0} version {1} is affected by {2}".format(product_data['product_name'], version, cve['cve']['CVE_data_meta']['ID']))


parser = argparse.ArgumentParser(description="This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. It gets feed with two files, the package list file and a cve database file. These can be obtained manually or by using the paramaters --download-cve-dbs and --create-packages-file.")

parser.add_argument('--download-cve-dbs', action="store_true", help='Download and extract all CVE databases since 2002 from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED). More than 1 GB of free harddrive space is needed.')
parser.add_argument('--create-packages-file', action="store_true", help='Create a list of installed packages and corresponding versions. Just works for packages installed with APT.')
parser.add_argument('--packages-file', help='A whitespace seperated list with software name and version. If parameter isn\'t set, the file ./packages.txt will be loaded by default.')
parser.add_argument('--cve-dbs', help='Path to CVE database file(s). Multiple paths must be seperated by a comma. The json content must follow the NVD JSON 0.1 beta Schema (https://nvd.nist.gov/vuln/data-feeds#JSON_FEED). If parameter isn\'t set, all files with the name \"nvdcve-1.0-YYYY.json\" will be loaded by default.')
parser.add_argument('--no-check', action="store_true", help='Use it together with --download-cve-db or --create-packages-file to skip the cve checking process afterwards.')

args = parser.parse_args()


def load_cve_dbs(cve_db_paths):
    cve_dbs = []
    for cve_db_path in cve_db_paths:
        with open(cve_db_path, encoding='utf-8') as path:
            cve_dbs.append(json.load(path))
    return cve_dbs


def check(packages, cve_dbs):
    for package in packages:
        check_package(package, cve_dbs)


# defaults
packages_file=""
cve_db_paths=[]

if args.download_cve_dbs:
    download_cve_dbs()

if args.create_packages_file:
    create_packages_file()

if args.packages_file:
    packages_file = args.packages_file
else:
    packages_file = './packages.txt'

if args.cve_dbs:
    cve_db_paths = args.cve_dbs.split(",")
else:
    cve_db_paths = get_cve_db_paths()



if not args.no_check:
    packages = get_installed_packages(packages_file)
    print ("\n[*] {0} packages to check:".format(len(packages)))
    for p in packages:
        name = p.split()[0]
        version = p.split()[1]
        print ("[*] {0} {1}".format(name,version))
    cve_dbs = load_cve_dbs (cve_db_paths)
    print ("\n[*] {0} CVE databases loaded:".format(len(cve_db_paths)))
    for db_path in cve_db_paths:
        print ("[*] {0}".format(db_path))
    check(packages, cve_dbs)
