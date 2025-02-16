# sigma-lookup

sigma-lookup is a Python command-line tool that allows security analysts and threat hunters to search Sigma detection rules based on MITRE ATT&CK Techniques and Tactics or free-text queries.
The script parses the Sigma rules from the repository [sigma](https://github.com/SigmaHQ/sigma) enabling quick and deep searches.

## Features

- Search Sigma rules by MITRE ATT&CK Technique/Tactic ID
- Perform free-text searches in rule titles and descriptions (regex are supported)
- Filter rules by Status and/or platform

## Usage

### Setup

1. Clone this repository and update the submodule (sigma repository)

```
git clone https://github.com/vincenzocaputo/sigma-lookup
cd sigma-lookup
git submodule update --init
```

2. Create a virtual environment and install the required libraries

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements
```

### First run

On the first run, the tool will parse the Sigma rules (from `sigma/rules` folder) and create a cache file. The cache will be stored as a JSON file at `cache/cache.json`.

You can force the cache to regenerate using the `-F` option.

```
python3 sigma-lookup.py -F
```

### Usage

```
usage: sigma-lookup.py [-h] [-i ID] [-t TECHNIQUE] [-T] [-p] [-S  [...]] [-s SEARCH] [-F]

options:
  -h, --help            show this help message and exit
  -i ID, --id ID        Get Sigma Rule by Rule ID. The Rule ID is an internal reference used only by this tool.
  -t TECHNIQUE, --technique TECHNIQUE
                        MITRE ATT&CK Technique to lookup
  -T , --tactic         MITRE ATT&CK Tactic to lookup. Allowed values are: collection, command-and-control, credential-access, defense-evasion, discovery, execution, exfiltration, impact, initial-access, lateral-movement,
                        persistence, privilege-escalation, reconnaissance, resource-development
  -p , --product        Search by Product. Allowed values are: macos, sql, spring, linux, python, github, huawei, qualys, rpc_firewall, nodejs, jvm, m365, windows, aws, cisco, django, bitbucket, gcp, opencanary,
                        kubernetes, azure, okta, onelogin, ruby_on_rails, juniper, velocity, zeek
  -S  [ ...], --status  [ ...]
                        Filter by Sigma Rule status. Allowed values are: stable, test, experimental, deprecated, unsupported
  -s SEARCH, --search SEARCH
                        Search for free text in rule titles and descriptions.
  -F, --force-caching   Force the regeneration of the detection rule cache.
```

### Examples

1. Search for the technique **OS Credential Dumping**, filtering only rules that reference **LSASS** process. Consider only rules with status "stable"

```
python3 sigma-lookup.py -t T1003 -s LSASS -S stable
```
![image](https://github.com/user-attachments/assets/78ad648d-60df-4c10-b02d-38abc4b6524c)


2. Search for all detection rules related to Defense Evasion tactics involving the use of Base64 encoding in PowerShell.
```
python3 sigma-lookup.py -T defense-evasion -s "(?=.*Powershell)(?=.*Base64)"
```
![image](https://github.com/user-attachments/assets/83e081c3-3a01-429f-a7eb-16ba878fb571)


3. Display the Sigma Rule "Suspicious Obfuscated PowerShell Code"
```
python3 sigma-lookup.py -i 2119
```
![image](https://github.com/user-attachments/assets/e40f19a1-fdb0-4834-85b1-acb6a3ed5d5f)

**Note**: The Rule ID field is generated during the cache file creation and serves as an internal reference to facilitate detection rule lookups. Triggering the cache operation may generate new Rule IDs. Therefore, you should rely solely on the Rule IDs provided in the tool's outputs.
