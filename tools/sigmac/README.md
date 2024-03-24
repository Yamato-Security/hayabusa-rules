# Automatic conversion of Sigma to Hayabusa rules

[**English**] | [\[日本語\]](README-Japanese.md)

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

## Pre-converted Sigma rules

Sigma rules have already been pre-converted to hayabusa format and placed in the `./rules/sigma` directory. 
Please refer to this documentation to convert rules on your own for local testing, using the latest rules, etc...

## Environment
To run this script, [Poetry](https://python-poetry.org/) is required.
Please refer to the official documentation for Poetry installation at the following link:
https://python-poetry.org/docs/#installation

## About Sigma

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## About logsource_mapping.py
`logsource_mapping.py` is a tool to convert the `logsource` field of Sigma rules to Hayabusa format.
Since `Hayabusa` at the moment does not support `logsource` for filtering on `Channel` and `EventID` fields and rewriting field names when necessary, we use the following `yaml` mapping files to convert the contents of `logsource` to the `detection` and `condition` fields.
- sysmon.yaml
- windows-antivirus.yaml
- windows-audit.yaml
- windows-services.yaml

### Conversion example
The following Sigma rules are converted to the following two Hayabusa formats after running `logsource_mapping.py`.

#### Before conversion
Sigma rule:
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    detection: selection
```
#### After conversion
Hayabusa rule (for Sysmon rules):
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        - Image|endswith: '.exe'
    detection: process_creation and selection
```
Hayabusa rule (for Windows built-in rules)
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - NewProcessName|endswith: '.exe'
    detection: process_creation and selection
```

## Usage

1. `git clone https://github.com/SigmaHQ/sigma.git`
2. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
3. `cd hayabusa-rules/tools/sigmac`
4. `poetry install --no-root`
5. `poetry run python logsource_mapping.py -r ../../../sigma -o ./converted_sigma_rules`

After executing the commands above, the rules converted to Hayabusa format will be output to the `./converted_sigma_rules` directory.