# Automatic conversion of Sigma to Hayabusa rules

[**English**] | [\[日本語\]](README-Japanese.md)

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

## Pre-converted Sigma rules

Sigma rules have already been pre-converted to hayabusa format and placed in the `./rules/sigma` directory. 
Please refer to this documentation to convert rules on your own for local testing, using the latest rules, etc...

## Python requirements

You need Python 3.8+ and the following modules: `oyaml`

```sh
pip3 install oyaml
```

## About Sigma

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## About logsource_mapping.py
`logsource_mapping.py` is a tool to convert `logsource` of Sigma rule to Hayabusa format.
Since `Hayabusa` does not use `logsource` for detection processing, use the following `yaml` mapping to convert the contents of `logsource` to `detection` and `condition`.
- sysmon.yaml
- windows-audit.yaml
- windows-services.yaml

### Conversion example
The following Sigma rules are converted to the following two Hayabusa formats after running `logsource_mapping.py`.
#### Before conversion
Sigma rule
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
Hayabusa rule(For Sysmon)
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
Hayabusa rule(For Windows builtin)
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        - Image|endswith: '.exe'
    detection: process_creation and selection
```

## Usage

1. `pip install oyaml`
2. `git clone https://github.com/SigmaHQ/sigma.git`
3. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
4. `cd hayabusa-rules`
5. `cd tools/sigmac`
6. `python logsource_mapping.py -r ../../../sigma -o ./hayabusa_rule`

After executing the above, the rules converted to Hayabusa format will be output to `./hayabusa_rule`.