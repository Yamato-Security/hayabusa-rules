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


## Usage

1. `pip install oyaml`
2. `git clone https://github.com/SigmaHQ/sigma.git`
3. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
4. `cd hayabusa-rules`
5. `cd tools/sigmac`
6. `python logsource_mapping.py -r ../../../sigma -o ./hayabusa_rule`

After executing the above, the rules converted to Hayabusa format will be output to `./hayabusa_rule`.