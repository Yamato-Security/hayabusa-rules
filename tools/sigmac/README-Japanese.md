# SIGMAからHayabusaルールへの自動変換

[\[English\]](README.md) | [**日本語**]

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

## 事前に変換されたSigmaルールについて

SigmaからHayabusa形式に変換されたルールが`./rules/sigma`ディレクトリに用意されています。 
ローカル環境で新しいルールをテストしたり、Sigmaの最新のルールを変換したりしたい場合は、以下のドキュメンテーションをご参考下さい。

## 実行環境

このスクリプトの実行には[Poetry](https://python-poetry.org/)が必要です。  
以下公式ドキュメントを参考にPoetryをインストールしてください。  
https://python-poetry.org/docs/#installation

## Sigmaについて

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## logsource_mapping.pyについて
`logsource_mapping.py`は、Sigmaルールの`logsource`をHayabusa形式に変換するツールです。  
`Hayabusa`では`logsource`は検知処理に使われないため、 以下`yaml`のマッピングを使い、`logsource`の内容を`detection`,`condition`に変換します。
- sysmon.yaml
- windows-antivirus.yaml
- windows-audit.yaml
- windows-services.yaml

### 変換の例
以下のSigmaルールは、`logsource_mapping.py`実行後、以下2つのHayabusa形式に変換されます。

#### 変換前
Sigmaルール
```yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '.exe'
    detection: selection
```

#### 変換後
Hayabusaルール(Sysmon用)
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
Hayabusaルール(Windowsビルトイン用)
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

## 使い方

1. `git clone https://github.com/SigmaHQ/sigma.git`
2. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
3. `cd hayabusa-rules/tools/sigmac`
4. `poetry install --no-root`
5. `poetry run python logsource_mapping.py -r ../../../sigma -o ./converted_sigma_rules`

上記実行後、`./converted_sigma_rules`にHayabusa形式に変換されたルールが出力されます。

