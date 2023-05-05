# SIGMAからHayabusaルールへの自動変換

[\[English\]](README.md) | [**日本語**]

[![python](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/)
![version](https://img.shields.io/badge/Platform-Win-green)
![version](https://img.shields.io/badge/Platform-Lin-green)
![version](https://img.shields.io/badge/Platform-Mac-green)

## 事前に変換されたSigmaルールについて

SigmaからHayabusa形式に変換されたルールが`./rules/sigma`ディレクトリに用意されています。 
ローカル環境で新しいルールをテストしたり、Sigmaの最新のルールを変換したりしたい場合は、以下のドキュメンテーションをご参考下さい。

## Pythonの環境依存

Python 3.8以上と次のモジュールが必要です：`oyaml`
以下のコマンドでインストール可能です。

```sh
pip3 install oyaml
```

## Sigmaについて

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)


## 使い方

1. `pip install oyaml`
2. `git clone https://github.com/SigmaHQ/sigma.git`
3. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
4. `cd hayabusa-rules`
5. `cd tools/sigmac`
6. `python logsource_mapping.py -r ../../../sigma -o ./hayabusa_rule`

上記実行後、`./hayabusa_rule`にHayabusa形式に変換されたルールが出力されます。

