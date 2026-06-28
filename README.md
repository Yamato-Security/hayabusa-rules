<div align="center">
 <p>
    <img alt="Hayabusa Logo" src="https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/logo.png" width="60%">
 </p>

 <p>
   <b>Curated Sigma detection rules and Hayabusa rules for Windows event log analysis.</b><br/>
   Detection rules and config files used by <a href="https://github.com/Yamato-Security/hayabusa">Hayabusa</a>
   and <a href="https://github.com/Velocidex/velociraptor">Velociraptor</a>'s built-in Sigma support.
 </p>

 <h2>
   📖 <a href="https://yamato-security.github.io/hayabusa/rules/">Read the Rules Documentation&nbsp;→</a>
 </h2>
</div>

---

## 📖 Documentation

How to write and use these rules — rule file format, detection fields, field modifiers, Sigma
correlations, deprecated features and rule-creation advice — now lives on the Hayabusa
documentation site:

> ### 👉 **[yamato-security.github.io/hayabusa/rules](https://yamato-security.github.io/hayabusa/rules/)**

| Topic | |
| --- | --- |
| 📝 [Creating Rule Files](https://yamato-security.github.io/hayabusa/rules/creating-rules/) | Rule file format and structure |
| 🔎 [Detection Fields](https://yamato-security.github.io/hayabusa/rules/detection-fields/) | Selection, field modifiers, wildcards, conditions |
| 🧮 [Sigma Correlations](https://yamato-security.github.io/hayabusa/rules/correlations/) | Event count, value count and temporal rules |
| 🧩 [Field Modifiers](https://yamato-security.github.io/hayabusa/rules/field-modifiers/) | Supported modifiers reference |
| 🗑️ [Deprecated Features](https://yamato-security.github.io/hayabusa/rules/deprecated/) | Deprecated keywords and `count` rules |
| 💡 [Rule Creation Advice](https://yamato-security.github.io/hayabusa/rules/advice/) | Tips for writing good rules |

## 🦅 About these rules

This repository contains curated Sigma rules that detect attacks in Windows event logs. It is used
mainly for [Hayabusa](https://github.com/Yamato-Security/hayabusa) detection rules and config files,
as well as [Velociraptor](https://github.com/Velocidex/velociraptor)'s built-in Sigma detection.

Compared with the [upstream Sigma repository](https://github.com/SigmaHQ/sigma), these rules:

- include only rules that most Sigma-native tools can parse;
- de-abstract the `logsource` field by adding the necessary `Channel`, `EventID`, etc. to reduce false positives;
- add converted `process_creation` and `registry` rules so they detect on built-in Windows logs, not just Sysmon.

Rules live in the `hayabusa/` and `sigma/` directories. Please file rule issues and pull requests in
**this** repository (not the main Hayabusa repository).

## 🗂️ Looking for the old README?

The previous single-page README is preserved unchanged:

- 📄 [**OLD-README.md**](OLD-README.md) — English
- 📄 [**OLD-README-Japanese.md**](OLD-README-Japanese.md) — 日本語

## 📜 License

The rules in this repository are released under the [Detection Rule License (DRL) 1.1](LICENSE.md).

---

<div align="center">
  Maintained by <a href="https://yamatosecurity.connpass.com/">Yamato Security</a>
  &nbsp;·&nbsp; <a href="https://twitter.com/SecurityYamato">@SecurityYamato</a>
</div>
