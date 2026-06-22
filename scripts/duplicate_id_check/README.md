# About

Every Sigma / Hayabusa rule must carry a globally unique `id` (a UUID). When a
rule is copied to create a new one, it is easy to forget to regenerate this
`id`, leaving two rules that share the same UUID. A duplicate id silently
shadows a detection and breaks any tooling that addresses rules by their id.

This script scans every `.yml` rule, reads the top-level `id` of every YAML
document (correlation rules hold several documents in one file), and exits with
a non-zero status if any id is used more than once. It is wired into CI
(`.github/workflows/duplicate-id-check.yaml`) so a pull request that introduces
a duplicate id fails before it can be merged. See issue
[#745](https://github.com/Yamato-Security/hayabusa-rules/issues/745).

# How to use

## Run locally

1. `git clone https://github.com/Yamato-Security/hayabusa-rules.git`
2. `cd hayabusa-rules/scripts/duplicate_id_check`
3. `poetry install --no-root`
4. `poetry run python duplicate-id-check.py ../../hayabusa ../../sigma`

Exit code `0` means all rule ids are unique; exit code `1` means at least one
id is duplicated, and each offending rule is printed.

You can scan any set of directories, and skip paths with `--exclude`:

```
poetry run python duplicate-id-check.py ../.. --exclude /scripts/
```

## Run Actions

- Manual: trigger the **Duplicate rule id check** workflow via `workflow_dispatch`.
- Pull request: the workflow runs automatically on every PR and blocks the merge
  if a duplicate id is detected.

# Tests

```
poetry install --no-root
poetry run pytest
```

# Authors

* Devam Shah
* Yamato Security
