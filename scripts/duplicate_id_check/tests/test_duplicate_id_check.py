"""Tests for the duplicate rule id linter.

The entry-point file uses a hyphenated name (matching the repository's
``supported-modifier.py`` convention) so it is loaded by path rather than a
normal import.
"""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'duplicate-id-check.py'
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def _load_module():
    spec = importlib.util.spec_from_file_location('duplicate_id_check', SCRIPT)
    assert spec is not None and spec.loader is not None, (
        f'could not create an import spec for {SCRIPT}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


def test_clean_set_has_no_duplicates():
    files = mod.iter_yaml_files([str(FIXTURES / 'clean')])
    assert len(files) == 2
    assert mod.find_duplicates(mod.collect_ids(files)) == {}


def test_duplicate_id_is_detected():
    files = mod.iter_yaml_files([str(FIXTURES / 'duplicates')])
    duplicates = mod.find_duplicates(mod.collect_ids(files))
    assert len(duplicates) == 1
    rid, locs = next(iter(duplicates.items()))
    assert rid == '00000000-0000-0000-0000-000000000001'
    assert len(locs) == 2


def test_correlation_multi_document_ids_tracked_separately():
    files = mod.iter_yaml_files([str(FIXTURES / 'correlation')])
    ids = mod.collect_ids(files)
    # One file, two documents -> two distinct ids, no duplicates.
    assert len(files) == 1
    assert len(ids) == 2
    assert mod.find_duplicates(ids) == {}


def test_id_comparison_is_case_insensitive(tmp_path):
    (tmp_path / 'a.yml').write_text('id: ABCDEF00-0000-0000-0000-000000000001\n')
    (tmp_path / 'b.yml').write_text('id: abcdef00-0000-0000-0000-000000000001\n')
    files = mod.iter_yaml_files([str(tmp_path)])
    duplicates = mod.find_duplicates(mod.collect_ids(files))
    assert len(duplicates) == 1


def test_malformed_yaml_is_skipped_not_fatal():
    files = mod.iter_yaml_files([str(FIXTURES / 'malformed')])
    # Must not raise; the broken file is simply skipped.
    assert mod.find_duplicates(mod.collect_ids(files)) == {}


def test_exclude_filters_paths():
    all_files = mod.iter_yaml_files([str(FIXTURES)])
    filtered = mod.iter_yaml_files([str(FIXTURES)], excludes=('/duplicates/',))
    assert len(filtered) < len(all_files)
    assert all('/duplicates/' not in f.replace('\\', '/') for f in filtered)


def test_main_returns_one_on_duplicates():
    assert mod.main([str(FIXTURES / 'duplicates')]) == 1


def test_main_returns_zero_on_clean():
    assert mod.main([str(FIXTURES / 'clean')]) == 0


def test_main_detects_duplicate_across_directories(tmp_path):
    # Same id lives in two separate trees -> still caught when both are scanned.
    tree_a = tmp_path / 'a'
    tree_b = tmp_path / 'b'
    tree_a.mkdir()
    tree_b.mkdir()
    (tree_a / 'x.yml').write_text('id: 00000000-0000-0000-0000-0000000000ff\n')
    (tree_b / 'y.yml').write_text('id: 00000000-0000-0000-0000-0000000000ff\n')
    assert mod.main([str(tree_a), str(tree_b)]) == 1
