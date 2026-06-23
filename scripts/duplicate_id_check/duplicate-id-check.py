#!/usr/bin/env python3
"""Fail when the same rule `id` (UUID) is used by more than one rule.

Every Sigma / Hayabusa detection rule must carry a globally unique ``id``.
When a rule is copied as the starting point for a new one, the ``id`` is
sometimes left unchanged. Two rules then share a UUID, which silently shadows
a detection and breaks any tooling that addresses rules by their id.

This linter walks every ``.yml`` rule under the given path(s), reads the
top-level ``id`` of every YAML document (correlation files contain several),
and exits with a non-zero status if any id appears in more than one place so
that CI blocks the merge.

Usage:
    python duplicate-id-check.py <dir> [<dir> ...] [--exclude SUBSTRING]
"""
import argparse
import glob
import logging
import os
import sys
from collections import defaultdict

import yaml

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def iter_yaml_files(paths: list[str], excludes: tuple[str, ...] = ()) -> list[str]:
    """Return a de-duplicated, sorted list of YAML rule files under ``paths``.

    Both ``.yml`` and ``.yaml`` files are collected (Sigma permits either
    extension). A file is skipped if its path contains any string in
    ``excludes``. Both the candidate path and the exclude patterns are
    normalised to forward slashes before matching, so a pattern such as
    ``/scripts/`` works identically on POSIX and Windows. The match uses
    surrounding slashes so that ``tests`` only matches a ``tests`` path
    component, not a substring of a file name.
    """
    norm_excludes = tuple(ex.replace(os.sep, '/') for ex in excludes)
    seen: set[str] = set()
    for p in paths:
        for pattern in ('*.yml', '*.yaml'):
            for f in glob.glob(os.path.join(p, '**', pattern), recursive=True):
                norm = os.path.normpath(f)
                haystack = f"/{norm.replace(os.sep, '/')}/"
                if any(ex in haystack for ex in norm_excludes):
                    continue
                seen.add(norm)
    return sorted(seen)


def collect_ids(files: list[str]) -> dict[str, list[tuple[str, int]]]:
    """Map each rule id to every ``(file, document_index)`` that declares it.

    UUIDs are compared case-insensitively (RFC 4122). Files that cannot be
    parsed as YAML are reported as a warning and skipped — malformed YAML is
    the responsibility of the dedicated rule-parse-error check, not this one.
    """
    id_locations: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for f in files:
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                for idx, doc in enumerate(yaml.safe_load_all(fh)):
                    if isinstance(doc, dict) and doc.get('id'):
                        key = str(doc['id']).strip().lower()
                        id_locations[key].append((f, idx))
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            logging.warning(f'Skipping unparsable YAML file {f}: {e}')
    return id_locations


def find_duplicates(id_locations: dict[str, list[tuple[str, int]]]) -> dict[str, list[tuple[str, int]]]:
    """Return only the ids that are used by more than one rule."""
    return {rid: locs for rid, locs in id_locations.items() if len(locs) > 1}


def _annotation_path(path: str) -> str:
    """Return a path suitable for a GitHub Actions ``::error file=`` annotation.

    The linter is invoked from ``scripts/duplicate_id_check`` in CI, so the
    scanned paths are relative and contain ``../..``. GitHub only renders an
    annotation when ``file=`` is a path inside the workspace with no ``..``
    segments, so resolve the absolute path and make it relative to
    ``GITHUB_WORKSPACE`` (falling back to the original path when it lies
    outside the workspace, e.g. local runs).
    """
    workspace = os.environ.get('GITHUB_WORKSPACE')
    if not workspace:
        return path.replace(os.sep, '/')
    try:
        rel = os.path.relpath(os.path.realpath(path), os.path.realpath(workspace))
    except ValueError:
        return path.replace(os.sep, '/')
    if rel.startswith('..'):
        return path.replace(os.sep, '/')
    return rel.replace(os.sep, '/')


def report(duplicates: dict[str, list[tuple[str, int]]]) -> None:
    """Print a human-readable report plus GitHub Actions error annotations."""
    for rid, locs in sorted(duplicates.items()):
        logging.error(f'Duplicate rule id {rid} is used by {len(locs)} rules:')
        for f, idx in locs:
            logging.error(f'    - {f} (document #{idx})')
            print(f'::error file={_annotation_path(f)}::Duplicate rule id {rid} '
                  f'(also used elsewhere) at document #{idx}')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Fail if any rule id (UUID) is used by more than one rule.')
    parser.add_argument(
        'paths', nargs='*', default=['.'],
        help='Directories to scan recursively for .yml rules (default: current directory).')
    parser.add_argument(
        '--exclude', action='append', default=[], metavar='SUBSTRING',
        help='Skip files whose path contains SUBSTRING (repeatable).')
    args = parser.parse_args(argv)

    paths = args.paths or ['.']
    excludes = tuple(args.exclude)

    files = iter_yaml_files(paths, excludes)
    logging.info(f'Scanning {len(files)} YAML rule file(s) under: {", ".join(paths)}')

    id_locations = collect_ids(files)
    logging.info(f'Found {len(id_locations)} unique rule id(s).')

    duplicates = find_duplicates(id_locations)
    if duplicates:
        report(duplicates)
        logging.error(f'FAILED: {len(duplicates)} duplicate rule id(s) found.')
        return 1

    logging.info('OK: no duplicate rule ids found.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
