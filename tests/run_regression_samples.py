#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

import jsonschema

from report_semantics import validate_report_semantics

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / 'tests' / 'samples' / 'manifest.json'
SAMPLE_BUILDER = ROOT / 'tests' / 'samples' / 'build_samples.py'
REPORT_SCHEMA = ROOT / 'docs' / 'report.schema.json'


def get_path(obj, dotted):
    cur = obj
    for part in dotted.split('.'):
        if part == 'functions_len':
            return len(cur['functions'])
        cur = cur[part]
    return cur


def check_expectations(data, expect: dict[str, object]) -> list[str]:
    errors: list[str] = []
    for key, expected in expect.items():
        if key.endswith('_ge'):
            actual = get_path(data, key[:-3])
            if actual < expected:
                errors.append(f'{key[:-3]} expected >= {expected}, got {actual}')
        else:
            actual = get_path(data, key)
            if actual != expected:
                errors.append(f'{key} expected {expected!r}, got {actual!r}')
    return errors


def ensure_sample_binaries(manifest: dict[str, object]) -> bool:
    missing = []
    for item in manifest['samples']:
        sample = ROOT / item['path']
        if not sample.exists():
            missing.append(sample)
    if not missing:
        return True
    print('[INFO] Sample binaries missing, trying to rebuild with tests/samples/build_samples.py')
    if not SAMPLE_BUILDER.exists():
        print('[FAIL] sample builder script not found', file=sys.stderr)
        return False
    proc = subprocess.run([sys.executable, str(SAMPLE_BUILDER)], capture_output=True, text=True)
    if proc.returncode != 0:
        print('[FAIL] sample rebuild failed', file=sys.stderr)
        if proc.stdout:
            print(proc.stdout.rstrip(), file=sys.stderr)
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        return False
    still_missing = [p for p in missing if not p.exists()]
    if still_missing:
        print('[FAIL] some samples are still missing after rebuild:', file=sys.stderr)
        for p in still_missing:
            print(f'  - {p}', file=sys.stderr)
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description='Run minimal EH/Unwind Analyzer regression samples')
    ap.add_argument('tool', help='path to EH/Unwind Analyzer executable')
    args = ap.parse_args()

    tool = Path(args.tool).resolve()
    if not tool.exists():
        print(f'tool not found: {tool}', file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    schema = json.loads(REPORT_SCHEMA.read_text(encoding='utf-8'))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    if not ensure_sample_binaries(manifest):
        return 2

    failed = False
    for item in manifest['samples']:
        sample = ROOT / item['path']
        expect = item['expect']
        with tempfile.TemporaryDirectory() as td:
            out_json = Path(td) / 'out.json'
            dump = subprocess.run([str(tool), str(sample), '--dump', '--limit', '1'], capture_output=True, text=True)
            if dump.returncode != 0:
                print(f'[FAIL] static analysis run failed for {sample.name}')
                print(dump.stderr)
                failed = True
                continue
            prot = subprocess.run([str(tool), str(sample), '--heuristics', '--json', str(out_json)], capture_output=True, text=True)
            if prot.returncode != 0 or not out_json.exists():
                print(f'[FAIL] heuristic/json run failed for {sample.name}')
                print(prot.stderr)
                failed = True
                continue
            data = json.loads(out_json.read_text(encoding="utf-8"))
            errors = [
                f"schema: {error.message} at {'/'.join(str(p) for p in error.absolute_path) or '<root>'}"
                for error in validator.iter_errors(data)
            ]
            errors.extend(f"semantics: {error}" for error in validate_report_semantics(data))
            errors.extend(check_expectations(data, expect))
            if errors:
                failed = True
                print(f'[FAIL] {sample.name}')
                for err in errors:
                    print('  -', err)
            else:
                print(f'[OK] {sample.name}')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
