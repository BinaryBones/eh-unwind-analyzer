#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / 'tests' / 'samples' / 'manifest.json'
SAMPLE_BUILDER = ROOT / 'tests' / 'samples' / 'build_samples.py'


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
    ap = argparse.ArgumentParser(description='Print score/verdict/evidence summary for the bundled sample corpus')
    ap.add_argument('tool', help='path to EH/Unwind Analyzer executable')
    args = ap.parse_args()

    tool = Path(args.tool).resolve()
    if not tool.exists():
        print(f'tool not found: {tool}', file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not ensure_sample_binaries(manifest):
        return 2

    for item in manifest['samples']:
        sample = ROOT / item['path']
        with tempfile.TemporaryDirectory() as td:
            out_json = Path(td) / 'out.json'
            proc = subprocess.run([str(tool), str(sample), '--heuristics', '--json', str(out_json)], capture_output=True, text=True)
            if proc.returncode != 0 or not out_json.exists():
                print(f'[FAIL] {sample.name}: heuristic/json run failed')
                if proc.stderr:
                    print(proc.stderr.rstrip())
                continue
            data = json.loads(out_json.read_text(encoding="utf-8"))
            pr = data['heuristic_analysis']
            findings = ','.join(f['code'] for f in pr.get('findings', [])) or '-'
            print(f"{sample.name}: score={pr['score']} verdict={pr['verdict']} evidence={pr['evidence_level']} findings={findings}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
