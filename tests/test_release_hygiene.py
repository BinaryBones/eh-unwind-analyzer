#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
IGNORED_TREES = {
    ROOT / "build",
    ROOT / "release-output",
    ROOT / "artifacts",
}


def ignored(path: Path) -> bool:
    return any(path == tree or tree in path.parents for tree in IGNORED_TREES)


def main() -> int:
    forbidden: list[str] = []
    for path in ROOT.rglob("*"):
        if ignored(path):
            continue
        if path.name == ".DS_Store" or path.name.startswith("._"):
            forbidden.append(path.relative_to(ROOT).as_posix())
        elif path.is_dir() and path.name in {"__pycache__", ".pytest_cache"}:
            forbidden.append(path.relative_to(ROOT).as_posix() + "/")
        elif path.is_file() and path.suffix in {".pyc", ".pyo", ".plist"}:
            forbidden.append(path.relative_to(ROOT).as_posix())

    stale_binaries = [
        ROOT / "eh_unwind_analyzer.exe",
        ROOT
        / "reports"
        / "dynamic_validation_2026-06-08"
        / "tool"
        / "eh_unwind_analyzer_current.exe",
    ]
    forbidden.extend(
        path.relative_to(ROOT).as_posix()
        for path in stale_binaries
        if path.exists()
    )

    if forbidden:
        raise AssertionError(
            "release hygiene violations:\n  " + "\n  ".join(sorted(set(forbidden)))
        )

    runner = (ROOT / "tests" / "run_real_corpus.py").read_text(encoding="utf-8")
    if 'not path.name.startswith("._")' not in runner:
        raise AssertionError("run_real_corpus.py must ignore AppleDouble files")

    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    for marker in ('PATTERN ".DS_Store" EXCLUDE', 'PATTERN "._*" EXCLUDE'):
        if marker not in cmake:
            raise AssertionError(f"CMake install rules are missing {marker}")

    print("test_release_hygiene: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
