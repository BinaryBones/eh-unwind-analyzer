#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "release-output"
WINDOWS_EXE = (
    ROOT
    / "artifacts"
    / "windows-x64"
    / "eh_unwind_analyzer.exe"
)
MANIFEST = ROOT / "release" / "VERIFIED_WINDOWS_BUILD.json"
ZIP_TIME = (2026, 6, 8, 0, 0, 0)

SOURCE_DIRS = (
    ".github",
    ".vscode",
    "book_source",
    "docs",
    "examples",
    "ghidra",
    "include",
    "release",
    "scripts",
    "src",
    "tests",
    "бинарники на тестирование",
)
SOURCE_FILES = (
    "AUDIT_INVESTOR_READINESS_RU.md",
    ".gitignore",
    ".gitattributes",
    "CHANGELOG.md",
    "CMakeLists.txt",
    "CMakePresets.json",
    "CONTRIBUTING.md",
    "LICENSE",
    "PATCH_NOTES.md",
    "README.md",
    "real_samples/SOURCES.md",
    "requirements-validation.txt",
    "SECURITY.md",
    "build_mingw.bat",
    "build_msvc.bat",
    "requirements-dev.txt",
)
CUSTOMER_FILES = (
    "AUDIT_INVESTOR_READINESS_RU.md",
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "docs/ARCHITECTURE.md",
    "docs/DELIVERY_RU.md",
    "docs/PRODUCT_READINESS.md",
    "docs/evidence_matrix.md",
    "docs/report.schema.json",
    "docs/threshold_calibration.md",
    "docs/windows_dynamic_validation.md",
    "docs/ru/EH_Unwind_Analyzer_Защита_проекта.pdf",
    "docs/ru/EH_Unwind_Analyzer_Паспорт_проекта_для_презентации.pdf",
    "docs/ru/EH_Unwind_Analyzer_Полное_руководство_по_признакам_и_эвристикам.pdf",
    "docs/ru/EH_Unwind_Analyzer_Строгий_учебный_курс.md",
    "docs/ru/EH_Unwind_Analyzer_Строгий_учебный_курс.pdf",
    "docs/ru/преза/EH_Unwind_Analyzer_Техническая_презентация_1.0.0_RU.pptx",
    "docs/ru/преза/EH_Unwind_Analyzer_Техническое_описание_1.0.0_RU.md",
    "docs/ru/преза/EH_Unwind_Analyzer_Техническое_описание_1.0.0_RU.pdf",
    "docs/ru/теория 2/EH_Unwind_Analyzer_Теоретическая_база_с_нуля_RU.pdf",
    "examples/sample_cmds.txt",
    "ghidra/import_unwind_csv.py",
    "release/VERIFIED_WINDOWS_BUILD.json",
)
CUSTOMER_DIRS = (
    "docs/ru",
)
EVIDENCE_SUPPORT_FILES = (
    "release/VERIFIED_WINDOWS_BUILD.json",
    "docs/report.schema.json",
    "requirements-validation.txt",
    "tests/report_semantics.py",
    "tests/run_dynamic_corpus.py",
    "tests/validate_dynamic_corpus_evidence.py",
    "tests/validate_dynamic_reports.py",
)


def product_version() -> str:
    text = (ROOT / "include" / "app_info.h").read_text(encoding="utf-8")
    match = re.search(r'#define\s+EHUA_VERSION\s+"([^"]+)"', text)
    if not match:
        raise RuntimeError("cannot read product version")
    return match.group(1)


def report_schema_version() -> str:
    text = (ROOT / "include" / "app_info.h").read_text(encoding="utf-8")
    match = re.search(r'#define\s+EHUA_REPORT_SCHEMA_VERSION\s+"([^"]+)"', text)
    if not match:
        raise RuntimeError("cannot read report schema version")
    return match.group(1)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def allowed(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name == ".DS_Store" or path.name.startswith("._"):
        return False
    if "__pycache__" in path.parts or ".pytest_cache" in path.parts:
        return False
    excluded_trees = (
        ROOT / "docs" / "ru" / "пэт",
        ROOT / "docs" / "ru" / "beauty_crm_reference_source",
        ROOT / "бинарники на тестирование" / "reports_static_extended",
        ROOT / "бинарники на тестирование" / "reports_showcase_html",
        ROOT / "бинарники на тестирование" / "reports_input_validation",
    )
    if any(tree in path.parents for tree in excluded_trees):
        return False
    if ".backup_" in path.name or path.suffix in {".bak", ".tmp"}:
        return False
    if path.parent == ROOT / "tests" and (
        path.suffix.lower() in {".exe", ".obj", ".o"}
        or path.name.endswith(("_dynamic_report.json", "_dynamic_console.txt"))
    ):
        return False
    return path.suffix not in {".pyc", ".pyo", ".plist"}


def source_files() -> list[Path]:
    files = [ROOT / name for name in SOURCE_FILES]
    for directory in SOURCE_DIRS:
        files.extend((ROOT / directory).rglob("*"))
    return sorted({path for path in files if allowed(path)})


def manifest_path(manifest: dict[str, object], key: str) -> Path:
    value = manifest.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"release manifest is missing {key!r}")
    path = (ROOT / value).resolve()
    if ROOT not in path.parents:
        raise RuntimeError(f"release manifest path escapes project root: {value}")
    return path


def release_status_path(manifest: dict[str, object]) -> Path:
    value = manifest.get("release_status", "release/RELEASE_STATUS_RU.md")
    if not isinstance(value, str) or not value:
        raise RuntimeError("invalid release_status in release manifest")
    path = (ROOT / value).resolve()
    if ROOT not in path.parents:
        raise RuntimeError(f"release status path escapes project root: {value}")
    return path


def evidence_files(manifest: dict[str, object]) -> list[Path]:
    evidence_root = manifest_path(manifest, "source_evidence")
    files = [ROOT / name for name in EVIDENCE_SUPPORT_FILES]
    files.append(release_status_path(manifest))
    if evidence_root.is_dir():
        files.extend(evidence_root.rglob("*"))
    return sorted({path for path in files if allowed(path)})


def customer_files() -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for name in CUSTOMER_FILES:
        path = ROOT / name
        if path.is_file() and allowed(path):
            files.append((path, name))
    for directory in CUSTOMER_DIRS:
        directory_path = ROOT / directory
        if directory_path.is_dir():
            files.extend(
                (path, path.relative_to(ROOT).as_posix())
                for path in directory_path.rglob("*")
                if allowed(path)
            )
    return sorted(set(files), key=lambda item: item[1])


def add_file(archive: zipfile.ZipFile, source: Path, target: str) -> None:
    info = zipfile.ZipInfo(target, ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (source.stat().st_mode & 0xFFFF) << 16
    archive.writestr(info, source.read_bytes(), compresslevel=9)


def write_zip(path: Path, prefix: str, files: list[tuple[Path, str]]) -> None:
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        for source, target in sorted(files, key=lambda item: item[1]):
            if not allowed(source):
                continue
            add_file(archive, source, f"{prefix}/{target}")


def verify_windows_exe(path: Path, manifest: dict[str, object]) -> None:
    if not path.is_file():
        raise RuntimeError(f"validated Windows executable is missing: {path}")
    actual = digest(path)
    expected = str(manifest["sha256"])
    if actual != expected:
        raise RuntimeError(
            f"Windows executable SHA-256 mismatch: {actual} != {expected}"
        )
    version = str(manifest["product_version"]).encode("ascii")
    if version not in path.read_bytes():
        raise RuntimeError("Windows executable does not contain expected version")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create clean EHUA release bundles")
    parser.add_argument("--windows-exe", type=Path, default=WINDOWS_EXE)
    parser.add_argument(
        "--native-package",
        type=Path,
        help="Optional CPack ZIP to copy into release-output and checksum",
    )
    parser.add_argument(
        "--require-windows",
        action="store_true",
        help="Fail unless the current version has a matching verified Windows build",
    )
    args = parser.parse_args()

    version = product_version()
    schema_version = report_schema_version()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    windows_exe = args.windows_exe.resolve()
    windows_verified = (
        manifest.get("product_version") == version
        and manifest.get("report_schema_version") == schema_version
        and windows_exe.is_file()
    )
    if windows_verified:
        verify_windows_exe(windows_exe, manifest)
    elif args.require_windows:
        raise RuntimeError(
            "current version/schema has no matching available verified Windows build: "
            f"application={version}, schema={schema_version}, "
            f"manifest={manifest.get('product_version')}/"
            f"{manifest.get('report_schema_version')}, executable={windows_exe}"
        )

    OUTPUT.mkdir(parents=True, exist_ok=True)
    for old in OUTPUT.glob(f"eh-unwind-analyzer-{version}-*.zip"):
        old.unlink()

    source_name = f"eh-unwind-analyzer-{version}-source"
    windows_name = f"eh-unwind-analyzer-{version}-windows-x64"
    evidence_name = f"eh-unwind-analyzer-{version}-evidence"
    packages = [
        (
            OUTPUT / f"{source_name}.zip",
            source_name,
            [(path, path.relative_to(ROOT).as_posix()) for path in source_files()],
        ),
    ]
    if windows_verified:
        status_path = release_status_path(manifest)
        packages.extend(
            (
                (
                    OUTPUT / f"{windows_name}.zip",
                    windows_name,
                    [(windows_exe, "bin/eh_unwind_analyzer.exe")]
                    + customer_files()
                    + [(status_path, status_path.relative_to(ROOT).as_posix())],
                ),
                (
                    OUTPUT / f"{evidence_name}.zip",
                    evidence_name,
                    [
                        (path, path.relative_to(ROOT).as_posix())
                        for path in evidence_files(manifest)
                    ],
                ),
            )
        )
    else:
        print(
            "Skipping Windows and evidence bundles: "
            f"verified manifest is {manifest.get('product_version')}/"
            f"{manifest.get('report_schema_version')}, "
            f"current application is {version}/{schema_version}; "
            f"Windows executable available: {windows_exe.is_file()}."
        )

    output_packages: list[Path] = []
    for path, prefix, files in packages:
        missing = [source for source, _ in files if not source.is_file()]
        if missing:
            raise RuntimeError(f"package {path.name} has missing files: {missing}")
        write_zip(path, prefix, files)
        output_packages.append(path)
        print(path)

    if args.native_package is not None:
        native_source = args.native_package.resolve()
        if not native_source.is_file() or not zipfile.is_zipfile(native_source):
            raise RuntimeError(f"invalid native CPack ZIP: {native_source}")
        native_output = OUTPUT / native_source.name
        shutil.copy2(native_source, native_output)
        output_packages.append(native_output)
        print(native_output)

    sums = "".join(
        f"{digest(path)}  {path.name}\n" for path in output_packages
    )
    versioned_sums = OUTPUT / f"SHA256SUMS-{version}.txt"
    versioned_sums.write_text(sums, encoding="ascii")
    (OUTPUT / "SHA256SUMS.txt").write_text(sums, encoding="ascii")
    print(versioned_sums)
    print(OUTPUT / "SHA256SUMS.txt")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"release bundle error: {exc}", file=sys.stderr)
        raise SystemExit(2)
