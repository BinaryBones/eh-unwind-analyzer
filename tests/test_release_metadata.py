#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def require_match(pattern: str, text: str, source: str) -> str:
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    if not match:
        raise AssertionError(f"{source}: pattern not found: {pattern}")
    return match.group(1)


def main() -> int:
    app_info = (ROOT / "include" / "app_info.h").read_text(encoding="utf-8")
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    readiness = (ROOT / "docs" / "PRODUCT_READINESS.md").read_text(
        encoding="utf-8"
    )
    schema = json.loads(
        (ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8")
    )

    product_version = require_match(
        r'#define\s+EHUA_VERSION\s+"([^"]+)"', app_info, "include/app_info.h"
    )
    schema_version = require_match(
        r'#define\s+EHUA_REPORT_SCHEMA_VERSION\s+"([^"]+)"',
        app_info,
        "include/app_info.h",
    )
    cmake_version = require_match(
        r"project\s*\(\s*eh_unwind_analyzer\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
        cmake,
        "CMakeLists.txt",
    )
    package_version = require_match(
        r'set\s*\(\s*CPACK_PACKAGE_VERSION\s+"([^"]+)"',
        cmake,
        "CMakeLists.txt",
    )

    if product_version.split("-", 1)[0] != cmake_version:
        raise AssertionError(
            f"CMake base version {cmake_version} != product {product_version}"
        )
    if package_version != product_version:
        raise AssertionError(
            f"CPack version {package_version} != product {product_version}"
        )

    schema_id = schema.get("$id")
    expected_schema_id = f"urn:ehua:report-schema:{schema_version}"
    if schema_id != expected_schema_id:
        raise AssertionError(f"schema $id {schema_id!r} != {expected_schema_id!r}")
    schema_const = (
        schema.get("$defs", {})
        .get("report_metadata", {})
        .get("properties", {})
        .get("schema_version", {})
        .get("const")
    )
    if schema_const != schema_version:
        raise AssertionError(
            f"schema metadata const {schema_const!r} != {schema_version!r}"
        )

    required_text = {
        "README.md": (readme, f"Current release: **{product_version}**"),
        "CHANGELOG.md": (changelog, f"## {product_version} - "),
        "docs/PRODUCT_READINESS.md": (
            readiness,
            f"The codebase is at `{product_version}`.",
        ),
    }
    for source, (text, marker) in required_text.items():
        if marker not in text:
            raise AssertionError(f"{source}: missing release marker {marker!r}")

    print(
        "test_release_metadata: OK "
        f"(product={product_version}, schema={schema_version})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
