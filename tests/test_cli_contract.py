#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "samples" / "bin" / "benign_minimal.exe"


def run(tool: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(tool), *arguments],
        capture_output=True,
        text=True,
        timeout=15,
    )


def expect_code(
    tool: Path,
    expected: int,
    arguments: tuple[str, ...],
    required_text: str | None = None,
) -> None:
    result = run(tool, *arguments)
    if result.returncode != expected:
        raise AssertionError(
            "%r returned %d, expected %d\nstdout:\n%s\nstderr:\n%s"
            % (arguments, result.returncode, expected, result.stdout, result.stderr)
        )
    if required_text and required_text not in result.stdout + result.stderr:
        raise AssertionError("%r did not contain %r" % (arguments, required_text))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the public CLI contract")
    parser.add_argument("tool", type=Path)
    args = parser.parse_args()
    tool = args.tool.resolve()
    if not tool.is_file() or not SAMPLE.is_file():
        print("tool or sample is missing", file=sys.stderr)
        return 2

    expect_code(tool, 0, ("--help",), "--html")
    expect_code(tool, 0, ("--version",), "Report schema: 1.3.0")
    expect_code(tool, 2, tuple(), "Usage:")
    expect_code(tool, 1, ("definitely-missing-file.exe",), "Failed to read file")
    expect_code(tool, 2, (str(SAMPLE), "--unknown"), "Unknown/invalid option")
    expect_code(tool, 2, (str(SAMPLE), "--limit", "-1"), "Invalid value")
    expect_code(tool, 2, (str(SAMPLE), "--max-chain-depth", "17"), "Invalid value")
    expect_code(tool, 2, (str(SAMPLE), "--timeout-ms", "0"), "Invalid value")
    expect_code(tool, 2, (str(SAMPLE), "--trace-steps", "257"), "Invalid value")
    expect_code(tool, 0, (str(SAMPLE), "--strict-abi"), "RUNTIME_FUNCTION entries")

    with tempfile.TemporaryDirectory(prefix="ehua-cli-") as temp:
        temp_path = Path(temp)
        report_path = Path(temp) / "report.json"
        csv_path = Path(temp) / "functions.csv"
        ghidra_path = Path(temp) / "ghidra.csv"
        for output in (report_path, csv_path, ghidra_path):
            output.write_text("pre-existing report", encoding="utf-8")
        secret = "do-not-store-this-secret"
        result = run(
            tool,
            str(SAMPLE),
            "--json",
            str(report_path),
            "--csv",
            str(csv_path),
            "--ghidra-csv",
            str(ghidra_path),
            "--",
            "--password",
            secret,
        )
        if result.returncode != 0:
            raise AssertionError("redaction report run failed: %s" % result.stderr)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        command_line = report["report_metadata"]["command_line"]
        if secret in command_line or "--password" in command_line:
            raise AssertionError("target arguments leaked into report metadata")
        if "[2 target arguments redacted]" not in command_line:
            raise AssertionError("redaction marker is missing")
        if not csv_path.read_text(encoding="utf-8").startswith(
            "index,begin_rva,end_rva"
        ):
            raise AssertionError("normal CSV header is missing")
        if not ghidra_path.read_text(encoding="utf-8").startswith(
            "begin_rva,end_rva,name,comment"
        ):
            raise AssertionError("Ghidra CSV header is missing")
        leftovers = list(Path(temp).glob("*.tmp.*"))
        if leftovers:
            raise AssertionError(f"atomic report temporary files remain: {leftovers}")

        malformed_path = temp_path / "exception-directory-oob.exe"
        malformed_report_path = temp_path / "exception-directory-oob.json"
        malformed = bytearray(SAMPLE.read_bytes())
        pe_offset = struct.unpack_from("<I", malformed, 0x3C)[0]
        optional_header = pe_offset + 4 + 20
        size_of_image = struct.unpack_from("<I", malformed, optional_header + 0x38)[0]
        exception_directory = optional_header + 0x70 + 3 * 8
        struct.pack_into("<I", malformed, exception_directory, size_of_image + 0x1000)
        malformed_path.write_bytes(malformed)
        result = run(
            tool,
            str(malformed_path),
            "--heuristics",
            "--json",
            str(malformed_report_path),
        )
        if result.returncode != 1:
            raise AssertionError(
                "out-of-bounds exception directory returned %d, expected 1\n%s"
                % (result.returncode, result.stderr)
            )
        if not malformed_report_path.is_file():
            raise AssertionError("partial JSON report was not created")
        malformed_report = json.loads(
            malformed_report_path.read_text(encoding="utf-8")
        )
        findings = malformed_report["heuristic_analysis"]["findings"]
        finding_codes = {finding["code"] for finding in findings}
        if "pe_exception_directory_oob" not in finding_codes:
            raise AssertionError("partial report missed pe_exception_directory_oob")
        if "no_runtime_functions" in finding_codes:
            raise AssertionError("unreadable exception directory was treated as absent")

        for filename, invalid_size in (
            ("exception-directory-too-small.exe", 8),
            ("exception-directory-size-remainder.exe", 13),
        ):
            invalid_path = temp_path / filename
            invalid_report_path = temp_path / f"{filename}.json"
            invalid = bytearray(SAMPLE.read_bytes())
            pe_offset = struct.unpack_from("<I", invalid, 0x3C)[0]
            optional_header = pe_offset + 4 + 20
            exception_directory = optional_header + 0x70 + 3 * 8
            exception_rva = struct.unpack_from(
                "<I", invalid, exception_directory
            )[0]
            if exception_rva == 0:
                raise AssertionError("sample has no exception directory")
            struct.pack_into("<I", invalid, exception_directory + 4, invalid_size)
            invalid_path.write_bytes(invalid)
            result = run(
                tool,
                str(invalid_path),
                "--heuristics",
                "--json",
                str(invalid_report_path),
            )
            if result.returncode != 1:
                raise AssertionError(
                    "%s returned %d, expected partial-analysis code 1\n%s"
                    % (filename, result.returncode, result.stderr)
                )
            invalid_report = json.loads(
                invalid_report_path.read_text(encoding="utf-8")
            )
            invalid_codes = {
                finding["code"]
                for finding in invalid_report["heuristic_analysis"]["findings"]
            }
            if "pe_exception_directory_oob" not in invalid_codes:
                raise AssertionError(
                    f"{filename} malformed directory finding was missed"
                )

        for filename, field_offset, invalid_value in (
            ("invalid-file-alignment.exe", 0x24, 1),
            ("invalid-size-of-headers.exe", 0x3C, 1),
        ):
            invalid_path = temp_path / filename
            invalid_report_path = temp_path / f"{filename}.json"
            invalid = bytearray(SAMPLE.read_bytes())
            pe_offset = struct.unpack_from("<I", invalid, 0x3C)[0]
            optional_header = pe_offset + 4 + 20
            struct.pack_into(
                "<I", invalid, optional_header + field_offset, invalid_value
            )
            invalid_path.write_bytes(invalid)
            result = run(
                tool,
                str(invalid_path),
                "--heuristics",
                "--json",
                str(invalid_report_path),
            )
            if result.returncode != 0:
                raise AssertionError(
                    "%s analysis failed unexpectedly:\n%s"
                    % (filename, result.stderr)
                )
            invalid_report = json.loads(
                invalid_report_path.read_text(encoding="utf-8")
            )
            if invalid_report["pe_validation"]["section_misaligned"] < 1:
                raise AssertionError(f"{filename} alignment violation was missed")
            invalid_codes = {
                finding["code"]
                for finding in invalid_report["heuristic_analysis"]["findings"]
            }
            if "pe_section_misaligned" not in invalid_codes:
                raise AssertionError(f"{filename} finding was not emitted")

    print("test_cli_contract: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
