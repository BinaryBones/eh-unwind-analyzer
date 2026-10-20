#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import struct
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parents[1]
PACK_ROOT = PROJECT_ROOT / "бинарники на тестирование"
STATIC_BIN = PACK_ROOT / "бинарники" / "static"
DESCRIPTIONS_DIR = PACK_ROOT / "описания"
MATRIX_CSV = PACK_ROOT / "матрица_покрытия_бинарников.csv"
MANIFEST_JSON = PACK_ROOT / "manifest_extended.json"
README_MD = PACK_ROOT / "README_БИНАРНИКИ_НА_ТЕСТИРОВАНИЕ.md"

BASE = STATIC_BIN / "02_benign_richer.exe"


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_pe_layout(data: bytes) -> dict:
    pe_off = u32(data, 0x3C)
    size_opt = u16(data, pe_off + 20)
    opt_off = pe_off + 24
    exc_dir_off = opt_off + 0x70 + 3 * 8
    exc_rva = u32(data, exc_dir_off)
    exc_size = u32(data, exc_dir_off + 4)
    sec_off = opt_off + size_opt
    sections = []
    for i in range(u16(data, pe_off + 6)):
        off = sec_off + i * 40
        name = data[off : off + 8].split(b"\0", 1)[0].decode("ascii", errors="ignore")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append(
            {
                "name": name,
                "vaddr": vaddr,
                "vsize": vsize,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "header_off": off,
            }
        )
    return {
        "exception_directory_offset": exc_dir_off,
        "exception_rva": exc_rva,
        "exception_size": exc_size,
        "sections": sections,
    }


def rva_to_raw(layout: dict, rva: int) -> int:
    for section in layout["sections"]:
        span = max(section["vsize"], section["raw_size"])
        if section["vaddr"] <= rva < section["vaddr"] + span:
            delta = rva - section["vaddr"]
            if delta >= section["raw_size"]:
                raise ValueError(f"RVA 0x{rva:08x} points into virtual tail")
            return section["raw_ptr"] + delta
    raise ValueError(f"RVA 0x{rva:08x} is not mapped")


def section_by_name(layout: dict, name: str) -> dict:
    for section in layout["sections"]:
        if section["name"] == name:
            return section
    raise ValueError(f"section {name!r} not found")


def read_runtime_functions(data: bytes, layout: dict) -> list[dict]:
    out = []
    raw = rva_to_raw(layout, layout["exception_rva"])
    for index in range(layout["exception_size"] // 12):
        off = raw + index * 12
        begin, end, unwind = struct.unpack_from("<III", data, off)
        out.append({"index": index, "off": off, "begin": begin, "end": end, "unwind": unwind})
    return out


def write_rf(data: bytearray, rf: dict) -> None:
    struct.pack_into("<III", data, rf["off"], rf["begin"], rf["end"], rf["unwind"])


def write_unwind_header(data: bytearray, raw: int, *, flags: int, prolog: int, count: int, frame: int) -> None:
    data[raw + 0] = 1 | ((flags & 0x1F) << 3)
    data[raw + 1] = prolog & 0xFF
    data[raw + 2] = count & 0xFF
    data[raw + 3] = frame & 0xFF


def patch_count_codes_section_boundary(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    xdata = section_by_name(layout, ".xdata")
    target_rva = xdata["vaddr"] + xdata["raw_size"] - 6
    target_raw = rva_to_raw(layout, target_rva)

    write_unwind_header(data, target_raw, flags=0, prolog=4, count=2, frame=0)
    data[target_raw + 4] = 4
    data[target_raw + 5] = 0x02  # UWOP_ALLOC_SMALL, only one 2-byte slot is physically available.

    rfs[0]["unwind"] = target_rva
    write_rf(data, rfs[0])


def patch_uwop_slots_beyond_count(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    target_raw = rva_to_raw(layout, rfs[0]["unwind"])

    write_unwind_header(data, target_raw, flags=0, prolog=4, count=1, frame=0)
    data[target_raw + 4] = 4
    data[target_raw + 5] = 0x11  # UWOP_ALLOC_LARGE, opinfo=1: needs two operand slots after the opcode slot.


def patch_chain_loop_path(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    if len(rfs) < 2:
        raise RuntimeError("need at least two runtime functions for a chain loop sample")

    xdata = section_by_name(layout, ".xdata")
    first_rva = xdata["vaddr"] + 0xC0
    second_rva = xdata["vaddr"] + 0xE0
    first_raw = rva_to_raw(layout, first_rva)
    second_raw = rva_to_raw(layout, second_rva)

    write_unwind_header(data, first_raw, flags=0x04, prolog=0, count=0, frame=0)  # UNW_FLAG_CHAININFO
    struct.pack_into("<III", data, first_raw + 4, rfs[1]["begin"], rfs[1]["end"], second_rva)

    write_unwind_header(data, second_raw, flags=0x04, prolog=0, count=0, frame=0)
    struct.pack_into("<III", data, second_raw + 4, rfs[0]["begin"], rfs[0]["end"], first_rva)

    rfs[0]["unwind"] = first_rva
    rfs[1]["unwind"] = second_rva
    write_rf(data, rfs[0])
    write_rf(data, rfs[1])


SAMPLES = [
    {
        "binary": "76_static_diag_count_codes_section_boundary.exe",
        "patcher": patch_count_codes_section_boundary,
        "target_signals": "unwind_parse_fail with diagnostic expected/available bytes",
        "heuristic_family_or_mode": "diagnostic evidence / unwind_integrity",
        "primary_expected_findings": "unwind_parse_fail",
        "what_is_broken": (
            "UnwindInfoRVA перенесен к концу .xdata: заголовок читается, "
            "но CountOfCodes требует два UNWIND_CODE slot, а до границы секции доступен только один."
        ),
        "project_stage_demonstrated": "UNWIND_INFO boundary diagnostics",
        "defense_comment": (
            "Показывает, что отчет называет поле CountOfCodes / UNWIND_CODE array, "
            "file offset, expected/available size и доступные байты."
        ),
    },
    {
        "binary": "77_static_diag_uwop_slots_beyond_count.exe",
        "patcher": patch_uwop_slots_beyond_count,
        "target_signals": "unwind_parse_fail with diagnostic expected/available operand slots",
        "heuristic_family_or_mode": "diagnostic evidence / unwind_integrity",
        "primary_expected_findings": "unwind_parse_fail",
        "what_is_broken": (
            "В первый UNWIND_INFO записан UWOP_ALLOC_LARGE opinfo=1, "
            "который занимает три slot-а, но CountOfCodes равен одному."
        ),
        "project_stage_demonstrated": "UNWIND_CODE operand-slot accounting",
        "defense_comment": (
            "Показывает защиту от ошибки 'один UWOP = один slot': отчет объясняет, "
            "что операция требует больше slots, чем объявлено."
        ),
    },
    {
        "binary": "78_static_diag_chain_loop_path.exe",
        "patcher": patch_chain_loop_path,
        "target_signals": "unwind_anomalies chain loop with chain_path evidence",
        "heuristic_family_or_mode": "diagnostic evidence / unwind chain",
        "primary_expected_findings": "unwind_anomalies",
        "what_is_broken": (
            "Две UNWIND_INFO структуры с UNW_FLAG_CHAININFO указывают друг на друга, "
            "образуя цикл в chain path."
        ),
        "project_stage_demonstrated": "CHAININFO loop diagnostics",
        "defense_comment": (
            "Показывает, что отчет выводит не только факт цикла, но и цепочку UnwindInfoRVA, "
            "по которой анализатор пришел к выводу."
        ),
    },
]


def build_samples() -> None:
    data = BASE.read_bytes()
    for sample in SAMPLES:
        mutated = bytearray(data)
        layout = parse_pe_layout(mutated)
        sample["patcher"](mutated, layout)
        out = STATIC_BIN / sample["binary"]
        out.write_bytes(mutated)


def sample_row(sample: dict) -> dict:
    return {
        "binary": sample["binary"],
        "target_signals": sample["target_signals"],
        "heuristic_family_or_mode": sample["heuristic_family_or_mode"],
        "category": "static",
        "path": f"бинарники/static/{sample['binary']}",
        "primary_expected_findings": sample["primary_expected_findings"],
        "secondary_expected_findings": "",
        "what_is_broken": sample["what_is_broken"],
        "project_stage_demonstrated": sample["project_stage_demonstrated"],
        "defense_comment": sample["defense_comment"],
        "run_mode": "static --heuristics",
        "actual_findings_last_run": "",
        "last_score": "",
        "last_verdict": "",
        "last_exit_code": "",
    }


def update_manifest() -> None:
    manifest = json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))
    rows = manifest["rows"]
    existing = {row["binary"]: row for row in rows}
    for sample in SAMPLES:
        row = sample_row(sample)
        if row["binary"] in existing:
            existing[row["binary"]].update(row)
        else:
            rows.append(row)
    manifest["total_binaries"] = len(rows)
    MANIFEST_JSON.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def update_matrix() -> None:
    with MATRIX_CSV.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    by_name = {row["binary"]: row for row in rows}
    for sample in SAMPLES:
        row = sample_row(sample)
        if row["binary"] in by_name:
            by_name[row["binary"]].update(row)
        else:
            rows.append(row)

    with MATRIX_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def update_readme() -> None:
    text = README_MD.read_text(encoding="utf-8")
    text = text.replace("Всего файлов в матрице: 75.", "Всего файлов в матрице: 78.")
    for sample in SAMPLES:
        row = (
            f"| `{sample['binary']}` | static | {sample['primary_expected_findings']} | "
            f"{sample['what_is_broken']} |"
        )
        if sample["binary"] not in text:
            text = text.rstrip() + "\n" + row + "\n"
    README_MD.write_text(text, encoding="utf-8")


def write_descriptions() -> None:
    DESCRIPTIONS_DIR.mkdir(parents=True, exist_ok=True)
    for sample in SAMPLES:
        number = sample["binary"].split("_", 1)[0]
        path = DESCRIPTIONS_DIR / f"{number}_{sample['binary'][3:-4]}.txt"
        text = f"""{sample['binary']}

Категория: static
Путь: бинарники/static/{sample['binary']}
Режим проверки: static --heuristics

Что специально сделано с бинарником:
{sample['what_is_broken']}

Какой этап проекта демонстрирует:
{sample['project_stage_demonstrated']}

Какие признаки/сигналы ожидались:
{sample['primary_expected_findings']}

Что фактически поймал последний статический прогон:
Будет заполнено после запуска анализатора.

Score / verdict последнего статического прогона:
Будет заполнено после запуска анализатора.

Как объяснять на защите:
{sample['defense_comment']}
"""
        path.write_text(text, encoding="utf-8")


def main() -> int:
    build_samples()
    update_manifest()
    update_matrix()
    update_readme()
    write_descriptions()
    print("[OK] added diagnostic evidence samples 76-78")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
