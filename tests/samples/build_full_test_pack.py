#!/usr/bin/env python3
from __future__ import annotations

import csv
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Callable


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

THIS_DIR = Path(__file__).resolve().parent
SRC_DIR = THIS_DIR / "src"
PROJECT_ROOT = THIS_DIR.parents[1]
PACK_ROOT = PROJECT_ROOT / "бинарники на тестирование"
BIN_ROOT = PACK_ROOT / "бинарники"
STATIC_BIN = BIN_ROOT / "static"
DYNAMIC_BIN = BIN_ROOT / "dynamic"
MATRIX_CSV = PACK_ROOT / "матрица_покрытия_бинарников.csv"

CLANG = shutil.which("clang") or "/usr/local/swift/usr/bin/clang"
LLD = shutil.which("lld-link") or "/usr/local/swift/usr/bin/lld-link"
GCC = shutil.which("gcc")
TARGET = "x86_64-pc-windows-msvc"


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def tool_available(tool: str) -> bool:
    return bool(shutil.which(tool)) or Path(tool).exists()


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_pe_layout(data: bytes) -> dict:
    pe_off = u32(data, 0x3C)
    num_sections = u16(data, pe_off + 6)
    size_opt = u16(data, pe_off + 20)
    opt_off = pe_off + 24
    size_image = u32(data, opt_off + 0x38)
    exc_rva = u32(data, opt_off + 0x70 + 3 * 8)
    exc_size = u32(data, opt_off + 0x70 + 3 * 8 + 4)
    sec_off = opt_off + size_opt
    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name_raw = data[off : off + 8]
        name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        chars = u32(data, off + 36)
        sections.append(
            {
                "name": name,
                "vaddr": vaddr,
                "vsize": vsize,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "chars": chars,
                "header_off": off,
            }
        )
    return {
        "pe_off": pe_off,
        "size_image": size_image,
        "exception_rva": exc_rva,
        "exception_size": exc_size,
        "sections": sections,
    }


def rva_to_raw(layout: dict, rva: int) -> int:
    for s in layout["sections"]:
        span = max(s["vsize"], s["raw_size"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            return s["raw_ptr"] + (rva - s["vaddr"])
    raise ValueError(f"RVA 0x{rva:08x} is not mapped to raw data")


def section_for_rva(layout: dict, rva: int) -> dict:
    for s in layout["sections"]:
        span = max(s["vsize"], s["raw_size"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            return s
    raise ValueError(f"No section found for RVA 0x{rva:08x}")


def set_section_bits(data: bytearray, sec: dict, bits: int) -> None:
    off = sec["header_off"] + 36
    current = u32(data, off)
    struct.pack_into("<I", data, off, current | bits)
    sec["chars"] = current | bits


def set_section_name(data: bytearray, sec: dict, new_name: str) -> None:
    raw = new_name.encode("ascii", errors="ignore")[:8]
    raw = raw + b"\x00" * (8 - len(raw))
    data[sec["header_off"] : sec["header_off"] + 8] = raw
    sec["name"] = new_name


def read_runtime_functions(data: bytes, layout: dict) -> list[dict]:
    exc_rva = layout["exception_rva"]
    exc_size = layout["exception_size"]
    if exc_rva == 0 or exc_size < 12:
        raise RuntimeError("exception directory is empty or too small")
    exc_raw = rva_to_raw(layout, exc_rva)
    n = exc_size // 12
    out = []
    for i in range(n):
        off = exc_raw + i * 12
        b, e, u = struct.unpack_from("<III", data, off)
        out.append({"index": i, "off": off, "begin": b, "end": e, "unwind": u})
    return out


def write_rf_entry(data: bytearray, rf: dict) -> None:
    struct.pack_into("<III", data, rf["off"], rf["begin"], rf["end"], rf["unwind"])


def first_unwind_meta(data: bytes, layout: dict) -> dict:
    rf = read_runtime_functions(data, layout)
    if not rf:
        raise RuntimeError("no runtime functions")
    unwind_rva = rf[0]["unwind"]
    off = rva_to_raw(layout, unwind_rva)
    if off + 4 > len(data):
        raise RuntimeError("unwind header out of file")
    version = data[off] & 0x7
    flags = data[off] >> 3
    count = data[off + 2]
    slots_even = (count + 1) & ~1
    after_codes = off + 4 + slots_even * 2
    return {
        "unwind_rva": unwind_rva,
        "off": off,
        "version": version,
        "flags": flags,
        "count": count,
        "after_codes": after_codes,
    }


def set_ehandler(data: bytearray, layout: dict, unwind_rva: int, handler_rva: int) -> None:
    off = rva_to_raw(layout, unwind_rva)
    version = data[off] & 0x7
    count = data[off + 2]
    slots_even = (count + 1) & ~1
    after_codes = off + 4 + slots_even * 2
    if after_codes + 4 > len(data):
        raise RuntimeError("cannot write handler tail: out of bounds")
    data[off] = (version & 0x7) | (0x01 << 3)  # UNW_FLAG_EHANDLER
    struct.pack_into("<I", data, after_codes, handler_rva)


def choose_nonexec_section(layout: dict, exclude_name: str | None = None, prefer_writable: bool = False) -> dict:
    sections = layout["sections"]
    pool = []
    for s in sections:
        if exclude_name and s["name"] == exclude_name:
            continue
        if s["chars"] & IMAGE_SCN_MEM_EXECUTE:
            continue
        pool.append(s)
    if not pool:
        raise RuntimeError("no non-executable section available")
    if prefer_writable:
        for s in pool:
            if s["chars"] & IMAGE_SCN_MEM_WRITE:
                return s
    return pool[0]


def patch_unwind_oob(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    rfs[0]["unwind"] = layout["size_image"] + 0x100
    write_rf_entry(data, rfs[0])


def patch_invalid_ranges(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    rfs[0]["end"] = rfs[0]["begin"]
    write_rf_entry(data, rfs[0])


def patch_rf_oob(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    rfs[0]["begin"] = layout["size_image"] + 0x100
    rfs[0]["end"] = layout["size_image"] + 0x180
    write_rf_entry(data, rfs[0])


def patch_unsorted_overlap_duplicate(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    if len(rfs) < 3:
        raise RuntimeError("need at least 3 RUNTIME_FUNCTION entries")
    rfs[0]["begin"], rfs[0]["end"] = 0x2200, 0x2600
    rfs[1]["begin"], rfs[1]["end"] = 0x2200, 0x2500
    rfs[2]["begin"], rfs[2]["end"] = 0x2100, 0x2300
    for i in range(3):
        write_rf_entry(data, rfs[i])


def patch_unwind_bad_opcode(data: bytearray, layout: dict) -> None:
    meta = first_unwind_meta(data, layout)
    off = meta["off"]
    data[off + 1] = 1  # prolog
    data[off + 2] = 1  # count_codes
    data[off + 4] = 0  # code offset
    data[off + 5] = 0x0F  # invalid opcode 15


def patch_unwind_bad_operands(data: bytearray, layout: dict) -> None:
    meta = first_unwind_meta(data, layout)
    off = meta["off"]
    data[off + 3] = 0x10  # frame_reg=0, frame_off=1 => BAD_OPERAND


def patch_unusual_section(data: bytearray, layout: dict) -> None:
    meta = first_unwind_meta(data, layout)
    sec = section_for_rva(layout, meta["unwind_rva"])
    set_section_name(data, sec, ".meta")


def patch_exec_handler_nonexec(data: bytearray, layout: dict) -> None:
    meta = first_unwind_meta(data, layout)
    unwind_sec = section_for_rva(layout, meta["unwind_rva"])
    handler_sec = choose_nonexec_section(layout, exclude_name=unwind_sec["name"], prefer_writable=False)
    set_ehandler(data, layout, meta["unwind_rva"], handler_sec["vaddr"])
    set_section_bits(data, unwind_sec, IMAGE_SCN_MEM_EXECUTE)


def patch_writable_only(data: bytearray, layout: dict) -> None:
    meta = first_unwind_meta(data, layout)
    unwind_sec = section_for_rva(layout, meta["unwind_rva"])
    set_section_bits(data, unwind_sec, IMAGE_SCN_MEM_WRITE)


def patch_writable_metadata_handler_writable(data: bytearray, layout: dict) -> None:
    meta = first_unwind_meta(data, layout)
    unwind_sec = section_for_rva(layout, meta["unwind_rva"])
    handler_sec = choose_nonexec_section(layout, prefer_writable=True)
    set_ehandler(data, layout, meta["unwind_rva"], handler_sec["vaddr"])
    set_section_bits(data, unwind_sec, IMAGE_SCN_MEM_WRITE)


def patch_placement_integrity_combo(data: bytearray, layout: dict) -> None:
    patch_exec_handler_nonexec(data, layout)
    rfs = read_runtime_functions(data, layout)
    idx = 1 if len(rfs) > 1 else 0
    rfs[idx]["unwind"] = layout["size_image"] + 0x200
    write_rf_entry(data, rfs[idx])


def patch_reuse_dominance_combo(data: bytearray, layout: dict) -> None:
    rfs = read_runtime_functions(data, layout)
    if len(rfs) < 220:
        raise RuntimeError(f"need >=220 runtime functions, got {len(rfs)}")
    common_unwind = rfs[0]["unwind"]
    handler_rva = rfs[0]["begin"]
    set_ehandler(data, layout, common_unwind, handler_rva)
    for rf in rfs:
        rf["unwind"] = common_unwind
        write_rf_entry(data, rf)


def save_variant(src_path: Path, dst_path: Path, patcher: Callable[[bytearray, dict], None]) -> None:
    data = bytearray(src_path.read_bytes())
    layout = parse_pe_layout(data)
    patcher(data, layout)
    dst_path.write_bytes(data)


def compile_static(src: Path, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    if tool_available(CLANG) and tool_available(LLD):
        obj = out.with_suffix(".obj")
        run([CLANG, "--target=" + TARGET, "-O1", "-c", str(src), "-o", str(obj)])
        run([LLD, "/entry:start", "/subsystem:console", "/nodefaultlib", "/out:" + str(out), str(obj)])
        if obj.exists():
            obj.unlink()
        return
    if GCC:
        run(
            [
                GCC,
                "-std=c17",
                "-O1",
                "-ffreestanding",
                "-nostdlib",
                "-Wl,-e,start",
                "-Wl,--subsystem,console",
                str(src),
                "-o",
                str(out),
            ]
        )
        return
    raise RuntimeError("Neither clang/lld-link nor gcc available")


def compile_dynamic(src: Path, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    if not GCC:
        raise RuntimeError("gcc is required to build dynamic test binaries")
    cmd = [
        GCC,
        "-std=c17",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-DWIN32_LEAN_AND_MEAN",
        str(src),
        "-o",
        str(out),
    ]
    # ntdll symbols may be needed for some MinGW setups.
    if src.name == "dyn_rtl_ftable.c":
        cmd.append("-lntdll")
    run(cmd)


def generate_manyfunc_source(path: Path, count: int = 260) -> None:
    lines = []
    lines.append("volatile unsigned long long g_sink;")
    lines.append("#if defined(__GNUC__)")
    lines.append("#define NOINLINE __attribute__((noinline))")
    lines.append("#else")
    lines.append("#define NOINLINE __declspec(noinline)")
    lines.append("#endif")
    lines.append("")
    for i in range(count):
        lines.append(
            f"NOINLINE unsigned long long f{i}(unsigned long long x) {{ "
            f"unsigned long long a[4]; a[0] = x + {i + 1}ULL; g_sink ^= a[0]; return a[0]; }}"
        )
    lines.append("")
    lines.append("void start(void) {")
    lines.append("    unsigned long long v = 1ULL;")
    for i in range(count):
        lines.append(f"    v = f{i}(v);")
    lines.append("    g_sink = v;")
    lines.append("    for (;;) { }")
    lines.append("}")
    path.write_text("\n".join(lines), encoding="utf-8")


def ensure_dirs() -> None:
    STATIC_BIN.mkdir(parents=True, exist_ok=True)
    DYNAMIC_BIN.mkdir(parents=True, exist_ok=True)


def build_pack() -> None:
    ensure_dirs()

    base_min = STATIC_BIN / "01_benign_minimal.exe"
    base_rich = STATIC_BIN / "02_benign_richer.exe"
    base_many_tmp = STATIC_BIN / "_tmp_manyfunc_base.exe"
    base_many_final = STATIC_BIN / "14_static_reuse_dominance_combo.exe"

    compile_static(SRC_DIR / "benign_minimal.c", base_min)
    compile_static(SRC_DIR / "benign_richer.c", base_rich)

    tmp_many = STATIC_BIN / "_tmp_manyfunc.c"
    generate_manyfunc_source(tmp_many, 260)
    compile_static(tmp_many, base_many_tmp)
    if tmp_many.exists():
        tmp_many.unlink()

    save_variant(base_rich, STATIC_BIN / "03_static_unwind_oob_parse_fail.exe", patch_unwind_oob)
    save_variant(base_rich, STATIC_BIN / "04_static_invalid_ranges.exe", patch_invalid_ranges)
    save_variant(base_rich, STATIC_BIN / "05_static_rf_oob.exe", patch_rf_oob)
    save_variant(base_rich, STATIC_BIN / "06_static_unsorted_overlap_duplicate.exe", patch_unsorted_overlap_duplicate)
    save_variant(base_rich, STATIC_BIN / "07_static_unwind_bad_opcode.exe", patch_unwind_bad_opcode)
    save_variant(base_rich, STATIC_BIN / "08_static_unwind_bad_operands.exe", patch_unwind_bad_operands)
    save_variant(base_rich, STATIC_BIN / "09_static_unwind_unusual_section.exe", patch_unusual_section)
    save_variant(base_rich, STATIC_BIN / "10_static_unwind_exec_handler_nonexec.exe", patch_exec_handler_nonexec)
    save_variant(base_rich, STATIC_BIN / "11_static_unwind_writable_only.exe", patch_writable_only)
    save_variant(base_rich, STATIC_BIN / "12_static_writable_metadata_handler_writable.exe", patch_writable_metadata_handler_writable)
    save_variant(base_rich, STATIC_BIN / "13_static_placement_integrity_combo.exe", patch_placement_integrity_combo)
    save_variant(base_many_tmp, base_many_final, patch_reuse_dominance_combo)
    if base_many_tmp.exists():
        base_many_tmp.unlink()

    compile_dynamic(SRC_DIR / "dyn_veh.c", DYNAMIC_BIN / "15_dynamic_veh.exe")
    compile_dynamic(SRC_DIR / "dyn_vch.c", DYNAMIC_BIN / "16_dynamic_vch.exe")
    compile_dynamic(SRC_DIR / "dyn_uef.c", DYNAMIC_BIN / "17_dynamic_uef.exe")
    compile_dynamic(SRC_DIR / "dyn_rtl_ftable.c", DYNAMIC_BIN / "18_dynamic_rtl_function_table.exe")


def write_matrix() -> None:
    rows = [
        ("01_benign_minimal.exe", "baseline clean", "no findings, score=0"),
        ("02_benign_richer.exe", "baseline clean", "no findings, score=0"),
        ("03_static_unwind_oob_parse_fail.exe", "unwind_rva_oob + unwind_parse_fail", "table_integrity + unwind_integrity"),
        ("04_static_invalid_ranges.exe", "invalid_ranges", "table_integrity"),
        ("05_static_rf_oob.exe", "rf_oob", "table_integrity"),
        ("06_static_unsorted_overlap_duplicate.exe", "rf_unsorted + rf_overlaps + duplicate_begin", "table_integrity"),
        ("07_static_unwind_bad_opcode.exe", "unwind_anomalies (bad opcode)", "unwind_integrity"),
        ("08_static_unwind_bad_operands.exe", "unwind_anomalies (bad operand)", "unwind_integrity"),
        ("09_static_unwind_unusual_section.exe", "unwind_unusual_section", "metadata_placement"),
        ("10_static_unwind_exec_handler_nonexec.exe", "unwind_in_exec_section + handler_nonexec_section + combo", "metadata_placement"),
        ("11_static_unwind_writable_only.exe", "unwind_writable_section", "metadata_placement"),
        ("12_static_writable_metadata_handler_writable.exe", "unwind_writable_section + handler_writable_section + combo", "metadata_placement"),
        ("13_static_placement_integrity_combo.exe", "placement_integrity_combo", "unwind_integrity + metadata_placement"),
        ("14_static_reuse_dominance_combo.exe", "unwind_reuse_* + handler_dominance + reuse_dominance_combo", "unwind_reuse + handler_dominance"),
        ("15_dynamic_veh.exe", "veh_registrations/veh_hits", "dynamic"),
        ("16_dynamic_vch.exe", "vch_registrations/vch_hits", "dynamic"),
        ("17_dynamic_uef.exe", "uef_set_calls/uef_hits + first/second chance", "dynamic"),
        ("18_dynamic_rtl_function_table.exe", "rtl_add_function_table_calls / rtl_install_function_table_cb_calls", "dynamic"),
    ]
    with MATRIX_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["binary", "target_signals", "heuristic_family_or_mode"])
        w.writerows(rows)


def main() -> int:
    try:
        build_pack()
        write_matrix()
    except Exception as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        return 1
    print("[OK] full test pack generated")
    print(f"[OK] static binaries: {STATIC_BIN}")
    print(f"[OK] dynamic binaries: {DYNAMIC_BIN}")
    print(f"[OK] coverage matrix: {MATRIX_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
