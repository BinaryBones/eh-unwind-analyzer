#!/usr/bin/env python3
from __future__ import annotations
import shutil, struct, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'src'
BIN = ROOT / 'bin'
CLANG = shutil.which('clang') or '/usr/local/swift/usr/bin/clang'
LLD = shutil.which('lld-link') or '/usr/local/swift/usr/bin/lld-link'
MINGW_GCC = (
    shutil.which('x86_64-w64-mingw32-gcc')
    or (shutil.which('gcc') if sys.platform == 'win32' else None)
)
TARGET = 'x86_64-pc-windows-msvc'


def run(cmd):
    subprocess.run(cmd, check=True)


def tool_available(tool: str) -> bool:
    return bool(shutil.which(tool)) or Path(tool).exists()


def build_exe(src_name: str, out_name: str) -> Path:
    c_path = SRC / src_name
    obj = BIN / (Path(src_name).stem + '.obj')
    exe = BIN / out_name
    BIN.mkdir(parents=True, exist_ok=True)
    run([CLANG, '--target=' + TARGET, '-O1', '-c', str(c_path), '-o', str(obj)])
    run([LLD, '/entry:start', '/subsystem:console', '/nodefaultlib', '/out:' + str(exe), str(obj)])
    if obj.exists():
        obj.unlink()
    return exe


def build_exe_gcc(src_name: str, out_name: str) -> Path:
    if not MINGW_GCC:
        raise RuntimeError('MinGW-w64 gcc is not available')
    c_path = SRC / src_name
    exe = BIN / out_name
    BIN.mkdir(parents=True, exist_ok=True)
    # Produce a tiny PE with custom entrypoint similar to clang/lld path.
    run([
        MINGW_GCC,
        '-std=c17',
        '-O1',
        '-ffreestanding',
        '-nostdlib',
        '-Wl,-e,start',
        '-Wl,--subsystem,console',
        str(c_path),
        '-o',
        str(exe),
    ])
    return exe


def find_section_headers(data: bytes):
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    size_opt = struct.unpack_from('<H', data, pe_off + 20)[0]
    sect_off = pe_off + 24 + size_opt
    headers = []
    for i in range(num_sections):
        off = sect_off + i * 40
        name = data[off:off+8].split(b'\x00', 1)[0].decode('ascii', errors='ignore')
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from('<IIII', data, off + 8)
        headers.append((name, vaddr, vsize, raw_ptr, raw_size))
    return headers


def first_runtime_function_unwind_rva(data: bytes) -> int:
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    exc_dir_off = pe_off + 24 + 112 + 3 * 8  # PE32+ data directory[3]
    exc_rva, exc_size = struct.unpack_from('<II', data, exc_dir_off)
    if exc_size < 12:
        raise RuntimeError('Exception directory is unexpectedly small')
    headers = find_section_headers(data)
    rf_raw = rva_to_raw(headers, exc_rva)
    return struct.unpack_from('<I', data, rf_raw + 8)[0]


def section_header_offset_for_rva(data: bytes, rva: int) -> int:
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    size_opt = struct.unpack_from('<H', data, pe_off + 20)[0]
    sect_off = pe_off + 24 + size_opt
    for i in range(num_sections):
        off = sect_off + i * 40
        vsize, vaddr, raw_size, _raw_ptr = struct.unpack_from('<IIII', data, off + 8)
        span = max(vsize, raw_size)
        if vaddr <= rva < vaddr + span:
            return off
    raise RuntimeError(f'RVA 0x{rva:x} is not inside any section')


def rva_to_raw(headers, rva: int) -> int:
    for name, vaddr, vsize, raw_ptr, raw_size in headers:
        span = max(vsize, raw_size)
        if vaddr <= rva < vaddr + span:
            return raw_ptr + (rva - vaddr)
    raise ValueError(f'RVA 0x{rva:x} not mapped')


def patch_first_unwind_rva_to_oob(src_exe: Path, dst_exe: Path, new_rva: int = 0x9000) -> None:
    data = bytearray(src_exe.read_bytes())
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    exc_dir_off = pe_off + 24 + 112 + 3 * 8  # PE32+ data directory[3]
    exc_rva, exc_size = struct.unpack_from('<II', data, exc_dir_off)
    headers = find_section_headers(data)
    rf_raw = rva_to_raw(headers, exc_rva)
    if exc_size < 12:
        raise RuntimeError('Exception directory is unexpectedly small')
    struct.pack_into('<I', data, rf_raw + 8, new_rva)
    dst_exe.write_bytes(data)


def patch_section_characteristics(src_exe: Path, dst_exe: Path, section_name: str, set_bits: int) -> None:
    data = bytearray(src_exe.read_bytes())
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    size_opt = struct.unpack_from('<H', data, pe_off + 20)[0]
    sect_off = pe_off + 24 + size_opt
    target = section_name.encode('ascii')
    for i in range(num_sections):
        off = sect_off + i * 40
        raw_name = data[off:off+8].split(b'\x00', 1)[0]
        if raw_name == target:
            chars = struct.unpack_from('<I', data, off + 36)[0]
            struct.pack_into('<I', data, off + 36, chars | set_bits)
            dst_exe.write_bytes(data)
            return
    raise RuntimeError(f'section {section_name!r} not found in {src_exe.name}')


def patch_section_raw_range(src_exe: Path,
                            dst_exe: Path,
                            section_name: str,
                            raw_ptr: int,
                            raw_size: int) -> None:
    data = bytearray(src_exe.read_bytes())
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
    size_opt = struct.unpack_from('<H', data, pe_off + 20)[0]
    sect_off = pe_off + 24 + size_opt
    target = section_name.encode('ascii')
    for i in range(num_sections):
        off = sect_off + i * 40
        raw_name = data[off:off+8].split(b'\x00', 1)[0]
        if raw_name == target:
            struct.pack_into('<II', data, off + 16, raw_size, raw_ptr)
            dst_exe.write_bytes(data)
            return
    raise RuntimeError(f'section {section_name!r} not found in {src_exe.name}')


def patch_section_for_rva_characteristics(src_exe: Path, dst_exe: Path, rva: int, set_bits: int) -> None:
    data = bytearray(src_exe.read_bytes())
    off = section_header_offset_for_rva(data, rva)
    chars = struct.unpack_from('<I', data, off + 36)[0]
    struct.pack_into('<I', data, off + 36, chars | set_bits)
    dst_exe.write_bytes(data)


def patch_first_unwind_section_writable(src_exe: Path, dst_exe: Path) -> None:
    data = src_exe.read_bytes()
    unwind_rva = first_runtime_function_unwind_rva(data)
    patch_section_for_rva_characteristics(src_exe, dst_exe, unwind_rva, 0x80000000)


def patch_first_unwind_with_fake_handler(src_exe: Path,
                                         dst_exe: Path,
                                         new_unwind_rva: int = 0x2010,
                                         handler_rva: int = 0x2000) -> None:
    data = bytearray(src_exe.read_bytes())
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    exc_dir_off = pe_off + 24 + 112 + 3 * 8  # PE32+ data directory[3]
    exc_rva, exc_size = struct.unpack_from('<II', data, exc_dir_off)
    headers = find_section_headers(data)
    rf_raw = rva_to_raw(headers, exc_rva)
    if exc_size < 12:
        raise RuntimeError('Exception directory is unexpectedly small')

    orig_unwind_rva = struct.unpack_from('<I', data, rf_raw + 8)[0]
    orig_unwind_raw = rva_to_raw(headers, orig_unwind_rva)
    new_unwind_raw = rva_to_raw(headers, new_unwind_rva)

    version = data[orig_unwind_raw] & 0x7
    flags = (data[orig_unwind_raw] >> 3) & 0x1F
    count_codes = data[orig_unwind_raw + 2]
    body_size = 4 + count_codes * 2
    if body_size & 0x3:
        body_size += 2

    blob = bytearray(data[orig_unwind_raw:orig_unwind_raw + body_size])
    blob[0] = (version & 0x7) | (((flags | 0x1) & 0x1F) << 3)
    blob.extend(b'\x00\x00\x00\x00')
    struct.pack_into('<I', blob, body_size, handler_rva)

    data[new_unwind_raw:new_unwind_raw + len(blob)] = blob
    struct.pack_into('<I', data, rf_raw + 8, new_unwind_rva)
    dst_exe.write_bytes(data)


def main() -> int:
    if tool_available(CLANG) and tool_available(LLD):
        minimal = build_exe('benign_minimal.c', 'benign_minimal.exe')
        richer = build_exe('benign_richer.c', 'benign_richer.exe')
    elif MINGW_GCC:
        minimal = build_exe_gcc('benign_minimal.c', 'benign_minimal.exe')
        richer = build_exe_gcc('benign_richer.c', 'benign_richer.exe')
    else:
        minimal = BIN / 'benign_minimal.exe'
        richer = BIN / 'benign_richer.exe'
        if not minimal.exists() or not richer.exists():
            print('clang/lld-link and MinGW-w64 gcc not found, and cached benign samples are missing', file=sys.stderr)
            return 2
        print('Reusing cached benign samples (clang/lld-link/gcc not available).')
    patch_first_unwind_rva_to_oob(richer, BIN / 'suspicious_unwind_oob.exe')
    patch_first_unwind_section_writable(richer, BIN / 'suspicious_unwind_writable.exe')
    patch_section_raw_range(
        richer,
        BIN / 'suspicious_section_raw_oob.exe',
        '.bss',
        raw_ptr=0,
        raw_size=0x2000,
    )
    tamper = BIN / 'suspicious_eh_unwind_tamper.exe'
    patch_first_unwind_with_fake_handler(richer, tamper)
    patch_first_unwind_section_writable(tamper, tamper)
    print(
        'Built:',
        minimal.name,
        richer.name,
        'suspicious_unwind_oob.exe',
        'suspicious_unwind_writable.exe',
        'suspicious_section_raw_oob.exe',
        'suspicious_eh_unwind_tamper.exe',
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
