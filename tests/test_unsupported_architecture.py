#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import hashlib
import json
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BASE_SAMPLE = ROOT / "tests" / "samples" / "bin" / "benign_minimal.exe"
EXPECTED_ERROR = "Unsupported Machine: 0xaa64 (only x64/AMD64 supported)."


def generate(source: Path, output: Path) -> int:
    original = source.read_bytes()
    data = bytearray(original)
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise AssertionError("baseline sample is not a DOS/PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    machine_offset = pe_offset + 4
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise AssertionError("baseline sample has no PE signature")
    if struct.unpack_from("<H", data, machine_offset)[0] != 0x8664:
        raise AssertionError("baseline sample is not AMD64")
    struct.pack_into("<H", data, machine_offset, 0xAA64)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return machine_offset


def run_check(
    tool: Path,
    sample: Path,
    html_path: Path | None = None,
    json_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [str(tool), str(sample), "--heuristics"]
    if html_path:
        command.extend(("--html", str(html_path)))
    if json_path:
        command.extend(("--json", str(json_path)))
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=15,
    )
    combined = result.stdout + result.stderr
    if result.returncode != 1:
        raise AssertionError(f"exit={result.returncode}, expected 1\n{combined}")
    if EXPECTED_ERROR not in combined:
        raise AssertionError(f"expected architecture diagnostic is absent\n{combined}")
    for forbidden in ("RUNTIME_FUNCTION entries:", "Heuristic score:", "Verdict:"):
        if forbidden in combined:
            raise AssertionError(
                f"analysis continued after the fatal architecture check: {forbidden!r}"
            )
    if html_path:
        report_html = html_path.read_text(encoding="utf-8")
        if "machine_amd64" not in report_html:
            raise AssertionError("product HTML misses machine_amd64")
    if json_path:
        report_json = json.loads(json_path.read_text(encoding="utf-8"))
        failed = {
            check["code"]
            for check in report_json["input_validation"]["checks"]
            if check["status"] == "failed"
        }
        if failed != {"machine_amd64"}:
            raise AssertionError(f"unexpected failed checks: {failed}")
    return result


def write_html_report(
    output: Path,
    tool: Path,
    sample: Path,
    machine_offset: int,
    result: subprocess.CompletedProcess[str],
) -> None:
    data = sample.read_bytes()
    observed_machine = struct.unpack_from("<H", data, machine_offset)[0]
    digest = hashlib.sha256(data).hexdigest()
    diagnostic = (result.stderr or result.stdout).strip()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    document = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Результат контроля архитектуры PE-образа</title>
<style>
:root{{--ink:#162536;--muted:#5c7082;--line:#cbd9df;--panel:#fff;--bg:#edf4f6;--accent:#087d82;--danger:#b42335}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}}
main{{max-width:1180px;margin:32px auto;padding:0 24px}} h1{{font-size:32px;margin:0 0 8px}} h2{{font-size:21px;margin:0 0 14px}} p{{margin:8px 0}}
.subtitle{{color:var(--muted);margin-bottom:24px}} .panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin:16px 0;box-shadow:0 4px 14px rgba(22,37,54,.05)}}
.status{{display:inline-block;color:var(--danger);border:1px solid var(--danger);border-radius:999px;padding:4px 11px;font-weight:700}}
.grid{{display:grid;grid-template-columns:minmax(190px,30%) 1fr;border:1px solid var(--line);border-radius:10px;overflow:hidden}} .grid div{{padding:11px 14px;border-bottom:1px solid var(--line)}} .grid div:nth-child(odd){{font-weight:700;background:#e7f0f3}} .grid div:nth-last-child(-n+2){{border-bottom:0}}
code,pre{{font-family:"SFMono-Regular",Consolas,monospace}} code{{background:#e8f4f4;color:#00656a;padding:2px 5px;border-radius:5px}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#102332;color:#edf7f8;padding:16px;border-radius:10px}}
.chain{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}} .step{{padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#f7fafb}} .arrow{{color:var(--accent);font-weight:700}} footer{{color:var(--muted);padding:10px 2px 30px}}
@media(max-width:700px){{.grid{{grid-template-columns:1fr}}.grid div:nth-child(odd){{border-bottom:0}}}}
</style></head><body><main>
<h1>Результат контроля архитектуры PE-образа</h1>
<section class="panel"><span class="status">Неподдерживаемая архитектура</span>
<p>Распознан PE-контейнер. В поле <code>Machine</code> зарегистрировано значение <code>0xAA64</code> (ARM64), не соответствующее поддерживаемой архитектуре <code>0x8664</code> (AMD64). Дальнейшая обработка входного файла прекращена.</p></section>
<section class="panel"><h2>Параметры проверки</h2><div class="grid">
<div>Тестовый файл</div><div>{html.escape(sample.name)}</div>
<div>Размер файла</div><div>{len(data)} байт</div>
<div>SHA-256</div><div><code>{digest}</code></div>
<div>Поле COFF Machine</div><div><code>0x{observed_machine:04x}</code> (ARM64)</div>
<div>Смещение поля в файле</div><div><code>0x{machine_offset:x}</code></div>
<div>Поддерживаемое значение</div><div><code>0x8664</code> (AMD64)</div>
<div>Код завершения</div><div><code>{result.returncode}</code> (фатальная ошибка входного формата)</div>
<div>Время формирования</div><div>{generated}</div></div></section>
<section class="panel"><h2>Последовательность контроля</h2><div class="chain">
<span class="step">Buf: файл загружен</span><span class="arrow">→</span>
<span class="step">MZ и PE-сигнатура подтверждены</span><span class="arrow">→</span>
<span class="step">Machine = 0xAA64</span><span class="arrow">→</span>
<span class="step">Входная проверка завершена с кодом 1</span></div></section>
<section class="panel"><h2>Диагностика анализатора</h2><pre>{html.escape(diagnostic)}</pre></section>
<section class="panel"><h2>Результат входного контроля</h2>
<p><b>Критерий допуска:</b> значение поля <code>Machine</code> равно <code>IMAGE_FILE_MACHINE_AMD64 (0x8664)</code>.</p>
<p><b>Зарегистрированное значение:</b> <code>IMAGE_FILE_MACHINE_ARM64 (0xAA64)</code>.</p>
<p><b>Статус обработки:</b> входной файл отклонён на этапе проверки архитектуры; код завершения процесса - <code>1</code>.</p></section>
<footer>EH/Unwind Analyzer</footer></main></body></html>"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Test rejection of unsupported PE architectures")
    parser.add_argument("tool", type=Path)
    parser.add_argument("--sample", type=Path)
    parser.add_argument("--html", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    tool = args.tool.resolve()
    if not tool.is_file() or not BASE_SAMPLE.is_file():
        raise SystemExit("tool or baseline sample is missing")

    if args.sample:
        sample = args.sample.resolve()
        generate(BASE_SAMPLE, sample)
        run_check(
            tool,
            sample,
            args.html.resolve() if args.html else None,
            args.json.resolve() if args.json else None,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="ehua-unsupported-arch-") as temp:
            sample = Path(temp) / "unsupported-arm64-machine.exe"
            generate(BASE_SAMPLE, sample)
            run_check(tool, sample)

    print("unsupported ARM64 Machine rejection: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
