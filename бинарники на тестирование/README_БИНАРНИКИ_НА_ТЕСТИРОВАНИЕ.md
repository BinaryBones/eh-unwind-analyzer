# Бинарники на тестирование EH/Unwind Analyzer

Всего файлов в матрице: 84.

Назначение корпуса: показать работу проекта по всем слоям: PE layout, Exception Directory, RUNTIME_FUNCTION, UNWIND_INFO, эвристики placement/reuse/dominance, динамические Windows-сигналы и смешанные static+dynamic сценарии.

Важно: это защитный учебно-тестовый корпус. Бинарники предназначены для проверки анализатора и демонстрации контролируемых повреждений EH/unwind metadata. Они не являются вредоносной нагрузкой.

Основные файлы:
- `матрица_покрытия_бинарников.csv` — главная таблица: бинарник, что сломано, что ожидается, какой этап проекта покрывает.
- `manifest_extended.json` — машинно-читаемый манифест корпуса.
- `описания/*.txt` — отдельная подпись к каждому бинарнику простым языком.
- `reports_static_extended/` — отчеты, полученные статическим прогоном анализатора на macOS.

Структура папки `бинарники`:
- `static/` — файлы с контролируемо поврежденной PE/EH/unwind-структурой.
- `dynamic/` — Windows x64 программы для проверки `--dynamic` на Windows.
- `mixed/` — запускаемые dynamic-сэмплы, которым дополнительно испорчены статические EH/unwind metadata.

Команда для статического отчета:
```bash
eh_unwind_analyzer <file.exe> --heuristics --json out.json --html out.html --csv out.csv --ghidra-csv out_ghidra.csv
```

Команда для динамической проверки запускается только на Windows x64:
```powershell
.\eh_unwind_analyzer.exe .\бинарники\dynamic\15_dynamic_veh.exe --heuristics --dynamic --timeout-ms 5000 --json veh.json --html veh.html
```

Краткая карта:

| Бинарник | Категория | Что ожидается | Что сломано |
|---|---|---|---|
| `01_benign_minimal.exe` | static | baseline clean | Нет повреждения; минимальный корректный PE x64. |
| `02_benign_richer.exe` | static | baseline clean | Нет повреждения; чуть более богатый корректный PE x64. |
| `03_static_unwind_oob_parse_fail.exe` | static | unwind_rva_oob + unwind_parse_fail | UnwindInfoRVA указывает за пределы образа. |
| `04_static_invalid_ranges.exe` | static | invalid_ranges | В RUNTIME_FUNCTION EndAddress <= BeginAddress. |
| `05_static_rf_oob.exe` | static | rf_oob | Begin/End выходят за SizeOfImage. |
| `06_static_unsorted_overlap_duplicate.exe` | static | rf_unsorted + rf_overlaps + duplicate_begin | Таблица не отсортирована, диапазоны пересекаются, BeginAddress повторяется. |
| `07_static_unwind_bad_opcode.exe` | static | unwind_anomalies | В UNWIND_CODE внедрен некорректный opcode. |
| `08_static_unwind_bad_operands.exe` | static | unwind_anomalies | Некорректные операнды/поля UNWIND_INFO. |
| `09_static_unwind_unusual_section.exe` | static | unwind_unusual_section | Секция unwind metadata переименована в необычную. |
| `10_static_unwind_exec_handler_nonexec.exe` | static | unwind_in_exec_section + handler_nonexec_section + placement_exec_nonexec_handler_combo | UNWIND_INFO в executable-секции, handler в non-exec. |
| `11_static_unwind_writable_only.exe` | static | unwind_writable_section | Секция UNWIND_INFO сделана writable. |
| `12_static_writable_metadata_handler_writable.exe` | static | unwind_writable_section + handler_writable_section + writable_metadata_handler_combo | Metadata и handler находятся в writable-областях. |
| `13_static_placement_integrity_combo.exe` | static | placement_integrity_combo | Размещение metadata подозрительное и дополнительно поврежден UnwindInfoRVA. |
| `14_static_reuse_dominance_combo.exe` | static | unwind_reuse_strong + handler_dominance + reuse_dominance_combo | Массовое reuse одного UnwindInfoRVA и один доминирующий handler. |
| `15_dynamic_veh.exe` | dynamic | veh_registrations/veh_hits | Программа регистрирует VEH и вызывает исключение. |
| `16_dynamic_vch.exe` | dynamic | vch_registrations/vch_hits | Программа регистрирует VCH/UEF и вызывает исключение. |
| `17_dynamic_uef.exe` | dynamic | uef_set_calls/uef_hits + first/second chance | Программа устанавливает UEF и вызывает исключение. |
| `18_dynamic_rtl_function_table.exe` | dynamic | rtl_add_function_table_calls / rtl_install_function_table_cb_calls | Программа вызывает Rtl*FunctionTable API. |
| `19_mixed_static_unwind_oob_dynamic_rtl.exe` | mixed | unwind_rva_oob + dynamic rtl function table activity | Динамический RTL-сэмпл с поврежденным статическим UnwindInfoRVA. |
| `20_mixed_static_unwind_oob_dynamic_uef.exe` | mixed | unwind_rva_oob + dynamic UEF activity | Динамический UEF-сэмпл с поврежденным статическим UnwindInfoRVA. |
| `21_static_pe_section_raw_oob_bss.exe` | static | pe_section_raw_oob | У .bss искусственно задан raw range за концом файла. |
| `22_static_pe_section_raw_oob_xdata.exe` | static | pe_section_raw_oob | RawSize .xdata сделан больше файла. |
| `23_static_pe_section_virtual_oob_bss.exe` | static | pe_section_virtual_oob | VirtualSize .bss выходит за SizeOfImage. |
| `24_static_pe_section_virtual_oob_xdata.exe` | static | pe_section_virtual_oob | VirtualSize .xdata выходит за SizeOfImage. |
| `25_static_pe_section_raw_overlap_bss_text.exe` | static | pe_section_raw_overlap | Raw range .bss пересекается с .text. |
| `26_static_pe_section_virtual_overlap_bss_xdata.exe` | static | pe_section_virtual_overlap | RVA range .bss пересекается с .xdata. |
| `27_static_pe_section_misaligned_file_alignment.exe` | static | pe_section_misaligned | FileAlignment выставлен в некорректное значение. |
| `28_static_pe_section_misaligned_imagebase.exe` | static | pe_section_misaligned | ImageBase сделан не кратным 64K. |
| `29_static_exception_directory_rva_oob.exe` | static | pe_exception_directory_oob | Exception Directory RVA за пределами SizeOfImage. |
| `30_static_exception_directory_size_not_multiple.exe` | static | pe_exception_directory_oob | Exception Directory size не кратен 12 байтам RUNTIME_FUNCTION. |
| `31_static_exception_directory_size_too_small.exe` | static | pe_exception_directory_oob | Exception Directory size меньше одной записи RUNTIME_FUNCTION. |
| `32_static_exception_directory_rva_zero_size_nonzero.exe` | static | pe_exception_directory_oob | RVA=0 при ненулевом размере Exception Directory. |
| `33_static_no_runtime_functions.exe` | static | no_runtime_functions | Exception Directory обнулена при наличии executable-секции. |
| `34_static_rf_end_equal_begin.exe` | static | invalid_ranges | EndAddress равен BeginAddress. |
| `35_static_rf_end_less_begin.exe` | static | invalid_ranges | EndAddress меньше BeginAddress. |
| `36_static_rf_begin_oob.exe` | static | rf_oob | Begin/End вынесены за SizeOfImage. |
| `37_static_rf_end_oob.exe` | static | rf_oob | EndAddress выходит за SizeOfImage. |
| `38_static_unwind_rva_zero.exe` | static | unwind_rva_oob + unwind_parse_fail | UnwindInfoAddress равен нулю. |
| `39_static_unwind_rva_after_image.exe` | static | unwind_rva_oob + unwind_parse_fail | UnwindInfoAddress выходит за SizeOfImage. |
| `40_static_rf_unsorted_only.exe` | static | rf_unsorted | Записи RUNTIME_FUNCTION переставлены не по BeginAddress без пересечения. |
| `41_static_rf_overlap_only.exe` | static | rf_overlaps | Диапазоны функций пересекаются. |
| `42_static_rf_duplicate_begin.exe` | static | duplicate_begin | Две записи имеют одинаковый BeginAddress. |
| `43_static_unwind_bad_version.exe` | static | unwind_parse_fail | UNWIND_INFO version выставлена в неподдерживаемое значение. |
| `44_static_unwind_truncated_codes.exe` | static | unwind_parse_fail | CountOfCodes завышен, данных не хватает. |
| `45_static_unwind_codeoffset_outside.exe` | static | unwind_anomalies | CodeOffset больше PrologSize. |
| `46_static_unwind_codeoffset_order.exe` | static | unwind_anomalies | CodeOffset идет в неправильном порядке. |
| `47_static_unwind_alloc_large_bad_opinfo.exe` | static | unwind_anomalies | UWOP_ALLOC_LARGE получил недопустимый opinfo. |
| `48_static_unwind_frame_register_without_setfp.exe` | static | unwind_anomalies | FrameRegister задан без UWOP_SET_FPREG. |
| `49_static_unwind_chain_ehandler_conflict.exe` | static | unwind_anomalies | Одновременно выставлены CHAININFO и EHANDLER. |
| `50_static_unwind_chain_loop.exe` | static | unwind_anomalies | CHAININFO указывает сам на себя. |
| `51_static_unwind_handler_oob.exe` | static | unwind_anomalies + handler_nonexec_section | EHANDLER указывает за пределы образа. |
| `52_static_handler_nonexec_only.exe` | static | handler_nonexec_section | EHANDLER указывает в .rdata. |
| `53_static_handler_writable_exec_section.exe` | static | handler_writable_section | EHANDLER указывает в секцию с WRITE+EXECUTE. |
| `54_static_unwind_in_exec_only.exe` | static | unwind_in_exec_section | Секция .xdata помечена executable. |
| `55_static_unwind_plausible_xdata_name_clean.exe` | static | baseline clean / no unusual section | Секция .xdata переименована в myxdata, имя все еще plausibly unwind-named. |
| `56_static_unwind_in_rdata_clean.exe` | static | baseline clean / allowed .rdata placement | Одна UNWIND_INFO скопирована в .rdata, что считается допустимым placement. |
| `57_static_manyfunc_baseline_clean.exe` | static | baseline clean many functions | Большой нормальный PE с сотнями функций. |
| `58_static_unwind_reuse_moderate_correlated.exe` | static | unwind_reuse_moderate + rf_unsorted | Часть функций использует один UnwindInfoRVA, плюс есть контекстный table signal. |
| `59_static_unwind_reuse_strong.exe` | static | unwind_reuse_strong | Большая доля функций использует один UnwindInfoRVA. |
| `60_static_handler_dominance_nonexec.exe` | static | handler_dominance + handler_nonexec_section | Много функций ссылаются на один non-exec handler. |
| `61_static_handler_dominance_contextual.exe` | static | handler_dominance + unwind_rva_oob | Много функций ссылаются на один code handler, плюс добавлен context signal. |
| `62_static_single_weak_unusual_small_sample.exe` | static | negative control / no finding expected | Похожее на xdata имя без реального нарушения. |
| `63_static_high_suspicion_full_combo.exe` | static | high_suspicion_static combo | Смешаны OOB unwind, writable/executable metadata, handler placement и duplicate begin. |
| `64_dynamic_plain_no_signal.exe` | dynamic | no dynamic signal expected | Программа запускается и ничего exception-related не регистрирует. |
| `65_dynamic_timeout_sleep.exe` | dynamic | timed_out expected | Программа засыпает на 60 секунд. |
| `66_dynamic_veh_two_handlers.exe` | dynamic | multiple veh_registrations/veh_hits | Два VEH, первый пропускает, второй обрабатывает исключение. |
| `67_dynamic_veh_register_remove.exe` | dynamic | veh_registration without hit | VEH регистрируется и удаляется без исключения. |
| `68_dynamic_multi_signal.exe` | dynamic | VEH + VCH + UEF + RtlAddFunctionTable registrations | Один сэмпл вызывает несколько dynamic-сигналов. |
| `69_mixed_veh_unwind_writable.exe` | mixed | unwind_writable_section + VEH runtime | VEH-сэмпл с writable .xdata. |
| `70_mixed_veh_unwind_exec.exe` | mixed | unwind_in_exec_section + VEH runtime | VEH-сэмпл с executable .xdata. |
| `71_mixed_vch_unusual_section.exe` | mixed | unwind_unusual_section + VCH runtime | VCH-сэмпл с переименованной .xdata в .meta. |
| `72_mixed_uef_handler_nonexec.exe` | mixed | handler_nonexec_section + UEF runtime | UEF-сэмпл с EHANDLER, указывающим в non-exec область. |
| `73_mixed_rtl_unwind_oob.exe` | mixed | unwind_rva_oob + RtlAddFunctionTable runtime | RTL function table sample с поврежденным UnwindInfoRVA. |
| `74_mixed_rtl_rf_overlap.exe` | mixed | rf_overlaps + RtlAddFunctionTable runtime | RTL sample с пересечением RUNTIME_FUNCTION ranges. |
| `75_mixed_plain_no_static_clean.exe` | mixed | baseline clean dynamic-capable | Обычная dynamic-capable программа без static EH/unwind аномалии. |
| `76_static_diag_count_codes_section_boundary.exe` | static | unwind_parse_fail | UnwindInfoRVA перенесен к концу .xdata: заголовок читается, но CountOfCodes требует два UNWIND_CODE slot, а до границы секции доступен только один. |
| `77_static_diag_uwop_slots_beyond_count.exe` | static | unwind_parse_fail | В первый UNWIND_INFO записан UWOP_ALLOC_LARGE opinfo=1, который занимает три slot-а, но CountOfCodes равен одному. |
| `78_static_diag_chain_loop_path.exe` | static | unwind_anomalies | Две UNWIND_INFO структуры с UNW_FLAG_CHAININFO указывают друг на друга, образуя цикл в chain path. |
| `79_static_unsupported_arm64_machine.exe` | static / входной контроль | machine_amd64 | Поле COFF Machine изменено с AMD64 `0x8664` на ARM64 `0xAA64`. |
| `80_static_input_invalid_mz.exe` | static / входной контроль | dos_magic | Сигнатура DOS-заголовка `MZ` заменена недопустимым значением. |
| `81_static_input_e_lfanew_oob.exe` | static / входной контроль | pe_header_range | `e_lfanew` указывает за пределы файла; зависимые проверки PE-заголовка не выполняются. |
| `82_static_input_invalid_pe_signature.exe` | static / входной контроль | pe_signature | Сигнатура `PE\\0\\0` заменена недопустимым значением при сохранении доступности остальных заголовков. |
| `83_static_input_pe32_magic.exe` | static / входной контроль | optional_magic_pe32_plus | Поле Magic в Optional Header изменено с PE32+ `0x20B` на PE32 `0x10B`. |
| `84_static_input_combined_header_failures.exe` | static / входной контроль | pe_signature; machine_amd64; optional_magic_pe32_plus | Одновременно повреждены сигнатура PE, архитектура Machine и формат Optional Header. |
