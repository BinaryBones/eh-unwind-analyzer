# Учебник по 27 признакам EH/Unwind Analyzer

Это Markdown-источник PDF. Основной материал находится в PDF, но текстовая версия оставлена для поиска и правок.

## 27 признаков
### 1. pe_section_raw_oob
- Family: `table_integrity`
- Meaning: секция ссылается на байты за пределами файла, поэтому чтение raw data становится недостоверным
- Severity rule: high
- Score weight: +25

### 2. pe_section_virtual_oob
- Family: `table_integrity`
- Meaning: виртуальный диапазон секции выходит за объявленный SizeOfImage
- Severity rule: high
- Score weight: +20

### 3. pe_section_raw_overlap
- Family: `table_integrity`
- Meaning: две секции пересекаются в файле и могут трактовать одни байты по-разному
- Severity rule: medium
- Score weight: +15

### 4. pe_section_virtual_overlap
- Family: `table_integrity`
- Meaning: две секции пересекаются в виртуальной памяти, создавая неоднозначность RVA
- Severity rule: high
- Score weight: +20

### 5. pe_section_misaligned
- Family: `table_integrity`
- Meaning: адреса или размеры секций не согласованы с file/section alignment
- Severity rule: medium
- Score weight: +8

### 6. pe_exception_directory_oob
- Family: `table_integrity`
- Meaning: Exception Directory находится вне допустимого образа или не переводится в валидные байты
- Severity rule: high
- Score weight: +25

### 7. no_runtime_functions
- Family: `table_integrity`
- Meaning: для AMD64 образа не найдено записей RUNTIME_FUNCTION
- Severity rule: medium
- Score weight: +10

### 8. invalid_ranges
- Family: `table_integrity`
- Meaning: в RUNTIME_FUNCTION начало, конец и размер функции образуют невозможный диапазон
- Severity rule: medium` if `<=1%`, else `high
- Score weight: +10 / +20

### 9. rf_oob
- Family: `table_integrity`
- Meaning: диапазон функции выходит за границы валидного image/section context
- Severity rule: medium` if `<=1%`, else `high
- Score weight: +10 / +25

### 10. unwind_rva_oob
- Family: `table_integrity`
- Meaning: адрес UNWIND_INFO не отображается в валидный file offset или секцию
- Severity rule: medium` if `<=1%`, else `high
- Score weight: +10 / +25

### 11. rf_unsorted
- Family: `table_integrity`
- Meaning: таблица функций не отсортирована по BeginAddress
- Severity rule: medium
- Score weight: +15

### 12. rf_overlaps
- Family: `table_integrity`
- Meaning: диапазоны функций пересекаются и создают неоднозначное соответствие адреса функции
- Severity rule: high
- Score weight: +25

### 13. duplicate_begin
- Family: `table_integrity`
- Meaning: несколько записей имеют одинаковое начало функции
- Severity rule: medium
- Score weight: +10

### 14. unwind_parse_fail
- Family: `unwind_integrity`
- Meaning: UNWIND_INFO невозможно разобрать до конца по формату Windows x64
- Severity rule: medium` if `<=1%`, else `high
- Score weight: +10 / +25

### 15. unwind_anomalies
- Family: `unwind_integrity`
- Meaning: UNWIND_INFO читается, но содержит странности в version, opcode, operand, chain или ABI pattern
- Severity rule: medium` if `<=5%`, else `high
- Score weight: +10 / +20

### 16. unwind_reuse_moderate
- Family: `unwind_reuse`
- Meaning: заметная доля функций использует один и тот же UnwindInfoRVA при наличии других сигналов
- Severity rule: medium
- Score weight: +10

### 17. unwind_reuse_strong
- Family: `unwind_reuse`
- Meaning: слишком большая доля функций использует один и тот же UnwindInfoRVA
- Severity rule: high
- Score weight: +20

### 18. handler_dominance
- Family: `handler_dominance`
- Meaning: один handler target обслуживает подозрительно много функций
- Severity rule: medium
- Score weight: +15

### 19. unwind_in_exec_section
- Family: `metadata_placement`
- Meaning: UNWIND_INFO лежит в исполняемой секции, где обычно ожидается код, а не metadata
- Severity rule: high
- Score weight: +20

### 20. unwind_unusual_section
- Family: `metadata_placement`
- Meaning: UNWIND_INFO лежит не в типичной секции .xdata/.rdata/.pdata или близком data-аналоге
- Severity rule: medium` if `<=5%`, else `high
- Score weight: +8 / +15

### 21. unwind_writable_section
- Family: `metadata_placement`
- Meaning: UNWIND_INFO лежит в секции с правом записи
- Severity rule: medium` if `<=5%`, else `high
- Score weight: +10 / +18

### 22. handler_nonexec_section
- Family: `metadata_placement`
- Meaning: handler RVA указывает в неисполняемую или неизвестную секцию
- Severity rule: high
- Score weight: +15

### 23. handler_writable_section
- Family: `metadata_placement`
- Meaning: handler RVA указывает в writable секцию
- Severity rule: medium
- Score weight: +10

### 24. placement_exec_nonexec_handler_combo
- Family: `metadata_placement`
- Meaning: одновременно странно размещены unwind metadata и handler target
- Severity rule: high
- Score weight: +10

### 25. placement_integrity_combo
- Family: `unwind_integrity`
- Meaning: placement anomaly подтверждается повреждением или странностью UNWIND_INFO
- Severity rule: medium
- Score weight: +8

### 26. reuse_dominance_combo
- Family: `unwind_reuse`
- Meaning: массовое повторное использование unwind metadata сочетается с доминированием handler
- Severity rule: medium
- Score weight: +8

### 27. writable_metadata_handler_combo
- Family: `metadata_placement`
- Meaning: и unwind metadata, и handler target связаны с writable context
- Severity rule: high
- Score weight: +10
