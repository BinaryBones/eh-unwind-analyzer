#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "report.h"
#include "util.h"

static char* slurp(const char* path) {
    FILE* f = fopen(path, "rb");
    assert(f != NULL);
    assert(fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f);
    assert(size >= 0);
    assert(fseek(f, 0, SEEK_SET) == 0);
    char* text = (char*)malloc((size_t)size + 1u);
    assert(text != NULL);
    assert(fread(text, 1, (size_t)size, f) == (size_t)size);
    assert(fclose(f) == 0);
    text[size] = '\0';
    return text;
}

int main(void) {
    PeSection sections[2];
    memset(sections, 0, sizeof(sections));
    memcpy(sections[0].name, ".text", 5);
    sections[0].virtual_address = 0x1000;
    sections[0].virtual_size = 0x1000;
    sections[0].raw_ptr = 0x200;
    sections[0].raw_size = 0x1000;
    sections[0].characteristics = 0x60000020u;
    const unsigned char raw_section_name[] = { '.', 'x', 0xf6u };
    memcpy(sections[1].name, raw_section_name, sizeof(raw_section_name));
    sections[1].virtual_address = 0x2000;
    sections[1].virtual_size = 0x1000;
    sections[1].raw_ptr = 0x1200;
    sections[1].raw_size = 0x1000;
    sections[1].characteristics = 0x40000040u;

    PeImage image;
    memset(&image, 0, sizeof(image));
    image.ok = true;
    image.is_pe64 = true;
    image.machine = IMAGE_FILE_MACHINE_AMD64;
    image.image_base = 0x140000000ull;
    image.size_of_image = 0x4000;
    image.size_of_headers = 0x200;
    image.section_alignment = 0x1000;
    image.file_alignment = 0x200;
    image.exception_rva = 0x2000;
    image.exception_size = 12;
    image.num_sections = 2;
    image.sections = sections;

    RuntimeFunction functions[1] = {
        { .begin_rva = 0x1100, .end_rva = 0x1140, .unwind_rva = 0x2000 }
    };
    UnwindSummary unwind[1];
    memset(unwind, 0, sizeof(unwind));
    unwind[0].version = 1;
    unwind[0].prolog_size = 5;
    unwind[0].count_codes = 1;
    unwind[0].frame_reg = 3;
    unwind[0].frame_off = 2;
    unwind[0].pushed_nonvol_count = 1;
    unwind[0].saved_nonvol_mask = (uint16_t)(1u << 3);
    unwind[0].has_handler = true;
    unwind[0].handler_rva = 0x1120;
    unwind[0].fixed_stack_bytes = 32;
    unwind[0].anomalies = UA_BAD_OPERAND;
    snprintf(unwind[0].parse_error, sizeof(unwind[0].parse_error),
             "%s", "bad <operand> & \"value\"");
    snprintf(unwind[0].diagnostic_field, sizeof(unwind[0].diagnostic_field),
             "%s", "exception handler RVA tail");
    unwind[0].diagnostic_has_file_offset = true;
    unwind[0].diagnostic_file_offset = 0x1208;
    unwind[0].diagnostic_has_size = true;
    unwind[0].diagnostic_expected_size = 4;
    unwind[0].diagnostic_available_size = 1;
    unwind[0].diagnostic_has_bytes = true;
    unwind[0].diagnostic_bytes_file_offset = 0x1208;
    unwind[0].diagnostic_bytes[0] = 0xaa;
    unwind[0].diagnostic_bytes_count = 1;
    bool unwind_ok[1] = { false };

    HeuristicReport heuristic;
    memset(&heuristic, 0, sizeof(heuristic));
    heuristic.score = 100;
    heuristic.score_weight_sum = 118;
    heuristic.suspicion = 1.0;
    heuristic.confidence = 0.82;
    heuristic.requires_manual_review = true;
    snprintf(heuristic.verdict, sizeof(heuristic.verdict), "%s", "high_suspicion");
    snprintf(heuristic.evidence_level, sizeof(heuristic.evidence_level), "%s", "strong");
    heuristic.total = 1;
    heuristic.rf_invalid_ranges = 2;
    heuristic.unwind_parse_fail = 1;
    heuristic.unwind_anomalies = 1;
    heuristic.handler_count = 3;
    heuristic.handler_reuse_ratio = 0.75;
    heuristic.unwind_reuse_ratio = 0.25;
    heuristic.unwind_unique_ratio = 0.50;
    heuristic.strong_finding_count = 1;
    heuristic.evidence_families_mask = HEF_UNWIND_INTEGRITY | HEF_METADATA_PLACEMENT;
    heuristic.finding_count = 1;
    snprintf(heuristic.findings[0].severity, sizeof(heuristic.findings[0].severity),
             "%s", "high");
    snprintf(heuristic.findings[0].code, sizeof(heuristic.findings[0].code),
             "%s", "unsafe_text_test");
    snprintf(heuristic.findings[0].family, sizeof(heuristic.findings[0].family),
             "%s", "unwind_integrity");
    snprintf(heuristic.findings[0].message, sizeof(heuristic.findings[0].message),
             "%s", "<script>alert('report')</script>");
    heuristic.findings[0].affected_count = 1;
    heuristic.findings[0].has_location = true;
    heuristic.findings[0].representative_rva = 0x1100;
    assert(sb_init(&heuristic.details, 128));
    assert(sb_append(&heuristic.details, "detail <unsafe> & checked"));

    DynamicReport dynamic;
    memset(&dynamic, 0, sizeof(dynamic));
    dynamic.enabled = true;
    dynamic.ran = true;
    dynamic.ok = false;
    dynamic.timed_out = true;
    dynamic.target_exited = false;
    dynamic.instrumentation_complete = false;
    dynamic.modules_observed_peak = 7;
    dynamic.module_refresh_failures = 1;
    dynamic.module_list_truncations = 1;
    dynamic.breakpoint_set_attempts = 8;
    dynamic.breakpoint_set_failures = 1;
    dynamic.breakpoint_capacity_drops = 1;
    dynamic.pending_rearm_failures = 1;
    dynamic.breakpoint_rearm_failures = 1;
    dynamic.trace_steps = 3;
    dynamic.runtime_image_base = image.image_base;
    dynamic.unwind_handlers_discovered = 2;
    dynamic.unwind_handler_bp_set = 2;
    dynamic.exceptions_seen = 1;
    dynamic.first_chance_seen = 1;
    dynamic.uef_set_calls = 1;
    dynamic.uef_hits = 1;
    dynamic.event_count = 2;
    dynamic.trace_count = 3;
    dynamic.trace[0] = 0x140001120ull;
    dynamic.trace[1] = 0x140001121ull;
    dynamic.trace[2] = 0x140001128ull;
    snprintf(dynamic.events[0].type, sizeof(dynamic.events[0].type), "%s", "exception");
    snprintf(dynamic.events[0].module, sizeof(dynamic.events[0].module),
             "%s", "module<&>.dll");
    dynamic.events[0].address = 0x140001100ull;
    snprintf(dynamic.events[1].type, sizeof(dynamic.events[1].type), "%s", "timeout");
    dynamic.events[1].arg0 = 5000;
    assert(sb_init(&dynamic.details, 128));
    assert(sb_append(&dynamic.details, "runtime <detail>"));

    ReportMetadata metadata = {
        .tool_version = "1.0.0-test",
        .report_schema_version = "1.3.0",
        .generated_at_utc = "2026-06-07T12:00:00Z",
        .input_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .input_size = 4096,
        .command_line = "tool sample.exe -- [2 target arguments redacted]",
        .build_compiler = "test compiler",
        .build_platform = "test platform",
        .build_mode = "debug",
        .strict_abi = true,
        .follow_chain = true,
        .max_chain_depth = 8,
    };

    StrBuf err;
    assert(sb_init(&err, 256));
    const char* path = "unit_report_test_output.html";
    bool report_ok = report_write_html(path, "sample<&>.exe", &image, functions, unwind,
                                       unwind_ok, 1, &heuristic, &dynamic, &metadata, &err);
    if (!report_ok) fprintf(stderr, "%s", err.s ? err.s : "report generation failed\n");
    assert(report_ok);

    char* html = slurp(path);
    assert(strstr(html, "<!doctype html>") != NULL);
    assert(strstr(html, "Content-Security-Policy") != NULL);
    assert(strstr(html, "text-align:left;text-wrap:pretty;hyphens:none") != NULL);
    assert(strstr(html, "justify-content:space-between") != NULL);
    assert(strstr(html, "width:100%;max-width:none") != NULL);
    assert(strstr(html, "th+th,td+td{border-left") != NULL);
    assert(strstr(html, "class=\"dynamic-evidence\"") != NULL);
    assert(strstr(html, "class=\"runtime-table\"") != NULL);
    assert(strstr(html, ".runtime-table{width:100%;min-width:100%;table-layout:fixed}") != NULL);
    assert(strstr(html, ".evidence-table{width:100%;min-width:100%;table-layout:fixed}") != NULL);
    assert(strstr(html, "<table class=\"diagnostics-table\">") != NULL);
    assert(strstr(html, ".diagnostics-table{width:100%;min-width:100%;table-layout:fixed}") != NULL);
    assert(strstr(html, ".diagnostic-field>span{display:block;color:var(--muted);font-size:12px;margin-bottom:2px}") != NULL);
    assert(strstr(html, ".diagnostic-field code{display:inline-block;max-width:100%;white-space:nowrap}") != NULL);
    assert(strstr(html, ".diagnostics-table .code-wrap{white-space:normal;overflow-wrap:anywhere;word-break:break-word}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table{width:100%;min-width:100%;table-layout:fixed}") != NULL);
    assert(strstr(html, "<table class=\"heuristic-matrix-table\">") != NULL);
    assert(strstr(html, "overflow-x:hidden") == NULL);
    assert(strstr(html, ".code-wrap{white-space:normal;overflow-wrap:normal;word-break:normal}") != NULL);
    assert(strstr(html, ".finding-detail>summary>code{max-width:100%;white-space:normal;overflow-wrap:anywhere;word-break:break-word}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table .finding-link{display:block;min-width:0}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table .finding-link code{display:block;white-space:normal;overflow-wrap:anywhere;word-break:break-word}") != NULL);
    assert(strstr(html, "list-style-position:inside") != NULL);
    assert(strstr(html, "@media(min-width:701px){.table-wrap{overflow-x:clip}}") != NULL);
    assert(strstr(html, "for(const wrap of document.querySelectorAll('.table-wrap'))wrap.scrollLeft=0;") != NULL);
    assert(strstr(html, "<colgroup><col style=\"width:4%\"><col style=\"width:20%\"><col style=\"width:16%\">") != NULL);
    assert(strstr(html, "<col style=\"width:8%\"><col style=\"width:7%\"><col style=\"width:12%\">") != NULL);
    assert(strstr(html, ".heuristic-matrix-table thead th{height:58px;padding:10px 12px;text-align:left;vertical-align:middle;line-height:1.25;hyphens:none}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table th:first-child{text-align:left;white-space:nowrap}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table td:first-child{text-align:center;white-space:nowrap}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table th:nth-child(5){white-space:nowrap;text-align:left}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table td:nth-child(5){white-space:nowrap;text-align:left}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table thead th.matrix-status-head{text-align:left;padding-left:12px;padding-right:8px}") != NULL);
    assert(strstr(html, ".heuristic-matrix-table td:nth-child(6){overflow-wrap:anywhere;word-break:break-word}") != NULL);
    assert(strstr(html, ".runtime-table .code-wrap{display:block;margin-top:4px;white-space:normal;overflow-wrap:anywhere;word-break:break-word}") != NULL);
    assert(strstr(html, "<colgroup><col style=\"width:4%\"><col style=\"width:14%\"><col style=\"width:11%\">") != NULL);
    assert(strstr(html, ".register-cell .register-row{grid-template-columns:132px") != NULL);
    assert(strstr(html, "PUSH_NONVOL</span><span class=\"register-value\"><code>") != NULL);
    assert(strstr(html, "Flags</span><span class=\"register-value\"><code>") != NULL);
    assert(strstr(html, "Stack</span><span class=\"register-value\"><code>") != NULL);
    assert(strstr(html, "failed_field=<code class=\"code-wrap\">") != NULL);
    assert(strstr(html, "default-src 'none'") != NULL);
    assert(strstr(html, "http://") == NULL);
    assert(strstr(html, "https://") == NULL);
    assert(strstr(html, "Статическая оценка") != NULL);
    assert(strstr(html, "Итоговый вывод") != NULL);
    assert(strstr(html, "Статика / динамика") != NULL);
    assert(strstr(html, "Динамические сигналы") != NULL);
    assert(strstr(html, "Уверенность итоговой оценки") != NULL);
    assert(strstr(html, "Runtime evidence динамического слоя") != NULL);
    assert(strstr(html, "RIP trace после handler hit") != NULL);
    assert(strstr(html, "Запрошенный бюджет trace") != NULL);
    assert(strstr(html, "Записано RIP-адресов") != NULL);
    assert(strstr(html, "Runtime ImageBase") != NULL);
    assert(strstr(html, "0x140001120") != NULL);
    assert(strstr(html, "0x00001120") != NULL);
    assert(strstr(html, ".text") != NULL);
    assert(strstr(html, "Сводка участков RIP trace") != NULL);
    assert(strstr(html, "Детальная таблица RIP trace") != NULL);
    assert(strstr(html, "Старт трассировки после handler hit") != NULL);
    assert(strstr(html, "Линейное продвижение в том же участке: RIP +0x1") != NULL);
    assert(strstr(html, "Линейное продвижение в том же участке: RIP +0x7") != NULL);
    assert(strstr(html, "Статус: исполняемая область основного модуля") != NULL);
    assert(strstr(html, "Аналитическая интерпретация") != NULL);
    assert(strstr(html, "тайм-аут динамической сессии") != NULL);
    assert(strstr(html, "Динамическая сессия достигла лимита --timeout-ms") != NULL);
    assert(strstr(html, "Тайм-аут: да") != NULL);
    assert(strstr(html, "Таблица RUNTIME_FUNCTION") != NULL);
    assert(strstr(html, "Ключевые структурные диагностики") != NULL);
    assert(strstr(html, "<th>UnwindInfo RVA</th><th>Размещение метаданных</th>") != NULL);
    assert(strstr(html, "<span>Индекс записи</span>") != NULL);
    assert(strstr(html, "<span>Begin RVA</span>") != NULL);
    assert(strstr(html, "<span>End RVA</span>") != NULL);
    assert(strstr(html, "RUNTIME_FUNCTION[0]") != NULL);
    assert(strstr(html, "failed_field=<code class=\"code-wrap\">exception handler RVA tail</code>") != NULL);
    assert(strstr(html, "expected_size=4; available_size=1") != NULL);
    assert(strstr(html, "UNWIND_INFO не прошел структурный разбор") != NULL);
    assert(strstr(html, "Prolog / CountOfCodes") != NULL);
    assert(strstr(html, "Stack, frame и сохранённые регистры") != NULL);
    assert(strstr(html, "Сохранённые GPR") != NULL);
    assert(strstr(html, "Сохранённые XMM") != NULL);
    assert(strstr(html, "Handler и CHAININFO") != NULL);
    assert(strstr(html, "SizeOfProlog") != NULL);
    assert(strstr(html, "CountOfCodes") != NULL);
    assert(strstr(html, ">5 B</code></span>") != NULL);
    assert(strstr(html, "Полная контрольная карта статического анализа") != NULL);
    assert(strstr(html, "Матрица покрытия 27 эвристических признаков") != NULL);
    assert(strstr(html, "Код признака") != NULL);
    assert(strstr(html, "<th class=\"matrix-status-head\">Нарушение</th>") != NULL);
    assert(strstr(html, ">да</b>") != NULL);
    assert(strstr(html, ">нет</b>") != NULL);
    assert(strstr(html, ">не выполнены</b>") != NULL);
    assert(strstr(html, "целостность таблиц") != NULL);
    assert(strstr(html, "размещение метаданных") != NULL);
    const char* matrix_codes[] = {
        "pe_section_raw_oob",
        "pe_section_virtual_oob",
        "pe_section_raw_overlap",
        "pe_section_virtual_overlap",
        "pe_section_misaligned",
        "pe_exception_directory_oob",
        "no_runtime_functions",
        "invalid_ranges",
        "rf_oob",
        "unwind_rva_oob",
        "rf_unsorted",
        "rf_overlaps",
        "duplicate_begin",
        "unwind_parse_fail",
        "unwind_anomalies",
        "unwind_reuse_strong",
        "unwind_reuse_moderate",
        "handler_dominance",
        "unwind_in_exec_section",
        "unwind_unusual_section",
        "unwind_writable_section",
        "handler_nonexec_section",
        "handler_writable_section",
        "placement_exec_nonexec_handler_combo",
        "placement_integrity_combo",
        "reuse_dominance_combo",
        "writable_metadata_handler_combo"
    };
    for (size_t i = 0; i < sizeof(matrix_codes) / sizeof(matrix_codes[0]); i++) {
        assert(strstr(html, matrix_codes[i]) != NULL);
    }
    assert(strstr(html, "Section raw OOB") != NULL);
    assert(strstr(html, "RUNTIME_FUNCTION total") != NULL);
    assert(strstr(html, "Unwind reuse ratio") != NULL);
    assert(strstr(html, "handler_reuse_ratio") == NULL);
    assert(strstr(html, "metadata_placement") != NULL);
    assert(strstr(html, "Результаты статического анализа") != NULL);
    assert(strstr(html, "Доказательные карточки") != NULL);
    assert(strstr(html, "Краткий журнал findings") == NULL);
    assert(strstr(html, "Базовый вес") != NULL);
    assert(strstr(html, "Сумма базовых весов: 118") != NULL);
    assert(strstr(html, "min(118, 100) = <b>100</b>") != NULL);
    assert(strstr(html, "Вклад в score") == NULL);
    assert(strstr(html, "Число нарушений: 1") != NULL);
    assert(strstr(html, "1 нарушений") == NULL);
    assert(strstr(html, "Динамическая проверка") != NULL);
    assert(strstr(html, "Эвристические признаки") != NULL);
    assert(strstr(html, "Инструментация завершена") != NULL);
    assert(strstr(html, "Точки останова обработчиков") != NULL);
    assert(strstr(html, "Состояние breakpoint") != NULL);
    assert(strstr(html, "Попытки установки") != NULL);
    assert(strstr(html, "Покрытие модулей") != NULL);
    assert(strstr(html, "Сводная оценка") != NULL);
    assert(strstr(html, "Сводная экспертная оценка") == NULL);
    assert(strstr(html, "Методика расчёта.") == NULL);
    assert(strstr(html, "а не вероятность вредоносности") == NULL);
    assert(strstr(html, "не подтверждает отсутствие ненаблюдавшихся событий") == NULL);
    assert(strstr(html, "Программа ручной верификации") != NULL);
    assert(strstr(html, "строгая проверка ABI x64: да") != NULL);
    assert(strstr(html, "Показать полную команду") != NULL);
    assert(strstr(html, "высокая статическая подозрительность") != NULL);
    assert(strstr(html, "sample&lt;&amp;&gt;.exe") != NULL);
    assert(strstr(html, "&lt;script&gt;alert(&#39;report&#39;)&lt;/script&gt;") != NULL);
    assert(strstr(html, "<script>alert('report')</script>") == NULL);
    assert(strstr(html, "<b>Аналитическая формулировка</b>: Эвристический признак") != NULL);
    assert(strstr(html, "<b>Техническое основание</b>: Код finding-а не сопоставлен") != NULL);
    assert(strstr(html, "<b>Проверяемый инвариант</b>: Эвристическое правило определяется кодом найденного признака.") != NULL);
    assert(strstr(html, "<b>Рекомендуемая ручная верификация</b>:") != NULL);
    assert(strstr(html, "Эксперт") == NULL);
    assert(strstr(html, "эксперт") == NULL);
    assert(strstr(html, "<b>Доказательная трассировка</b>:") != NULL);
    assert(strstr(html, "RUNTIME_FUNCTION[0]") != NULL);
    assert(strstr(html, "Диагностические данные") != NULL);
    assert(strstr(html, "failed_field=<code class=\"code-wrap\">exception handler RVA tail</code>") != NULL);
    assert(strstr(html, "expected_size=4; available_size=1") != NULL);
    assert(strstr(html, "bytes@<code>0x00001208</code>=<code class=\"code-wrap\">aa</code>") != NULL);
    assert(strstr(html, "representative RVA: 0x00001100") != NULL);
    assert(strstr(html, "file offset: 0x00000300") != NULL);
    assert(strstr(html, "координаты функции: index=0") != NULL);
    assert(strstr(html, "<b>Аналитическое значение</b>: Признак влияет на доверие к PE/unwind-анализу") != NULL);
    assert(strstr(html, "module&lt;&amp;&gt;.dll") != NULL);
    assert(strstr(html, ".x&#xf6;") != NULL);
    assert(strstr(html, "[2 target arguments redacted]") != NULL);
    assert(strstr(html, "function-filter") != NULL);
    assert(strstr(html, "hashchange") != NULL);
    assert(strstr(html, "target.open=true") != NULL);
    assert(strstr(html, "Параметры события") != NULL);
    assert(strstr(html, "LimitMs=5000") != NULL);
    assert(strstr(html, "Уверенность итоговой оценки") != NULL);
    assert(strstr(html, "Динамические сигналы (категории)") != NULL);

    free(html);
    if (!getenv("EHUA_KEEP_TEST_REPORTS")) assert(remove(path) == 0);

    const char* static_only_path = "unit_report_static_only.html";
    assert(report_write_html(static_only_path, "sample-static.exe", &image, functions, unwind,
                             unwind_ok, 1, &heuristic, NULL, &metadata, &err));
    char* static_only_html = slurp(static_only_path);
    assert(strstr(static_only_html, "Статическая оценка") != NULL);
    assert(strstr(static_only_html, "Итоговый вывод") != NULL);
    assert(strstr(static_only_html, "Статика / динамика") != NULL);
    assert(strstr(static_only_html, "Динамическая проверка") != NULL);
    assert(strstr(static_only_html, "не запрашивалась") != NULL);
    assert(strstr(static_only_html, "Runtime evidence динамического слоя") == NULL);
    free(static_only_html);
    assert(remove(static_only_path) == 0);

    const char* dynamic_only_path = "unit_report_dynamic_only.html";
    assert(report_write_html(dynamic_only_path, "sample-dynamic.exe", &image, functions, unwind,
                             unwind_ok, 1, NULL, &dynamic, &metadata, &err));
    char* dynamic_only_html = slurp(dynamic_only_path);
    assert(strstr(dynamic_only_html, "Эвристические признаки") != NULL);
    assert(strstr(dynamic_only_html, "Статическая оценка") != NULL);
    assert(strstr(dynamic_only_html, "не запускалась") != NULL);
    assert(strstr(dynamic_only_html, "Итоговый вывод") != NULL);
    assert(strstr(dynamic_only_html, "Статика / динамика") != NULL);
    assert(strstr(dynamic_only_html, "Динамические сигналы") != NULL);
    assert(strstr(dynamic_only_html, "Runtime evidence динамического слоя") != NULL);
    assert(strstr(dynamic_only_html, "RIP trace после handler hit") != NULL);
    free(dynamic_only_html);
    assert(remove(dynamic_only_path) == 0);

    sb_free(&err);
    sb_free(&dynamic.details);
    sb_free(&heuristic.details);
    puts("unit_report_html: OK");
    return 0;
}
