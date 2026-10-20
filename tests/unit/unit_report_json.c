#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "report.h"
#include "heuristics.h"
#include "dynamic.h"
#include "util.h"

static void setup_sections(PeImage* img, PeSection* secs, size_t n) {
    memset(img, 0, sizeof(*img));
    img->ok = true;
    img->is_pe64 = true;
    img->machine = IMAGE_FILE_MACHINE_AMD64;
    img->image_base = 0x140000000ull;
    img->size_of_image = 0x5000;
    img->exception_rva = 0x2000;
    img->exception_size = 0x60;
    img->num_sections = n;
    img->sections = secs;
}

static char* slurp(const char* path) {
    FILE* f = fopen(path, "rb");
    assert(f != NULL);
    assert(fseek(f, 0, SEEK_END) == 0);
    long sz = ftell(f);
    assert(sz >= 0);
    assert(fseek(f, 0, SEEK_SET) == 0);
    char* buf = (char*)malloc((size_t)sz + 1);
    assert(buf != NULL);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    assert(rd == (size_t)sz);
    fclose(f);
    buf[sz] = 0;
    return buf;
}

int main(void) {
    const ReportMetadata metadata = {
        .tool_version = "1.0.0-test",
        .report_schema_version = "1.3.0",
        .generated_at_utc = "2026-06-07T12:00:00Z",
        .input_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .input_size = 4096,
        .command_line = "tool sample.exe --heuristics",
        .build_compiler = "test compiler",
        .build_platform = "test platform",
        .build_mode = "debug",
        .strict_abi = true,
        .follow_chain = true,
        .max_chain_depth = 8,
    };

    PeSection secs[2];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x1000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x1000;
    secs[0].characteristics = 0x60000020u;

    const unsigned char raw_section_name[] = { '.', 'x', 0xf6u };
    memcpy(secs[1].name, raw_section_name, sizeof(raw_section_name));
    secs[1].virtual_address = 0x2000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x1200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 2);

    RuntimeFunction rf[1];
    memset(rf, 0, sizeof(rf));
    rf[0].begin_rva = 0x1100;
    rf[0].end_rva = 0x1120;
    rf[0].unwind_rva = 0x2000;

    UnwindSummary us[1];
    memset(us, 0, sizeof(us));
    us[0].valid = true;
    us[0].version = 1;
    us[0].prolog_size = 4;
    us[0].count_codes = 1;
    us[0].fixed_stack_bytes = 32;
    us[0].has_handler = true;
    us[0].handler_rva = 0x1100;
    snprintf(us[0].parse_error, sizeof(us[0].parse_error), "%s", "synthetic parse error");
    snprintf(us[0].diagnostic_field, sizeof(us[0].diagnostic_field), "%s",
             "CountOfCodes / UWOP operand slots");
    us[0].diagnostic_has_file_offset = true;
    us[0].diagnostic_file_offset = 0x1204;
    us[0].diagnostic_has_size = true;
    us[0].diagnostic_expected_size = 6;
    us[0].diagnostic_available_size = 2;
    us[0].diagnostic_has_slots = true;
    us[0].diagnostic_expected_slots = 3;
    us[0].diagnostic_available_slots = 1;
    us[0].diagnostic_has_bytes = true;
    us[0].diagnostic_bytes_file_offset = 0x1204;
    us[0].diagnostic_bytes[0] = 0x04;
    us[0].diagnostic_bytes[1] = 0x11;
    us[0].diagnostic_bytes_count = 2;
    us[0].chain_path[0] = 0x2000;
    us[0].chain_path[1] = 0x2040;
    us[0].chain_path_count = 2;

    bool us_ok[1] = { true };

    HeuristicReport pr;
    memset(&pr, 0, sizeof(pr));
    pr.score = 55;
    pr.score_weight_sum = 55;
    pr.suspicion = 0.55;
    pr.confidence = 0.71;
    pr.requires_manual_review = true;
    pr.evidence_families_mask = HEF_TABLE_INTEGRITY | HEF_METADATA_PLACEMENT;
    snprintf(pr.verdict, sizeof(pr.verdict), "%s", "moderate_suspicion");
    pr.total = 10;
    snprintf(pr.evidence_level, sizeof(pr.evidence_level), "%s", "medium");
    pr.weak_finding_count = 0;
    pr.medium_finding_count = 0;
    pr.strong_finding_count = 1;
    pr.mitigation_count = 1;
    snprintf(pr.mitigations[0].code, sizeof(pr.mitigations[0].code), "%s", "single_family_only");
    snprintf(pr.mitigations[0].message, sizeof(pr.mitigations[0].message), "%s", "Cross-layer corroboration is recommended.");
    pr.rf_duplicate_begins = 3;
    pr.unwind_unusual_section = 4;
    pr.unwind_exec_section = 5;
    pr.unwind_writable_section = 2;
    pr.unwind_abi_warnings = 7;
    pr.handler_nonexec_section = 6;
    pr.handler_writable_section = 1;
    pr.handler_count = 12;
    pr.handler_reuse_ratio = 0.75;
    pr.finding_count = 1;
    snprintf(pr.findings[0].code, sizeof(pr.findings[0].code), "%s", "unwind_in_exec_section");
    snprintf(pr.findings[0].family, sizeof(pr.findings[0].family), "%s", "metadata_placement");
    snprintf(pr.findings[0].severity, sizeof(pr.findings[0].severity), "%s", "high");
    snprintf(pr.findings[0].message, sizeof(pr.findings[0].message), "%s", "UnwindInfo in executable section");
    pr.findings[0].has_location = true;
    pr.findings[0].representative_rva = 0x1100;
    pr.findings[0].affected_count = 5;
    assert(sb_init(&pr.details, 128));
    sb_append(&pr.details, "- test detail\nUTF8=");
    sb_append(&pr.details, "\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82");

    DynamicReport dr;
    memset(&dr, 0, sizeof(dr));
    dr.enabled = true;
    dr.ran = true;
    dr.ok = true;
    dr.target_exited = true;
    dr.instrumentation_complete = true;
    dr.modules_observed_peak = 12;
    dr.unwind_handlers_discovered = 3;
    dr.breakpoint_set_attempts = 8;
    dr.target_exit_code = 7;
    dr.timeout_ms = 1000;
    dr.trace_steps = 8;
    dr.exceptions_seen = 9;
    dr.first_chance_seen = 7;
    dr.second_chance_seen = 2;
    dr.event_count = 1;
    snprintf(dr.events[0].type, sizeof(dr.events[0].type), "%s", "exception");
    snprintf(dr.events[0].module, sizeof(dr.events[0].module), "%s", "sample.exe");
    dr.events[0].thread_id = 42;
    dr.events[0].exception_code = 0xe0000001u;
    dr.events[0].first_chance = true;
    dr.events[0].address = 0x140001100ull;
    assert(sb_init(&dr.details, 128));
    sb_append(&dr.details, "dynamic detail\n");

    StrBuf err;
    assert(sb_init(&err, 256));
    const char* output_path = "unit_report_test_output.json";
    assert(!report_write_json_ex(output_path, "sample.exe", &img, rf, us, us_ok,
                                 1, &pr, &dr, NULL, &err));
    assert(report_write_json_ex(output_path, "sample.exe", &img, rf, us, us_ok,
                                1, &pr, &dr, &metadata, &err));

    char* json = slurp(output_path);
    assert(strstr(json, "\"report_metadata\":{") != NULL);
    assert(strstr(json, "\"schema_version\":\"1.3.0\"") != NULL);
    assert(strstr(json, "\"strict_abi\":true") != NULL);
    assert(strstr(json, "\"follow_chain\":true") != NULL);
    assert(strstr(json, "\"max_chain_depth\":8") != NULL);
    assert(strstr(json, "\"heuristic_analysis\":{") != NULL);
    assert(strstr(json, "\"score_weight_sum\":55") != NULL);
    assert(strstr(json, "\"dynamic_validation\":{") != NULL);
    assert(strstr(json, "\"rf_duplicate_begins\":3") != NULL);
    assert(strstr(json, "\"unwind_unusual_section\":4") != NULL);
    assert(strstr(json, "\"unwind_exec_section\":5") != NULL);
    assert(strstr(json, "\"unwind_writable_section\":2") != NULL);
    assert(strstr(json, "\"unwind_abi_warnings\":7") != NULL);
    assert(strstr(json, "\"handler_nonexec_section\":6") != NULL);
    assert(strstr(json, "\"handler_writable_section\":1") != NULL);
    assert(strstr(json, "\"handler_count\":12") != NULL);
    assert(strstr(json, "\"first_chance_seen\":7") != NULL);
    assert(strstr(json, "\"second_chance_seen\":2") != NULL);
    assert(strstr(json, "\"target_exited\":true") != NULL);
    assert(strstr(json, "\"target_exit_code\":7") != NULL);
    assert(strstr(json, "\"instrumentation_complete\":true") != NULL);
    assert(strstr(json, "\"modules_observed_peak\":12") != NULL);
    assert(strstr(json, "\"unwind_handlers_discovered\":3") != NULL);
    assert(strstr(json, "\"breakpoint_set_attempts\":8") != NULL);
    assert(strstr(json, "\"events\":[{\"type\":\"exception\"") != NULL);
    assert(strstr(json, "\"thread_id\":42") != NULL);
    assert(strstr(json, "\"unwind_error\":\"synthetic parse error\"") != NULL);
    assert(strstr(json, "\"evidence_families\":[\"table_integrity\",\"metadata_placement\"]") != NULL);
    assert(strstr(json, "\"affected_count\":5") != NULL);
    assert(strstr(json, "\"representative_rva\":\"0x00001100\"") != NULL);
    assert(strstr(json, "\"representative_section\":\".text\"") != NULL);
    assert(strstr(json, "\"representative_file_offset\":\"0x00000300\"") != NULL);
    assert(strstr(json, "\"representative_section_characteristics\":\"0x60000020\"") != NULL);
    assert(strstr(json, "\"representative_section_permissions\":\"R-X\"") != NULL);
    assert(strstr(json, "\"related_function_index\":0") != NULL);
    assert(strstr(json, "\"related_function_begin_rva\":\"0x00001100\"") != NULL);
    assert(strstr(json, "\"related_function_end_rva\":\"0x00001120\"") != NULL);
    assert(strstr(json, "\"related_function_unwind_rva\":\"0x00002000\"") != NULL);
    assert(strstr(json, "\"rule\":\"UNWIND_INFO не должна размещаться") != NULL);
    assert(strstr(json, "\"observed\":\"Число зафиксированных нарушений: 5; representative RVA: 0x00001100;") != NULL);
    assert(strstr(json, "\"expected\":\"UNWIND_INFO должна лежать") != NULL);
    assert(strstr(json, "\"impact\":\"Нетипичное placement metadata") != NULL);
    assert(strstr(json, "\"title_ru\":\"UNWIND_INFO размещена в исполняемой секции\"") != NULL);
    assert(strstr(json, "\"meaning_ru\":\"Данные x64 unwind находятся в секции с правом исполнения") != NULL);
    assert(strstr(json, "\"what_to_check_next_ru\":\"Сопоставить RVA, file offset, характеристики секции") != NULL);
    assert(strstr(json, "\"evidence_chain\":{") != NULL);
    assert(strstr(json, "\"runtime_function_index\":0") != NULL);
    assert(strstr(json, "\"unwind_file_offset\":\"0x00001200\"") != NULL);
    assert(strstr(json, "\"failed_field\":\"CountOfCodes / UWOP operand slots\"") != NULL);
    assert(strstr(json, "\"diagnostic\":{") != NULL);
    assert(strstr(json, "\"expected_size\":6") != NULL);
    assert(strstr(json, "\"available_size\":2") != NULL);
    assert(strstr(json, "\"expected_slots\":3") != NULL);
    assert(strstr(json, "\"available_slots\":1") != NULL);
    assert(strstr(json, "\"bytes_hex\":\"04 11\"") != NULL);
    assert(strstr(json, "\"chain_path\":[\"0x00002000\",\"0x00002040\"]") != NULL);
    assert(strstr(json, "\"final_verdict\":\"moderate_suspicion_static\"") != NULL);
    assert(strstr(json, ".x\\u00f6") != NULL);
    assert(strstr(json, "\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82") != NULL);

    free(json);
    remove(output_path);

    const char* known_codes[] = {
        "pe_section_raw_oob", "pe_section_virtual_oob", "pe_section_raw_overlap",
        "pe_section_virtual_overlap", "pe_section_misaligned", "pe_exception_directory_oob",
        "no_runtime_functions", "invalid_ranges", "rf_oob", "unwind_rva_oob",
        "rf_unsorted", "rf_overlaps", "duplicate_begin", "unwind_parse_fail",
        "unwind_anomalies", "unwind_reuse_strong", "unwind_reuse_moderate",
        "handler_dominance", "unwind_in_exec_section", "unwind_unusual_section",
        "unwind_writable_section", "handler_nonexec_section", "handler_writable_section",
        "placement_exec_nonexec_handler_combo", "placement_integrity_combo",
        "reuse_dominance_combo", "writable_metadata_handler_combo"
    };
    HeuristicReport mapping_report;
    memset(&mapping_report, 0, sizeof(mapping_report));
    mapping_report.total = 1;
    mapping_report.confidence = 0.5;
    mapping_report.evidence_families_mask = HEF_TABLE_INTEGRITY;
    snprintf(mapping_report.verdict, sizeof(mapping_report.verdict), "%s", "low_suspicion");
    snprintf(mapping_report.evidence_level, sizeof(mapping_report.evidence_level), "%s", "weak");
    mapping_report.finding_count = sizeof(known_codes) / sizeof(known_codes[0]);
    assert(sb_init(&mapping_report.details, 128));
    for (size_t i = 0; i < mapping_report.finding_count; i++) {
        HeuristicFinding* finding = &mapping_report.findings[i];
        snprintf(finding->code, sizeof(finding->code), "%s", known_codes[i]);
        snprintf(finding->family, sizeof(finding->family), "%s", "table_integrity");
        snprintf(finding->severity, sizeof(finding->severity), "%s", "medium");
        snprintf(finding->message, sizeof(finding->message), "%s", "mapping coverage");
        finding->affected_count = 1;
        finding->has_location = true;
        finding->representative_rva = 0x1100;
    }
    const char* mapping_path = "unit_report_mapping_output.json";
    assert(report_write_json_ex(mapping_path, "mapping.exe", &img, rf, us, us_ok,
                                1, &mapping_report, NULL, &metadata, &err));
    char* mapping_json = slurp(mapping_path);
    assert(strstr(mapping_json, "\"title_ru\":\"Эвристический признак\"") == NULL);
    assert(strstr(mapping_json, "Код finding-а не сопоставлен") == NULL);
    assert(strstr(mapping_json, "Эвристическое правило определяется кодом") == NULL);
    assert(strstr(mapping_json, "Наблюдаемое состояние должно удовлетворять") == NULL);
    assert(strstr(mapping_json, "Сопоставить исходный код finding-а") == NULL);
    for (size_t i = 0; i < mapping_report.finding_count; i++) {
        assert(strstr(mapping_json, known_codes[i]) != NULL);
    }
    const char* pe_finding = strstr(mapping_json, "\"code\":\"pe_section_raw_oob\"");
    assert(pe_finding != NULL);
    const char* pe_related = strstr(pe_finding, "\"related_function_index\":");
    assert(pe_related != NULL);
    assert(strncmp(pe_related, "\"related_function_index\":null", 29) == 0);
    free(mapping_json);
    remove(mapping_path);
    sb_free(&mapping_report.details);

    sb_free(&err);
    sb_free(&dr.details);
    sb_free(&pr.details);

    printf("unit_report_json: OK\n");
    return 0;
}
