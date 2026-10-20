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
    img->size_of_image = 0x6000;
    img->exception_rva = 0x4000;
    img->exception_size = 0x0c;
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
    assert(fread(buf, 1, (size_t)sz, f) == (size_t)sz);
    fclose(f);
    buf[sz] = 0;
    return buf;
}

static void fill_common_input(PeImage* img, RuntimeFunction* rf, UnwindSummary* us, bool* us_ok) {
    PeSection* secs = (PeSection*)calloc(3, sizeof(PeSection));
    assert(secs != NULL);
    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x1000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x1000;
    secs[0].characteristics = 0x60000020u;

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x2000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x1200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    memcpy(secs[2].name, ".rdata", 6);
    secs[2].virtual_address = 0x3000;
    secs[2].virtual_size = 0x1000;
    secs[2].raw_ptr = 0x2200;
    secs[2].raw_size = 0x1000;
    secs[2].characteristics = 0x40000040u;

    setup_sections(img, secs, 3);

    memset(rf, 0, sizeof(*rf));
    rf->begin_rva = 0x1100;
    rf->end_rva = 0x1140;
    rf->unwind_rva = 0x2000;

    memset(us, 0, sizeof(*us));
    us->valid = true;
    us->version = 1;
    us->prolog_size = 6;
    us->count_codes = 2;
    us->fixed_stack_bytes = 40;
    us->has_handler = true;
    us->handler_rva = 0x1100;
    *us_ok = true;
}

static void fill_strong_static(HeuristicReport* pr) {
    memset(pr, 0, sizeof(*pr));
    pr->score = 82;
    pr->score_weight_sum = 82;
    pr->suspicion = 0.82;
    pr->confidence = 0.81;
    pr->requires_manual_review = true;
    pr->evidence_families_mask = HEF_METADATA_PLACEMENT | HEF_HANDLER_DOMINANCE;
    snprintf(pr->verdict, sizeof(pr->verdict), "%s", "high_suspicion");
    snprintf(pr->evidence_level, sizeof(pr->evidence_level), "%s", "strong");
    pr->handler_count = 5;
    pr->handler_reuse_ratio = 0.90;
    pr->handler_nonexec_section = 1;
    pr->finding_count = 2;
    snprintf(pr->findings[0].code, sizeof(pr->findings[0].code), "%s", "handler_dominance");
    snprintf(pr->findings[0].family, sizeof(pr->findings[0].family), "%s", "handler_dominance");
    snprintf(pr->findings[0].severity, sizeof(pr->findings[0].severity), "%s", "medium");
    snprintf(pr->findings[0].message, sizeof(pr->findings[0].message), "%s", "One handler dominates the table");
    snprintf(pr->findings[1].code, sizeof(pr->findings[1].code), "%s", "handler_nonexec_section");
    snprintf(pr->findings[1].family, sizeof(pr->findings[1].family), "%s", "metadata_placement");
    snprintf(pr->findings[1].severity, sizeof(pr->findings[1].severity), "%s", "high");
    snprintf(pr->findings[1].message, sizeof(pr->findings[1].message), "%s", "Handler target in non-exec section");
    assert(sb_init(&pr->details, 128));
    sb_append(&pr->details, "- strong static detail\n");
}

static void fill_weak_static(HeuristicReport* pr) {
    memset(pr, 0, sizeof(*pr));
    pr->score = 16;
    pr->score_weight_sum = 16;
    pr->suspicion = 0.16;
    pr->confidence = 0.32;
    pr->requires_manual_review = true;
    pr->evidence_families_mask = HEF_METADATA_PLACEMENT;
    snprintf(pr->verdict, sizeof(pr->verdict), "%s", "low_suspicion");
    snprintf(pr->evidence_level, sizeof(pr->evidence_level), "%s", "weak");
    pr->finding_count = 1;
    snprintf(pr->findings[0].code, sizeof(pr->findings[0].code), "%s", "unwind_unusual_section");
    snprintf(pr->findings[0].family, sizeof(pr->findings[0].family), "%s", "metadata_placement");
    snprintf(pr->findings[0].severity, sizeof(pr->findings[0].severity), "%s", "medium");
    snprintf(pr->findings[0].message, sizeof(pr->findings[0].message), "%s", "UnwindInfo in unusual section");
    assert(sb_init(&pr->details, 128));
    sb_append(&pr->details, "- weak static detail\n");
}

static void clear_dynamic(DynamicReport* dr) {
    memset(dr, 0, sizeof(*dr));
    assert(sb_init(&dr->details, 128));
}

int main(void) {
    const ReportMetadata metadata = {
        .tool_version = "1.0.0-test",
        .report_schema_version = "1.3.0",
        .generated_at_utc = "2026-06-07T12:00:00Z",
        .input_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .input_size = 4096,
        .command_line = "tool matrix.exe --heuristics",
        .build_compiler = "test compiler",
        .build_platform = "test platform",
        .build_mode = "debug",
        .strict_abi = false,
        .follow_chain = true,
        .max_chain_depth = 8,
    };

    const char* case1_path = "matrix_case1_test_output.json";
    const char* case2_path = "matrix_case2_test_output.json";
    const char* case3_path = "matrix_case3_test_output.json";
    PeImage img;
    RuntimeFunction rf[1];
    UnwindSummary us[1];
    bool us_ok[1];
    fill_common_input(&img, rf, us, us_ok);

    StrBuf err;
    assert(sb_init(&err, 256));

    /* Case 1: strong static, no dynamic => strong_unconfirmed_case + valid comma before assessment */
    HeuristicReport pr1;
    fill_strong_static(&pr1);
    assert(report_write_json_ex(case1_path, "case1.exe", &img, rf, us, us_ok,
                                1, &pr1, NULL, &metadata, &err));
    char* j1 = slurp(case1_path);
    assert(strstr(j1, "\"details\":\"- strong static detail") != NULL);
    assert(strstr(j1, "},\"assessment\":{") != NULL);
    assert(strstr(j1, "\"case_strength\":\"strong_unconfirmed_case\"") != NULL);
    assert(strstr(j1, "\"final_verdict\":\"high_suspicion_static\"") != NULL);
    assert(strstr(j1, "Исследование dominant handler target") != NULL);
    assert(strstr(j1, "Дизассемблерная верификация handler target") != NULL);
    free(j1);
    sb_free(&pr1.details);
    remove(case1_path);

    /* Case 2: weak static + weak dynamic => weak_case, runtime registration review step */
    HeuristicReport pr2;
    fill_weak_static(&pr2);
    DynamicReport dr2;
    clear_dynamic(&dr2);
    dr2.enabled = true; dr2.ran = true; dr2.ok = true; dr2.target_exited = true;
    dr2.instrumentation_complete = true;
    dr2.first_chance_seen = 1;
    dr2.veh_registrations = 1;
    assert(report_write_json_ex(case2_path, "case2.exe", &img, rf, us, us_ok,
                                1, &pr2, &dr2, &metadata, &err));
    char* j2 = slurp(case2_path);
    assert(strstr(j2, "\"case_strength\":\"weak_case\"") != NULL);
    assert(strstr(j2, "\"static_dynamic_correlation\":false") != NULL);
    assert(strstr(j2, "Для каждой регистрации VEH/VCH/UEF фиксируется target address") != NULL);
    free(j2);
    sb_free(&dr2.details);
    sb_free(&pr2.details);
    remove(case2_path);

    /* Case 3: strong static + confirming dynamic => strong_correlated_case */
    HeuristicReport pr3;
    fill_strong_static(&pr3);
    DynamicReport dr3;
    clear_dynamic(&dr3);
    dr3.enabled = true; dr3.ran = true; dr3.ok = true; dr3.target_exited = true;
    dr3.instrumentation_complete = true;
    dr3.unwind_handler_hits = 1;
    dr3.second_chance_seen = 1;
    assert(report_write_json_ex(case3_path, "case3.exe", &img, rf, us, us_ok,
                                1, &pr3, &dr3, &metadata, &err));
    char* j3 = slurp(case3_path);
    assert(strstr(j3, "\"static_dynamic_correlation\":true") != NULL);
    assert(strstr(j3, "\"case_strength\":\"strong_correlated_case\"") != NULL);
    assert(strstr(j3, "\"final_verdict\":\"high_suspicion_correlated\"") != NULL);
    assert(strstr(j3, "Достигнутый unwind handler сопоставляется") != NULL);
    free(j3);
    sb_free(&dr3.details);
    sb_free(&pr3.details);
    remove(case3_path);

    /* Case 4: timed-out runtime signals remain visible but cannot become strong evidence. */
    DynamicReport dr4;
    clear_dynamic(&dr4);
    dr4.enabled = true; dr4.ran = true; dr4.ok = false; dr4.timed_out = true;
    dr4.unwind_handler_hits = 3;
    dr4.rtl_add_function_table_calls = 1;
    const char* case4_path = "matrix_case4_test_output.json";
    assert(report_write_json_ex(case4_path, "case4.exe", &img, rf, us, us_ok,
                                1, NULL, &dr4, &metadata, &err));
    char* j4 = slurp(case4_path);
    assert(strstr(j4, "\"runtime_evidence_level\":\"weak\"") != NULL);
    assert(strstr(j4, "\"case_strength\":\"weak_case\"") != NULL);
    assert(strstr(j4, "\"static_dynamic_correlation\":false") != NULL);
    assert(strstr(j4, "\"final_verdict\":\"no_strong_correlated_evidence\"") != NULL);
    assert(strstr(j4, "\"final_confidence\":0.100000") != NULL);
    free(j4);
    sb_free(&dr4.details);
    remove(case4_path);

    free(img.sections);
    sb_free(&err);
    printf("unit_matrix_report: OK\n");
    return 0;
}
