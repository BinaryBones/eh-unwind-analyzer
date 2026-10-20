#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "heuristics.h"
#include "util.h"

static void setup_sections(PeImage* img, PeSection* secs, size_t n) {
    memset(img, 0, sizeof(*img));
    img->ok = true;
    img->is_pe64 = true;
    img->image_base = 0x140000000ull;
    img->size_of_image = 0x10000;
    img->num_sections = n;
    img->sections = secs;
}

static int finding_index(const HeuristicReport* pr, const char* code) {
    for (size_t i = 0; i < pr->finding_count; i++) {
        if (strcmp(pr->findings[i].code, code) == 0) return (int)i;
    }
    return -1;
}

static void test_clean_image_has_no_false_positive_metadata_case(void) {
    PeSection secs[2];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x3000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x3000;
    secs[0].characteristics = 0x60000020u;

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x5000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x3200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 2);

    RuntimeFunction rf[2];
    UnwindSummary us[2];
    bool us_ok[2];
    memset(rf, 0, sizeof(rf));
    memset(us, 0, sizeof(us));
    memset(us_ok, 0, sizeof(us_ok));
    for (size_t i = 0; i < 2; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x20u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = 0x5000u + (uint32_t)(i * 4u);
        us[i].valid = true;
        us_ok[i] = true;
    }

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 2, &pr, &err));
    assert(pr.score == 0);
    assert(pr.finding_count == 0);
    assert(pr.mitigation_count == 0);
    assert(strcmp(pr.evidence_level, "none") == 0);
    assert(strcmp(pr.verdict, "no_strong_static_anomalies") == 0);
    assert(!pr.requires_manual_review);
    heuristics_free(&pr);
    sb_free(&err);
}

static void test_gnu_xdata_is_not_flagged_as_unusual(void) {
    PeSection secs[2];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x4000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x4000;
    secs[0].characteristics = 0x60000020u;

    memcpy(secs[1].name, "xdata$g", 7); /* PE names are 8 bytes max; keep an xdata-like toolchain suffix */
    secs[1].virtual_address = 0x6000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x4200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 2);

    RuntimeFunction rf[1];
    memset(rf, 0, sizeof(rf));
    rf[0].begin_rva = 0x1100;
    rf[0].end_rva = 0x1120;
    rf[0].unwind_rva = 0x6000;

    UnwindSummary us[1];
    memset(us, 0, sizeof(us));
    us[0].valid = true;
    bool us_ok[1] = { true };

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 1, &pr, &err));
    assert(pr.unwind_unusual_section == 0);
    heuristics_free(&pr);
    sb_free(&err);
}

static void test_runtime_like_handler_dominance_is_suppressed_without_context(void) {
    PeSection secs[2];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x6000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x6000;
    secs[0].characteristics = 0x60000020u;

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x7000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x6200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 2);

    RuntimeFunction rf[60];
    UnwindSummary us[60];
    bool us_ok[60];
    memset(rf, 0, sizeof(rf));
    memset(us, 0, sizeof(us));
    memset(us_ok, 1, sizeof(us_ok));
    for (size_t i = 0; i < 60; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x20u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = 0x7000u + (uint32_t)(i * 4u);
        us[i].valid = true;
        us[i].has_handler = true;
        us[i].handler_rva = 0x1200u; /* normal .text target */
        us_ok[i] = true;
    }

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 60, &pr, &err));
    assert(finding_index(&pr, "handler_dominance") < 0);
    assert(pr.score == 0);
    heuristics_free(&pr);
    sb_free(&err);
}

static void test_handler_dominance_reappears_with_context(void) {
    PeSection secs[2];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x7000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x7000;
    secs[0].characteristics = 0x60000020u;

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x8000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x7200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 2);

    RuntimeFunction rf[60];
    UnwindSummary us[60];
    bool us_ok[60];
    memset(rf, 0, sizeof(rf));
    memset(us, 0, sizeof(us));
    memset(us_ok, 1, sizeof(us_ok));
    for (size_t i = 0; i < 60; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x20u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = 0x8000u + (uint32_t)(i * 4u);
        us[i].valid = true;
        us[i].has_handler = true;
        us[i].handler_rva = 0x1200u;
        us_ok[i] = true;
    }
    rf[0].unwind_rva = 0x1200u; /* unwind metadata inside .text => corroborating placement anomaly */

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 60, &pr, &err));
    assert(finding_index(&pr, "handler_dominance") >= 0);
    assert(pr.score >= 15);
    heuristics_free(&pr);
    sb_free(&err);
}

static void test_moderate_reuse_is_suppressed_without_context(void) {
    PeSection secs[2];
    memset(secs, 0, sizeof(secs));
    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x6000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x6000;
    secs[0].characteristics = 0x60000020u;
    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x8000;
    secs[1].virtual_size = 0x2000;
    secs[1].raw_ptr = 0x6200;
    secs[1].raw_size = 0x2000;
    secs[1].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 2);

    enum { COUNT = 240 };
    RuntimeFunction rf[COUNT];
    UnwindSummary us[COUNT];
    bool us_ok[COUNT];
    memset(rf, 0, sizeof(rf));
    memset(us, 0, sizeof(us));
    memset(us_ok, 1, sizeof(us_ok));
    for (size_t i = 0; i < COUNT; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x20u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = i < 30 ? 0x8000u : 0x8100u + (uint32_t)(i * 4u);
        us[i].valid = true;
        us_ok[i] = true;
    }

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, COUNT, &pr, &err));
    assert(pr.unwind_reuse_ratio > 0.10);
    assert(finding_index(&pr, "unwind_reuse_moderate") < 0);
    assert(pr.score == 0);
    assert(!pr.requires_manual_review);
    heuristics_free(&pr);
    sb_free(&err);
}

static void test_writable_metadata_and_handler_are_flagged(void) {
    PeSection secs[2];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x3000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x3000;
    secs[0].characteristics = 0xE0000020u; /* execute + write */

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x5000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x3200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0xC0000040u; /* read + write */

    PeImage img;
    setup_sections(&img, secs, 2);

    RuntimeFunction rf[4];
    UnwindSummary us[4];
    bool us_ok[4];
    memset(rf, 0, sizeof(rf));
    memset(us, 0, sizeof(us));
    memset(us_ok, 0, sizeof(us_ok));
    for (size_t i = 0; i < 4; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x20u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = 0x5000u + (uint32_t)(i * 4u);
        us[i].valid = true;
        us[i].has_handler = true;
        us[i].handler_rva = 0x1200u;
        us_ok[i] = true;
    }

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 4, &pr, &err));
    assert(pr.unwind_writable_section == 4);
    assert(pr.handler_writable_section == 4);
    assert(finding_index(&pr, "unwind_writable_section") >= 0);
    assert(finding_index(&pr, "handler_writable_section") >= 0);
    assert(finding_index(&pr, "writable_metadata_handler_combo") >= 0);
    assert(pr.score >= 20);
    assert(pr.requires_manual_review);
    heuristics_free(&pr);
    sb_free(&err);
}

int main(void) {
    test_clean_image_has_no_false_positive_metadata_case();
    test_gnu_xdata_is_not_flagged_as_unusual();
    test_runtime_like_handler_dominance_is_suppressed_without_context();
    test_handler_dominance_reappears_with_context();
    test_moderate_reuse_is_suppressed_without_context();
    test_writable_metadata_and_handler_are_flagged();
    printf("unit_heuristics_context: OK\n");
    return 0;
}
