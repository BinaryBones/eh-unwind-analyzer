#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "heuristics.h"
#include "pe.h"
#include "unwind.h"
#include "util.h"

static int finding_index(const HeuristicReport* report, const char* code) {
    for (size_t i = 0; i < report->finding_count; i++) {
        if (strcmp(report->findings[i].code, code) == 0) return (int)i;
    }
    return -1;
}

static void test_section_range_wrap(void) {
    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".edge", 5);
    sec.virtual_address = 0xffffff00u;
    sec.virtual_size = 0x300u;
    sec.raw_ptr = 0x200u;
    sec.raw_size = 0x300u;

    PeImage img;
    memset(&img, 0, sizeof(img));
    img.num_sections = 1;
    img.sections = &sec;

    assert(pe_find_section_for_rva(&img, 0xffffff80u) == &sec);
    uint32_t off = 0;
    assert(pe_rva_to_fileoff(&img, 0xffffff80u, &off));
    assert(off == 0x280u);
}

static void test_header_mapping_uses_declared_size(void) {
    PeImage img;
    memset(&img, 0, sizeof(img));
    img.size_of_headers = 0x200;
    img.file_size = 0x300;

    uint32_t off = 0;
    assert(pe_rva_to_fileoff(&img, 0x180, &off));
    assert(off == 0x180);
    assert(!pe_rva_to_fileoff(&img, 0x280, &off));
}

static void test_empty_exception_directory(void) {
    uint8_t byte = 0;
    Buf b = { &byte, 1 };
    PeImage img;
    memset(&img, 0, sizeof(img));

    RuntimeFunction* rf = (RuntimeFunction*)0x1;
    size_t count = 123;
    StrBuf err;
    assert(sb_init(&err, 128));
    assert(unwind_read_runtime_functions(&b, &img, &rf, &count, &err));
    assert(rf == NULL);
    assert(count == 0);
    assert(err.len == 0);
    sb_free(&err);
}

static void test_malformed_exception_directory_status(void) {
    uint8_t bytes[32] = {0};
    Buf b = { bytes, sizeof(bytes) };
    PeImage img;
    memset(&img, 0, sizeof(img));
    img.exception_rva = 1;
    img.exception_size = 1;
    img.size_of_headers = sizeof(bytes);
    img.file_size = sizeof(bytes);

    RuntimeFunction* rf = NULL;
    size_t count = 0;
    StrBuf err;
    assert(sb_init(&err, 128));
    assert(unwind_read_runtime_functions_ex(
               &b, &img, &rf, &count, &err) ==
           RUNTIME_FUNCTION_READ_MALFORMED);
    assert(rf == NULL);
    assert(count == 0);
    assert(err.len > 0);
    sb_free(&err);
}

static void test_empty_heuristic_input(void) {
    PeSection text;
    memset(&text, 0, sizeof(text));
    memcpy(text.name, ".text", 5);
    text.virtual_address = 0x200;
    text.virtual_size = 0x400;
    text.raw_size = 0x400;
    text.characteristics = 0x60000020u;

    PeImage img;
    memset(&img, 0, sizeof(img));
    img.size_of_image = 0x1000;
    img.num_sections = 1;
    img.sections = &text;

    HeuristicReport report;
    StrBuf err;
    assert(sb_init(&err, 128));
    assert(heuristics_analyze(&img, NULL, NULL, NULL, 0, &report, &err));
    assert(report.total == 0);
    assert(report.score == 10);
    assert(finding_index(&report, "no_runtime_functions") >= 0);
    assert(strcmp(report.evidence_level, "weak") == 0);
    assert(report.requires_manual_review);
    heuristics_free(&report);
    sb_free(&err);
}

static void test_empty_nonexec_image_is_not_flagged(void) {
    PeSection rdata;
    memset(&rdata, 0, sizeof(rdata));
    memcpy(rdata.name, ".rdata", 6);
    rdata.virtual_address = 0x200;
    rdata.virtual_size = 0x400;
    rdata.raw_size = 0x400;
    rdata.characteristics = 0x40000040u;

    PeImage img;
    memset(&img, 0, sizeof(img));
    img.size_of_image = 0x1000;
    img.num_sections = 1;
    img.sections = &rdata;

    HeuristicReport report;
    StrBuf err;
    assert(sb_init(&err, 128));
    assert(heuristics_analyze(&img, NULL, NULL, NULL, 0, &report, &err));
    assert(report.score == 0);
    assert(finding_index(&report, "no_runtime_functions") < 0);
    assert(!report.requires_manual_review);
    heuristics_free(&report);
    sb_free(&err);
}

static void test_nested_overlap_detection(void) {
    PeSection sections[2];
    memset(sections, 0, sizeof(sections));
    memcpy(sections[0].name, ".text", 5);
    sections[0].virtual_address = 0x1000;
    sections[0].virtual_size = 0x1000;
    sections[0].raw_size = 0x1000;
    sections[0].characteristics = 0x60000020u;
    memcpy(sections[1].name, ".xdata", 6);
    sections[1].virtual_address = 0x2000;
    sections[1].virtual_size = 0x1000;
    sections[1].raw_size = 0x1000;
    sections[1].characteristics = 0x40000040u;

    PeImage img;
    memset(&img, 0, sizeof(img));
    img.size_of_image = 0x4000;
    img.num_sections = 2;
    img.sections = sections;

    RuntimeFunction rf[3] = {
        { 0x1000, 0x1100, 0x2000 },
        { 0x1010, 0x1020, 0x2004 },
        { 0x1030, 0x1040, 0x2008 },
    };
    UnwindSummary us[3];
    memset(us, 0, sizeof(us));
    bool us_ok[3] = { true, true, true };

    HeuristicReport report;
    StrBuf err;
    assert(sb_init(&err, 128));
    assert(heuristics_analyze(&img, rf, us, us_ok, 3, &report, &err));
    assert(report.rf_overlaps == 2);
    assert(finding_index(&report, "rf_overlaps") >= 0);
    heuristics_free(&report);
    sb_free(&err);
}

static void test_sha256(void) {
    static const uint8_t abc[] = { 'a', 'b', 'c' };
    char digest[65];
    assert(sha256_hex(abc, sizeof(abc), digest));
    assert(strcmp(digest, "ba7816bf8f01cfea414140de5dae2223"
                          "b00361a396177a9cb410ff61f20015ad") == 0);
}

static void test_empty_file_and_string_overflow(void) {
    const char* path = "unit_empty_input.bin";
    FILE* file = fopen(path, "wb");
    assert(file != NULL);
    assert(fclose(file) == 0);

    Buf buffer;
    uint8_t* owned = NULL;
    assert(buf_init_from_file(&buffer, path, &owned));
    assert(buffer.size == 0);
    assert(owned != NULL);
    buf_free_owned(owned);
    assert(remove(path) == 0);

    StrBuf text;
    assert(sb_init(&text, 16));
    assert(sb_ok(&text));
    size_t saved_len = text.len;
    text.len = SIZE_MAX;
    assert(!sb_appendn(&text, "x", 1));
    assert(!sb_ok(&text));
    assert(!sb_appendf(&text, "%s", "x"));
    text.len = saved_len;
    sb_free(&text);

    assert(sb_init(&text, 16));
    assert(!sb_append(&text, NULL));
    assert(!sb_ok(&text));
    sb_free(&text);
    assert(!file_write_atomic(NULL, "", 0));

    const char* atomic_path = "unit_atomic_write.bin";
    assert(file_write_atomic(atomic_path, "first", 5));
    assert(file_write_atomic(atomic_path, "second", 6));
    assert(!file_write_atomic(atomic_path, NULL, 1));
    assert(buf_init_from_file(&buffer, atomic_path, &owned));
    assert(buffer.size == 6);
    assert(memcmp(buffer.data, "second", 6) == 0);
    buf_free_owned(owned);
    assert(remove(atomic_path) == 0);
}

static void test_pe_structure_findings(void) {
    PeSection section;
    memset(&section, 0, sizeof(section));
    memcpy(section.name, ".bad", 4);
    section.virtual_address = 0x1800;
    section.virtual_size = 0x1000;
    section.raw_ptr = 0x180;
    section.raw_size = 0x1000;

    PeImage img;
    memset(&img, 0, sizeof(img));
    img.size_of_image = 0x2000;
    img.size_of_headers = 0x200;
    img.section_alignment = 0x1000;
    img.file_alignment = 0x200;
    img.file_size = 0x400;
    img.num_sections = 1;
    img.sections = &section;
    img.section_raw_oob = 1;
    img.section_virtual_oob = 1;
    img.section_misaligned = 1;

    HeuristicReport report;
    StrBuf err;
    assert(sb_init(&err, 128));
    assert(heuristics_analyze(&img, NULL, NULL, NULL, 0, &report, &err));
    assert(report.pe_section_raw_oob == 1);
    assert(report.pe_section_virtual_oob == 1);
    assert(report.pe_section_misaligned == 1);
    assert(finding_index(&report, "pe_section_raw_oob") >= 0);
    assert(finding_index(&report, "pe_section_virtual_oob") >= 0);
    assert(finding_index(&report, "pe_section_misaligned") >= 0);
    assert(report.score >= 50);
    heuristics_free(&report);
    sb_free(&err);
}

int main(void) {
    test_section_range_wrap();
    test_header_mapping_uses_declared_size();
    test_empty_exception_directory();
    test_malformed_exception_directory_status();
    test_empty_heuristic_input();
    test_empty_nonexec_image_is_not_flagged();
    test_nested_overlap_detection();
    test_sha256();
    test_empty_file_and_string_overflow();
    test_pe_structure_findings();
    printf("unit_core_edges: OK\n");
    return 0;
}
