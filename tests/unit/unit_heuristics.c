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
    img->size_of_image = 0x5000;
    img->num_sections = n;
    img->sections = secs;
}

int main(void) {
    PeSection secs[3];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x1000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x1000;
    secs[0].characteristics = 0x60000020u; /* execute */

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x2000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x1200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u; /* read */

    memcpy(secs[2].name, ".rdata", 6);
    secs[2].virtual_address = 0x3000;
    secs[2].virtual_size = 0x1000;
    secs[2].raw_ptr = 0x2200;
    secs[2].raw_size = 0x1000;
    secs[2].characteristics = 0x40000040u; /* read (non-exec) */

    PeImage img;
    setup_sections(&img, secs, 3);

    RuntimeFunction rf[3];
    memset(rf, 0, sizeof(rf));
    rf[0].begin_rva = 0x1100; rf[0].end_rva = 0x1110; rf[0].unwind_rva = 0x1200; /* .text -> unusual+exec */
    rf[1].begin_rva = 0x2100; rf[1].end_rva = 0x2110; rf[1].unwind_rva = 0x2000; /* ok */
    rf[2].begin_rva = 0x3100; rf[2].end_rva = 0x3110; rf[2].unwind_rva = 0x3000; /* ok (rdata allowed) */

    UnwindSummary us[3];
    bool us_ok[3] = { true, true, true };
    memset(us, 0, sizeof(us));

    us[0].has_handler = true;
    us[0].handler_rva = 0x3000; /* non-exec => suspicious */

    HeuristicReport pr;
    StrBuf err; sb_init(&err, 256);

    bool ok = heuristics_analyze(&img, rf, us, us_ok, 3, &pr, &err);
    assert(ok);

    assert(pr.unwind_exec_section == 1);
    assert(pr.unwind_unusual_section == 1);
    assert(pr.handler_nonexec_section == 1);
    assert(pr.score > 0);
    assert(pr.finding_count >= 3);
    assert(pr.confidence > 0.0);
    assert(strcmp(pr.evidence_level, "weak") == 0 || strcmp(pr.evidence_level, "medium") == 0 || strcmp(pr.evidence_level, "strong") == 0);
    assert(strcmp(pr.verdict, "low_suspicion") == 0 || strcmp(pr.verdict, "moderate_suspicion") == 0 || strcmp(pr.verdict, "high_suspicion") == 0);
    assert(pr.requires_manual_review);

    heuristics_free(&pr);
    sb_free(&err);

    printf("unit_heuristics: OK\n");
    return 0;
}
