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

static int mitigation_index(const HeuristicReport* pr, const char* code) {
    for (size_t i = 0; i < pr->mitigation_count; i++) {
        if (strcmp(pr->mitigations[i].code, code) == 0) return (int)i;
    }
    return -1;
}

int main(void) {
    PeSection secs[3];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x1000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x1000;
    secs[0].characteristics = 0x60000020u; /* exec */

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x2000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x1200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u; /* normal read-only unwind section */

    memcpy(secs[2].name, ".weird", 6);
    secs[2].virtual_address = 0x3000;
    secs[2].virtual_size = 0x1000;
    secs[2].raw_ptr = 0x2200;
    secs[2].raw_size = 0x1000;
    secs[2].characteristics = 0x40000040u; /* read only, unusual but non-exec */

    PeImage img;
    setup_sections(&img, secs, 3);

    RuntimeFunction rf[21];
    memset(rf, 0, sizeof(rf));
    UnwindSummary us[21];
    memset(us, 0, sizeof(us));
    bool us_ok[21];
    memset(us_ok, 0, sizeof(us_ok));
    for (size_t i = 0; i < 21; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x20u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = (i == 0) ? 0x3000u : 0x2000u; /* only one placement anomaly => medium severity */
        us[i].valid = true;
        us_ok[i] = true;
    }

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 21, &pr, &err));

    assert(pr.finding_count >= 1);
    assert(pr.mitigation_count >= 4);
    assert(mitigation_index(&pr, "single_signal_only") >= 0);
    assert(mitigation_index(&pr, "small_sample_size") >= 0);
    assert(mitigation_index(&pr, "placement_only_signal") >= 0);
    assert(mitigation_index(&pr, "single_family_only") >= 0);
    assert(pr.confidence <= 0.20);
    assert(pr.requires_manual_review);
    assert(strcmp(pr.evidence_level, "weak") == 0 || strcmp(pr.evidence_level, "medium") == 0);

    heuristics_free(&pr);
    sb_free(&err);

    printf("unit_heuristics_mitigations: OK\n");
    return 0;
}
