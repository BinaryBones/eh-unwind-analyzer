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
    img->size_of_image = 0x9000;
    img->num_sections = n;
    img->sections = secs;
}

static int finding_index(const HeuristicReport* pr, const char* code) {
    for (size_t i = 0; i < pr->finding_count; i++) {
        if (strcmp(pr->findings[i].code, code) == 0) return (int)i;
    }
    return -1;
}

int main(void) {
    PeSection secs[3];
    memset(secs, 0, sizeof(secs));

    memcpy(secs[0].name, ".text", 5);
    secs[0].virtual_address = 0x1000;
    secs[0].virtual_size = 0x3000;
    secs[0].raw_ptr = 0x200;
    secs[0].raw_size = 0x3000;
    secs[0].characteristics = 0x60000020u;

    memcpy(secs[1].name, ".xdata", 6);
    secs[1].virtual_address = 0x4000;
    secs[1].virtual_size = 0x1000;
    secs[1].raw_ptr = 0x3200;
    secs[1].raw_size = 0x1000;
    secs[1].characteristics = 0x40000040u;

    memcpy(secs[2].name, ".rdata", 6);
    secs[2].virtual_address = 0x5000;
    secs[2].virtual_size = 0x1000;
    secs[2].raw_ptr = 0x4200;
    secs[2].raw_size = 0x1000;
    secs[2].characteristics = 0x40000040u;

    PeImage img;
    setup_sections(&img, secs, 3);

    RuntimeFunction rf[260];
    UnwindSummary us[260];
    bool us_ok[260];
    memset(rf, 0, sizeof(rf));
    memset(us, 0, sizeof(us));
    memset(us_ok, 0, sizeof(us_ok));

    for (size_t i = 0; i < 260; i++) {
        rf[i].begin_rva = 0x1100u + (uint32_t)(i * 0x10u);
        rf[i].end_rva = rf[i].begin_rva + 0x10u;
        rf[i].unwind_rva = (i < 220) ? 0x1200u : (0x4000u + (uint32_t)((i - 220) * 4u)); /* strong reuse on .text */
        us[i].valid = true;
        us[i].has_handler = true;
        us[i].handler_rva = 0x5000u; /* non-exec */
        us[i].anomalies = (i == 0) ? 1u : 0u; /* integrity corroboration */
        us_ok[i] = true;
    }

    HeuristicReport pr;
    StrBuf err;
    assert(sb_init(&err, 256));
    assert(heuristics_analyze(&img, rf, us, us_ok, 260, &pr, &err));

    int placement_combo = finding_index(&pr, "placement_exec_nonexec_handler_combo");
    int integrity_combo = finding_index(&pr, "placement_integrity_combo");
    int reuse_combo = finding_index(&pr, "reuse_dominance_combo");
    assert(placement_combo >= 0);
    assert(integrity_combo >= 0);
    assert(reuse_combo >= 0);
    assert(pr.findings[placement_combo].has_location);
    assert(pr.findings[placement_combo].affected_count > 0);
    assert(pr.findings[integrity_combo].has_location);
    assert(pr.findings[integrity_combo].affected_count > 0);
    assert(pr.findings[reuse_combo].has_location);
    assert(pr.findings[reuse_combo].representative_rva == 0x1200u);
    assert(pr.findings[reuse_combo].affected_count == 220u);
    assert(pr.score >= 70);
    int contribution_sum = 0;
    for (size_t i = 0; i < pr.finding_count; i++) {
        contribution_sum += heuristics_finding_score_contribution(&pr, pr.findings[i].code);
    }
    assert(pr.score_weight_sum == contribution_sum);
    assert(pr.score_weight_sum > 100);
    assert(pr.score == (contribution_sum > 100 ? 100 : contribution_sum));

    heuristics_free(&pr);
    sb_free(&err);
    printf("unit_heuristics_combos: OK\n");
    return 0;
}
