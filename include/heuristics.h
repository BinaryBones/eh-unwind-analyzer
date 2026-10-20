#pragma once
/*
  heuristics.h - heuristic assessment of broken / shadowed / low-informative unwind metadata
*/

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "pe.h"
#include "unwind.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum HeuristicEvidenceFamily {
    HEF_TABLE_INTEGRITY    = 1u << 0,
    HEF_UNWIND_INTEGRITY   = 1u << 1,
    HEF_METADATA_PLACEMENT = 1u << 2,
    HEF_UNWIND_REUSE       = 1u << 3,
    HEF_HANDLER_DOMINANCE  = 1u << 4
};

enum { HEURISTICS_MAX_FINDINGS = 32, HEURISTICS_MAX_MITIGATIONS = 16 };

typedef struct HeuristicFinding {
    char code[40];
    char family[32];
    char severity[16];
    char message[192];
    bool has_location;
    uint32_t representative_rva;
    size_t affected_count;
} HeuristicFinding;

typedef struct HeuristicMitigation {
    char code[40];
    char message[192];
} HeuristicMitigation;

typedef struct HeuristicReport {
    int    score; /* 0..100 (higher => more suspicious) */
    int    score_weight_sum; /* Sum of active finding weights before the 100-point cap. */
    double suspicion;  /* 0..1 derived from score */
    double confidence; /* 0..1 confidence in the static verdict */
    bool   requires_manual_review;
    uint32_t evidence_families_mask;
    char   verdict[48];

    size_t total;

    size_t pe_section_raw_oob;
    size_t pe_section_virtual_oob;
    size_t pe_section_raw_overlaps;
    size_t pe_section_virtual_overlaps;
    size_t pe_section_misaligned;
    bool   pe_exception_directory_oob;

    size_t rf_invalid_ranges;
    size_t rf_oob;
    size_t rf_unwind_oob;
    size_t rf_unsorted;
    size_t rf_overlaps;
    size_t rf_duplicate_begins;

    size_t unwind_parse_fail;
    size_t unwind_anomalies;
    size_t unwind_abi_warnings;

    size_t unwind_unusual_section;
    size_t unwind_exec_section;
    size_t unwind_writable_section;
    size_t handler_nonexec_section;
    size_t handler_writable_section;

    double unwind_reuse_ratio;    /* max_count / total */
    double unwind_unique_ratio;   /* unique / total */

    double handler_reuse_ratio;   /* max_count / handler_count (if any) */
    size_t handler_count;

    size_t finding_count;
    HeuristicFinding findings[HEURISTICS_MAX_FINDINGS];
    size_t weak_finding_count;
    size_t medium_finding_count;
    size_t strong_finding_count;
    char evidence_level[16];

    size_t mitigation_count;
    HeuristicMitigation mitigations[HEURISTICS_MAX_MITIGATIONS];

    StrBuf details; /* human-readable findings */
} HeuristicReport;

bool heuristics_analyze(const PeImage* img,
                        const RuntimeFunction* rf,
                        const UnwindSummary* us,
                        const bool* us_ok,
                        size_t n,
                        HeuristicReport* out,
                        StrBuf* err);

void heuristics_free(HeuristicReport* r);
const char* heuristics_evidence_family_name(uint32_t bit);
size_t heuristics_evidence_family_count(uint32_t mask);
int heuristics_finding_score_contribution(const HeuristicReport* report,
                                          const char* finding_code);

#ifdef __cplusplus
}
#endif
