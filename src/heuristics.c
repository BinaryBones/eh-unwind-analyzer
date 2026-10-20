#include "heuristics.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#endif
#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE 0x80000000u
#endif

#define UA_ABI_MASK \
    (UA_ABI_REGISTER_CLASS | UA_ABI_RESERVED_OPINFO | UA_ABI_PUSH_ORDER | \
     UA_ABI_CHAIN_RESTRICTION | UA_ABI_SAVE_OFFSET)


/*
 * Heuristic calibration notes
 * ---------------------------
 * These constants intentionally form a conservative engineering model rather
 * than a mathematically validated classifier. The weights are grouped by the
 * evidence family discussed in the thesis so the rationale stays stable and
 * reviewable:
 *   - table/unwind integrity violations => strongest static weights
 *   - placement anomalies => medium/high depending on prevalence
 *   - reuse/dominance patterns => moderate unless they are very strong
 *   - mitigations reduce confidence when evidence is isolated or sample size is tiny
 */
static const int SCORE_EMPTY_PDATA = 10;
static const int SCORE_PE_SECTION_RAW_OOB = 25;
static const int SCORE_PE_SECTION_VIRTUAL_OOB = 20;
static const int SCORE_PE_SECTION_RAW_OVERLAP = 15;
static const int SCORE_PE_SECTION_VIRTUAL_OVERLAP = 20;
static const int SCORE_PE_SECTION_MISALIGNED = 8;
static const int SCORE_PE_EXCEPTION_DIRECTORY_OOB = 25;
static const int SCORE_INVALID_RANGE_LOW = 10;
static const int SCORE_INVALID_RANGE_HIGH = 20;
static const int SCORE_RF_OOB_LOW = 10;
static const int SCORE_RF_OOB_HIGH = 25;
static const int SCORE_UNWIND_RVA_OOB_LOW = 10;
static const int SCORE_UNWIND_RVA_OOB_HIGH = 25;
static const int SCORE_RF_UNSORTED = 15;
static const int SCORE_RF_OVERLAP = 25;
static const int SCORE_DUPLICATE_BEGIN = 10;
static const int SCORE_UNWIND_PARSE_FAIL_LOW = 10;
static const int SCORE_UNWIND_PARSE_FAIL_HIGH = 25;
static const int SCORE_UNWIND_ANOM_LOW = 10;
static const int SCORE_UNWIND_ANOM_HIGH = 20;
static const int SCORE_UNWIND_REUSE_MEDIUM = 10;
static const int SCORE_UNWIND_REUSE_HIGH = 20;
static const int SCORE_HANDLER_DOMINANCE = 15;
static const int SCORE_UNWIND_EXEC_SECTION = 20;
static const int SCORE_UNWIND_UNUSUAL_SECTION_LOW = 8;
static const int SCORE_UNWIND_UNUSUAL_SECTION_HIGH = 15;
static const int SCORE_UNWIND_WRITABLE_SECTION_LOW = 10;
static const int SCORE_UNWIND_WRITABLE_SECTION_HIGH = 18;
static const int SCORE_HANDLER_NONEXEC = 15;
static const int SCORE_HANDLER_WRITABLE = 10;
static const int SCORE_COMBO_PLACEMENT_EXEC_AND_HANDLER = 10;
static const int SCORE_COMBO_PLACEMENT_AND_INTEGRITY = 8;
static const int SCORE_COMBO_REUSE_AND_DOMINANCE = 8;
static const int SCORE_COMBO_WRITABLE_METADATA_AND_HANDLER = 10;

static const double CONFIDENCE_BASE = 0.15;
static const double CONFIDENCE_ZERO_SCORE_BASE = 0.20;
static const double CONFIDENCE_PER_FAMILY = 0.11;
static const double CONFIDENCE_PER_STRONG = 0.08;
static const double CONFIDENCE_PER_MEDIUM = 0.04;
static const double CONFIDENCE_BONUS_TABLE_HARD = 0.08;
static const double CONFIDENCE_BONUS_UNWIND_HARD = 0.08;
static const double CONFIDENCE_PENALTY_SINGLE_SIGNAL = 0.12;
static const double CONFIDENCE_PENALTY_SMALL_SAMPLE = 0.06;
static const double CONFIDENCE_PENALTY_PLACEMENT_ONLY = 0.10;
static const double CONFIDENCE_PENALTY_SINGLE_FAMILY = 0.08;
static const double CONFIDENCE_MIN = 0.05;
static const double CONFIDENCE_MAX = 0.90;

static const double THRESHOLD_HIGH_PERCENT = 0.01;   /* >1% of entries => not just a one-off glitch */
static const double THRESHOLD_UNWIND_ANOM_HIGH = 0.05; /* >5% anomalies => broad integrity issue */
static const double THRESHOLD_UNWIND_REUSE_MEDIUM = 0.10;
static const double THRESHOLD_UNWIND_REUSE_HIGH = 0.30;
static const double THRESHOLD_HANDLER_DOMINANCE = 0.80;

static bool sec_name_eq(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static bool sec_name_contains_ci(const char* haystack, const char* needle) {
    if (!haystack || !needle || !*needle) return false;
    size_t nlen = strlen(needle);
    for (const char* h = haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen) {
            char ca = h[i];
            char cb = needle[i];
            if (!ca) return false;
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
            if (ca != cb) break;
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

static bool sec_name_allowed_for_unwind(const char* name8) {
    /* Common placements: .xdata (MSVC), .rdata/.pdata in practice, and toolchain-specific xdata-like sections. */
    return sec_name_eq(name8, ".xdata") || sec_name_eq(name8, ".rdata") || sec_name_eq(name8, ".pdata") ||
           sec_name_eq(name8, ".gnu_xdata") || sec_name_eq(name8, ".mrdata") ||
           sec_name_eq(name8, "xdata") || sec_name_eq(name8, "rdata") || sec_name_eq(name8, "pdata");
}

static bool sec_name_plausibly_unwind_named(const char* name8) {
    return sec_name_contains_ci(name8, "xdata") || sec_name_contains_ci(name8, "pdata") || sec_name_contains_ci(name8, "rdata");
}

static bool sec_name_code_like(const char* name8) {
    return sec_name_eq(name8, ".text") || sec_name_eq(name8, "text") ||
           sec_name_contains_ci(name8, "text") || sec_name_contains_ci(name8, "code") || sec_name_contains_ci(name8, "init");
}

static bool image_has_executable_section(const PeImage* img) {
    if (!img || !img->sections) return false;
    for (size_t i = 0; i < img->num_sections; i++) {
        const PeSection* section = &img->sections[i];
        if ((section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            (section->virtual_size != 0 || section->raw_size != 0)) {
            return true;
        }
    }
    return false;
}

/* Very small u32->count hash map (open addressing, linear probing). */
typedef struct HEntry {
    uint32_t key;
    uint32_t val;
    bool used;
} HEntry;

typedef struct HMap {
    HEntry* e;
    size_t cap;
    size_t len;
} HMap;

static uint32_t h32(uint32_t x) {
    /* xorshift-ish */
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static bool hmap_init(HMap* m, size_t cap) {
    if (!m) return false;
    m->cap = cap < 64 ? 64 : cap;
    m->len = 0;
    m->e = (HEntry*)calloc(m->cap, sizeof(HEntry));
    return m->e != NULL;
}

static void hmap_free(HMap* m) {
    if (!m) return;
    free(m->e);
    m->e = NULL;
    m->cap = 0;
    m->len = 0;
}

static bool hmap_grow(HMap* m);

static bool hmap_inc(HMap* m, uint32_t key, uint32_t* out_newval) {
    if (!m || !m->e) return false;
    if ((m->len + 1) * 10 >= m->cap * 7) {
        if (!hmap_grow(m)) return false;
    }
    uint32_t hv = h32(key);
    size_t idx = (size_t)hv % m->cap;
    for (size_t step = 0; step < m->cap; step++) {
        HEntry* ent = &m->e[idx];
        if (!ent->used) {
            ent->used = true;
            ent->key = key;
            ent->val = 1;
            m->len++;
            if (out_newval) *out_newval = 1;
            return true;
        }
        if (ent->key == key) {
            ent->val++;
            if (out_newval) *out_newval = ent->val;
            return true;
        }
        idx = (idx + 1) % m->cap;
    }
    return false;
}

static bool hmap_grow(HMap* m) {
    size_t oldcap = m->cap;
    HEntry* old = m->e;
    if (oldcap > (SIZE_MAX - 1u) / 2u) return false;
    size_t newcap = oldcap * 2 + 1;
    HEntry* ne = (HEntry*)calloc(newcap, sizeof(HEntry));
    if (!ne) return false;

    m->e = ne;
    m->cap = newcap;
    m->len = 0;

    for (size_t i = 0; i < oldcap; i++) {
        if (!old[i].used) continue;
        /* reinsert */
        uint32_t key = old[i].key;
        uint32_t val = old[i].val;
        uint32_t hv = h32(key);
        size_t idx = (size_t)hv % m->cap;
        for (;;) {
            HEntry* ent = &m->e[idx];
            if (!ent->used) {
                ent->used = true;
                ent->key = key;
                ent->val = val;
                m->len++;
                break;
            }
            idx = (idx + 1) % m->cap;
        }
    }
    free(old);
    return true;
}

static uint32_t hmap_max_val(const HMap* m) {
    uint32_t mx = 0;
    if (!m || !m->e) return 0;
    for (size_t i = 0; i < m->cap; i++) {
        if (m->e[i].used && m->e[i].val > mx) mx = m->e[i].val;
    }
    return mx;
}

static bool hmap_max_entry(const HMap* m, uint32_t* out_key, uint32_t* out_val) {
    uint32_t best_key = 0;
    uint32_t best_val = 0;
    if (!m || !m->e) return false;
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->e[i].used) continue;
        if (m->e[i].val > best_val) {
            best_key = m->e[i].key;
            best_val = m->e[i].val;
        }
    }
    if (best_val == 0) return false;
    if (out_key) *out_key = best_key;
    if (out_val) *out_val = best_val;
    return true;
}

static size_t hmap_unique(const HMap* m) { return m ? m->len : 0; }

typedef struct RfIdx {
    uint32_t begin;
    uint32_t end;
} RfIdx;

typedef struct FindingLocation {
    bool set;
    uint32_t rva;
} FindingLocation;

static void remember_location(FindingLocation* location, uint32_t rva) {
    if (!location || location->set) return;
    location->set = true;
    location->rva = rva;
}

enum PeSectionIssue {
    PE_ISSUE_RAW_OOB,
    PE_ISSUE_VIRTUAL_OOB,
    PE_ISSUE_RAW_OVERLAP,
    PE_ISSUE_VIRTUAL_OVERLAP,
    PE_ISSUE_MISALIGNED
};

static FindingLocation first_pe_section_issue(const PeImage* img, enum PeSectionIssue issue) {
    FindingLocation result = {0};
    if (!img || !img->sections) return result;

    for (size_t i = 0; i < img->num_sections; i++) {
        const PeSection* s = &img->sections[i];
        uint64_t span = s->virtual_size > s->raw_size ? s->virtual_size : s->raw_size;
        bool match = false;
        if (issue == PE_ISSUE_RAW_OOB) {
            match = s->raw_size > 0 &&
                    ((uint64_t)s->raw_ptr + (uint64_t)s->raw_size > (uint64_t)img->file_size);
        } else if (issue == PE_ISSUE_VIRTUAL_OOB) {
            match = span > 0 &&
                    ((uint64_t)s->virtual_address + span > (uint64_t)img->size_of_image);
        } else if (issue == PE_ISSUE_MISALIGNED) {
            match = (img->section_alignment > 0 &&
                     (s->virtual_address % img->section_alignment) != 0) ||
                    (s->raw_size > 0 && img->file_alignment > 0 &&
                     (s->raw_ptr % img->file_alignment) != 0);
        } else {
            for (size_t j = 0; j < i && !match; j++) {
                const PeSection* p = &img->sections[j];
                uint64_t pspan = p->virtual_size > p->raw_size ? p->virtual_size : p->raw_size;
                if (issue == PE_ISSUE_RAW_OVERLAP) {
                    match = s->raw_size > 0 && p->raw_size > 0 &&
                            (uint64_t)s->raw_ptr < (uint64_t)p->raw_ptr + p->raw_size &&
                            (uint64_t)p->raw_ptr < (uint64_t)s->raw_ptr + s->raw_size;
                } else if (issue == PE_ISSUE_VIRTUAL_OVERLAP) {
                    match = span > 0 && pspan > 0 &&
                            (uint64_t)s->virtual_address < (uint64_t)p->virtual_address + pspan &&
                            (uint64_t)p->virtual_address < (uint64_t)s->virtual_address + span;
                }
            }
        }
        if (match) {
            remember_location(&result, s->virtual_address);
            break;
        }
    }
    return result;
}

static int cmp_rfidx(const void* a, const void* b) {
    const RfIdx* x = (const RfIdx*)a;
    const RfIdx* y = (const RfIdx*)b;
    if (x->begin < y->begin) return -1;
    if (x->begin > y->begin) return 1;
    if (x->end < y->end) return -1;
    if (x->end > y->end) return 1;
    return 0;
}

static int clamp_int(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static void add_score(int* score, int add) {
    if (!score) return;
    *score += add;
}

static double safe_ratio(double a, double b) { return (b == 0.0) ? 0.0 : (a / b); }


const char* heuristics_evidence_family_name(uint32_t bit) {
    switch (bit) {
        case HEF_TABLE_INTEGRITY: return "table_integrity";
        case HEF_UNWIND_INTEGRITY: return "unwind_integrity";
        case HEF_METADATA_PLACEMENT: return "metadata_placement";
        case HEF_UNWIND_REUSE: return "unwind_reuse";
        case HEF_HANDLER_DOMINANCE: return "handler_dominance";
        default: return "unknown";
    }
}

size_t heuristics_evidence_family_count(uint32_t mask) {
    size_t n = 0;
    while (mask) {
        n += (mask & 1u) ? 1u : 0u;
        mask >>= 1;
    }
    return n;
}

static uint32_t family_bit_from_name(const char* family) {
    if (!family) return 0;
    if (strcmp(family, "table_integrity") == 0) return HEF_TABLE_INTEGRITY;
    if (strcmp(family, "unwind_integrity") == 0) return HEF_UNWIND_INTEGRITY;
    if (strcmp(family, "metadata_placement") == 0) return HEF_METADATA_PLACEMENT;
    if (strcmp(family, "unwind_reuse") == 0) return HEF_UNWIND_REUSE;
    if (strcmp(family, "handler_dominance") == 0) return HEF_HANDLER_DOMINANCE;
    return 0;
}

static void safe_copy(char* dst, size_t dst_cap, const char* src) {
    if (!dst || dst_cap == 0) return;
    if (!src) src = "";
    snprintf(dst, dst_cap, "%s", src);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

static HeuristicFinding* add_finding(HeuristicReport* out,
                                     const char* code,
                                     const char* family,
                                     const char* severity,
                                     const char* fmt,
                                     ...) {
    if (!out || !fmt) return NULL;

    char msg[192];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    out->evidence_families_mask |= family_bit_from_name(family);

    HeuristicFinding* stored = NULL;
    if (out->finding_count < HEURISTICS_MAX_FINDINGS) {
        HeuristicFinding* f = &out->findings[out->finding_count++];
        memset(f, 0, sizeof(*f));
        safe_copy(f->code, sizeof(f->code), code ? code : "unspecified");
        safe_copy(f->family, sizeof(f->family), family ? family : "unknown");
        safe_copy(f->severity, sizeof(f->severity), severity ? severity : "info");
        safe_copy(f->message, sizeof(f->message), msg);
        stored = f;
    }

    sb_appendf(&out->details, "- [%s/%s] %s\n",
               severity ? severity : "info",
               code ? code : "unspecified",
               msg);
    return stored;
}

static void annotate_finding(HeuristicFinding* finding,
                             FindingLocation location,
                             size_t affected_count) {
    if (!finding) return;
    finding->has_location = location.set;
    finding->representative_rva = location.rva;
    finding->affected_count = affected_count;
}

static void append_note(HeuristicReport* out, const char* fmt, ...) {
    if (!out || !fmt) return;

    char msg[192];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    sb_appendf(&out->details, "- [info] %s\n", msg);
}

static size_t count_findings_with_severity(const HeuristicReport* out, const char* sev) {
    size_t n = 0;
    if (!out || !sev) return 0;
    for (size_t i = 0; i < out->finding_count; i++) {
        if (strcmp(out->findings[i].severity, sev) == 0) n++;
    }
    return n;
}

static bool has_finding_code(const HeuristicReport* out, const char* code) {
    if (!out || !code) return false;
    for (size_t i = 0; i < out->finding_count; i++) {
        if (strcmp(out->findings[i].code, code) == 0) return true;
    }
    return false;
}

static void add_mitigation(HeuristicReport* out, const char* code, const char* fmt, ...) {
    if (!out || !fmt) return;
    if (out->mitigation_count >= HEURISTICS_MAX_MITIGATIONS) return;

    char msg[192];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    HeuristicMitigation* m = &out->mitigations[out->mitigation_count++];
    memset(m, 0, sizeof(*m));
    safe_copy(m->code, sizeof(m->code), code ? code : "unspecified");
    safe_copy(m->message, sizeof(m->message), msg);

    sb_appendf(&out->details, "  [mitigation/%s] %s\n",
               code ? code : "unspecified",
               msg);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

static const char* evidence_level_from_counts(size_t weak_count,
                                              size_t medium_count,
                                              size_t strong_count,
                                              int score) {
    if (strong_count >= 2 || score >= 70) return "strong";
    if (strong_count >= 1 || medium_count >= 2 || score >= 30) return "medium";
    if (weak_count || medium_count || strong_count || score > 0) return "weak";
    return "none";
}

static void finalize_verdict(HeuristicReport* out) {
    if (!out) return;

    out->suspicion = safe_ratio((double)out->score, 100.0);

    size_t family_count = heuristics_evidence_family_count(out->evidence_families_mask);
    size_t strong_count = count_findings_with_severity(out, "high") + count_findings_with_severity(out, "critical");
    size_t medium_count = count_findings_with_severity(out, "medium");
    size_t weak_count = 0;
    if (out->finding_count >= strong_count + medium_count) weak_count = out->finding_count - strong_count - medium_count;

    out->strong_finding_count = strong_count;
    out->medium_finding_count = medium_count;
    out->weak_finding_count = weak_count;
    safe_copy(out->evidence_level, sizeof(out->evidence_level),
              evidence_level_from_counts(weak_count, medium_count, strong_count, out->score));

    double confidence = CONFIDENCE_BASE;
    confidence += (double)family_count * CONFIDENCE_PER_FAMILY;
    confidence += (double)strong_count * CONFIDENCE_PER_STRONG;
    confidence += (double)medium_count * CONFIDENCE_PER_MEDIUM;

    if (out->rf_invalid_ranges || out->rf_oob || out->rf_unwind_oob || out->rf_overlaps) confidence += CONFIDENCE_BONUS_TABLE_HARD;
    if (out->unwind_parse_fail || out->unwind_anomalies) confidence += CONFIDENCE_BONUS_UNWIND_HARD;
    if (out->score == 0) confidence = CONFIDENCE_ZERO_SCORE_BASE;

    /* Weakening rules: lower confidence when only isolated / non-correlated static signals exist. */
    if (out->finding_count == 1 && strong_count == 0) {
        add_mitigation(out, "single_signal_only",
                       "Only one non-strong signal contributed; treat as weak standalone evidence.");
        confidence -= CONFIDENCE_PENALTY_SINGLE_SIGNAL;
    }
    if (out->total < 32 && strong_count == 0 && out->finding_count > 0) {
        add_mitigation(out, "small_sample_size",
                       "Very small .pdata sample can overstate ratios; confidence reduced until more functions are observed.");
        confidence -= CONFIDENCE_PENALTY_SMALL_SAMPLE;
    }
    if (out->unwind_unusual_section > 0 &&
        out->unwind_exec_section == 0 &&
        out->unwind_writable_section == 0 &&
        out->handler_nonexec_section == 0 &&
        out->handler_writable_section == 0 &&
        out->rf_invalid_ranges == 0 &&
        out->rf_oob == 0 &&
        out->rf_unwind_oob == 0 &&
        out->unwind_parse_fail == 0 &&
        out->unwind_anomalies == 0) {
        add_mitigation(out, "placement_only_signal",
                       "Placement-only anomalies may come from uncommon but benign layouts; manual verification required.");
        confidence -= CONFIDENCE_PENALTY_PLACEMENT_ONLY;
    }
    if ((out->strong_finding_count == 0) && (family_count <= 1) && out->finding_count > 0) {
        add_mitigation(out, "single_family_only",
                       "Evidence comes from only one family; cross-layer corroboration is recommended before strong conclusions.");
        confidence -= CONFIDENCE_PENALTY_SINGLE_FAMILY;
    }

    if (confidence < CONFIDENCE_MIN) confidence = CONFIDENCE_MIN;
    if (confidence > CONFIDENCE_MAX) confidence = CONFIDENCE_MAX;
    out->confidence = confidence;

    out->requires_manual_review =
        (out->score >= 20) ||
        (out->unwind_exec_section > 0) ||
        (out->unwind_writable_section > 0) ||
        (out->handler_nonexec_section > 0) ||
        (out->handler_writable_section > 0) ||
        (out->unwind_parse_fail > 0) ||
        (out->mitigation_count > 0);

    if (out->score >= 70) safe_copy(out->verdict, sizeof(out->verdict), "high_suspicion");
    else if (out->score >= 40) safe_copy(out->verdict, sizeof(out->verdict), "moderate_suspicion");
    else if (out->score >= 15) safe_copy(out->verdict, sizeof(out->verdict), "low_suspicion");
    else safe_copy(out->verdict, sizeof(out->verdict), "no_strong_static_anomalies");
}

bool heuristics_analyze(const PeImage* img,
                        const RuntimeFunction* rf,
                        const UnwindSummary* us,
                        const bool* us_ok,
                        size_t n,
                        HeuristicReport* out,
                        StrBuf* err) {
    if (!img || !out || !err) return false;
    if (n > 0 && (!rf || !us || !us_ok)) return false;
    memset(out, 0, sizeof(*out));
    if (!sb_init(&out->details, 1024)) {
        sb_append(err, "Out of memory (details buffer).\n");
        return false;
    }
    out->total = n;
    out->pe_section_raw_oob = img->section_raw_oob;
    out->pe_section_virtual_oob = img->section_virtual_oob;
    out->pe_section_raw_overlaps = img->section_raw_overlaps;
    out->pe_section_virtual_overlaps = img->section_virtual_overlaps;
    out->pe_section_misaligned = img->section_misaligned;
    out->pe_exception_directory_oob = img->exception_directory_oob;

    /* RUNTIME_FUNCTION sanity */
    uint32_t prev_begin = 0;
    bool prev_valid = false;
    size_t unsorted = 0;
    FindingLocation invalid_range_loc = {0};
    FindingLocation rf_oob_loc = {0};
    FindingLocation unwind_oob_loc = {0};
    FindingLocation unsorted_loc = {0};
    FindingLocation overlap_loc = {0};
    FindingLocation duplicate_loc = {0};
    FindingLocation parse_fail_loc = {0};
    FindingLocation anomaly_loc = {0};
    FindingLocation unusual_unwind_loc = {0};
    FindingLocation executable_unwind_loc = {0};
    FindingLocation writable_unwind_loc = {0};
    FindingLocation nonexec_handler_loc = {0};
    FindingLocation writable_handler_loc = {0};

    HMap unwind_counts = {0};
    HMap handler_counts = {0};
    if (n > (SIZE_MAX - 1u) / 2u) {
        sb_append(err, "Runtime function count is too large for reuse analysis.\n");
        sb_free(&out->details);
        return false;
    }
    if (!hmap_init(&unwind_counts, n * 2 + 1u) ||
        !hmap_init(&handler_counts, 128)) {
        sb_append(err, "Out of memory (hash maps).\n");
        hmap_free(&unwind_counts);
        hmap_free(&handler_counts);
        sb_free(&out->details);
        return false;
    }

    for (size_t i = 0; i < n; i++) {
        uint32_t b = rf[i].begin_rva;
        uint32_t e = rf[i].end_rva;
        uint32_t u = rf[i].unwind_rva;

        if (e <= b) {
            out->rf_invalid_ranges++;
            remember_location(&invalid_range_loc, b);
        }
        if (b >= img->size_of_image || e > img->size_of_image) {
            out->rf_oob++;
            remember_location(&rf_oob_loc, b);
        }
        if (u >= img->size_of_image || u == 0) {
            out->rf_unwind_oob++;
            remember_location(&unwind_oob_loc, u);
        }

        if (prev_valid && b < prev_begin) {
            unsorted++;
            remember_location(&unsorted_loc, b);
        }
        prev_begin = b;
        prev_valid = true;

        if (!hmap_inc(&unwind_counts, u, NULL)) {
            sb_append(err, "Out of memory while counting unwind metadata reuse.\n");
            hmap_free(&unwind_counts);
            hmap_free(&handler_counts);
            sb_free(&out->details);
            return false;
        }

        if (us_ok[i] && us[i].has_handler) {
            out->handler_count++;
            if (!hmap_inc(&handler_counts, us[i].handler_rva, NULL)) {
                sb_append(err, "Out of memory while counting handler reuse.\n");
                hmap_free(&unwind_counts);
                hmap_free(&handler_counts);
                sb_free(&out->details);
                return false;
            }
        }

        /* Section placement sanity: unwind info is typically in non-executable data (.xdata/.rdata).
           Placing unwind metadata in executable / unusual sections is a common interception/tampering artifact. */
        if (us_ok[i]) {
            const PeSection* su = pe_find_section_for_rva(img, u);
            if (!su) {
                out->unwind_unusual_section++;
                remember_location(&unusual_unwind_loc, u);
            } else {
                bool allowed = sec_name_allowed_for_unwind(su->name);
                bool plausible = sec_name_plausibly_unwind_named(su->name);
                if (!allowed && !plausible) {
                    out->unwind_unusual_section++;
                    remember_location(&unusual_unwind_loc, u);
                }
                if (su->characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    out->unwind_exec_section++;
                    remember_location(&executable_unwind_loc, u);
                }
                if (su->characteristics & IMAGE_SCN_MEM_WRITE) {
                    out->unwind_writable_section++;
                    remember_location(&writable_unwind_loc, u);
                }
            }

            if (us[i].has_handler) {
                const PeSection* sh = pe_find_section_for_rva(img, us[i].handler_rva);
                if (!sh || !(sh->characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                    out->handler_nonexec_section++;
                    remember_location(&nonexec_handler_loc, us[i].handler_rva);
                }
                if (sh && (sh->characteristics & IMAGE_SCN_MEM_WRITE)) {
                    out->handler_writable_section++;
                    remember_location(&writable_handler_loc, us[i].handler_rva);
                }
            }
        }

        if (!us_ok[i]) {
            out->unwind_parse_fail++;
            remember_location(&parse_fail_loc, u);
        } else if (us[i].anomalies & (uint32_t)~UA_ABI_MASK) {
            out->unwind_anomalies++;
            remember_location(&anomaly_loc, u);
        }
        if (us_ok[i] && (us[i].anomalies & UA_ABI_MASK)) {
            out->unwind_abi_warnings++;
        }
    }
    out->rf_unsorted = unsorted;

    /* Overlap / duplicates check on sorted array */
    RfIdx* idx = NULL;
    if (n > 0) {
        idx = (RfIdx*)malloc(n * sizeof(RfIdx));
        if (!idx) {
            sb_append(err, "Out of memory (sort array).\n");
            hmap_free(&unwind_counts);
            hmap_free(&handler_counts);
            sb_free(&out->details);
            return false;
        }
        for (size_t i = 0; i < n; i++) { idx[i].begin = rf[i].begin_rva; idx[i].end = rf[i].end_rva; }
        qsort(idx, n, sizeof(RfIdx), cmp_rfidx);

        uint32_t max_end = 0;
        uint32_t sorted_prev_begin = 0;
        bool have_prev = false;
        for (size_t i = 0; i < n; i++) {
            if (have_prev) {
                if (idx[i].begin == sorted_prev_begin) {
                    out->rf_duplicate_begins++;
                    remember_location(&duplicate_loc, idx[i].begin);
                }
                if (idx[i].begin < max_end) {
                    out->rf_overlaps++;
                    remember_location(&overlap_loc, idx[i].begin);
                }
            }
            sorted_prev_begin = idx[i].begin;
            if (!have_prev || idx[i].end > max_end) max_end = idx[i].end;
            have_prev = true;
        }
    }
    free(idx);

    uint32_t unwind_max = hmap_max_val(&unwind_counts);
    uint32_t dominant_unwind_rva = 0;
    (void)hmap_max_entry(&unwind_counts, &dominant_unwind_rva, NULL);
    size_t unwind_unique = hmap_unique(&unwind_counts);
    out->unwind_reuse_ratio = safe_ratio((double)unwind_max, (double)n);
    out->unwind_unique_ratio = safe_ratio((double)unwind_unique, (double)n);

    uint32_t handler_max = hmap_max_val(&handler_counts);
    uint32_t dominant_handler_rva = 0;
    (void)hmap_max_entry(&handler_counts, &dominant_handler_rva, NULL);
    out->handler_reuse_ratio = (out->handler_count > 0) ? safe_ratio((double)handler_max, (double)out->handler_count) : 0.0;

    /* Scoring */
    int score = 0;
    if (out->pe_section_raw_oob) {
        add_score(&score, SCORE_PE_SECTION_RAW_OOB);
        annotate_finding(
            add_finding(out, "pe_section_raw_oob", "table_integrity", "high",
                        "Section raw ranges exceed the input file: %zu", out->pe_section_raw_oob),
            first_pe_section_issue(img, PE_ISSUE_RAW_OOB), out->pe_section_raw_oob);
    }
    if (out->pe_section_virtual_oob) {
        add_score(&score, SCORE_PE_SECTION_VIRTUAL_OOB);
        annotate_finding(
            add_finding(out, "pe_section_virtual_oob", "table_integrity", "high",
                        "Section virtual ranges exceed SizeOfImage: %zu", out->pe_section_virtual_oob),
            first_pe_section_issue(img, PE_ISSUE_VIRTUAL_OOB), out->pe_section_virtual_oob);
    }
    if (out->pe_section_raw_overlaps) {
        add_score(&score, SCORE_PE_SECTION_RAW_OVERLAP);
        annotate_finding(
            add_finding(out, "pe_section_raw_overlap", "table_integrity", "medium",
                        "Overlapping section raw ranges: %zu", out->pe_section_raw_overlaps),
            first_pe_section_issue(img, PE_ISSUE_RAW_OVERLAP), out->pe_section_raw_overlaps);
    }
    if (out->pe_section_virtual_overlaps) {
        add_score(&score, SCORE_PE_SECTION_VIRTUAL_OVERLAP);
        annotate_finding(
            add_finding(out, "pe_section_virtual_overlap", "table_integrity", "high",
                        "Overlapping section virtual ranges: %zu", out->pe_section_virtual_overlaps),
            first_pe_section_issue(img, PE_ISSUE_VIRTUAL_OVERLAP), out->pe_section_virtual_overlaps);
    }
    if (out->pe_section_misaligned) {
            add_score(&score, SCORE_PE_SECTION_MISALIGNED);
        annotate_finding(
            add_finding(out, "pe_section_misaligned", "table_integrity", "medium",
                        "PE alignment/header invariants or section alignment rules are violated: %zu",
                        out->pe_section_misaligned),
            first_pe_section_issue(img, PE_ISSUE_MISALIGNED), out->pe_section_misaligned);
    }
    if (out->pe_exception_directory_oob) {
        FindingLocation location = { true, img->exception_rva };
        add_score(&score, SCORE_PE_EXCEPTION_DIRECTORY_OOB);
        annotate_finding(
            add_finding(out, "pe_exception_directory_oob", "table_integrity", "high",
                        "Exception directory is malformed, unreadable, incomplete, or out of bounds."),
            location, 1);
    }
    if (n == 0 &&
        img->exception_rva == 0 &&
        img->exception_size == 0 &&
        image_has_executable_section(img)) {
        add_score(&score, SCORE_EMPTY_PDATA);
        add_finding(out, "no_runtime_functions", "table_integrity", "medium",
                    "No RUNTIME_FUNCTION entries found; this can be valid for a leaf-only image, so confirm code complexity manually.");
    } else if (n == 0 && img->exception_rva == 0 && img->exception_size == 0) {
        append_note(out, "No RUNTIME_FUNCTION entries and no executable sections; this is consistent with a resource-only or forwarding image.");
    }

    double invalid_ranges_pct = safe_ratio((double)out->rf_invalid_ranges, (double)n);
    double oob_pct = safe_ratio((double)out->rf_oob, (double)n);
    double unwind_oob_pct = safe_ratio((double)out->rf_unwind_oob, (double)n);
    double unwind_fail_pct = safe_ratio((double)out->unwind_parse_fail, (double)n);
    double unwind_anom_pct = safe_ratio((double)out->unwind_anomalies, (double)n);

    if (out->rf_invalid_ranges) {
        add_score(&score, invalid_ranges_pct > THRESHOLD_HIGH_PERCENT ? SCORE_INVALID_RANGE_HIGH : SCORE_INVALID_RANGE_LOW);
        annotate_finding(
            add_finding(out, "invalid_ranges", "table_integrity", invalid_ranges_pct > THRESHOLD_HIGH_PERCENT ? "high" : "medium",
                        "Invalid ranges (End<=Begin): %zu (%.2f%%)", out->rf_invalid_ranges, invalid_ranges_pct*100.0),
            invalid_range_loc, out->rf_invalid_ranges);
    }
    if (out->rf_oob) {
        add_score(&score, oob_pct > THRESHOLD_HIGH_PERCENT ? SCORE_RF_OOB_HIGH : SCORE_RF_OOB_LOW);
        annotate_finding(
            add_finding(out, "rf_oob", "table_integrity", oob_pct > THRESHOLD_HIGH_PERCENT ? "high" : "medium",
                        "Begin/End out of SizeOfImage: %zu (%.2f%%)", out->rf_oob, oob_pct*100.0),
            rf_oob_loc, out->rf_oob);
    }
    if (out->rf_unwind_oob) {
        add_score(&score, unwind_oob_pct > THRESHOLD_HIGH_PERCENT ? SCORE_UNWIND_RVA_OOB_HIGH : SCORE_UNWIND_RVA_OOB_LOW);
        annotate_finding(
            add_finding(out, "unwind_rva_oob", "table_integrity", unwind_oob_pct > THRESHOLD_HIGH_PERCENT ? "high" : "medium",
                        "UnwindInfoRVA missing/out-of-bounds: %zu (%.2f%%)", out->rf_unwind_oob, unwind_oob_pct*100.0),
            unwind_oob_loc, out->rf_unwind_oob);
    }
    if (out->rf_unsorted) {
        add_score(&score, out->rf_unsorted > 0 ? SCORE_RF_UNSORTED : 0);
        annotate_finding(
            add_finding(out, "rf_unsorted", "table_integrity", "medium",
                        "Table not sorted by BeginAddress: %zu inversions", out->rf_unsorted),
            unsorted_loc, out->rf_unsorted);
    }
    if (out->rf_overlaps) {
        add_score(&score, out->rf_overlaps > 0 ? SCORE_RF_OVERLAP : 0);
        annotate_finding(
            add_finding(out, "rf_overlaps", "table_integrity", "high",
                        "Overlapping ranges (after sorting): %zu", out->rf_overlaps),
            overlap_loc, out->rf_overlaps);
    }
    if (out->rf_duplicate_begins) {
        add_score(&score, SCORE_DUPLICATE_BEGIN);
        annotate_finding(
            add_finding(out, "duplicate_begin", "table_integrity", "medium",
                        "Duplicate BeginAddress (after sorting): %zu", out->rf_duplicate_begins),
            duplicate_loc, out->rf_duplicate_begins);
    }

    if (out->unwind_parse_fail) {
        add_score(&score, unwind_fail_pct > THRESHOLD_HIGH_PERCENT ? SCORE_UNWIND_PARSE_FAIL_HIGH : SCORE_UNWIND_PARSE_FAIL_LOW);
        annotate_finding(
            add_finding(out, "unwind_parse_fail", "unwind_integrity", unwind_fail_pct > THRESHOLD_HIGH_PERCENT ? "high" : "medium",
                        "UnwindInfo parse failures: %zu (%.2f%%)", out->unwind_parse_fail, unwind_fail_pct*100.0),
            parse_fail_loc, out->unwind_parse_fail);
    }
    if (out->unwind_anomalies) {
        add_score(&score, unwind_anom_pct > THRESHOLD_UNWIND_ANOM_HIGH ? SCORE_UNWIND_ANOM_HIGH : SCORE_UNWIND_ANOM_LOW);
        annotate_finding(
            add_finding(out, "unwind_anomalies", "unwind_integrity", unwind_anom_pct > THRESHOLD_UNWIND_ANOM_HIGH ? "high" : "medium",
                        "UnwindInfo anomalies (version/opcode/chain/etc): %zu (%.2f%%)", out->unwind_anomalies, unwind_anom_pct*100.0),
            anomaly_loc, out->unwind_anomalies);
    }

    bool moderate_reuse_candidate =
        out->unwind_reuse_ratio > THRESHOLD_UNWIND_REUSE_MEDIUM && n > 200;
    if (out->unwind_reuse_ratio > THRESHOLD_UNWIND_REUSE_HIGH && n > 200) {
        add_score(&score, SCORE_UNWIND_REUSE_HIGH);
        FindingLocation location = { true, dominant_unwind_rva };
        annotate_finding(
            add_finding(out, "unwind_reuse_strong", "unwind_reuse", "high",
                        "Strong UnwindInfo reuse: max %u entries share same UnwindInfoRVA (ratio=%.2f)",
                        (unsigned)unwind_max, out->unwind_reuse_ratio),
            location, unwind_max);
    }

    if (out->handler_count > 50 && out->handler_reuse_ratio > THRESHOLD_HANDLER_DOMINANCE) {
        bool has_static_context =
            out->rf_invalid_ranges > 0 || out->rf_oob > 0 || out->rf_unwind_oob > 0 || out->rf_unsorted > 0 ||
            out->rf_overlaps > 0 || out->rf_duplicate_begins > 0 || out->unwind_parse_fail > 0 || out->unwind_anomalies > 0 ||
            out->unwind_exec_section > 0 || out->unwind_unusual_section > 0 || out->unwind_writable_section > 0 ||
            out->handler_nonexec_section > 0 || out->handler_writable_section > 0 ||
            moderate_reuse_candidate;
        const PeSection* dominant_sec = dominant_handler_rva ? pe_find_section_for_rva(img, dominant_handler_rva) : NULL;
        bool dominant_runtime_like = dominant_sec &&
                                     (dominant_sec->characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                                     sec_name_code_like(dominant_sec->name) &&
                                     out->handler_nonexec_section == 0;

        if (!(dominant_runtime_like && !has_static_context)) {
            add_score(&score, SCORE_HANDLER_DOMINANCE);
            FindingLocation location = { true, dominant_handler_rva };
            annotate_finding(
                add_finding(out, "handler_dominance", "handler_dominance", "medium",
                            "One handler dominates: max %u entries share same HandlerRVA (ratio=%.2f%s%s)",
                            (unsigned)handler_max, out->handler_reuse_ratio,
                            dominant_sec ? ", section=" : "",
                            dominant_sec ? dominant_sec->name : ""),
                location, handler_max);
        }
    }

    if (moderate_reuse_candidate &&
        !has_finding_code(out, "unwind_reuse_strong") &&
        (has_finding_code(out, "handler_dominance") ||
         out->rf_invalid_ranges > 0 || out->rf_oob > 0 || out->rf_unwind_oob > 0 ||
         out->rf_unsorted > 0 || out->rf_overlaps > 0 || out->rf_duplicate_begins > 0 ||
         out->unwind_parse_fail > 0 || out->unwind_anomalies > 0 ||
         out->unwind_exec_section > 0 || out->unwind_unusual_section > 0 ||
         out->unwind_writable_section > 0 || out->handler_nonexec_section > 0 ||
         out->handler_writable_section > 0)) {
        add_score(&score, SCORE_UNWIND_REUSE_MEDIUM);
        FindingLocation location = { true, dominant_unwind_rva };
        annotate_finding(
            add_finding(out, "unwind_reuse_moderate", "unwind_reuse", "medium",
                        "Moderate UnwindInfo reuse is corroborated by another static signal: max %u entries share same UnwindInfoRVA (ratio=%.2f)",
                        (unsigned)unwind_max, out->unwind_reuse_ratio),
            location, unwind_max);
    }

    /* Placement heuristics */
    if (out->unwind_exec_section) {
        add_score(&score, SCORE_UNWIND_EXEC_SECTION);
        annotate_finding(
            add_finding(out, "unwind_in_exec_section", "metadata_placement", "high",
                        "UnwindInfo located in executable section(s): %zu", out->unwind_exec_section),
            executable_unwind_loc, out->unwind_exec_section);
    }
    if (out->unwind_unusual_section) {
        int add = (out->unwind_unusual_section > (n / 20)) ? SCORE_UNWIND_UNUSUAL_SECTION_HIGH : SCORE_UNWIND_UNUSUAL_SECTION_LOW; /* >5% => broader placement pattern */
        add_score(&score, add);
        annotate_finding(
            add_finding(out, "unwind_unusual_section", "metadata_placement", add >= 15 ? "high" : "medium",
                        "UnwindInfo located in unusual sections (not .xdata/.rdata/.pdata): %zu", out->unwind_unusual_section),
            unusual_unwind_loc, out->unwind_unusual_section);
    }
    if (out->unwind_writable_section) {
        int add = (out->unwind_writable_section > (n / 20)) ? SCORE_UNWIND_WRITABLE_SECTION_HIGH : SCORE_UNWIND_WRITABLE_SECTION_LOW;
        add_score(&score, add);
        annotate_finding(
            add_finding(out, "unwind_writable_section", "metadata_placement", add >= 18 ? "high" : "medium",
                        "UnwindInfo located in writable section(s): %zu", out->unwind_writable_section),
            writable_unwind_loc, out->unwind_writable_section);
    }
    if (out->handler_nonexec_section) {
        add_score(&score, SCORE_HANDLER_NONEXEC);
        annotate_finding(
            add_finding(out, "handler_nonexec_section", "metadata_placement", "high",
                        "Exception handler RVA in non-executable/unknown section: %zu", out->handler_nonexec_section),
            nonexec_handler_loc, out->handler_nonexec_section);
    }
    if (out->handler_writable_section) {
        add_score(&score, SCORE_HANDLER_WRITABLE);
        annotate_finding(
            add_finding(out, "handler_writable_section", "metadata_placement", "medium",
                        "Exception handler RVA in writable section(s): %zu", out->handler_writable_section),
            writable_handler_loc, out->handler_writable_section);
    }

    if (out->unwind_exec_section > 0 && out->handler_nonexec_section > 0) {
        add_score(&score, SCORE_COMBO_PLACEMENT_EXEC_AND_HANDLER);
        annotate_finding(
            add_finding(out, "placement_exec_nonexec_handler_combo", "metadata_placement", "high",
                        "Unwind metadata in executable section(s) coincides with handler targets in non-executable/unknown section(s); the combined placement pattern is much harder to explain benignly."),
            executable_unwind_loc,
            out->unwind_exec_section + out->handler_nonexec_section);
    }
    if ((out->unwind_exec_section > 0 || out->handler_nonexec_section > 0) &&
        (out->unwind_parse_fail > 0 || out->unwind_anomalies > 0 || out->rf_unwind_oob > 0)) {
        add_score(&score, SCORE_COMBO_PLACEMENT_AND_INTEGRITY);
        FindingLocation placement_loc = executable_unwind_loc.set
            ? executable_unwind_loc
            : nonexec_handler_loc;
        annotate_finding(
            add_finding(out, "placement_integrity_combo", "unwind_integrity", "medium",
                        "Suspicious metadata placement is corroborated by UNWIND_INFO / UnwindInfoRVA integrity problems; treat the combination as stronger than either signal alone."),
            placement_loc,
            out->unwind_exec_section + out->handler_nonexec_section +
                out->unwind_parse_fail + out->unwind_anomalies + out->rf_unwind_oob);
    }
    if (out->unwind_reuse_ratio > THRESHOLD_UNWIND_REUSE_MEDIUM && has_finding_code(out, "handler_dominance")) {
        add_score(&score, SCORE_COMBO_REUSE_AND_DOMINANCE);
        FindingLocation location = { true, dominant_unwind_rva };
        annotate_finding(
            add_finding(out, "reuse_dominance_combo", "unwind_reuse", "medium",
                        "Heavy UnwindInfo reuse coincides with a dominant handler target, which is consistent with centralized dispatcher-style metadata reuse."),
            location, unwind_max);
    }
    if (out->unwind_writable_section > 0 && out->handler_writable_section > 0) {
        add_score(&score, SCORE_COMBO_WRITABLE_METADATA_AND_HANDLER);
        annotate_finding(
            add_finding(out, "writable_metadata_handler_combo", "metadata_placement", "high",
                        "Writable unwind metadata coincides with writable handler targets; this combination is uncommon for normal compiler-produced images and deserves close review."),
            writable_unwind_loc,
            out->unwind_writable_section + out->handler_writable_section);
    }

    if (score == 0) {
        append_note(out, "No strong anomalies detected by heuristics.");
    }
    out->score_weight_sum = score;
    out->score = clamp_int(score, 0, 100);
    finalize_verdict(out);

    hmap_free(&unwind_counts);
    hmap_free(&handler_counts);
    if (!sb_ok(&out->details)) {
        sb_append(err, "Out of memory while building heuristic details.\n");
        return false;
    }
    return true;
}

int heuristics_finding_score_contribution(const HeuristicReport* report,
                                          const char* finding_code) {
    if (!report || !finding_code) return 0;
    if (strcmp(finding_code, "pe_section_raw_oob") == 0) return SCORE_PE_SECTION_RAW_OOB;
    if (strcmp(finding_code, "pe_section_virtual_oob") == 0) return SCORE_PE_SECTION_VIRTUAL_OOB;
    if (strcmp(finding_code, "pe_section_raw_overlap") == 0) return SCORE_PE_SECTION_RAW_OVERLAP;
    if (strcmp(finding_code, "pe_section_virtual_overlap") == 0) return SCORE_PE_SECTION_VIRTUAL_OVERLAP;
    if (strcmp(finding_code, "pe_section_misaligned") == 0) return SCORE_PE_SECTION_MISALIGNED;
    if (strcmp(finding_code, "pe_exception_directory_oob") == 0) return SCORE_PE_EXCEPTION_DIRECTORY_OOB;
    if (strcmp(finding_code, "no_runtime_functions") == 0) return SCORE_EMPTY_PDATA;
    if (strcmp(finding_code, "invalid_ranges") == 0) {
        return safe_ratio((double)report->rf_invalid_ranges, (double)report->total) > THRESHOLD_HIGH_PERCENT
            ? SCORE_INVALID_RANGE_HIGH : SCORE_INVALID_RANGE_LOW;
    }
    if (strcmp(finding_code, "rf_oob") == 0) {
        return safe_ratio((double)report->rf_oob, (double)report->total) > THRESHOLD_HIGH_PERCENT
            ? SCORE_RF_OOB_HIGH : SCORE_RF_OOB_LOW;
    }
    if (strcmp(finding_code, "unwind_rva_oob") == 0) {
        return safe_ratio((double)report->rf_unwind_oob, (double)report->total) > THRESHOLD_HIGH_PERCENT
            ? SCORE_UNWIND_RVA_OOB_HIGH : SCORE_UNWIND_RVA_OOB_LOW;
    }
    if (strcmp(finding_code, "rf_unsorted") == 0) return SCORE_RF_UNSORTED;
    if (strcmp(finding_code, "rf_overlaps") == 0) return SCORE_RF_OVERLAP;
    if (strcmp(finding_code, "duplicate_begin") == 0) return SCORE_DUPLICATE_BEGIN;
    if (strcmp(finding_code, "unwind_parse_fail") == 0) {
        return safe_ratio((double)report->unwind_parse_fail, (double)report->total) > THRESHOLD_HIGH_PERCENT
            ? SCORE_UNWIND_PARSE_FAIL_HIGH : SCORE_UNWIND_PARSE_FAIL_LOW;
    }
    if (strcmp(finding_code, "unwind_anomalies") == 0) {
        return safe_ratio((double)report->unwind_anomalies, (double)report->total) > THRESHOLD_UNWIND_ANOM_HIGH
            ? SCORE_UNWIND_ANOM_HIGH : SCORE_UNWIND_ANOM_LOW;
    }
    if (strcmp(finding_code, "unwind_reuse_strong") == 0) return SCORE_UNWIND_REUSE_HIGH;
    if (strcmp(finding_code, "unwind_reuse_moderate") == 0) return SCORE_UNWIND_REUSE_MEDIUM;
    if (strcmp(finding_code, "handler_dominance") == 0) return SCORE_HANDLER_DOMINANCE;
    if (strcmp(finding_code, "unwind_in_exec_section") == 0) return SCORE_UNWIND_EXEC_SECTION;
    if (strcmp(finding_code, "unwind_unusual_section") == 0) {
        return report->unwind_unusual_section > (report->total / 20u)
            ? SCORE_UNWIND_UNUSUAL_SECTION_HIGH : SCORE_UNWIND_UNUSUAL_SECTION_LOW;
    }
    if (strcmp(finding_code, "unwind_writable_section") == 0) {
        return report->unwind_writable_section > (report->total / 20u)
            ? SCORE_UNWIND_WRITABLE_SECTION_HIGH : SCORE_UNWIND_WRITABLE_SECTION_LOW;
    }
    if (strcmp(finding_code, "handler_nonexec_section") == 0) return SCORE_HANDLER_NONEXEC;
    if (strcmp(finding_code, "handler_writable_section") == 0) return SCORE_HANDLER_WRITABLE;
    if (strcmp(finding_code, "placement_exec_nonexec_handler_combo") == 0) return SCORE_COMBO_PLACEMENT_EXEC_AND_HANDLER;
    if (strcmp(finding_code, "placement_integrity_combo") == 0) return SCORE_COMBO_PLACEMENT_AND_INTEGRITY;
    if (strcmp(finding_code, "reuse_dominance_combo") == 0) return SCORE_COMBO_REUSE_AND_DOMINANCE;
    if (strcmp(finding_code, "writable_metadata_handler_combo") == 0) return SCORE_COMBO_WRITABLE_METADATA_AND_HANDLER;
    return 0;
}

void heuristics_free(HeuristicReport* r) {
    if (!r) return;
    sb_free(&r->details);
    memset(r, 0, sizeof(*r));
}
