#pragma once
/*
  report.h - output helpers (stdout, CSV, JSON)
*/

#include <stddef.h>
#include <stdbool.h>
#include "pe.h"
#include "unwind.h"
#include "heuristics.h"
#include "dynamic.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ReportMetadata {
    const char* tool_version;
    const char* report_schema_version;
    const char* generated_at_utc;
    const char* input_sha256;
    uint64_t input_size;
    const char* command_line;
    const char* build_compiler;
    const char* build_platform;
    const char* build_mode;
    bool strict_abi;
    bool follow_chain;
    uint32_t max_chain_depth;
} ReportMetadata;

void report_print_brief(const char* path, const PeImage* img, size_t rf_count);

bool report_write_input_validation_json(const char* path,
                                        const char* input_path,
                                        const PeInputValidation* validation,
                                        const char* parser_diagnostic,
                                        const ReportMetadata* metadata,
                                        StrBuf* err);

bool report_write_input_validation_html(const char* path,
                                        const char* input_path,
                                        const PeInputValidation* validation,
                                        const char* parser_diagnostic,
                                        const ReportMetadata* metadata,
                                        StrBuf* err);

bool report_write_csv(const char* path,
                      const PeImage* img,
                      const RuntimeFunction* rf,
                      const UnwindSummary* us,
                      const bool* us_ok,
                      size_t n,
                      bool ghidra_mode,
                      StrBuf* err);

bool report_write_json_ex(const char* path,
                          const char* input_path,
                          const PeImage* img,
                          const RuntimeFunction* rf,
                          const UnwindSummary* us,
                          const bool* us_ok,
                          size_t n,
                          const HeuristicReport* hr,
                          const DynamicReport* dr,
                          const ReportMetadata* metadata,
                          StrBuf* err);

bool report_write_html(const char* path,
                       const char* input_path,
                       const PeImage* img,
                       const RuntimeFunction* rf,
                       const UnwindSummary* us,
                       const bool* us_ok,
                       size_t n,
                       const HeuristicReport* hr,
                       const DynamicReport* dr,
                       const ReportMetadata* metadata,
                       StrBuf* err);

void report_print_heuristics(const HeuristicReport* hr);

#ifdef __cplusplus
}
#endif
