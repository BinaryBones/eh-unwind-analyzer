#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "heuristics.h"
#include "pe.h"
#include "unwind.h"
#include "util.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Buf buffer = { .data = data, .size = size };
    StrBuf error = {0};
    PeImage image;
    RuntimeFunction* functions = NULL;
    size_t function_count = 0;

    if (!sb_init(&error, 256)) return 0;
    if (!pe_parse(&image, &buffer, &error)) {
        sb_free(&error);
        return 0;
    }

    error.len = 0;
    if (error.s) error.s[0] = '\0';
    if (!unwind_read_runtime_functions(
            &buffer, &image, &functions, &function_count, &error)) {
        pe_free(&image);
        sb_free(&error);
        return 0;
    }

    size_t analyzed_count = function_count > 4096 ? 4096 : function_count;
    UnwindSummary* summaries = (UnwindSummary*)calloc(
        analyzed_count ? analyzed_count : 1, sizeof(UnwindSummary));
    bool* parsed = (bool*)calloc(analyzed_count ? analyzed_count : 1, sizeof(bool));
    if (summaries && parsed) {
        UnwindParseOpts options = {
            .max_chain_depth = 8,
            .follow_chain = true,
            .strict_abi = false
        };
        for (size_t i = 0; i < analyzed_count; i++) {
            StrBuf parse_error = {0};
            if (!sb_init(&parse_error, 128)) break;
            parsed[i] = unwind_parse(
                &buffer,
                &image,
                functions[i].unwind_rva,
                &options,
                &summaries[i],
                NULL,
                &parse_error);
            sb_free(&parse_error);
        }

        HeuristicReport report;
        StrBuf heuristic_error = {0};
        if (sb_init(&heuristic_error, 128)) {
            if (heuristics_analyze(
                    &image,
                    functions,
                    summaries,
                    parsed,
                    analyzed_count,
                    &report,
                    &heuristic_error)) {
                heuristics_free(&report);
            }
            sb_free(&heuristic_error);
        }
    }

    free(parsed);
    free(summaries);
    free(functions);
    pe_free(&image);
    sb_free(&error);
    return 0;
}
