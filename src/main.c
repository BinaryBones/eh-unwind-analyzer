#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#include "util.h"
#include "pe.h"
#include "unwind.h"
#include "heuristics.h"
#include "report.h"
#include "dynamic.h"
#include "app_info.h"

#if defined(_WIN32)
#include <windows.h>
#endif

typedef struct Args {
    const char* input;
    bool dump;
    bool show_ops;
    bool heuristics;
    const char* csv_path;
    const char* ghidra_csv_path;
    const char* json_path;
    const char* html_path;
    int  dump_limit;        /* -1 => all */
    bool follow_chain;
    bool strict_abi;
    int  max_chain_depth;
    bool dynamic;
    uint32_t timeout_ms;
    uint32_t trace_steps;
    const char** child_argv;
    int child_argc;
} Args;

typedef enum ParseResult {
    PARSE_OK = 0,
    PARSE_HELP = 1,
    PARSE_VERSION = 2,
    PARSE_ERR = 3
} ParseResult;

static char* dup_cstr(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char* out = (char*)malloc(n + 1u);
    if (!out) return NULL;
    memcpy(out, s, n + 1u);
    return out;
}

static char* argv_text_to_utf8(const char* s) {
    if (!s) return NULL;
#if defined(_WIN32)
    int wide_len = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (wide_len <= 0) return dup_cstr(s);
    wchar_t* wide = (wchar_t*)calloc((size_t)wide_len, sizeof(wchar_t));
    if (!wide) return NULL;
    if (MultiByteToWideChar(CP_ACP, 0, s, -1, wide, wide_len) <= 0) {
        free(wide);
        return dup_cstr(s);
    }
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (utf8_len <= 0) {
        free(wide);
        return dup_cstr(s);
    }
    char* out = (char*)malloc((size_t)utf8_len);
    if (!out) {
        free(wide);
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, utf8_len, NULL, NULL) <= 0) {
        free(out);
        free(wide);
        return dup_cstr(s);
    }
    free(wide);
    return out;
#else
    return dup_cstr(s);
#endif
}

static void print_version(void) {
    printf("EH/Unwind Analyzer %s\n", app_version());
    printf("Report schema: %s\n", app_report_schema_version());
    printf("Build: %s, %s, %s\n", app_build_compiler(), app_build_platform(), app_build_mode());
}

static void usage(const char* argv0) {
    printf("EH/Unwind Analyzer %s (PE x64)\n", app_version());
    printf("Usage: %s <pefile> [options]\n\n", argv0);
    printf("Options:\n");
    printf("  --dump                Dump all RUNTIME_FUNCTION entries\n");
    printf("  --limit N             Limit dump to first N entries (default: all when --dump)\n");
    printf("  --ops                 With --dump: also print unwind ops list per function\n");
    printf("  --heuristics          Run EH/Unwind anomaly heuristics and print report\n");
    printf("  --csv <path>          Write analysis CSV (full fields)\n");
    printf("  --ghidra-csv <path>   Write CSV for Ghidra import (begin/end/name/comment)\n");
    printf("  --json <path>         Write JSON (functions + heuristic/dynamic assessment)\n");
    printf("  --html <path>         Write a self-contained interactive HTML report\n");
    printf("  --no-follow-chain     Do not follow UNW_FLAG_CHAININFO\n");
    printf("  --strict-abi          Flag formal Microsoft x64 unwind ABI violations\n");
    printf("  --max-chain-depth N   Max chain depth, 1..16 (default 8)\n");
    printf("  --dynamic             Run Windows-only dynamic exception validation (debugger)\n");
    printf("  --timeout-ms N        Dynamic mode: hard timeout, N>0 (default 15000)\n");
    printf("  --trace-steps N       Dynamic mode: single-step samples after handler hit (default 64, range 0..256)\n");
    printf("  --                    Separator: remaining args are passed to the target program\n");
    printf("  --version             Show version and build information\n");
    printf("  --help                Show this help\n");
}

static bool append_invocation_arg(StrBuf* out, const char* arg) {
    if (!out || !arg) return false;
    bool quote = (*arg == '\0') || strpbrk(arg, " \t\"") != NULL;
    if (!quote) return sb_append(out, arg);
    if (!sb_append(out, "\"")) return false;
    for (const char* p = arg; *p; p++) {
        if (*p == '"' || *p == '\\') {
            if (!sb_appendn(out, "\\", 1)) return false;
        }
        if (!sb_appendn(out, p, 1)) return false;
    }
    return sb_append(out, "\"");
}

static bool build_invocation(int argc, char** argv, StrBuf* out) {
    if (!out) return false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            int redacted = argc - i - 1;
            if (i && !sb_appendn(out, " ", 1)) return false;
            if (!sb_appendf(out, "-- [%d target argument%s redacted]",
                            redacted, redacted == 1 ? "" : "s")) {
                return false;
            }
            break;
        }
        if (i && !sb_appendn(out, " ", 1)) return false;
        char* utf8_arg = argv_text_to_utf8(argv[i]);
        if (!utf8_arg) return false;
        bool ok = append_invocation_arg(out, utf8_arg);
        free(utf8_arg);
        if (!ok) return false;
    }
    return true;
}

static bool parse_long_range(const char* text, long min_value, long max_value, long* out) {
    if (!text || !*text || !out) return false;
    errno = 0;
    char* end = NULL;
    long value = strtol(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0') return false;
    if (value < min_value || value > max_value) return false;
    *out = value;
    return true;
}

static bool parse_u32_range(const char* text, uint32_t min_value, uint32_t max_value, uint32_t* out) {
    if (!text || !*text || !out || text[0] == '-') return false;
    errno = 0;
    char* end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno == ERANGE || end == text || *end != '\0') return false;
    if (value < (unsigned long)min_value || value > (unsigned long)max_value) return false;
    *out = (uint32_t)value;
    return true;
}

static ParseResult parse_args(int argc, char** argv, Args* a) {
    memset(a, 0, sizeof(*a));
    a->dump_limit = -1;
    a->follow_chain = true;
    a->max_chain_depth = 8;
    a->timeout_ms = 15000;
    a->trace_steps = 64;

    if (argc < 2) return PARSE_ERR;
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) return PARSE_HELP;
    if (strcmp(argv[1], "--version") == 0) return PARSE_VERSION;
    a->input = argv[1];

    for (int i = 2; i < argc; i++) {
        const char* s = argv[i];
        if (strcmp(s, "--") == 0) {
            a->child_argc = argc - (i + 1);
            a->child_argv = (const char**)&argv[i + 1];
            break;
        }
        if (strcmp(s, "--help") == 0 || strcmp(s, "-h") == 0) return PARSE_HELP;
        else if (strcmp(s, "--version") == 0) return PARSE_VERSION;
        else if (strcmp(s, "--dump") == 0) a->dump = true;
        else if (strcmp(s, "--ops") == 0) a->show_ops = true;
        else if (strcmp(s, "--heuristics") == 0) a->heuristics = true;
        else if (strcmp(s, "--dynamic") == 0) a->dynamic = true;
        else if (strcmp(s, "--no-follow-chain") == 0) a->follow_chain = false;
        else if (strcmp(s, "--strict-abi") == 0) a->strict_abi = true;
        else if (strcmp(s, "--limit") == 0 && i + 1 < argc) {
            long value = 0;
            if (!parse_long_range(argv[++i], 0, INT_MAX, &value)) {
                fprintf(stderr, "Invalid value for --limit: %s (expected 0..%d)\n", argv[i], INT_MAX);
                return PARSE_ERR;
            }
            a->dump_limit = (int)value;
        }
        else if (strcmp(s, "--max-chain-depth") == 0 && i + 1 < argc) {
            long value = 0;
            if (!parse_long_range(argv[++i], 1, 16, &value)) {
                fprintf(stderr, "Invalid value for --max-chain-depth: %s (expected 1..16)\n", argv[i]);
                return PARSE_ERR;
            }
            a->max_chain_depth = (int)value;
        }
        else if (strcmp(s, "--timeout-ms") == 0 && i + 1 < argc) {
            if (!parse_u32_range(argv[++i], 1, UINT32_MAX, &a->timeout_ms)) {
                fprintf(stderr, "Invalid value for --timeout-ms: %s (expected 1..%u)\n",
                        argv[i], (unsigned)UINT32_MAX);
                return PARSE_ERR;
            }
        }
        else if (strcmp(s, "--trace-steps") == 0 && i + 1 < argc) {
            if (!parse_u32_range(argv[++i], 0, 256, &a->trace_steps)) {
                fprintf(stderr, "Invalid value for --trace-steps: %s (expected 0..256)\n", argv[i]);
                return PARSE_ERR;
            }
        }
        else if (strcmp(s, "--csv") == 0 && i + 1 < argc) { a->csv_path = argv[++i]; }
        else if (strcmp(s, "--ghidra-csv") == 0 && i + 1 < argc) { a->ghidra_csv_path = argv[++i]; }
        else if (strcmp(s, "--json") == 0 && i + 1 < argc) { a->json_path = argv[++i]; }
        else if (strcmp(s, "--html") == 0 && i + 1 < argc) { a->html_path = argv[++i]; }
        else {
            fprintf(stderr, "Unknown/invalid option: %s\n", s);
            return PARSE_ERR;
        }
    }
    return PARSE_OK;
}

static void print_one(size_t idx, const RuntimeFunction* r, const UnwindSummary* u, bool ok) {
    uint32_t size = (r->end_rva >= r->begin_rva) ? (r->end_rva - r->begin_rva) : 0;
    char fbuf[64];
    unwind_flags_to_string(u->flags, fbuf);

    printf("[%zu] 0x%08X..0x%08X  sz=%-6u  unwind=0x%08X  ",
           idx, (unsigned)r->begin_rva, (unsigned)r->end_rva, (unsigned)size, (unsigned)r->unwind_rva);

    if (!ok) {
        printf("UNWIND: <parse failed%s%s>\n",
               u->parse_error[0] ? ": " : "",
               u->parse_error);
        return;
    }

    printf("v%u flags=%s prolog=%u stack=%uB",
           (unsigned)u->version, fbuf, (unsigned)u->prolog_size, (unsigned)u->fixed_stack_bytes);

    if (u->frame_reg) printf(" fp=%s+%u", unwind_reg_name(u->frame_reg), (unsigned)(u->frame_off * 16u));
    if (u->has_handler) printf(" handler=0x%08X", (unsigned)u->handler_rva);
    if (u->has_chain) printf(" chain_u=0x%08X", (unsigned)u->chain.unwind_rva);
    if (u->anomalies) printf(" anom=0x%08X", (unsigned)u->anomalies);
    printf("\n");
}

int main(int argc, char** argv) {
    Args a;
    int exit_code = 0;
    ParseResult pres = parse_args(argc, argv, &a);
    if (pres != PARSE_OK) {
        if (pres == PARSE_VERSION) {
            print_version();
            return 0;
        }
        usage(argv[0]);
        return (pres == PARSE_HELP) ? 0 : 2;
    }

    uint8_t* owned = NULL;
    Buf b;
    if (!buf_init_from_file(&b, a.input, &owned)) {
        fprintf(stderr, "Failed to read file: %s\n", a.input);
        return 1;
    }

    StrBuf err;
    sb_init(&err, 1024);

    PeInputValidation input_validation;
    if (!pe_validate_input(&b, &input_validation)) {
        fprintf(stderr, "Failed to perform PE input validation.\n");
        sb_free(&err);
        buf_free_owned(owned);
        return 1;
    }

    PeImage img;
    if (!pe_parse(&img, &b, &err)) {
        fprintf(stderr, "PE parse error:\n%s", err.s ? err.s : "");

        if (a.json_path || a.html_path) {
            StrBuf invocation = {0};
            char timestamp[32] = "";
            char input_sha256[65] = "";
            char* input_display = argv_text_to_utf8(a.input);
            ReportMetadata metadata;
            memset(&metadata, 0, sizeof(metadata));
            bool metadata_ok = sb_init(&invocation, 256) &&
                               input_display &&
                               build_invocation(argc, argv, &invocation) &&
                               app_utc_timestamp(timestamp, sizeof(timestamp)) &&
                               sha256_hex(b.data, b.size, input_sha256);
            if (!metadata_ok) {
                fprintf(stderr, "Failed to prepare input-validation report metadata.\n");
            } else {
                metadata.tool_version = app_version();
                metadata.report_schema_version = app_report_schema_version();
                metadata.generated_at_utc = timestamp;
                metadata.input_sha256 = input_sha256;
                metadata.input_size = (uint64_t)b.size;
                metadata.command_line = invocation.s ? invocation.s : "";
                metadata.build_compiler = app_build_compiler();
                metadata.build_platform = app_build_platform();
                metadata.build_mode = app_build_mode();
                metadata.strict_abi = a.strict_abi;
                metadata.follow_chain = a.follow_chain;
                metadata.max_chain_depth = (uint32_t)a.max_chain_depth;

                if (a.json_path) {
                    StrBuf report_err;
                    sb_init(&report_err, 256);
                    if (!report_write_input_validation_json(
                            a.json_path, input_display, &input_validation,
                            err.s ? err.s : "", &metadata, &report_err)) {
                        fprintf(stderr, "Input-validation JSON write failed:\n%s",
                                report_err.s ? report_err.s : "");
                    } else {
                        printf("\nWrote input-validation JSON: %s\n", a.json_path);
                    }
                    sb_free(&report_err);
                }
                if (a.html_path) {
                    StrBuf report_err;
                    sb_init(&report_err, 256);
                    if (!report_write_input_validation_html(
                            a.html_path, input_display, &input_validation,
                            err.s ? err.s : "", &metadata, &report_err)) {
                        fprintf(stderr, "Input-validation HTML write failed:\n%s",
                                report_err.s ? report_err.s : "");
                    } else {
                        printf("\nWrote input-validation HTML: %s\n", a.html_path);
                    }
                    sb_free(&report_err);
                }
            }
            sb_free(&invocation);
            free(input_display);
        }
        sb_free(&err);
        buf_free_owned(owned);
        return 1;
    }

    RuntimeFunction* rf = NULL;
    size_t rf_count = 0;
    StrBuf err2;
    sb_init(&err2, 1024);

    RuntimeFunctionReadResult rf_read = unwind_read_runtime_functions_ex(
        &b, &img, &rf, &rf_count, &err2);
    if (rf_read != RUNTIME_FUNCTION_READ_OK) {
        fprintf(stderr, "Failed to read exception directory:\n%s", err2.s ? err2.s : "");
        if (rf_read == RUNTIME_FUNCTION_READ_OOM) {
            pe_free(&img);
            sb_free(&err);
            sb_free(&err2);
            buf_free_owned(owned);
            return 1;
        }
        /*
         * Keep the established report field/finding code for compatibility.
         * It now covers every structurally unreadable exception directory.
         */
        img.exception_directory_oob = true;
        fprintf(stderr, "Continuing with a partial structural report.\n");
        exit_code = 1;
    }

    report_print_brief(a.input, &img, rf_count);

    UnwindSummary* us = (UnwindSummary*)calloc(rf_count ? rf_count : 1, sizeof(UnwindSummary));
    bool* us_ok = (bool*)calloc(rf_count ? rf_count : 1, sizeof(bool));
    if (!us || !us_ok) {
        fprintf(stderr, "Out of memory.\n");
        free(us);
        free(us_ok);
        free(rf);
        pe_free(&img);
        sb_free(&err);
        sb_free(&err2);
        buf_free_owned(owned);
        return 1;
    }

    UnwindParseOpts uopts = {
        .max_chain_depth = a.max_chain_depth,
        .follow_chain = a.follow_chain,
        .strict_abi = a.strict_abi
    };

    StrBuf ops;
    sb_init(&ops, 1024);

    for (size_t i = 0; i < rf_count; i++) {
        StrBuf perr;
        sb_init(&perr, 256);
        if (a.show_ops) { ops.len = 0; if (ops.s) ops.s[0]=0; }
        bool ok = unwind_parse(&b, &img, rf[i].unwind_rva, &uopts, &us[i], a.show_ops ? &ops : NULL, &perr);
        us_ok[i] = ok;
        if (a.dump && a.show_ops && ok) {
            /* ops will be printed in dump loop below */
        }
        sb_free(&perr);
    }

    if (a.dump) {
        size_t limit = (a.dump_limit < 0) ? rf_count : (size_t)a.dump_limit;
        if (limit > rf_count) limit = rf_count;
        printf("\n[Dump] Showing %zu / %zu entries\n", limit, rf_count);
        for (size_t i = 0; i < limit; i++) {
            print_one(i, &rf[i], &us[i], us_ok[i]);
            if (a.show_ops && us_ok[i]) {
                StrBuf ops2;
                StrBuf perr;
                sb_init(&ops2, 1024);
                sb_init(&perr, 256);
                (void)unwind_parse(&b, &img, rf[i].unwind_rva, &uopts, &us[i], &ops2, &perr);
                if (ops2.s && ops2.len) printf("%s", ops2.s);
                sb_free(&ops2);
                sb_free(&perr);
            }
        }
    }

    HeuristicReport hr;
    HeuristicReport* hr_ptr = NULL;
    DynamicReport dr;
    memset(&dr, 0, sizeof(dr));
    DynamicReport* dr_ptr = NULL;
    bool dr_initialized = false;
    if (a.heuristics) {
        StrBuf perr;
        sb_init(&perr, 512);
        if (heuristics_analyze(&img, rf, us, us_ok, rf_count, &hr, &perr)) {
            report_print_heuristics(&hr);
            hr_ptr = &hr;
        } else {
            fprintf(stderr, "Heuristic analysis failed:\n%s", perr.s ? perr.s : "");
            exit_code = 1;
        }
        sb_free(&perr);
    }

    if (a.dynamic) {
        StrBuf derr;
        sb_init(&derr, 1024);
        printf("\n[Dynamic] Starting debugger evidence collection (Windows only)...\n");
        bool ran = dynamic_collect_windows(a.input, a.child_argv, a.child_argc,
                                           &img, rf, us, us_ok, rf_count,
                                           a.timeout_ms, a.trace_steps,
                                           &dr, &derr);
        dr_initialized = true;
        dr_ptr = &dr;
        if (!ran) {
            fprintf(stderr, "[Dynamic] Failed: %s", derr.s ? derr.s : "");
            exit_code = 1;
        } else {
            printf("[Dynamic] Done. exceptions_seen=%u unwind_handler_hits=%u veh_hits=%u dyn_ftable_calls=%u\n",
                   (unsigned)dr.exceptions_seen,
                   (unsigned)dr.unwind_handler_hits,
                   (unsigned)dr.veh_hits,
                   (unsigned)dr.rtl_add_function_table_calls);
            if (dr.details.s && dr.details.len) {
                printf("%s\n", dr.details.s);
            }
        }
        sb_free(&derr);
    }

    if (a.csv_path) {
        StrBuf e;
        sb_init(&e, 256);
        if (!report_write_csv(a.csv_path, &img, rf, us, us_ok, rf_count, false, &e)) {
            fprintf(stderr, "CSV write failed:\n%s", e.s ? e.s : "");
            exit_code = 1;
        } else {
            printf("\nWrote CSV: %s\n", a.csv_path);
        }
        sb_free(&e);
    }
    if (a.ghidra_csv_path) {
        StrBuf e;
        sb_init(&e, 256);
        if (!report_write_csv(a.ghidra_csv_path, &img, rf, us, us_ok, rf_count, true, &e)) {
            fprintf(stderr, "Ghidra CSV write failed:\n%s", e.s ? e.s : "");
            exit_code = 1;
        } else {
            printf("\nWrote Ghidra CSV: %s\n", a.ghidra_csv_path);
        }
        sb_free(&e);
    }

    StrBuf invocation = {0};
    char timestamp[32] = "";
    char input_sha256[65] = "";
    char* input_display = NULL;
    ReportMetadata metadata;
    memset(&metadata, 0, sizeof(metadata));
    ReportMetadata* metadata_ptr = NULL;
    if (a.json_path || a.html_path) {
        input_display = argv_text_to_utf8(a.input);
        bool metadata_ok = sb_init(&invocation, 256) &&
                           input_display &&
                           build_invocation(argc, argv, &invocation) &&
                           app_utc_timestamp(timestamp, sizeof(timestamp)) &&
                           sha256_hex(b.data, b.size, input_sha256);
        if (!metadata_ok) {
            fprintf(stderr, "Failed to prepare report metadata.\n");
            exit_code = 1;
        } else {
            metadata.tool_version = app_version();
            metadata.report_schema_version = app_report_schema_version();
            metadata.generated_at_utc = timestamp;
            metadata.input_sha256 = input_sha256;
            metadata.input_size = (uint64_t)b.size;
            metadata.command_line = invocation.s ? invocation.s : "";
            metadata.build_compiler = app_build_compiler();
            metadata.build_platform = app_build_platform();
            metadata.build_mode = app_build_mode();
            metadata.strict_abi = a.strict_abi;
            metadata.follow_chain = a.follow_chain;
            metadata.max_chain_depth = (uint32_t)a.max_chain_depth;
            metadata_ptr = &metadata;
        }
    }

    if (a.json_path) {
        StrBuf e;
        sb_init(&e, 256);
        if (metadata_ptr &&
            !report_write_json_ex(a.json_path, input_display ? input_display : a.input,
                                  &img, rf, us, us_ok, rf_count,
                                  hr_ptr, dr_ptr, metadata_ptr, &e)) {
            fprintf(stderr, "JSON write failed:\n%s", e.s ? e.s : "");
            exit_code = 1;
        } else if (metadata_ptr) {
            printf("\nWrote JSON: %s\n", a.json_path);
        }
        sb_free(&e);
    }
    if (a.html_path) {
        StrBuf e;
        sb_init(&e, 256);
        if (metadata_ptr &&
            !report_write_html(a.html_path, input_display ? input_display : a.input,
                               &img, rf, us, us_ok, rf_count,
                               hr_ptr, dr_ptr, metadata_ptr, &e)) {
            fprintf(stderr, "HTML write failed:\n%s", e.s ? e.s : "");
            exit_code = 1;
        } else if (metadata_ptr) {
            printf("\nWrote HTML: %s\n", a.html_path);
        }
        sb_free(&e);
    }
    sb_free(&invocation);
    free(input_display);

    if (a.heuristics && hr_ptr) heuristics_free(&hr);
    if (dr_initialized) dynamic_report_free(&dr);

    sb_free(&ops);
    free(us_ok);
    free(us);
    free(rf);
    pe_free(&img);
    sb_free(&err);
    sb_free(&err2);
    buf_free_owned(owned);
    return exit_code;
}
