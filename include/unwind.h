#pragma once
/*
  unwind.h - x64 UNWIND_INFO parsing (PE exception directory)
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "util.h"
#include "pe.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RuntimeFunction {
    uint32_t begin_rva;
    uint32_t end_rva;
    uint32_t unwind_rva;
} RuntimeFunction;

#define UNWIND_DIAG_MAX_BYTES 32u
#define UNWIND_DIAG_MAX_CHAIN_PATH 16u

typedef struct UnwindSummary {
    bool     valid;
    uint8_t  version;
    uint8_t  flags;
    uint8_t  prolog_size;
    uint8_t  count_codes;
    uint8_t  frame_reg;
    uint8_t  frame_off; /* scaled by 16 */
    bool     has_handler;
    uint32_t handler_rva;

    bool     has_chain;
    RuntimeFunction chain;

    uint32_t fixed_stack_bytes;     /* estimated fixed stack frame delta: push+alloc+machframe */
    uint32_t pushed_nonvol_count;
    uint16_t saved_nonvol_mask;     /* bits 0..15 => reg numbers */
    uint16_t saved_xmm_mask;        /* bits 0..15 => XMM reg numbers */

    uint32_t anomalies;             /* bitmask of internal anomalies */
    char     parse_error[160];       /* non-empty when unwind_parse returns false */

    char     diagnostic_field[64];   /* exact field/area that caused the strongest diagnostic */
    bool     diagnostic_has_file_offset;
    uint32_t diagnostic_file_offset;
    bool     diagnostic_has_size;
    uint32_t diagnostic_expected_size;
    uint32_t diagnostic_available_size;
    bool     diagnostic_has_slots;
    uint32_t diagnostic_expected_slots;
    uint32_t diagnostic_available_slots;
    bool     diagnostic_has_bytes;
    uint32_t diagnostic_bytes_file_offset;
    uint8_t  diagnostic_bytes[UNWIND_DIAG_MAX_BYTES];
    uint8_t  diagnostic_bytes_count;

    uint32_t chain_path[UNWIND_DIAG_MAX_CHAIN_PATH];
    uint8_t  chain_path_count;
    bool     chain_loop_detected;
    uint32_t chain_loop_rva;
} UnwindSummary;

enum UnwindFlags {
    UNW_FLAG_EHANDLER  = 0x01,
    UNW_FLAG_UHANDLER  = 0x02,
    UNW_FLAG_CHAININFO = 0x04
};

/* anomalies flags (for heuristic analysis / diagnostics) */
enum UnwindAnom {
    UA_VERSION_UNKNOWN       = 1u << 0,
    UA_TRUNCATED             = 1u << 1,
    UA_BAD_OPCODE            = 1u << 2,
    UA_BAD_OPERAND           = 1u << 3,
    UA_CODEOFFSET_OUTSIDE    = 1u << 4,
    UA_CHAIN_LOOP            = 1u << 5,
    UA_CHAIN_DEPTH_EXCEEDED  = 1u << 6,
    UA_HANDLER_OOB           = 1u << 7,
    UA_CODEOFFSET_ORDER      = 1u << 8,
    UA_OPERAND_SANITY        = 1u << 9,
    UA_ALIGNMENT             = 1u << 10,
    UA_CHAIN_INVALID         = 1u << 11,
    UA_ABI_REGISTER_CLASS    = 1u << 12,
    UA_ABI_RESERVED_OPINFO   = 1u << 13,
    UA_ABI_PUSH_ORDER        = 1u << 14,
    UA_ABI_CHAIN_RESTRICTION = 1u << 15,
    UA_ABI_SAVE_OFFSET       = 1u << 16
};

typedef struct UnwindParseOpts {
    int  max_chain_depth; /* default 8 */
    bool follow_chain;    /* compute + annotate chain info */
    bool strict_abi;      /* flag formal Microsoft x64 unwind ABI violations */
} UnwindParseOpts;

typedef enum RuntimeFunctionReadResult {
    RUNTIME_FUNCTION_READ_OK = 0,
    RUNTIME_FUNCTION_READ_MALFORMED,
    RUNTIME_FUNCTION_READ_OOM
} RuntimeFunctionReadResult;

/* Parse UNWIND_INFO at unwind_rva. Produces summary + optional text of unwind ops. */
bool unwind_parse(const Buf* b,
                  const PeImage* img,
                  uint32_t unwind_rva,
                  const UnwindParseOpts* opts,
                  UnwindSummary* out,
                  StrBuf* ops_text,
                  StrBuf* err);

/* Parse exception directory (RUNTIME_FUNCTION table) into array.
   Caller owns *out (malloc). */
RuntimeFunctionReadResult unwind_read_runtime_functions_ex(
                                  const Buf* b,
                                  const PeImage* img,
                                  RuntimeFunction** out,
                                  size_t* out_count,
                                  StrBuf* err);

bool unwind_read_runtime_functions(const Buf* b,
                                  const PeImage* img,
                                  RuntimeFunction** out,
                                  size_t* out_count,
                                  StrBuf* err);

/* Pretty helpers */
const char* unwind_reg_name(uint8_t reg);
void unwind_flags_to_string(uint8_t flags, char out[64]);

#ifdef __cplusplus
}
#endif
