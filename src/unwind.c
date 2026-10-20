#include "unwind.h"
#include <stdlib.h>
#include <string.h>

const char* unwind_reg_name(uint8_t reg) {
    /* mapping per MS x64 unwind encoding */
    static const char* names[16] = {
        "RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
        "R8","R9","R10","R11","R12","R13","R14","R15"
    };
    if (reg < 16) return names[reg];
    return "REG?";
}

void unwind_flags_to_string(uint8_t flags, char out[64]) {
    out[0] = 0;
    bool first = true;
    if (flags & UNW_FLAG_EHANDLER) { strcat(out, "EHANDLER"); first = false; }
    if (flags & UNW_FLAG_UHANDLER) { strcat(out, first ? "UHANDLER" : "|UHANDLER"); first = false; }
    if (flags & UNW_FLAG_CHAININFO){ strcat(out, first ? "CHAININFO" : "|CHAININFO"); first = false; }
    if (first) strcpy(out, "0");
}

static bool slots_for_code(uint8_t version,
                           uint8_t op,
                           uint8_t opinfo,
                           bool v2_seen_epilog,
                           uint8_t* out_slots) {
    /* based on documented v1 ops + v2 epilog/spare, and common implementations */
    switch (op) {
        case 0: /* UWOP_PUSH_NONVOL */ *out_slots = 1; return true;
        case 1: /* UWOP_ALLOC_LARGE */ if (opinfo > 1) return false; *out_slots = (uint8_t)(2 + opinfo); return true;
        case 2: /* UWOP_ALLOC_SMALL */ *out_slots = 1; return true;
        case 3: /* UWOP_SET_FPREG */   *out_slots = 1; return true;
        case 4: /* UWOP_SAVE_NONVOL */ *out_slots = 2; return true;
        case 5: /* UWOP_SAVE_NONVOL_FAR */ *out_slots = 3; return true;
        case 6: /* v2 UWOP_EPILOG, v1 UWOP_SAVE_XMM (undoc) */
            if (version == 2) {
                /* The first long-form epilog descriptor has one operand slot.
                   Short-form and subsequent descriptors occupy one slot. */
                *out_slots = (!v2_seen_epilog && (opinfo & 1u) == 0u) ? 2u : 1u;
                return true;
            }
            *out_slots = 2; return true;
        case 7: /* v2 UWOP_SPARE, v1 UWOP_SAVE_XMM_FAR (undoc) */
            if (version == 2) { *out_slots = 1; return true; }
            *out_slots = 3; return true;
        case 8: /* UWOP_SAVE_XMM128 */ *out_slots = 2; return true;
        case 9: /* UWOP_SAVE_XMM128_FAR */ *out_slots = 3; return true;
        case 10: /* UWOP_PUSH_MACHFRAME */ *out_slots = 1; return true;
        default:
            return false;
    }
}

static bool parse_unwindinfo_header(const Buf* b, const PeImage* img, uint32_t unwind_rva,
                                   uint32_t* out_fileoff, uint8_t hdr[4], StrBuf* err) {
    uint32_t off = 0;
    if (!pe_rva_to_fileoff(img, unwind_rva, &off)) {
        sb_appendf(err, "UnwindInfo RVA 0x%08x not mappable to file offset.\n", unwind_rva);
        return false;
    }
    if ((size_t)off + 4 > b->size) {
        sb_append(err, "UnwindInfo header out of file range.\n");
        return false;
    }
    if (!buf_read(b, off, hdr, 4)) {
        sb_append(err, "Failed to read UnwindInfo header bytes.\n");
        return false;
    }
    *out_fileoff = off;
    return true;
}

static bool read_u16_slot(const Buf* b, size_t off, uint16_t* out) {
    uint8_t tmp[2];
    if (!buf_read(b, off, tmp, 2)) return false;
    *out = (uint16_t)(tmp[0] | ((uint16_t)tmp[1] << 8));
    return true;
}


static uint32_t clamp_size_to_u32(size_t value) {
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

static size_t min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

static size_t safe_add_size(size_t a, size_t b) {
    if (SIZE_MAX - a < b) return SIZE_MAX;
    return a + b;
}

static size_t unwind_record_limit(const Buf* b, const PeImage* img, uint32_t unwind_rva) {
    size_t limit = b ? b->size : 0;
    const PeSection* section = pe_find_section_for_rva(img, unwind_rva);
    if (section && section->raw_size > 0) {
        size_t raw_start = (size_t)section->raw_ptr;
        size_t raw_end = safe_add_size(raw_start, (size_t)section->raw_size);
        limit = min_size(limit, raw_end);
    }
    return limit;
}

static size_t available_until_limit(const Buf* b, size_t off, size_t limit) {
    if (!b) return 0;
    size_t end = min_size(b->size, limit);
    if (off >= end) return 0;
    return end - off;
}

static void unwind_diag_capture_bytes(UnwindSummary* out,
                                      const Buf* b,
                                      size_t file_offset,
                                      size_t max_count) {
    if (!out || !b || file_offset >= b->size || max_count == 0) return;
    size_t count = b->size - file_offset;
    if (count > max_count) count = max_count;
    if (count > UNWIND_DIAG_MAX_BYTES) count = UNWIND_DIAG_MAX_BYTES;
    memcpy(out->diagnostic_bytes, b->data + file_offset, count);
    out->diagnostic_bytes_count = (uint8_t)count;
    out->diagnostic_bytes_file_offset = clamp_size_to_u32(file_offset);
    out->diagnostic_has_bytes = count > 0;
}

static void unwind_diag_set(UnwindSummary* out,
                            const Buf* b,
                            const char* field,
                            bool has_file_offset,
                            size_t file_offset,
                            bool has_size,
                            size_t expected_size,
                            size_t available_size,
                            bool has_slots,
                            uint32_t expected_slots,
                            uint32_t available_slots) {
    if (!out) return;
    if (field && field[0]) {
        size_t n = strlen(field);
        if (n >= sizeof(out->diagnostic_field)) n = sizeof(out->diagnostic_field) - 1;
        memcpy(out->diagnostic_field, field, n);
        out->diagnostic_field[n] = '\0';
    }
    out->diagnostic_has_file_offset = has_file_offset;
    if (has_file_offset) out->diagnostic_file_offset = clamp_size_to_u32(file_offset);
    out->diagnostic_has_size = has_size;
    if (has_size) {
        out->diagnostic_expected_size = clamp_size_to_u32(expected_size);
        out->diagnostic_available_size = clamp_size_to_u32(available_size);
    }
    out->diagnostic_has_slots = has_slots;
    if (has_slots) {
        out->diagnostic_expected_slots = expected_slots;
        out->diagnostic_available_slots = available_slots;
    }
    if (has_file_offset) {
        size_t max_bytes = has_size ? available_size : (size_t)UNWIND_DIAG_MAX_BYTES;
        unwind_diag_capture_bytes(out, b, file_offset, max_bytes);
    }
}

static void unwind_diag_set_read_failure(UnwindSummary* out,
                                         const Buf* b,
                                         const char* field,
                                         size_t file_offset,
                                         size_t expected_size,
                                         size_t limit) {
    size_t available = available_until_limit(b, file_offset, limit);
    unwind_diag_set(out, b, field, true, file_offset, true,
                    expected_size, available, false, 0, 0);
}

static uint32_t read_u32_from_slots(uint16_t lo, uint16_t hi) {
    return (uint32_t)lo | ((uint32_t)hi << 16);
}

static bool is_unwindable_gpr(uint8_t reg) {
    /* Real MSVC, Rust and OpenSSL records also describe volatile registers. */
    return reg < 16 && reg != 4;
}

static bool is_unwindable_xmm(uint8_t reg) {
    return reg < 16;
}

static bool is_abi_nonvolatile_gpr(uint8_t reg) {
    return reg == 3 || reg == 5 || reg == 6 || reg == 7 || reg >= 12;
}

static bool is_abi_nonvolatile_xmm(uint8_t reg) {
    return reg >= 6 && reg < 16;
}

static void add_fixed_stack(uint32_t* total, uint32_t amount, uint32_t* anomalies) {
    if (!total || !anomalies) return;
    if (UINT32_MAX - *total < amount) {
        *total = UINT32_MAX;
        *anomalies |= UA_OPERAND_SANITY;
        return;
    }
    *total += amount;
}

static bool alloc_large_mode0_suspicious(uint16_t scaled8) {
    uint32_t size = (uint32_t)scaled8 * 8u;
    return size == 0 || size <= 128u || (size % 8u) != 0;
}

static bool alloc_large_mode1_suspicious(uint32_t size) {
    return size == 0 || (size % 8u) != 0 || size < (512u * 1024u);
}

static bool save_nonvol_far_suspicious(uint32_t off) {
    return off == 0 || (off % 8u) != 0 || off < (512u * 1024u);
}

static bool save_xmm_far_suspicious(uint32_t off) {
    return off == 0 || (off % 16u) != 0 || off < (1024u * 1024u);
}

static bool parse_chain_rf(const Buf* b, const PeImage* img, size_t fileoff_after_codes,
                           RuntimeFunction* out_chain) {
    uint32_t a=0, c=0, u=0;
    if (!buf_read_u32(b, fileoff_after_codes + 0, &a)) return false;
    if (!buf_read_u32(b, fileoff_after_codes + 4, &c)) return false;
    if (!buf_read_u32(b, fileoff_after_codes + 8, &u)) return false;
    out_chain->begin_rva = a;
    out_chain->end_rva = c;
    out_chain->unwind_rva = u;
    (void)img;
    return true;
}

static bool unwind_parse_fail(UnwindSummary* out,
                              StrBuf* err,
                              size_t err_start,
                              const char* fallback) {
    if (!out) return false;
    out->valid = false;

    const char* message = fallback ? fallback : "UNWIND_INFO parse failed.";
    if (err && err->s && err->len > err_start) {
        message = err->s + err_start;
    } else if (err && fallback) {
        sb_appendf(err, "%s\n", fallback);
    }

    size_t n = strlen(message);
    while (n > 0 && (message[n - 1] == '\n' || message[n - 1] == '\r')) n--;
    if (n >= sizeof(out->parse_error)) n = sizeof(out->parse_error) - 1;
    memcpy(out->parse_error, message, n);
    out->parse_error[n] = '\0';
    return false;
}

bool unwind_parse(const Buf* b,
                  const PeImage* img,
                  uint32_t unwind_rva,
                  const UnwindParseOpts* opts,
                  UnwindSummary* out,
                  StrBuf* ops_text,
                  StrBuf* err) {
    if (!b || !img || !out || !err) return false;
    memset(out, 0, sizeof(*out));
    size_t err_start = err->len;
    if (ops_text) { ops_text->len = 0; if (ops_text->s) ops_text->s[0]=0; }

    int max_depth = 8;
    bool follow_chain = true;
    bool strict_abi = false;
    if (opts) {
        if (opts->max_chain_depth > 0) max_depth = opts->max_chain_depth;
        follow_chain = opts->follow_chain;
        strict_abi = opts->strict_abi;
    }
    if (max_depth > 16) max_depth = 16;

    uint8_t hdr[4];
    uint32_t uoff = 0;
    uint32_t attempted_uoff = 0;
    bool attempted_mapped = pe_rva_to_fileoff(img, unwind_rva, &attempted_uoff);
    if ((unwind_rva & 3u) != 0) {
        out->anomalies |= UA_ALIGNMENT;
    }
    if (!parse_unwindinfo_header(b, img, unwind_rva, &uoff, hdr, err)) {
        out->anomalies |= UA_TRUNCATED;
        unwind_diag_set(out, b, "UnwindInfoAddress / UNWIND_INFO header",
                        attempted_mapped, attempted_mapped ? (size_t)attempted_uoff : 0u,
                        attempted_mapped, 4u,
                        attempted_mapped ? available_until_limit(b, (size_t)attempted_uoff, b->size) : 0u,
                        false, 0, 0);
        return unwind_parse_fail(out, err, err_start, "Failed to read UNWIND_INFO header.");
    }
    size_t record_limit = unwind_record_limit(b, img, unwind_rva);

    uint8_t ver = (uint8_t)(hdr[0] & 0x7);
    uint8_t flags = (uint8_t)(hdr[0] >> 3);
    uint8_t prolog = hdr[1];
    uint8_t count = hdr[2];
    uint8_t fr = (uint8_t)(hdr[3] & 0x0f);
    uint8_t foff = (uint8_t)(hdr[3] >> 4);

    out->version = ver;
    out->flags = flags;
    out->prolog_size = prolog;
    out->count_codes = count;
    out->frame_reg = fr;
    out->frame_off = foff;

    if (!(ver == 1 || ver == 2)) {
        out->anomalies |= UA_VERSION_UNKNOWN;
        unwind_diag_set(out, b, "Version", true, (size_t)uoff, true, 1u, 1u, false, 0, 0);
        return unwind_parse_fail(out, err, err_start, "Unsupported UNWIND_INFO version.");
    }
    if (flags & (uint8_t)~(UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO)) {
        out->anomalies |= UA_BAD_OPERAND;
    }
    if ((flags & UNW_FLAG_CHAININFO) && (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))) {
        out->anomalies |= UA_BAD_OPERAND;
    }
    if (fr == 0 && foff != 0) {
        out->anomalies |= UA_BAD_OPERAND;
    }
    if (fr != 0 && !is_unwindable_gpr(fr)) {
        out->anomalies |= UA_BAD_OPERAND;
    }
    if (strict_abi && fr != 0 && !is_abi_nonvolatile_gpr(fr)) {
        out->anomalies |= UA_ABI_REGISTER_CLASS;
    }

    /* total slots stored on disk (aligned to even number) */
    uint32_t slots_even = (uint32_t)((count + 1u) & ~1u);
    size_t codes_off = (size_t)uoff + 4;
    size_t codes_bytes = (size_t)slots_even * 2u;
    size_t codes_available = available_until_limit(b, codes_off, record_limit);
    if (codes_bytes > codes_available) {
        out->anomalies |= UA_TRUNCATED;
        unwind_diag_set(out, b, "CountOfCodes / UNWIND_CODE array",
                        true, codes_off, true, codes_bytes, codes_available,
                        true, slots_even, (uint32_t)(codes_available / 2u));
        sb_append(err, "Unwind codes array out of file range.\n");
        return unwind_parse_fail(out, err, err_start, "Unwind codes array out of file range.");
    }

    uint32_t fixed_stack = 0;
    uint32_t pushed = 0;
    uint16_t nonvol_mask = 0;
    uint16_t xmm_mask = 0;
    bool have_prev_code_offset = false;
    uint8_t prev_code_offset = 0;
    bool saw_set_fpreg = false;
    bool saw_push_nonvol = false;
    bool v2_seen_epilog = false;

    /* parse slots 0..count-1 as unwind code starts */
    for (uint32_t i = 0; i < count; ) {
        uint16_t slot = 0;
        size_t slot_fileoff = codes_off + (size_t)i * 2u;
        if (!read_u16_slot(b, slot_fileoff, &slot)) {
            out->anomalies |= UA_TRUNCATED;
            unwind_diag_set_read_failure(out, b, "UNWIND_CODE slot", slot_fileoff, 2u, record_limit);
            sb_append(err, "Failed to read unwind slot.\n");
            return unwind_parse_fail(out, err, err_start, "Failed to read unwind slot.");
        }

        uint8_t code_offset = (uint8_t)(slot & 0xff);
        uint8_t op_byte = (uint8_t)(slot >> 8);
        uint8_t op = (uint8_t)(op_byte & 0x0f);
        uint8_t opinfo = (uint8_t)(op_byte >> 4);

        uint8_t slots = 0;
        if (!slots_for_code(ver, op, opinfo, v2_seen_epilog, &slots)) {
            out->anomalies |= UA_BAD_OPCODE;
            /* try to continue safely as 1 slot */
            slots = 1;
        }
        if (i + slots > count) {
            out->anomalies |= UA_TRUNCATED;
            unwind_diag_set(out, b, "CountOfCodes / UWOP operand slots",
                            true, slot_fileoff, true, (size_t)slots * 2u,
                            (size_t)(count - i) * 2u, true, slots, count - i);
            sb_append(err, "Unwind opcode spans beyond CountOfCodes.\n");
            return unwind_parse_fail(out, err, err_start, "Unwind opcode spans beyond CountOfCodes.");
        }
        bool v2_descriptor = ver == 2 && (op == 6 || op == 7);
        if (!v2_descriptor) {
            if (code_offset > prolog) {
                out->anomalies |= UA_CODEOFFSET_OUTSIDE;
            }
            if (have_prev_code_offset && code_offset > prev_code_offset) {
                out->anomalies |= UA_CODEOFFSET_ORDER;
            }
            have_prev_code_offset = true;
            prev_code_offset = code_offset;
        }
        if (strict_abi && !v2_descriptor) {
            if (saw_push_nonvol && op != 0 && op != 10) {
                out->anomalies |= UA_ABI_PUSH_ORDER;
            }
            if (op == 0) saw_push_nonvol = true;
            if ((flags & UNW_FLAG_CHAININFO) && op != 4) {
                out->anomalies |= UA_ABI_CHAIN_RESTRICTION;
            }
        }

        if (ops_text) {
            /* print one-line per op start */
            switch (op) {
                case 0: sb_appendf(ops_text, "  @%02x PUSH_NONVOL %s\n", code_offset, unwind_reg_name(opinfo)); break;
                case 1: sb_appendf(ops_text, "  @%02x ALLOC_LARGE mode=%u\n", code_offset, (unsigned)opinfo); break;
                case 2: sb_appendf(ops_text, "  @%02x ALLOC_SMALL %u\n", code_offset, (unsigned)(opinfo*8u + 8u)); break;
                case 3: sb_appendf(ops_text, "  @%02x SET_FPREG %s + %u\n", code_offset, unwind_reg_name(fr), (unsigned)(foff*16u)); break;
                case 4: sb_appendf(ops_text, "  @%02x SAVE_NONVOL %s\n", code_offset, unwind_reg_name(opinfo)); break;
                case 5: sb_appendf(ops_text, "  @%02x SAVE_NONVOL_FAR %s\n", code_offset, unwind_reg_name(opinfo)); break;
                case 6:
                    if (ver == 2) {
                        if (!v2_seen_epilog) {
                            if ((opinfo & 1u) == 0u) {
                                uint16_t epilog_slot = 0;
                                if (read_u16_slot(b, codes_off + (size_t)(i + 1) * 2,
                                                  &epilog_slot)) {
                                    unsigned epilog_offset =
                                        (unsigned)(epilog_slot & 0xffu) |
                                        ((unsigned)(epilog_slot >> 12) << 8);
                                    sb_appendf(ops_text,
                                               "  EPILOG size=%u offset_from_end=%u flags=%u (v2)\n",
                                               (unsigned)code_offset, epilog_offset,
                                               (unsigned)opinfo);
                                }
                            } else {
                                sb_appendf(ops_text, "  EPILOG size=%u flags=%u (v2)\n",
                                           (unsigned)code_offset, (unsigned)opinfo);
                            }
                        } else {
                            unsigned epilog_offset =
                                (unsigned)code_offset | ((unsigned)opinfo << 8);
                            sb_appendf(ops_text, "  EPILOG offset_from_end=%u (v2)\n",
                                       epilog_offset);
                        }
                    } else {
                        sb_appendf(ops_text, "  @%02x SAVE_XMM (undoc/v1)\n", code_offset);
                    }
                    break;
                case 7:
                    if (ver == 2) sb_appendf(ops_text, "  @%02x SPARE (v2)\n", code_offset);
                    else sb_appendf(ops_text, "  @%02x SAVE_XMM_FAR (undoc/v1)\n", code_offset);
                    break;
                case 8: sb_appendf(ops_text, "  @%02x SAVE_XMM128 XMM%u\n", code_offset, (unsigned)opinfo); break;
                case 9: sb_appendf(ops_text, "  @%02x SAVE_XMM128_FAR XMM%u\n", code_offset, (unsigned)opinfo); break;
                case 10: sb_appendf(ops_text, "  @%02x PUSH_MACHFRAME err=%u\n", code_offset, (unsigned)opinfo); break;
                default: sb_appendf(ops_text, "  @%02x OP_%u info=%u\n", code_offset, (unsigned)op, (unsigned)opinfo); break;
            }
        }

        /* compute effects */
        switch (op) {
            case 0: /* push nonvol */
                add_fixed_stack(&fixed_stack, 8, &out->anomalies);
                pushed++;
                if (!is_unwindable_gpr(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                if (strict_abi && !is_abi_nonvolatile_gpr(opinfo)) {
                    out->anomalies |= UA_ABI_REGISTER_CLASS;
                }
                if (opinfo < 16) nonvol_mask |= (uint16_t)(1u << opinfo);
                break;
            case 1: { /* alloc large */
                if (opinfo == 0) {
                    uint16_t scaled = 0;
                    if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &scaled)) {
                        out->anomalies |= UA_TRUNCATED;
                        unwind_diag_set_read_failure(out, b, "UWOP_ALLOC_LARGE operand",
                                                     codes_off + (size_t)(i + 1) * 2u,
                                                     2u, record_limit);
                        return unwind_parse_fail(out, err, err_start, "Truncated UWOP_ALLOC_LARGE operand.");
                    }
                    add_fixed_stack(&fixed_stack, (uint32_t)scaled * 8u, &out->anomalies);
                    if (alloc_large_mode0_suspicious(scaled)) out->anomalies |= UA_OPERAND_SANITY;
                    if (ops_text) sb_appendf(ops_text, "       size=%u\n", (unsigned)((uint32_t)scaled * 8u));
                } else if (opinfo == 1) {
                    uint16_t lo=0, hi=0;
                    if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &lo) ||
                        !read_u16_slot(b, codes_off + (size_t)(i+2) * 2, &hi)) {
                        out->anomalies |= UA_TRUNCATED;
                        unwind_diag_set_read_failure(out, b, "UWOP_ALLOC_LARGE operand",
                                                     codes_off + (size_t)(i + 1) * 2u,
                                                     4u, record_limit);
                        return unwind_parse_fail(out, err, err_start, "Truncated UWOP_ALLOC_LARGE operand.");
                    }
                    uint32_t size = read_u32_from_slots(lo, hi);
                    add_fixed_stack(&fixed_stack, size, &out->anomalies);
                    if (alloc_large_mode1_suspicious(size)) out->anomalies |= UA_OPERAND_SANITY;
                    if (ops_text) sb_appendf(ops_text, "       size=%u\n", (unsigned)size);
                } else {
                    out->anomalies |= UA_BAD_OPERAND;
                }
                break;
            }
            case 2: /* alloc small */
                add_fixed_stack(&fixed_stack, (uint32_t)opinfo * 8u + 8u, &out->anomalies);
                break;
            case 3: /* set frame reg */
                if (fr == 0 || saw_set_fpreg) out->anomalies |= UA_BAD_OPERAND;
                if (strict_abi && opinfo != 0) {
                    out->anomalies |= UA_ABI_RESERVED_OPINFO;
                }
                saw_set_fpreg = true;
                /* no fixed stack delta */
                break;
            case 4: { /* save nonvol */
                uint16_t scaled = 0;
                if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &scaled)) {
                    out->anomalies |= UA_TRUNCATED;
                    unwind_diag_set_read_failure(out, b, "UWOP_SAVE_NONVOL operand",
                                                 codes_off + (size_t)(i + 1) * 2u,
                                                 2u, record_limit);
                    return unwind_parse_fail(out, err, err_start, "Truncated UWOP_SAVE_NONVOL operand.");
                }
                if (!is_unwindable_gpr(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                if (strict_abi && !is_abi_nonvolatile_gpr(opinfo)) {
                    out->anomalies |= UA_ABI_REGISTER_CLASS;
                }
                if (strict_abi && scaled == 0) {
                    out->anomalies |= UA_ABI_SAVE_OFFSET;
                }
                if (opinfo < 16) nonvol_mask |= (uint16_t)(1u << opinfo);
                break;
            }
            case 5: { /* save nonvol far */
                uint16_t lo=0, hi=0;
                if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &lo) ||
                    !read_u16_slot(b, codes_off + (size_t)(i+2) * 2, &hi)) {
                    out->anomalies |= UA_TRUNCATED;
                    unwind_diag_set_read_failure(out, b, "UWOP_SAVE_NONVOL_FAR operand",
                                                 codes_off + (size_t)(i + 1) * 2u,
                                                 4u, record_limit);
                    return unwind_parse_fail(out, err, err_start, "Truncated UWOP_SAVE_NONVOL_FAR operand.");
                }
                uint32_t save_offset = read_u32_from_slots(lo, hi);
                if (save_nonvol_far_suspicious(save_offset)) out->anomalies |= UA_OPERAND_SANITY;
                if (!is_unwindable_gpr(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                if (strict_abi && !is_abi_nonvolatile_gpr(opinfo)) {
                    out->anomalies |= UA_ABI_REGISTER_CLASS;
                }
                if (strict_abi && save_offset == 0) {
                    out->anomalies |= UA_ABI_SAVE_OFFSET;
                }
                if (opinfo < 16) nonvol_mask |= (uint16_t)(1u << opinfo);
                break;
            }
            case 6: { /* save xmm (v1, undocumented encoding) or epilog (v2) */
                if (ver != 2) {
                    uint16_t scaled = 0;
                    if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &scaled)) {
                        out->anomalies |= UA_TRUNCATED;
                        unwind_diag_set_read_failure(out, b, "UWOP_SAVE_XMM operand",
                                                     codes_off + (size_t)(i + 1) * 2u,
                                                     2u, record_limit);
                        return unwind_parse_fail(out, err, err_start, "Truncated UWOP_SAVE_XMM operand.");
                    }
                    if (!is_unwindable_xmm(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                    if (strict_abi && !is_abi_nonvolatile_xmm(opinfo)) {
                        out->anomalies |= UA_ABI_REGISTER_CLASS;
                    }
                    if (strict_abi && scaled == 0) {
                        out->anomalies |= UA_ABI_SAVE_OFFSET;
                    }
                    if (opinfo < 16) xmm_mask |= (uint16_t)(1u << opinfo);
                }
                break;
            }
            case 7: { /* save xmm far (v1, undocumented encoding) or spare (v2) */
                if (ver != 2) {
                    uint16_t lo=0, hi=0;
                    if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &lo) ||
                        !read_u16_slot(b, codes_off + (size_t)(i+2) * 2, &hi)) {
                        out->anomalies |= UA_TRUNCATED;
                        unwind_diag_set_read_failure(out, b, "UWOP_SAVE_XMM_FAR operand",
                                                     codes_off + (size_t)(i + 1) * 2u,
                                                     4u, record_limit);
                        return unwind_parse_fail(out, err, err_start, "Truncated UWOP_SAVE_XMM_FAR operand.");
                    }
                    uint32_t save_offset = read_u32_from_slots(lo, hi);
                    if (save_xmm_far_suspicious(save_offset)) out->anomalies |= UA_OPERAND_SANITY;
                    if (!is_unwindable_xmm(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                    if (strict_abi && !is_abi_nonvolatile_xmm(opinfo)) {
                        out->anomalies |= UA_ABI_REGISTER_CLASS;
                    }
                    if (strict_abi && save_offset == 0) {
                        out->anomalies |= UA_ABI_SAVE_OFFSET;
                    }
                    if (opinfo < 16) xmm_mask |= (uint16_t)(1u << opinfo);
                }
                break;
            }
            case 8: { /* save xmm128 */
                uint16_t scaled = 0;
                if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &scaled)) {
                    out->anomalies |= UA_TRUNCATED;
                    unwind_diag_set_read_failure(out, b, "UWOP_SAVE_XMM128 operand",
                                                 codes_off + (size_t)(i + 1) * 2u,
                                                 2u, record_limit);
                    return unwind_parse_fail(out, err, err_start, "Truncated UWOP_SAVE_XMM128 operand.");
                }
                if (!is_unwindable_xmm(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                if (strict_abi && !is_abi_nonvolatile_xmm(opinfo)) {
                    out->anomalies |= UA_ABI_REGISTER_CLASS;
                }
                if (strict_abi && scaled == 0) {
                    out->anomalies |= UA_ABI_SAVE_OFFSET;
                }
                if (opinfo < 16) xmm_mask |= (uint16_t)(1u << opinfo);
                break;
            }
            case 9: { /* save xmm128 far */
                uint16_t lo=0, hi=0;
                if (!read_u16_slot(b, codes_off + (size_t)(i+1) * 2, &lo) ||
                    !read_u16_slot(b, codes_off + (size_t)(i+2) * 2, &hi)) {
                    out->anomalies |= UA_TRUNCATED;
                    unwind_diag_set_read_failure(out, b, "UWOP_SAVE_XMM128_FAR operand",
                                                 codes_off + (size_t)(i + 1) * 2u,
                                                 4u, record_limit);
                    return unwind_parse_fail(out, err, err_start, "Truncated UWOP_SAVE_XMM128_FAR operand.");
                }
                uint32_t save_offset = read_u32_from_slots(lo, hi);
                if (save_xmm_far_suspicious(save_offset)) out->anomalies |= UA_OPERAND_SANITY;
                if (!is_unwindable_xmm(opinfo)) out->anomalies |= UA_BAD_OPERAND;
                if (strict_abi && !is_abi_nonvolatile_xmm(opinfo)) {
                    out->anomalies |= UA_ABI_REGISTER_CLASS;
                }
                if (strict_abi && save_offset == 0) {
                    out->anomalies |= UA_ABI_SAVE_OFFSET;
                }
                if (opinfo < 16) xmm_mask |= (uint16_t)(1u << opinfo);
                break;
            }
            case 10: /* push machframe */
                if (opinfo > 1) out->anomalies |= UA_BAD_OPERAND;
                add_fixed_stack(&fixed_stack, (opinfo == 0) ? 40u : 48u, &out->anomalies);
                break;
            default:
                /* ignore */
                break;
        }

        if (ver == 2 && op == 6) v2_seen_epilog = true;
        i += slots;
    }
    if (fr != 0 && !saw_set_fpreg && !(flags & UNW_FLAG_CHAININFO)) {
        out->anomalies |= UA_BAD_OPERAND;
    }

    /* tail (handler or chained info) */
    size_t after_codes = codes_off + codes_bytes;

    if (flags & UNW_FLAG_CHAININFO) {
        out->has_chain = true;
        RuntimeFunction chain = {0};
        if (!parse_chain_rf(b, img, after_codes, &chain)) {
            out->anomalies |= UA_TRUNCATED;
            unwind_diag_set_read_failure(out, b, "CHAININFO RUNTIME_FUNCTION tail", after_codes, 12u, record_limit);
            return unwind_parse_fail(out, err, err_start, "Truncated CHAININFO RUNTIME_FUNCTION.");
        } else {
            out->chain = chain;
            if (chain.end_rva <= chain.begin_rva ||
                chain.begin_rva >= img->size_of_image ||
                chain.end_rva > img->size_of_image ||
                chain.unwind_rva == 0 ||
                chain.unwind_rva >= img->size_of_image) {
                out->anomalies |= UA_CHAIN_INVALID;
            }
        }
    }

    if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        out->has_handler = true;
        uint32_t handler_rva = 0;
        if (!buf_read_u32(b, after_codes + 0, &handler_rva)) {
            out->anomalies |= UA_TRUNCATED;
            unwind_diag_set_read_failure(out, b, "exception handler RVA tail", after_codes, 4u, record_limit);
            return unwind_parse_fail(out, err, err_start, "Truncated exception handler RVA.");
        } else {
            out->handler_rva = handler_rva;
            if (handler_rva >= img->size_of_image) {
                out->anomalies |= UA_HANDLER_OOB;
                unwind_diag_set(out, b, "exception handler RVA", true, after_codes,
                                true, 4u, 4u, false, 0, 0);
            }
        }
    }

    out->fixed_stack_bytes = fixed_stack;
    out->pushed_nonvol_count = pushed;
    out->saved_nonvol_mask = nonvol_mask;
    out->saved_xmm_mask = xmm_mask;

    /* follow chain (lightly): detect loops and depth. */
    if (follow_chain && out->has_chain) {
        uint32_t seen[16]; /* depth max 16 */
        int seen_n = 0;
        out->chain_path[0] = unwind_rva;
        out->chain_path_count = 1;
        uint32_t cur = out->chain.unwind_rva;
        for (int depth = 0; depth < max_depth; depth++) {
            bool loop = false;
            for (int j = 0; j < seen_n; j++) if (seen[j] == cur) loop = true;
            if (out->chain_path_count < UNWIND_DIAG_MAX_CHAIN_PATH) {
                out->chain_path[out->chain_path_count++] = cur;
            }
            if (loop) {
                out->anomalies |= UA_CHAIN_LOOP;
                out->chain_loop_detected = true;
                out->chain_loop_rva = cur;
                unwind_diag_set(out, b, "CHAININFO chain path", true, (size_t)uoff,
                                false, 0, 0, false, 0, 0);
                break;
            }
            if (seen_n < (int)(sizeof(seen)/sizeof(seen[0]))) seen[seen_n++] = cur;

            UnwindSummary tmp;
            StrBuf tmp_ops = {0};
            StrBuf tmp_err = {0};
            sb_init(&tmp_err, 256);
            sb_init(&tmp_ops, 256);
            UnwindParseOpts o2 = {
                .max_chain_depth = 0,
                .follow_chain = false,
                .strict_abi = strict_abi
            };
            if (!unwind_parse(b, img, cur, &o2, &tmp, NULL, &tmp_err)) {
                out->anomalies |= UA_TRUNCATED;
                sb_free(&tmp_err);
                sb_free(&tmp_ops);
                break;
            }
            /* combine fixed stack heuristically */
            add_fixed_stack(&out->fixed_stack_bytes, tmp.fixed_stack_bytes, &out->anomalies);
            out->pushed_nonvol_count += tmp.pushed_nonvol_count;
            out->saved_nonvol_mask |= tmp.saved_nonvol_mask;
            out->saved_xmm_mask |= tmp.saved_xmm_mask;
            if (tmp.frame_reg != out->frame_reg || tmp.frame_off != out->frame_off) {
                out->anomalies |= UA_BAD_OPERAND;
            }
            if (!out->has_handler && tmp.has_handler) {
                out->has_handler = true;
                out->handler_rva = tmp.handler_rva;
            }
            sb_free(&tmp_err);
            sb_free(&tmp_ops);

            if (!tmp.has_chain) break;
            cur = tmp.chain.unwind_rva;
            if (depth == max_depth-1) {
                out->anomalies |= UA_CHAIN_DEPTH_EXCEEDED;
                unwind_diag_set(out, b, "CHAININFO max depth", true, (size_t)uoff,
                                false, 0, 0, true, (uint32_t)max_depth, (uint32_t)depth + 1u);
            }
        }
    }

    out->valid = true;
    return true;
}

RuntimeFunctionReadResult unwind_read_runtime_functions_ex(
                                  const Buf* b,
                                  const PeImage* img,
                                  RuntimeFunction** out_rf,
                                  size_t* out_count,
                                  StrBuf* err) {
    if (!b || !img || !out_rf || !out_count || !err) {
        return RUNTIME_FUNCTION_READ_MALFORMED;
    }
    *out_rf = NULL;
    *out_count = 0;

    if (img->exception_rva == 0 && img->exception_size == 0) {
        return RUNTIME_FUNCTION_READ_OK;
    }
    if (img->exception_rva == 0 || img->exception_size == 0) {
        sb_append(err, "Malformed exception directory: RVA and size must both be zero or non-zero.\n");
        return RUNTIME_FUNCTION_READ_MALFORMED;
    }
    uint32_t off = 0;
    if (!pe_rva_to_fileoff(img, img->exception_rva, &off)) {
        sb_appendf(err, "Exception directory RVA 0x%08x not mappable.\n", img->exception_rva);
        return RUNTIME_FUNCTION_READ_MALFORMED;
    }
    if ((size_t)off + img->exception_size > b->size) {
        sb_append(err, "Exception directory out of file range.\n");
        return RUNTIME_FUNCTION_READ_MALFORMED;
    }
    if (img->exception_size < 12) {
        sb_append(err, "Exception directory size too small.\n");
        return RUNTIME_FUNCTION_READ_MALFORMED;
    }
    if ((img->exception_size % 12u) != 0) {
        sb_append(err, "Exception directory size is not a multiple of RUNTIME_FUNCTION size.\n");
        return RUNTIME_FUNCTION_READ_MALFORMED;
    }
    size_t n = img->exception_size / 12;
    RuntimeFunction* rf = (RuntimeFunction*)calloc(n, sizeof(RuntimeFunction));
    if (!rf) {
        sb_append(err, "Out of memory.\n");
        return RUNTIME_FUNCTION_READ_OOM;
    }

    for (size_t i = 0; i < n; i++) {
        size_t e = (size_t)off + i*12;
        uint32_t bva=0, eva=0, uva=0;
        if (!buf_read_u32(b, e + 0, &bva) ||
            !buf_read_u32(b, e + 4, &eva) ||
            !buf_read_u32(b, e + 8, &uva)) {
            free(rf);
            sb_append(err, "Failed to read runtime function entry.\n");
            return RUNTIME_FUNCTION_READ_MALFORMED;
        }
        rf[i].begin_rva = bva;
        rf[i].end_rva = eva;
        rf[i].unwind_rva = uva;
    }

    *out_rf = rf;
    *out_count = n;
    return RUNTIME_FUNCTION_READ_OK;
}

bool unwind_read_runtime_functions(const Buf* b,
                                  const PeImage* img,
                                  RuntimeFunction** out_rf,
                                  size_t* out_count,
                                  StrBuf* err) {
    return unwind_read_runtime_functions_ex(
               b, img, out_rf, out_count, err) == RUNTIME_FUNCTION_READ_OK;
}
