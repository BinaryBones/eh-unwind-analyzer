#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "unwind.h"
#include "pe.h"
#include "util.h"

static PeImage make_fake_img_1sec(PeSection* sec) {
    PeImage img;
    memset(&img, 0, sizeof(img));
    img.ok = true;
    img.is_pe64 = true;
    img.image_base = 0x140000000ull;
    img.size_of_image = 0x4000;
    img.num_sections = 1;
    img.sections = sec;
    return img;
}

static void test_alloc_small(void) {
    /* Build a minimal file buffer with UNWIND_INFO at RVA 0x1000 => file off 0x200 */
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    /* UNWIND_INFO:
       byte0: version=1 flags=0
       prolog=0x00
       count=1
       frame=0
       codes: one slot UWOP_ALLOC_SMALL (op=2), opinfo=0 => alloc=8
     */
    size_t off = 0x200;
    file[off + 0] = 0x01; /* ver1 flags0 */
    file[off + 1] = 0x00; /* prolog */
    file[off + 2] = 0x01; /* count */
    file[off + 3] = 0x00; /* frame */
    file[off + 4] = 0x00; /* CodeOffset */
    file[off + 5] = 0x02; /* UWOP_ALLOC_SMALL */
    file[off + 6] = 0x00;
    file[off + 7] = 0x00;

    Buf b = { file, sizeof(file) };

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;
    sec.characteristics = 0x40000040u; /* read */

    PeImage img = make_fake_img_1sec(&sec);

    StrBuf err; sb_init(&err, 256);
    UnwindSummary us;
    bool ok = unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err);
    assert(ok);
    assert(us.version == 1);
    assert(us.flags == 0);
    assert(us.fixed_stack_bytes == 8);
    assert(us.anomalies == 0);
    sb_free(&err);
}

static void test_push_nonvol(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    size_t off = 0x200;
    file[off + 0] = 0x01;
    file[off + 1] = 0x00;
    file[off + 2] = 0x01;
    file[off + 3] = 0x00;
    file[off + 4] = 0x00;
    file[off + 5] = 0x30; /* UWOP_PUSH_NONVOL op=0 opinfo=3 (RBX) */
    file[off + 6] = 0x00;
    file[off + 7] = 0x00;

    Buf b = { file, sizeof(file) };

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;
    sec.characteristics = 0x40000040u;

    PeImage img = make_fake_img_1sec(&sec);

    StrBuf err; sb_init(&err, 256);
    UnwindSummary us;
    bool ok = unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err);
    assert(ok);
    assert(us.fixed_stack_bytes == 8);
    assert((us.saved_nonvol_mask & (1u << 3)) != 0);
    sb_free(&err);
}

static void test_codeoffset_order_and_operand_sanity(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    /* Two op starts with ascending code offsets (spec expects descending order),
       plus a SAVE_NONVOL_FAR operand that uses a long form for a tiny offset. */
    size_t off = 0x200;
    file[off + 0] = 0x01; /* ver1 flags0 */
    file[off + 1] = 0x20; /* prolog */
    file[off + 2] = 0x04; /* count */
    file[off + 3] = 0x00; /* frame */

    file[off + 4] = 0x08; /* code offset */
    file[off + 5] = 0x05; /* UWOP_SAVE_NONVOL_FAR, reg=RAX */
    file[off + 6] = 0x20; /* lo = 0x0020 => offset 32 (too small for FAR) */
    file[off + 7] = 0x00;
    file[off + 8] = 0x00; /* hi */
    file[off + 9] = 0x00;
    file[off +10] = 0x10; /* next start op has larger offset => ordering anomaly */
    file[off +11] = 0x02; /* UWOP_ALLOC_SMALL */

    Buf b = { file, sizeof(file) };

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;
    sec.characteristics = 0x40000040u;

    PeImage img = make_fake_img_1sec(&sec);

    StrBuf err; sb_init(&err, 256);
    UnwindSummary us;
    bool ok = unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err);
    assert(ok);
    assert((us.anomalies & UA_CODEOFFSET_ORDER) != 0);
    assert((us.anomalies & UA_OPERAND_SANITY) != 0);
    sb_free(&err);
}

static void test_real_world_compatible_operands(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    /* MSVC, Rust and OpenSSL emit volatile register operands, zero save
       offsets and non-zero ignored SET_FPREG OpInfo values. */
    size_t off = 0x200;
    file[off + 0] = 0x01;
    file[off + 1] = 0x08;
    file[off + 2] = 0x06;
    file[off + 3] = 0x0b; /* frame register R11, offset 0 */
    file[off + 4] = 0x08;
    file[off + 5] = 0xb3; /* SET_FPREG, ignored OpInfo=11 */
    file[off + 6] = 0x06;
    file[off + 7] = 0x08; /* SAVE_XMM128 XMM0 */
    file[off + 8] = 0x00;
    file[off + 9] = 0x00; /* offset 0 */
    file[off +10] = 0x03;
    file[off +11] = 0x04; /* SAVE_NONVOL RAX */
    file[off +12] = 0x00;
    file[off +13] = 0x00; /* offset 0 */
    file[off +14] = 0x01;
    file[off +15] = 0x00; /* PUSH_NONVOL RAX */

    Buf b = { file, sizeof(file) };
    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert(us.anomalies == 0);
    assert(us.frame_reg == 11);
    assert(us.fixed_stack_bytes == 8);
    assert((us.saved_nonvol_mask & 1u) != 0);
    assert((us.saved_xmm_mask & 1u) != 0);

    UnwindParseOpts strict = {
        .max_chain_depth = 8,
        .follow_chain = true,
        .strict_abi = true
    };
    assert(unwind_parse(&b, &img, 0x1000, &strict, &us, NULL, &err));
    assert((us.anomalies & UA_ABI_REGISTER_CLASS) != 0);
    assert((us.anomalies & UA_ABI_RESERVED_OPINFO) != 0);
    assert((us.anomalies & UA_ABI_SAVE_OFFSET) != 0);
    sb_free(&err);
}

static void test_strict_abi_push_order_and_chain_restriction(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    size_t ordered = 0x200;
    file[ordered + 0] = 0x01;
    file[ordered + 1] = 0x08;
    file[ordered + 2] = 0x02;
    file[ordered + 4] = 0x08;
    file[ordered + 5] = 0x30; /* PUSH_NONVOL RBX */
    file[ordered + 6] = 0x04;
    file[ordered + 7] = 0x02; /* ALLOC_SMALL after PUSH in unwind array */

    size_t chained = 0x240;
    file[chained + 0] = 0x21; /* Version 1 + CHAININFO. */
    file[chained + 1] = 0x04;
    file[chained + 2] = 0x01;
    file[chained + 4] = 0x04;
    file[chained + 5] = 0x02; /* Additional fixed allocation is unsupported. */
    file[chained + 8] = 0x00;
    file[chained + 9] = 0x11; /* Begin RVA 0x1100. */
    file[chained +12] = 0x20;
    file[chained +13] = 0x11; /* End RVA 0x1120. */
    file[chained +16] = 0x00;
    file[chained +17] = 0x11; /* Parent unwind RVA 0x1100. */

    Buf b = { file, sizeof(file) };
    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x400;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x400;
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;
    UnwindParseOpts strict = {
        .max_chain_depth = 8,
        .follow_chain = false,
        .strict_abi = true
    };

    assert(unwind_parse(&b, &img, 0x1000, &strict, &us, NULL, &err));
    assert((us.anomalies & UA_ABI_PUSH_ORDER) != 0);

    assert(unwind_parse(&b, &img, 0x1040, &strict, &us, NULL, &err));
    assert((us.anomalies & UA_ABI_CHAIN_RESTRICTION) != 0);
    sb_free(&err);
}

static void test_v2_epilog_descriptors(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    size_t off = 0x200;
    file[off + 0] = 0x02; /* Version 2. */
    file[off + 1] = 0x02; /* Prolog size. */
    file[off + 2] = 0x04;
    file[off + 3] = 0x00;
    file[off + 4] = 0x03;
    file[off + 5] = 0x16; /* Short first epilog descriptor, size 3. */
    file[off + 6] = 0x00;
    file[off + 7] = 0x06; /* Epilog terminator/padding descriptor. */
    file[off + 8] = 0x02;
    file[off + 9] = 0x60; /* PUSH_NONVOL RSI. */
    file[off +10] = 0x01;
    file[off +11] = 0x70; /* PUSH_NONVOL RDI. */

    Buf b = { file, sizeof(file) };
    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert(us.anomalies == 0);
    assert(us.fixed_stack_bytes == 16);
    assert(us.pushed_nonvol_count == 2);

    size_t long_form = 0x240;
    static const uint8_t long_record[] = {
        0x02, 0x1d, 0x0a, 0x00,
        0x0b, 0x06, 0x7c, 0x16,
        0x1d, 0x92, 0x19, 0xf0,
        0x17, 0xe0, 0x15, 0xc0,
        0x13, 0x70, 0x12, 0x60,
        0x11, 0x50, 0x10, 0x30,
    };
    memcpy(file + long_form, long_record, sizeof(long_record));
    StrBuf ops;
    assert(sb_init(&ops, 128));
    assert(unwind_parse(&b, &img, 0x1040, NULL, &us, &ops, &err));
    assert(us.anomalies == 0);
    assert(us.fixed_stack_bytes == 136);
    assert(us.pushed_nonvol_count == 7);
    assert(strstr(ops.s, "offset_from_end=380") != NULL);
    sb_free(&ops);
    sb_free(&err);
}

static void test_chain_inherits_frame_and_handler(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    size_t child = 0x200;
    file[child + 0] = 0x21; /* Version 1 + CHAININFO. */
    file[child + 3] = 0x55; /* Inherited RBP + 80. */
    file[child + 4] = 0x00; file[child + 5] = 0x20;
    file[child + 8] = 0x20; file[child + 9] = 0x20;
    file[child +12] = 0x00; file[child +13] = 0x11; /* Parent RVA 0x1100. */

    size_t parent = 0x300;
    file[parent + 0] = 0x09; /* Version 1 + EHANDLER. */
    file[parent + 1] = 0x02;
    file[parent + 2] = 0x01;
    file[parent + 3] = 0x55;
    file[parent + 4] = 0x02;
    file[parent + 5] = 0x53; /* SET_FPREG, ignored OpInfo=5. */
    file[parent + 8] = 0x00; file[parent + 9] = 0x12; /* Handler RVA 0x1200. */

    Buf b = { file, sizeof(file) };
    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x400;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x400;
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert(us.anomalies == 0);
    assert(us.has_chain);
    assert(us.has_handler);
    assert(us.handler_rva == 0x1200);
    sb_free(&err);
}

static void test_flag_and_frame_sanity(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    /* CHAININFO combined with EHANDLER is invalid, and frame offset without frame register is suspicious. */
    size_t off = 0x200;
    file[off + 0] = 0x29; /* ver1, flags=CHAININFO|EHANDLER */
    file[off + 1] = 0x00;
    file[off + 2] = 0x00;
    file[off + 3] = 0x10; /* frame_reg=0, frame_off=1 */

    Buf b = { file, sizeof(file) };

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;
    sec.characteristics = 0x40000040u;

    PeImage img = make_fake_img_1sec(&sec);

    StrBuf err; sb_init(&err, 256);
    UnwindSummary us;
    bool ok = unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err);
    assert(ok);
    assert((us.anomalies & UA_BAD_OPERAND) != 0);
    sb_free(&err);
}

static void test_parse_error_is_preserved(void) {
    uint8_t file[0x220];
    memset(file, 0, sizeof(file));

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;

    Buf b = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    bool ok = unwind_parse(&b, &img, 0x1100, NULL, &us, NULL, &err);
    assert(!ok);
    assert((us.anomalies & UA_TRUNCATED) != 0);
    assert(strstr(us.parse_error, "header out of file range") != NULL);
    assert(strchr(us.parse_error, '\n') == NULL);
    sb_free(&err);
}

static void test_unsupported_version_is_fatal(void) {
    uint8_t file[0x400];
    memset(file, 0, sizeof(file));
    file[0x200] = 0x03; /* V3 has a different format and must not be parsed as V1/V2. */

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x200;

    Buf b = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(!unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert((us.anomalies & UA_VERSION_UNKNOWN) != 0);
    assert(strstr(us.parse_error, "Unsupported UNWIND_INFO version") != NULL);
    sb_free(&err);
}

static void test_truncated_handler_tail_is_fatal(void) {
    uint8_t file[0x204];
    memset(file, 0, sizeof(file));
    file[0x200] = 0x09; /* Version 1 + EHANDLER. */

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 4;
    sec.raw_ptr = 0x200;
    sec.raw_size = 4;

    Buf b = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(!unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert((us.anomalies & UA_TRUNCATED) != 0);
    assert(strstr(us.parse_error, "handler RVA") != NULL);
    sb_free(&err);
}

static void test_chain_validation_and_alignment(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));
    size_t chain_off = 0x204;
    file[chain_off] = 0x21; /* Version 1 + CHAININFO. */
    file[chain_off + 4] = 0x00; /* BeginRVA = 0x2000 */
    file[chain_off + 5] = 0x20;
    file[chain_off + 8] = 0x00; /* EndRVA = 0x1000 */
    file[chain_off + 9] = 0x10;
    /* Chained UnwindRVA remains zero. */

    size_t unaligned_off = 0x302;
    file[unaligned_off] = 0x01; /* Valid empty V1 record at an unaligned RVA. */

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x400;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x400;

    Buf b = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;
    UnwindParseOpts no_follow = { .max_chain_depth = 8, .follow_chain = false };

    assert(unwind_parse(&b, &img, 0x1004, &no_follow, &us, NULL, &err));
    assert((us.anomalies & UA_CHAIN_INVALID) != 0);
    assert((us.anomalies & UA_ALIGNMENT) == 0);

    assert(unwind_parse(&b, &img, 0x1102, NULL, &us, NULL, &err));
    assert((us.anomalies & UA_ALIGNMENT) != 0);
    sb_free(&err);
}


static void test_count_codes_section_boundary_diagnostic(void) {
    uint8_t file[0x240];
    memset(file, 0, sizeof(file));

    size_t off = 0x200;
    file[off + 0] = 0x01;
    file[off + 2] = 0x02; /* two slots on disk => four bytes after header */
    file[off + 4] = 0x00;
    file[off + 5] = 0x02; /* only one slot remains inside section raw range */

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x20;
    sec.raw_ptr = 0x200;
    sec.raw_size = 6; /* header + one slot: CountOfCodes crosses section boundary */

    Buf b = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(!unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert((us.anomalies & UA_TRUNCATED) != 0);
    assert(strcmp(us.diagnostic_field, "CountOfCodes / UNWIND_CODE array") == 0);
    assert(us.diagnostic_has_file_offset);
    assert(us.diagnostic_file_offset == 0x204);
    assert(us.diagnostic_has_size);
    assert(us.diagnostic_expected_size == 4);
    assert(us.diagnostic_available_size == 2);
    assert(us.diagnostic_has_slots);
    assert(us.diagnostic_expected_slots == 2);
    assert(us.diagnostic_available_slots == 1);
    assert(us.diagnostic_has_bytes);
    assert(us.diagnostic_bytes_count == 2);
    sb_free(&err);
}

static void test_count_codes_operand_slots_diagnostic(void) {
    uint8_t file[0x260];
    memset(file, 0, sizeof(file));

    size_t off = 0x200;
    file[off + 0] = 0x01;
    file[off + 1] = 0x04;
    file[off + 2] = 0x01; /* one logical slot */
    file[off + 4] = 0x04;
    file[off + 5] = 0x11; /* UWOP_ALLOC_LARGE opinfo=1 requires three slots */

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x100;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x100;

    Buf b = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(!unwind_parse(&b, &img, 0x1000, NULL, &us, NULL, &err));
    assert((us.anomalies & UA_TRUNCATED) != 0);
    assert(strcmp(us.diagnostic_field, "CountOfCodes / UWOP operand slots") == 0);
    assert(us.diagnostic_has_slots);
    assert(us.diagnostic_expected_slots == 3);
    assert(us.diagnostic_available_slots == 1);
    assert(us.diagnostic_expected_size == 6);
    assert(us.diagnostic_available_size == 2);
    assert(us.diagnostic_file_offset == 0x204);
    sb_free(&err);
}

static void test_chain_loop_path_diagnostic(void) {
    uint8_t file[0x600];
    memset(file, 0, sizeof(file));

    size_t a = 0x200;
    file[a + 0] = 0x21; /* Version 1 + CHAININFO */
    file[a + 4] = 0x00; file[a + 5] = 0x11;
    file[a + 8] = 0x20; file[a + 9] = 0x11;
    file[a +12] = 0x40; file[a +13] = 0x10; /* chain to 0x1040 */

    size_t b_off = 0x240;
    file[b_off + 0] = 0x21;
    file[b_off + 4] = 0x20; file[b_off + 5] = 0x11;
    file[b_off + 8] = 0x40; file[b_off + 9] = 0x11;
    file[b_off +12] = 0x00; file[b_off +13] = 0x10; /* chain back to 0x1000 */

    PeSection sec;
    memset(&sec, 0, sizeof(sec));
    memcpy(sec.name, ".xdata", 6);
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x400;
    sec.raw_ptr = 0x200;
    sec.raw_size = 0x400;

    Buf buf = { file, sizeof(file) };
    PeImage img = make_fake_img_1sec(&sec);
    StrBuf err;
    assert(sb_init(&err, 128));
    UnwindSummary us;

    assert(unwind_parse(&buf, &img, 0x1000, NULL, &us, NULL, &err));
    assert((us.anomalies & UA_CHAIN_LOOP) != 0);
    assert(us.chain_loop_detected);
    assert(us.chain_path_count >= 4);
    assert(us.chain_path[0] == 0x1000);
    assert(us.chain_path[1] == 0x1040);
    assert(us.chain_path[2] == 0x1000);
    assert(us.chain_path[3] == 0x1040);
    assert(us.chain_loop_rva == 0x1040);
    assert(strcmp(us.diagnostic_field, "CHAININFO chain path") == 0);
    sb_free(&err);
}

int main(void) {
    test_alloc_small();
    test_push_nonvol();
    test_codeoffset_order_and_operand_sanity();
    test_real_world_compatible_operands();
    test_strict_abi_push_order_and_chain_restriction();
    test_v2_epilog_descriptors();
    test_chain_inherits_frame_and_handler();
    test_flag_and_frame_sanity();
    test_parse_error_is_preserved();
    test_unsupported_version_is_fatal();
    test_truncated_handler_tail_is_fatal();
    test_chain_validation_and_alignment();
    test_count_codes_section_boundary_diagnostic();
    test_count_codes_operand_slots_diagnostic();
    test_chain_loop_path_diagnostic();
    printf("unit_unwind: OK\n");
    return 0;
}
