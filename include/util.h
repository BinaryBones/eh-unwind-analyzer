#pragma once
/*
  util.h - small helpers for safe parsing and dynamic arrays
  Project: EH/Unwind Analyzer (PE x64)
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Buf {
    const uint8_t* data;
    size_t size;
} Buf;

bool buf_init_from_file(Buf* out, const char* path, uint8_t** owned_mem);
void buf_free_owned(uint8_t* owned_mem);

bool buf_read(const Buf* b, size_t off, void* out, size_t len);
bool buf_read_u8 (const Buf* b, size_t off, uint8_t*  out);
bool buf_read_u16(const Buf* b, size_t off, uint16_t* out);
bool buf_read_u32(const Buf* b, size_t off, uint32_t* out);
bool buf_read_u64(const Buf* b, size_t off, uint64_t* out);

static inline uint16_t le16(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t le32(const uint8_t* p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}
static inline uint64_t le64(const uint8_t* p) {
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

typedef struct StrBuf {
    char*  s;
    size_t len;
    size_t cap;
    bool failed;
} StrBuf;

#if defined(__MINGW32__) && (defined(__GNUC__) || defined(__clang__))
#define EHUA_PRINTF_FORMAT(format_index, first_arg) \
    __attribute__((format(gnu_printf, format_index, first_arg)))
#elif defined(__GNUC__) || defined(__clang__)
#define EHUA_PRINTF_FORMAT(format_index, first_arg) \
    __attribute__((format(printf, format_index, first_arg)))
#else
#define EHUA_PRINTF_FORMAT(format_index, first_arg)
#endif

bool sb_init(StrBuf* sb, size_t initial_cap);
void sb_free(StrBuf* sb);
bool sb_appendf(StrBuf* sb, const char* fmt, ...)
    EHUA_PRINTF_FORMAT(2, 3);
bool sb_append(StrBuf* sb, const char* s);
bool sb_appendn(StrBuf* sb, const char* s, size_t n);
bool sb_ok(const StrBuf* sb);
bool file_write_atomic(const char* path, const char* data, size_t len);

/* SHA-256 digest encoded as 64 lowercase hexadecimal characters plus NUL. */
bool sha256_hex(const uint8_t* data, size_t size, char out_hex[65]);

#undef EHUA_PRINTF_FORMAT

#ifdef __cplusplus
}
#endif
