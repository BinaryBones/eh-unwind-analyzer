#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

bool buf_init_from_file(Buf* out, const char* path, uint8_t** owned_mem) {
    if (!out || !path || !owned_mem) return false;
    *owned_mem = NULL;
    FILE* f = fopen(path, "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return false; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return false; }

    size_t alloc_size = sz > 0 ? (size_t)sz : 1u;
    uint8_t* mem = (uint8_t*)malloc(alloc_size);
    if (!mem) { fclose(f); return false; }

    size_t rd = fread(mem, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(mem); return false; }

    out->data = mem;
    out->size = (size_t)sz;
    *owned_mem = mem;
    return true;
}

void buf_free_owned(uint8_t* owned_mem) {
    free(owned_mem);
}

bool buf_read(const Buf* b, size_t off, void* out, size_t len) {
    if (!b || !out) return false;
    if (off > b->size) return false;
    if (len > b->size - off) return false;
    memcpy(out, b->data + off, len);
    return true;
}

bool buf_read_u8(const Buf* b, size_t off, uint8_t* out) {
    return buf_read(b, off, out, 1);
}
bool buf_read_u16(const Buf* b, size_t off, uint16_t* out) {
    uint8_t tmp[2];
    if (!buf_read(b, off, tmp, 2)) return false;
    *out = le16(tmp);
    return true;
}
bool buf_read_u32(const Buf* b, size_t off, uint32_t* out) {
    uint8_t tmp[4];
    if (!buf_read(b, off, tmp, 4)) return false;
    *out = le32(tmp);
    return true;
}
bool buf_read_u64(const Buf* b, size_t off, uint64_t* out) {
    uint8_t tmp[8];
    if (!buf_read(b, off, tmp, 8)) return false;
    *out = le64(tmp);
    return true;
}

static bool sb_reserve(StrBuf* sb, size_t need_cap) {
    if (!sb || sb->failed) return false;
    if (need_cap <= sb->cap) return true;
    size_t newcap = sb->cap ? sb->cap : 128;
    while (newcap < need_cap) {
        size_t increment = newcap / 2u + 64u;
        if (increment > SIZE_MAX - newcap) {
            newcap = need_cap;
            break;
        }
        newcap += increment;
    }
    char* p = (char*)realloc(sb->s, newcap);
    if (!p) {
        sb->failed = true;
        return false;
    }
    sb->s = p;
    sb->cap = newcap;
    return true;
}

bool sb_init(StrBuf* sb, size_t initial_cap) {
    if (!sb) return false;
    sb->s = NULL;
    sb->len = 0;
    sb->cap = 0;
    sb->failed = false;
    if (initial_cap == 0) initial_cap = 256;
    if (!sb_reserve(sb, initial_cap) || !sb->s) {
        sb->failed = true;
        return false;
    }
    sb->s[0] = 0;
    return true;
}

void sb_free(StrBuf* sb) {
    if (!sb) return;
    free(sb->s);
    sb->s = NULL;
    sb->len = 0;
    sb->cap = 0;
    sb->failed = false;
}

bool sb_appendn(StrBuf* sb, const char* s, size_t n) {
    if (!sb) return false;
    if (sb->failed || (!s && n != 0)) {
        sb->failed = true;
        return false;
    }
    if (sb->len == SIZE_MAX || n > SIZE_MAX - sb->len - 1u) {
        sb->failed = true;
        return false;
    }
    if (!sb_reserve(sb, sb->len + n + 1)) return false;
    if (n != 0) memcpy(sb->s + sb->len, s, n);
    sb->len += n;
    sb->s[sb->len] = 0;
    return true;
}

bool sb_append(StrBuf* sb, const char* s) {
    if (!sb) return false;
    if (!s) {
        sb->failed = true;
        return false;
    }
    return sb_appendn(sb, s, strlen(s));
}

bool sb_appendf(StrBuf* sb, const char* fmt, ...) {
    if (!sb) return false;
    if (sb->failed || !fmt) {
        sb->failed = true;
        return false;
    }
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) {
        va_end(ap2);
        sb->failed = true;
        return false;
    }

    if (sb->len == SIZE_MAX || (size_t)need > SIZE_MAX - sb->len - 1u) {
        va_end(ap2);
        sb->failed = true;
        return false;
    }
    if (!sb_reserve(sb, sb->len + (size_t)need + 1u)) { va_end(ap2); return false; }
    int wrote = vsnprintf(sb->s + sb->len, sb->cap - sb->len, fmt, ap2);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    va_end(ap2);
    if (wrote != need) {
        sb->failed = true;
        return false;
    }
    sb->len += (size_t)wrote;
    return true;
}

bool sb_ok(const StrBuf* sb) {
    return sb && !sb->failed && sb->s && sb->len < sb->cap;
}

bool file_write_atomic(const char* path, const char* data, size_t len) {
    if (!path || (!data && len != 0)) return false;
    size_t path_len = strlen(path);
    if (path_len > SIZE_MAX - 48u) return false;

    size_t temp_size = path_len + 48u;
    char* temp_path = (char*)malloc(temp_size);
    if (!temp_path) return false;
#if defined(_WIN32)
    unsigned long process_id = (unsigned long)GetCurrentProcessId();
#else
    unsigned long process_id = (unsigned long)getpid();
#endif
    int written = snprintf(temp_path, temp_size, "%s.tmp.%lu", path, process_id);
    if (written < 0 || (size_t)written >= temp_size) {
        free(temp_path);
        return false;
    }

    FILE* f = fopen(temp_path, "wb");
    if (!f) {
        free(temp_path);
        return false;
    }
    size_t wr = len ? fwrite(data, 1, len, f) : 0u;
    bool ok = wr == len && ferror(f) == 0 && fflush(f) == 0;
    if (fclose(f) != 0) ok = false;

    if (ok) {
#if defined(_WIN32)
        ok = MoveFileExA(
                 temp_path,
                 path,
                 MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
        ok = rename(temp_path, path) == 0;
#endif
    }
    if (!ok) (void)remove(temp_path);
    free(temp_path);
    return ok;
}

typedef struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t block_len;
} Sha256Ctx;

static uint32_t sha256_rotr(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

static void sha256_transform(Sha256Ctx* ctx, const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++) {
        size_t j = i * 4;
        w[i] = ((uint32_t)block[j] << 24) |
               ((uint32_t)block[j + 1] << 16) |
               ((uint32_t)block[j + 2] << 8) |
               (uint32_t)block[j + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t s0 = sha256_rotr(w[i - 15], 7) ^ sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha256_rotr(w[i - 2], 17) ^ sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (size_t i = 0; i < 64; i++) {
        uint32_t s1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx* ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bit_count = 0;
    ctx->block_len = 0;
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t size) {
    if (size == 0) return;
    ctx->bit_count += (uint64_t)size * 8u;
    while (size > 0) {
        size_t available = 64u - ctx->block_len;
        size_t take = size < available ? size : available;
        memcpy(ctx->block + ctx->block_len, data, take);
        ctx->block_len += take;
        data += take;
        size -= take;
        if (ctx->block_len == 64u) {
            sha256_transform(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void sha256_final(Sha256Ctx* ctx, uint8_t digest[32]) {
    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len > 56u) {
        while (ctx->block_len < 64u) ctx->block[ctx->block_len++] = 0;
        sha256_transform(ctx, ctx->block);
        ctx->block_len = 0;
    }
    while (ctx->block_len < 56u) ctx->block[ctx->block_len++] = 0;
    for (int i = 7; i >= 0; i--) {
        ctx->block[ctx->block_len++] = (uint8_t)(ctx->bit_count >> (unsigned)(i * 8));
    }
    sha256_transform(ctx, ctx->block);

    for (size_t i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)ctx->state[i];
    }
}

bool sha256_hex(const uint8_t* data, size_t size, char out_hex[65]) {
    static const char digits[] = "0123456789abcdef";
    if (!out_hex || (size > 0 && !data)) return false;
    if ((uint64_t)size > UINT64_MAX / 8u) return false;
    Sha256Ctx ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, data, size);
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out_hex[i * 2] = digits[digest[i] >> 4];
        out_hex[i * 2 + 1] = digits[digest[i] & 0x0fu];
    }
    out_hex[64] = '\0';
    return true;
}
