#include "app_info.h"

#include <stdio.h>
#include <time.h>

const char* app_version(void) {
    return EHUA_VERSION;
}

const char* app_report_schema_version(void) {
    return EHUA_REPORT_SCHEMA_VERSION;
}

const char* app_build_compiler(void) {
#if defined(_MSC_VER)
    static char compiler[48];
    if (compiler[0] == '\0') {
        (void)snprintf(compiler, sizeof(compiler), "MSVC %d", _MSC_VER);
    }
    return compiler;
#elif defined(__clang__)
    return "Clang " __clang_version__;
#elif defined(__GNUC__)
    return "GCC " __VERSION__;
#else
    return "unknown";
#endif
}

const char* app_build_platform(void) {
#if defined(_WIN64)
    return "windows-x64";
#elif defined(_WIN32)
    return "windows-x86";
#elif defined(__APPLE__) && defined(__aarch64__)
    return "macos-arm64";
#elif defined(__APPLE__) && defined(__x86_64__)
    return "macos-x64";
#elif defined(__linux__) && defined(__x86_64__)
    return "linux-x64";
#elif defined(__linux__) && defined(__aarch64__)
    return "linux-arm64";
#else
    return "unknown";
#endif
}

const char* app_build_mode(void) {
#if defined(NDEBUG)
    return "release";
#else
    return "debug";
#endif
}

bool app_utc_timestamp(char* out, size_t out_size) {
    if (!out || out_size < 21) return false;
    time_t now = time(NULL);
    if (now == (time_t)-1) return false;

    struct tm utc;
#if defined(_WIN32)
    if (gmtime_s(&utc, &now) != 0) return false;
#else
    if (!gmtime_r(&now, &utc)) return false;
#endif
    return strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", &utc) == 20;
}
