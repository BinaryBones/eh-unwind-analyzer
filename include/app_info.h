#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EHUA_VERSION "1.0.0"
#define EHUA_REPORT_SCHEMA_VERSION "1.3.0"

const char* app_version(void);
const char* app_report_schema_version(void);
const char* app_build_compiler(void);
const char* app_build_platform(void);
const char* app_build_mode(void);

/* UTC timestamp in RFC 3339 form: YYYY-MM-DDTHH:MM:SSZ. */
bool app_utc_timestamp(char* out, size_t out_size);

#ifdef __cplusplus
}
#endif
