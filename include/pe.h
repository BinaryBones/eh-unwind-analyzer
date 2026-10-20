#pragma once
/*
  pe.h - minimal PE32+/x64 parser (no Windows headers)
*/

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PE_DOS_MAGIC 0x5A4D      /* 'MZ' */
#define PE_NT_MAGIC  0x00004550  /* 'PE\0\0' */

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

typedef enum PeInputCheckStatus {
    PE_INPUT_CHECK_NOT_EVALUATED = 0,
    PE_INPUT_CHECK_PASSED = 1,
    PE_INPUT_CHECK_FAILED = 2
} PeInputCheckStatus;

typedef enum PeInputCheckCode {
    PE_INPUT_DOS_HEADER_RANGE = 0,
    PE_INPUT_DOS_MAGIC,
    PE_INPUT_E_LFANEW_FIELD,
    PE_INPUT_PE_HEADER_RANGE,
    PE_INPUT_PE_SIGNATURE,
    PE_INPUT_COFF_HEADER,
    PE_INPUT_MACHINE_AMD64,
    PE_INPUT_OPTIONAL_HEADER_RANGE,
    PE_INPUT_OPTIONAL_HEADER_SIZE,
    PE_INPUT_OPTIONAL_MAGIC_PE32_PLUS,
    PE_INPUT_OPTIONAL_KEY_FIELDS,
    PE_INPUT_SIZE_OF_IMAGE,
    PE_INPUT_SIZE_OF_HEADERS,
    PE_INPUT_ALIGNMENTS,
    PE_INPUT_DIRECTORY_COUNT,
    PE_INPUT_EXCEPTION_DIRECTORY_ENTRY,
    PE_INPUT_SECTION_TABLE_RANGE,
    PE_INPUT_CHECK_COUNT
} PeInputCheckCode;

typedef struct PeInputCheck {
    PeInputCheckStatus status;
    bool has_file_range;
    size_t file_offset;
    size_t byte_length;
    bool has_observed_value;
    uint64_t observed_value;
    char detail[160];
} PeInputCheck;

typedef struct PeInputValidation {
    bool accepted;
    size_t passed_count;
    size_t failed_count;
    size_t not_evaluated_count;
    uint32_t pe_offset;
    uint16_t machine;
    uint16_t optional_magic;
    uint16_t number_of_sections;
    uint16_t optional_header_size;
    PeInputCheck checks[PE_INPUT_CHECK_COUNT];
} PeInputValidation;

typedef struct PeSection {
    char     name[9]; /* null-terminated */
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_ptr;
    uint32_t raw_size;
    uint32_t characteristics;
} PeSection;

typedef struct PeImage {
    bool     ok;
    bool     is_pe64;
    uint16_t machine;
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint32_t exception_rva;
    uint32_t exception_size;
    size_t   file_size;
    size_t   num_sections;
    PeSection* sections; /* owned */

    size_t section_raw_oob;
    size_t section_virtual_oob;
    size_t section_raw_overlaps;
    size_t section_virtual_overlaps;
    size_t section_misaligned;
    bool   exception_directory_oob;
} PeImage;

bool pe_parse(PeImage* out, const Buf* b, StrBuf* err);
bool pe_validate_input(const Buf* b, PeInputValidation* out);
const char* pe_input_check_code(PeInputCheckCode code);
const char* pe_input_check_title_ru(PeInputCheckCode code);
const char* pe_input_check_requirement_ru(PeInputCheckCode code);
const char* pe_input_check_status_name(PeInputCheckStatus status);
void pe_free(PeImage* img);

/* Map RVA -> file offset. Returns false if not mappable. */
bool pe_rva_to_fileoff(const PeImage* img, uint32_t rva, uint32_t* out_off);

/* Find section containing RVA (or NULL). */
const PeSection* pe_find_section_for_rva(const PeImage* img, uint32_t rva);

#ifdef __cplusplus
}
#endif
