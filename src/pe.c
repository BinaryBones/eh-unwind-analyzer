#include "pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t u32_max(uint32_t a, uint32_t b) { return a > b ? a : b; }

static bool is_power_of_two_u32(uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

static bool read_dos_lfanew(const Buf* b, uint32_t* out_lfanew) {
    uint16_t mz = 0;
    if (!buf_read_u16(b, 0, &mz)) return false;
    if (mz != PE_DOS_MAGIC) return false;
    uint32_t lfanew = 0;
    if (!buf_read_u32(b, 0x3c, &lfanew)) return false;
    *out_lfanew = lfanew;
    return true;
}

static bool safe_add_u32(uint32_t a, uint32_t b, uint32_t* out) {
    uint64_t t = (uint64_t)a + (uint64_t)b;
    if (t > 0xffffffffu) return false;
    *out = (uint32_t)t;
    return true;
}

static bool ranges_overlap_u64(uint64_t a_begin,
                               uint64_t a_size,
                               uint64_t b_begin,
                               uint64_t b_size) {
    if (a_size == 0 || b_size == 0) return false;
    return a_begin < b_begin + b_size && b_begin < a_begin + a_size;
}

static void input_check_set(PeInputValidation* validation,
                            PeInputCheckCode code,
                            PeInputCheckStatus status,
                            bool has_range,
                            size_t offset,
                            size_t length,
                            bool has_value,
                            uint64_t value,
                            const char* detail) {
    PeInputCheck* check = &validation->checks[(size_t)code];
    check->status = status;
    check->has_file_range = has_range;
    check->file_offset = offset;
    check->byte_length = length;
    check->has_observed_value = has_value;
    check->observed_value = value;
    if (detail) {
        (void)snprintf(check->detail, sizeof(check->detail), "%s", detail);
    }
}

static void input_check_skip(PeInputValidation* validation,
                             PeInputCheckCode code,
                             const char* detail) {
    input_check_set(validation, code, PE_INPUT_CHECK_NOT_EVALUATED,
                    false, 0, 0, false, 0, detail);
}

const char* pe_input_check_code(PeInputCheckCode code) {
    static const char* const names[PE_INPUT_CHECK_COUNT] = {
        "dos_header_range", "dos_magic", "e_lfanew_field", "pe_header_range",
        "pe_signature", "coff_header", "machine_amd64", "optional_header_range",
        "optional_header_size", "optional_magic_pe32_plus", "optional_key_fields",
        "size_of_image", "size_of_headers", "alignments", "directory_count",
        "exception_directory_entry", "section_table_range"
    };
    return code >= 0 && code < PE_INPUT_CHECK_COUNT ? names[(size_t)code] : "unknown";
}

const char* pe_input_check_title_ru(PeInputCheckCode code) {
    static const char* const titles[PE_INPUT_CHECK_COUNT] = {
        "Доступность DOS-заголовка", "Сигнатура MZ", "Поле e_lfanew",
        "Диапазон PE-заголовка", "Сигнатура PE\\0\\0", "COFF-заголовок",
        "Архитектура Machine", "Диапазон Optional Header", "Размер Optional Header",
        "Формат PE32+", "Ключевые поля Optional Header", "SizeOfImage",
        "SizeOfHeaders", "Параметры выравнивания", "Количество Data Directory",
        "Запись Exception Directory", "Таблица заголовков секций"
    };
    return code >= 0 && code < PE_INPUT_CHECK_COUNT ? titles[(size_t)code] : "Неизвестная проверка";
}

const char* pe_input_check_requirement_ru(PeInputCheckCode code) {
    static const char* const requirements[PE_INPUT_CHECK_COUNT] = {
        "Диапазон 0x00..0x3F должен полностью находиться в файле.",
        "Первые два байта должны содержать MZ (0x5A4D).",
        "Четырёхбайтовое поле e_lfanew по смещению 0x3C должно быть доступно.",
        "e_lfanew должен указывать на полностью доступные PE signature и COFF header.",
        "По смещению e_lfanew должна находиться сигнатура PE\\0\\0 (0x00004550).",
        "Двадцатибайтовый COFF header должен полностью находиться в файле.",
        "Поле Machine должно быть равно IMAGE_FILE_MACHINE_AMD64 (0x8664).",
        "Заявленный Optional Header должен полностью находиться в файле.",
        "Размер Optional Header должен покрывать обязательные поля PE32+ до Data Directory.",
        "Magic Optional Header должен быть равен PE32+ (0x020B).",
        "Обязательные поля PE32+ должны быть доступны в заявленном Optional Header.",
        "SizeOfImage должен быть больше нуля.",
        "SizeOfHeaders должен быть больше нуля и не превышать размер файла.",
        "SectionAlignment и FileAlignment должны быть ненулевыми.",
        "NumberOfRvaAndSizes должен включать Exception Directory.",
        "Запись Exception Directory должна находиться внутри Optional Header и файла.",
        "Все заявленные заголовки секций должны полностью находиться в файле."
    };
    return code >= 0 && code < PE_INPUT_CHECK_COUNT ? requirements[(size_t)code] : "";
}

const char* pe_input_check_status_name(PeInputCheckStatus status) {
    switch (status) {
        case PE_INPUT_CHECK_PASSED: return "passed";
        case PE_INPUT_CHECK_FAILED: return "failed";
        default: return "not_evaluated";
    }
}

bool pe_validate_input(const Buf* b, PeInputValidation* out) {
    if (!b || !out) return false;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < PE_INPUT_CHECK_COUNT; i++) {
        out->checks[i].status = PE_INPUT_CHECK_NOT_EVALUATED;
    }

    bool dos_range_ok = b->size >= 0x40u;
    input_check_set(out, PE_INPUT_DOS_HEADER_RANGE,
                    dos_range_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, 0, 0x40u, false, 0,
                    dos_range_ok ? "Диапазон DOS-заголовка полностью доступен."
                                 : "Размер файла меньше 64 байт, необходимых для DOS-заголовка.");
    if (!dos_range_ok) {
        for (size_t i = PE_INPUT_DOS_MAGIC; i < PE_INPUT_CHECK_COUNT; i++) {
            input_check_skip(out, (PeInputCheckCode)i,
                             "Проверка недоступна: полный DOS-заголовок отсутствует.");
        }
        goto summarize;
    }

    uint16_t mz = 0;
    (void)buf_read_u16(b, 0, &mz);
    input_check_set(out, PE_INPUT_DOS_MAGIC,
                    mz == PE_DOS_MAGIC ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, 0, 2, true, mz,
                    mz == PE_DOS_MAGIC ? "Зарегистрирована сигнатура MZ."
                                       : "Зарегистрированное значение не соответствует 0x5A4D.");

    uint32_t lfanew = 0;
    bool lfanew_read = buf_read_u32(b, 0x3c, &lfanew);
    out->pe_offset = lfanew;
    input_check_set(out, PE_INPUT_E_LFANEW_FIELD,
                    lfanew_read ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, 0x3c, 4, lfanew_read, lfanew,
                    lfanew_read ? "Поле e_lfanew полностью представлено в файле."
                                : "Поле e_lfanew выходит за доступный диапазон файла.");
    if (!lfanew_read) {
        for (size_t i = PE_INPUT_PE_HEADER_RANGE; i < PE_INPUT_CHECK_COUNT; i++) {
            input_check_skip(out, (PeInputCheckCode)i,
                             "Проверка недоступна: значение e_lfanew не прочитано.");
        }
        goto summarize;
    }

    bool pe_range_ok = (uint64_t)lfanew + 24u <= (uint64_t)b->size;
    input_check_set(out, PE_INPUT_PE_HEADER_RANGE,
                    pe_range_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, (size_t)lfanew, 24, true, lfanew,
                    pe_range_ok ? "Диапазон сигнатуры PE и COFF-заголовка полностью доступен."
                                : "e_lfanew указывает за пределы доступного диапазона PE-заголовка.");
    if (!pe_range_ok) {
        for (size_t i = PE_INPUT_PE_SIGNATURE; i < PE_INPUT_CHECK_COUNT; i++) {
            input_check_skip(out, (PeInputCheckCode)i,
                             "Проверка недоступна: кандидат PE-заголовка выходит за границы файла.");
        }
        goto summarize;
    }

    uint32_t signature = 0;
    (void)buf_read_u32(b, (size_t)lfanew, &signature);
    input_check_set(out, PE_INPUT_PE_SIGNATURE,
                    signature == PE_NT_MAGIC ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, (size_t)lfanew, 4, true, signature,
                    signature == PE_NT_MAGIC ? "Зарегистрирована сигнатура PE\\0\\0."
                                             : "Зарегистрированное значение не соответствует 0x00004550.");

    size_t filehdr = (size_t)lfanew + 4u;
    uint16_t machine = 0, nsects = 0, opt_size = 0;
    bool coff_read = buf_read_u16(b, filehdr, &machine) &&
                     buf_read_u16(b, filehdr + 2u, &nsects) &&
                     buf_read_u16(b, filehdr + 16u, &opt_size);
    out->machine = machine;
    out->number_of_sections = nsects;
    out->optional_header_size = opt_size;
    input_check_set(out, PE_INPUT_COFF_HEADER,
                    coff_read ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, filehdr, 20, false, 0,
                    coff_read ? "Обязательные поля COFF-заголовка доступны для чтения."
                              : "Обязательные поля COFF-заголовка прочитаны не полностью.");
    if (!coff_read) {
        for (size_t i = PE_INPUT_MACHINE_AMD64; i < PE_INPUT_CHECK_COUNT; i++) {
            input_check_skip(out, (PeInputCheckCode)i,
                             "Проверка недоступна: COFF-заголовок не прочитан.");
        }
        goto summarize;
    }

    input_check_set(out, PE_INPUT_MACHINE_AMD64,
                    machine == IMAGE_FILE_MACHINE_AMD64 ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, filehdr, 2, true, machine,
                    machine == IMAGE_FILE_MACHINE_AMD64 ? "Зарегистрировано значение AMD64 (0x8664)."
                                                        : "Зарегистрированное значение не соответствует AMD64 (0x8664).");

    size_t opthdr = filehdr + 20u;
    bool optional_range_ok = (uint64_t)opthdr + (uint64_t)opt_size <= (uint64_t)b->size;
    input_check_set(out, PE_INPUT_OPTIONAL_HEADER_RANGE,
                    optional_range_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, opthdr, opt_size, true, opt_size,
                    optional_range_ok ? "Заявленный диапазон Optional Header полностью доступен."
                                      : "Заявленный диапазон Optional Header выходит за границы файла.");
    bool optional_size_ok = opt_size >= 0x70u;
    input_check_set(out, PE_INPUT_OPTIONAL_HEADER_SIZE,
                    optional_size_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, filehdr + 16u, 2, true, opt_size,
                    optional_size_ok ? "Размер Optional Header покрывает обязательные поля PE32+."
                                     : "Размер Optional Header меньше обязательного диапазона 0x70 байт.");

    uint16_t optional_magic = 0;
    bool magic_read = (uint64_t)opthdr + 2u <= (uint64_t)b->size &&
                      buf_read_u16(b, opthdr, &optional_magic);
    out->optional_magic = optional_magic;
    if (magic_read) {
        input_check_set(out, PE_INPUT_OPTIONAL_MAGIC_PE32_PLUS,
                        optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                            ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, opthdr, 2, true, optional_magic,
                        optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                            ? "Поле Magic идентифицирует формат PE32+."
                            : "Поле Magic не соответствует формату PE32+ (0x020B).");
    } else {
        input_check_skip(out, PE_INPUT_OPTIONAL_MAGIC_PE32_PLUS,
                         "Проверка недоступна: поле Magic не находится в файле.");
    }

    bool key_fields_available = optional_size_ok &&
                                (uint64_t)opthdr + 0x70u <= (uint64_t)b->size;
    input_check_set(out, PE_INPUT_OPTIONAL_KEY_FIELDS,
                    key_fields_available ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                    true, opthdr, 0x70u, false, 0,
                    key_fields_available ? "Обязательные поля PE32+ полностью доступны."
                                         : "Обязательные поля PE32+ представлены не полностью.");
    if (!key_fields_available) {
        for (size_t i = PE_INPUT_SIZE_OF_IMAGE; i <= PE_INPUT_DIRECTORY_COUNT; i++) {
            input_check_skip(out, (PeInputCheckCode)i,
                             "Проверка недоступна: обязательные поля Optional Header отсутствуют.");
        }
        input_check_skip(out, PE_INPUT_EXCEPTION_DIRECTORY_ENTRY,
                         "Проверка недоступна: Optional Header не содержит требуемый диапазон.");
    } else {
        uint32_t section_alignment = 0, file_alignment = 0;
        uint32_t size_of_image = 0, size_of_headers = 0, directory_count = 0;
        (void)buf_read_u32(b, opthdr + 0x20u, &section_alignment);
        (void)buf_read_u32(b, opthdr + 0x24u, &file_alignment);
        (void)buf_read_u32(b, opthdr + 0x38u, &size_of_image);
        (void)buf_read_u32(b, opthdr + 0x3cu, &size_of_headers);
        (void)buf_read_u32(b, opthdr + 0x6cu, &directory_count);
        input_check_set(out, PE_INPUT_SIZE_OF_IMAGE,
                        size_of_image ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, opthdr + 0x38u, 4, true, size_of_image,
                        size_of_image ? "SizeOfImage имеет ненулевое значение." : "SizeOfImage равен нулю.");
        bool headers_ok = size_of_headers != 0 && (uint64_t)size_of_headers <= (uint64_t)b->size;
        input_check_set(out, PE_INPUT_SIZE_OF_HEADERS,
                        headers_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, opthdr + 0x3cu, 4, true, size_of_headers,
                        headers_ok ? "SizeOfHeaders находится в пределах файла."
                                   : "SizeOfHeaders равен нулю либо превышает размер файла.");
        bool alignments_ok = section_alignment != 0 && file_alignment != 0;
        char alignment_detail[160];
        (void)snprintf(alignment_detail, sizeof(alignment_detail),
                       "SectionAlignment=0x%x; FileAlignment=0x%x.",
                       (unsigned)section_alignment, (unsigned)file_alignment);
        input_check_set(out, PE_INPUT_ALIGNMENTS,
                        alignments_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, opthdr + 0x20u, 8, false, 0,
                        alignment_detail);
        bool directory_count_ok = directory_count > IMAGE_DIRECTORY_ENTRY_EXCEPTION;
        input_check_set(out, PE_INPUT_DIRECTORY_COUNT,
                        directory_count_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, opthdr + 0x6cu, 4, true, directory_count,
                        directory_count_ok ? "Индекс Exception Directory входит в заявленный массив."
                                           : "NumberOfRvaAndSizes не включает индекс Exception Directory.");

        size_t dd_rel = 0x70u + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8u;
        bool dd_ok = directory_count_ok && dd_rel + 8u <= opt_size &&
                     (uint64_t)opthdr + dd_rel + 8u <= (uint64_t)b->size;
        input_check_set(out, PE_INPUT_EXCEPTION_DIRECTORY_ENTRY,
                        dd_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, opthdr + dd_rel, 8, false, 0,
                        dd_ok ? "Запись Exception Directory полностью доступна."
                              : "Запись Exception Directory выходит за заявленный или доступный Optional Header.");
    }

    if (optional_range_ok) {
        size_t secthdr = opthdr + (size_t)opt_size;
        bool count_safe = (size_t)nsects <= (SIZE_MAX - secthdr) / 40u;
        bool table_ok = count_safe && secthdr + (size_t)nsects * 40u <= b->size;
        input_check_set(out, PE_INPUT_SECTION_TABLE_RANGE,
                        table_ok ? PE_INPUT_CHECK_PASSED : PE_INPUT_CHECK_FAILED,
                        true, secthdr, count_safe ? (size_t)nsects * 40u : 0u,
                        true, nsects,
                        table_ok ? "Все заявленные заголовки секций полностью доступны."
                                 : "Диапазон заявленных заголовков секций выходит за границы файла.");
    } else {
        input_check_skip(out, PE_INPUT_SECTION_TABLE_RANGE,
                         "Проверка недоступна: конец Optional Header не установлен достоверно.");
    }

summarize:
    for (size_t i = 0; i < PE_INPUT_CHECK_COUNT; i++) {
        switch (out->checks[i].status) {
            case PE_INPUT_CHECK_PASSED: out->passed_count++; break;
            case PE_INPUT_CHECK_FAILED: out->failed_count++; break;
            default: out->not_evaluated_count++; break;
        }
    }
    out->accepted = out->failed_count == 0;
    return true;
}

bool pe_parse(PeImage* out, const Buf* b, StrBuf* err) {
    if (!out || !b || !err) return false;
    memset(out, 0, sizeof(*out));

    uint32_t lfanew = 0;
    if (!read_dos_lfanew(b, &lfanew)) {
        sb_append(err, "Not a valid MZ/PE file (DOS header check failed).\n");
        return false;
    }
    if ((size_t)lfanew + 4 + 20 > b->size) {
        sb_append(err, "PE header offset out of range.\n");
        return false;
    }

    uint32_t sig = 0;
    if (!buf_read_u32(b, (size_t)lfanew, &sig) || sig != PE_NT_MAGIC) {
        sb_append(err, "Invalid PE signature.\n");
        return false;
    }

    size_t filehdr = (size_t)lfanew + 4;
    uint16_t machine = 0;
    uint16_t nsects = 0;
    uint16_t opt_size = 0;
    if (!buf_read_u16(b, filehdr + 0, &machine) ||
        !buf_read_u16(b, filehdr + 2, &nsects) ||
        !buf_read_u16(b, filehdr + 16, &opt_size)) {
        sb_append(err, "Failed to read COFF header.\n");
        return false;
    }

    if (machine != IMAGE_FILE_MACHINE_AMD64) {
        sb_appendf(err, "Unsupported Machine: 0x%04x (only x64/AMD64 supported).\n", machine);
        return false;
    }

    size_t opthdr = filehdr + 20;
    if (opthdr + opt_size > b->size) {
        sb_append(err, "Optional header out of range.\n");
        return false;
    }
    if (opt_size < 0x70u) {
        sb_append(err, "PE32+ optional header is too small for required fields.\n");
        return false;
    }

    uint16_t magic = 0;
    if (!buf_read_u16(b, opthdr + 0, &magic)) {
        sb_append(err, "Failed to read optional header magic.\n");
        return false;
    }
    if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        sb_appendf(err, "Unsupported OptionalHeader magic: 0x%04x (expect PE32+ 0x20b).\n", magic);
        return false;
    }

    uint64_t image_base = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint32_t number_of_rva_and_sizes = 0;

    /* PE32+ offsets */
    if (!buf_read_u64(b, opthdr + 0x18, &image_base) ||
        !buf_read_u32(b, opthdr + 0x20, &section_alignment) ||
        !buf_read_u32(b, opthdr + 0x24, &file_alignment) ||
        !buf_read_u32(b, opthdr + 0x38, &size_of_image) ||
        !buf_read_u32(b, opthdr + 0x3c, &size_of_headers) ||
        !buf_read_u32(b, opthdr + 0x6c, &number_of_rva_and_sizes)) {
        sb_append(err, "Failed to read key fields from optional header.\n");
        return false;
    }
    if (size_of_image == 0) {
        sb_append(err, "SizeOfImage is zero.\n");
        return false;
    }
    if (size_of_headers == 0 || (uint64_t)size_of_headers > (uint64_t)b->size) {
        sb_append(err, "SizeOfHeaders is zero or exceeds the file size.\n");
        return false;
    }
    if (section_alignment == 0 || file_alignment == 0) {
        sb_append(err, "SectionAlignment/FileAlignment must be non-zero.\n");
        return false;
    }
    if (number_of_rva_and_sizes < IMAGE_DIRECTORY_ENTRY_EXCEPTION + 1) {
        sb_append(err, "DataDirectory too small.\n");
        return false;
    }

    /* DataDirectory starts at 0x70 */
    size_t dd_rel = 0x70u + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8u;
    if (dd_rel + 8u > opt_size) {
        sb_append(err, "Exception data directory lies outside the optional header.\n");
        return false;
    }
    size_t dd = opthdr + dd_rel;
    uint32_t exc_rva = 0, exc_sz = 0;
    if (!buf_read_u32(b, dd + 0, &exc_rva) || !buf_read_u32(b, dd + 4, &exc_sz)) {
        sb_append(err, "Failed to read exception directory.\n");
        return false;
    }

    size_t secthdr = opthdr + opt_size;
    if ((size_t)nsects > (SIZE_MAX - secthdr) / 40u) {
        sb_append(err, "Section header size overflow.\n");
        return false;
    }
    size_t needed = secthdr + (size_t)nsects * 40u;
    if (needed > b->size) {
        sb_append(err, "Section headers out of range.\n");
        return false;
    }

    PeSection* secs = (PeSection*)calloc(nsects ? (size_t)nsects : 1, sizeof(PeSection));
    if (!secs) {
        sb_append(err, "Out of memory.\n");
        return false;
    }

    for (uint16_t i = 0; i < nsects; i++) {
        size_t sh = secthdr + (size_t)i * 40;
        uint8_t name8[8];
        if (!buf_read(b, sh + 0, name8, 8)) { free(secs); sb_append(err, "Failed to read section name.\n"); return false; }
        memcpy(secs[i].name, name8, 8);
        secs[i].name[8] = 0;

        if (!buf_read_u32(b, sh + 8, &secs[i].virtual_size) ||
            !buf_read_u32(b, sh + 12, &secs[i].virtual_address) ||
            !buf_read_u32(b, sh + 16, &secs[i].raw_size) ||
            !buf_read_u32(b, sh + 20, &secs[i].raw_ptr) ||
            !buf_read_u32(b, sh + 36, &secs[i].characteristics)) {
            free(secs);
            sb_append(err, "Failed to read section header.\n");
            return false;
        }
    }

    size_t raw_oob = 0;
    size_t virtual_oob = 0;
    size_t raw_overlaps = 0;
    size_t virtual_overlaps = 0;
    size_t misaligned = 0;

    bool compact_alignment =
        section_alignment < 0x1000u && file_alignment == section_alignment;
    bool file_alignment_valid =
        is_power_of_two_u32(file_alignment) &&
        ((file_alignment >= 0x200u && file_alignment <= 0x10000u) ||
         compact_alignment);
    if (!file_alignment_valid) misaligned++;
    if (section_alignment < file_alignment) misaligned++;
    if (section_alignment < 0x1000u && file_alignment != section_alignment) {
        misaligned++;
    }
    if ((size_of_image % section_alignment) != 0) misaligned++;
    if ((size_of_headers % file_alignment) != 0 ||
        (uint64_t)size_of_headers < (uint64_t)needed) {
        misaligned++;
    }
    if ((image_base & 0xffffu) != 0) misaligned++;

    for (size_t i = 0; i < (size_t)nsects; i++) {
        const PeSection* s = &secs[i];
        uint64_t raw_end = (uint64_t)s->raw_ptr + (uint64_t)s->raw_size;
        uint64_t virtual_span = (uint64_t)u32_max(s->virtual_size, s->raw_size);
        uint64_t virtual_end = (uint64_t)s->virtual_address + virtual_span;
        if (s->raw_size > 0 && raw_end > (uint64_t)b->size) raw_oob++;
        if (virtual_span > 0 && virtual_end > (uint64_t)size_of_image) virtual_oob++;
        if ((s->virtual_address % section_alignment) != 0 ||
            (s->raw_size > 0 &&
             ((s->raw_ptr % file_alignment) != 0 ||
              (s->raw_size % file_alignment) != 0))) {
            misaligned++;
        }
        if (i > 0 && s->virtual_address <= secs[i - 1].virtual_address) {
            misaligned++;
        }

        for (size_t j = 0; j < i; j++) {
            const PeSection* p = &secs[j];
            if (ranges_overlap_u64(s->raw_ptr, s->raw_size, p->raw_ptr, p->raw_size)) {
                raw_overlaps++;
            }
            if (ranges_overlap_u64(
                    s->virtual_address,
                    u32_max(s->virtual_size, s->raw_size),
                    p->virtual_address,
                    u32_max(p->virtual_size, p->raw_size))) {
                virtual_overlaps++;
            }
        }
    }

    bool exception_directory_oob = false;
    if (exc_rva != 0 || exc_sz != 0) {
        uint64_t exc_end = (uint64_t)exc_rva + (uint64_t)exc_sz;
        exception_directory_oob =
            exc_rva == 0 || exc_sz == 0 || exc_end > (uint64_t)size_of_image;
    }

    out->ok = true;
    out->is_pe64 = true;
    out->machine = machine;
    out->image_base = image_base;
    out->size_of_image = size_of_image;
    out->size_of_headers = size_of_headers;
    out->section_alignment = section_alignment;
    out->file_alignment = file_alignment;
    out->exception_rva = exc_rva;
    out->exception_size = exc_sz;
    out->file_size = b->size;
    out->num_sections = nsects;
    out->sections = secs;
    out->section_raw_oob = raw_oob;
    out->section_virtual_oob = virtual_oob;
    out->section_raw_overlaps = raw_overlaps;
    out->section_virtual_overlaps = virtual_overlaps;
    out->section_misaligned = misaligned;
    out->exception_directory_oob = exception_directory_oob;
    return true;
}

void pe_free(PeImage* img) {
    if (!img) return;
    free(img->sections);
    memset(img, 0, sizeof(*img));
}

const PeSection* pe_find_section_for_rva(const PeImage* img, uint32_t rva) {
    if (!img || !img->sections) return NULL;
    for (size_t i = 0; i < img->num_sections; i++) {
        const PeSection* s = &img->sections[i];
        uint32_t size = u32_max(s->virtual_size, s->raw_size);
        uint64_t start = (uint64_t)s->virtual_address;
        uint64_t end = start + (uint64_t)size;
        if ((uint64_t)rva >= start && (uint64_t)rva < end) return s;
    }
    return NULL;
}

bool pe_rva_to_fileoff(const PeImage* img, uint32_t rva, uint32_t* out_off) {
    if (!img || !out_off) return false;
    const PeSection* s = pe_find_section_for_rva(img, rva);
    if (s) {
        uint32_t delta = rva - s->virtual_address;
        if (delta >= s->raw_size) {
            /* RVA points into virtual tail (zero-fill) - not present in file */
            return false;
        }
        uint32_t off = 0;
        if (!safe_add_u32(s->raw_ptr, delta, &off)) return false;
        if (img->file_size > 0 && (uint64_t)off >= (uint64_t)img->file_size) return false;
        *out_off = off;
        return true;
    }

    /* RVAs inside SizeOfHeaders map directly to the corresponding file offset. */
    if (img->size_of_headers > 0 &&
        rva < img->size_of_headers &&
        (img->file_size == 0 || (uint64_t)rva < (uint64_t)img->file_size)) {
        *out_off = rva;
        return true;
    }
    return false;
}
