#include "report.h"
#include "app_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define IMAGE_SCN_MEM_READ    0x40000000u
#define IMAGE_SCN_MEM_WRITE   0x80000000u

static void append_regmask(StrBuf* sb, uint16_t mask, bool xmm) {
    bool first = true;
    for (uint8_t r = 0; r < 16; r++) {
        if (!(mask & (uint16_t)(1u << r))) continue;
        if (!first) sb_append(sb, ",");
        if (xmm) sb_appendf(sb, "XMM%u", (unsigned)r);
        else sb_append(sb, unwind_reg_name(r));
        first = false;
    }
    if (first) sb_append(sb, "-");
}

static void anomalies_to_str(StrBuf* sb, uint32_t anom) {
    bool first = true;
    struct { uint32_t bit; const char* name; } m[] = {
        {UA_VERSION_UNKNOWN, "ver"},
        {UA_TRUNCATED, "trunc"},
        {UA_BAD_OPCODE, "op"},
        {UA_BAD_OPERAND, "arg"},
        {UA_CODEOFFSET_OUTSIDE, "off"},
        {UA_CHAIN_LOOP, "chain_loop"},
        {UA_CHAIN_DEPTH_EXCEEDED, "chain_depth"},
        {UA_HANDLER_OOB, "handler_oob"},
        {UA_CODEOFFSET_ORDER, "order"},
        {UA_OPERAND_SANITY, "operand_sanity"},
        {UA_ALIGNMENT, "alignment"},
        {UA_CHAIN_INVALID, "chain_invalid"},
        {UA_ABI_REGISTER_CLASS, "abi_register_class"},
        {UA_ABI_RESERVED_OPINFO, "abi_reserved_opinfo"},
        {UA_ABI_PUSH_ORDER, "abi_push_order"},
        {UA_ABI_CHAIN_RESTRICTION, "abi_chain_restriction"},
        {UA_ABI_SAVE_OFFSET, "abi_save_offset"},
    };
    for (size_t i = 0; i < sizeof(m)/sizeof(m[0]); i++) {
        if (!(anom & m[i].bit)) continue;
        if (!first) sb_append(sb, "|");
        sb_append(sb, m[i].name);
        first = false;
    }
    if (first) sb_append(sb, "0");
}

static const char* section_name_or_dash(const PeImage* img, uint32_t rva) {
    const PeSection* s = pe_find_section_for_rva(img, rva);
    return s ? s->name : "-";
}

static void section_permissions(uint32_t characteristics, char out[4]) {
    if (!out) return;
    out[0] = (characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-';
    out[1] = (characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
    out[2] = (characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
    out[3] = '\0';
}


#define REPORT_RUNTIME_FUNCTION_ENTRY_SIZE 12u
#define REPORT_EVIDENCE_RECORD_LIMIT_JSON 128u
#define REPORT_EVIDENCE_RECORD_LIMIT_HTML 24u

static bool report_add_u32_size_mul(uint32_t base, size_t index, uint32_t item_size, uint32_t* out) {
    uint64_t offset = (uint64_t)index * (uint64_t)item_size;
    uint64_t value = (uint64_t)base + offset;
    if (!out || value > 0xffffffffull) return false;
    *out = (uint32_t)value;
    return true;
}

static bool pdata_entry_rva_for_index(const PeImage* img, size_t index, uint32_t* out_rva) {
    if (!img || !out_rva) return false;
    return report_add_u32_size_mul(img->exception_rva, index, REPORT_RUNTIME_FUNCTION_ENTRY_SIZE, out_rva);
}

static bool pdata_entry_fileoff_for_index(const PeImage* img, size_t index, uint32_t* out_off) {
    uint32_t entry_rva = 0;
    if (!img || !out_off || !pdata_entry_rva_for_index(img, index, &entry_rva)) return false;
    return pe_rva_to_fileoff(img, entry_rva, out_off);
}

static bool report_sec_name_eq(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static bool report_sec_name_contains_ci(const char* haystack, const char* needle) {
    if (!haystack || !needle || !*needle) return false;
    size_t nlen = strlen(needle);
    for (const char* h = haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen) {
            char ca = h[i];
            char cb = needle[i];
            if (!ca) return false;
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
            if (ca != cb) break;
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

static bool report_sec_name_allowed_for_unwind(const char* name8) {
    return report_sec_name_eq(name8, ".xdata") || report_sec_name_eq(name8, ".rdata") ||
           report_sec_name_eq(name8, ".pdata") || report_sec_name_eq(name8, ".gnu_xdata") ||
           report_sec_name_eq(name8, ".mrdata") || report_sec_name_eq(name8, "xdata") ||
           report_sec_name_eq(name8, "rdata") || report_sec_name_eq(name8, "pdata");
}

static bool report_sec_name_plausibly_unwind_named(const char* name8) {
    return report_sec_name_contains_ci(name8, "xdata") ||
           report_sec_name_contains_ci(name8, "pdata") ||
           report_sec_name_contains_ci(name8, "rdata");
}

static uint32_t report_abi_anomaly_mask(void) {
    return UA_ABI_REGISTER_CLASS | UA_ABI_RESERVED_OPINFO |
           UA_ABI_PUSH_ORDER | UA_ABI_CHAIN_RESTRICTION |
           UA_ABI_SAVE_OFFSET;
}

static uint32_t report_non_abi_anomaly_mask(void) {
    return ~report_abi_anomaly_mask();
}

static bool report_rf_range_valid(const RuntimeFunction* r) {
    return r && r->end_rva > r->begin_rva;
}

static bool report_rf_ranges_overlap(const RuntimeFunction* a, const RuntimeFunction* b) {
    if (!report_rf_range_valid(a) || !report_rf_range_valid(b)) return false;
    return a->begin_rva < b->end_rva && b->begin_rva < a->end_rva;
}

static bool report_rf_has_duplicate_begin(const RuntimeFunction* rf, size_t n, size_t index) {
    if (!rf || index >= n) return false;
    for (size_t j = 0; j < n; j++) {
        if (j != index && rf[j].begin_rva == rf[index].begin_rva) return true;
    }
    return false;
}

static bool report_rf_has_overlap(const RuntimeFunction* rf, size_t n, size_t index) {
    if (!rf || index >= n) return false;
    for (size_t j = 0; j < n; j++) {
        if (j != index && report_rf_ranges_overlap(&rf[index], &rf[j])) return true;
    }
    return false;
}

static bool report_unwind_section_is_unusual(const PeImage* img, uint32_t unwind_rva) {
    const PeSection* section = pe_find_section_for_rva(img, unwind_rva);
    if (!section) return true;
    return !report_sec_name_allowed_for_unwind(section->name) &&
           !report_sec_name_plausibly_unwind_named(section->name);
}

static bool report_unwind_section_has_flag(const PeImage* img, uint32_t unwind_rva, uint32_t flag) {
    const PeSection* section = pe_find_section_for_rva(img, unwind_rva);
    return section && ((section->characteristics & flag) != 0);
}

static bool report_handler_section_nonexec(const PeImage* img, const UnwindSummary* u) {
    if (!u || !u->has_handler) return false;
    const PeSection* section = pe_find_section_for_rva(img, u->handler_rva);
    return !section || ((section->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0);
}

static bool report_handler_section_writable(const PeImage* img, const UnwindSummary* u) {
    if (!u || !u->has_handler) return false;
    const PeSection* section = pe_find_section_for_rva(img, u->handler_rva);
    return section && ((section->characteristics & IMAGE_SCN_MEM_WRITE) != 0);
}

static bool evidence_record_matches(const HeuristicFinding* finding,
                                    const PeImage* img,
                                    const RuntimeFunction* rf,
                                    const UnwindSummary* us,
                                    const bool* us_ok,
                                    size_t n,
                                    size_t index) {
    if (!finding || !finding->code[0] || !img || !rf || index >= n) return false;
    const RuntimeFunction* r = &rf[index];
    const UnwindSummary* u = us ? &us[index] : NULL;
    bool ok = us_ok ? us_ok[index] : false;
    const char* code = finding->code;

    if (strcmp(code, "invalid_ranges") == 0) return r->end_rva <= r->begin_rva;
    if (strcmp(code, "rf_oob") == 0) return r->begin_rva >= img->size_of_image || r->end_rva > img->size_of_image;
    if (strcmp(code, "unwind_rva_oob") == 0) return r->unwind_rva == 0 || r->unwind_rva >= img->size_of_image;
    if (strcmp(code, "rf_unsorted") == 0) return index > 0 && r->begin_rva < rf[index - 1u].begin_rva;
    if (strcmp(code, "rf_overlaps") == 0) return report_rf_has_overlap(rf, n, index);
    if (strcmp(code, "duplicate_begin") == 0) return report_rf_has_duplicate_begin(rf, n, index);
    if (strcmp(code, "unwind_parse_fail") == 0) return !ok;
    if (strcmp(code, "unwind_anomalies") == 0) return ok && u && ((u->anomalies & report_non_abi_anomaly_mask()) != 0);
    if (strcmp(code, "unwind_in_exec_section") == 0) return ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_EXECUTE);
    if (strcmp(code, "unwind_unusual_section") == 0) return ok && report_unwind_section_is_unusual(img, r->unwind_rva);
    if (strcmp(code, "unwind_writable_section") == 0) return ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_WRITE);
    if (strcmp(code, "handler_nonexec_section") == 0) return ok && report_handler_section_nonexec(img, u);
    if (strcmp(code, "handler_writable_section") == 0) return ok && report_handler_section_writable(img, u);
    if (strcmp(code, "unwind_reuse_strong") == 0 || strcmp(code, "unwind_reuse_moderate") == 0) {
        return finding->has_location && r->unwind_rva == finding->representative_rva;
    }
    if (strcmp(code, "handler_dominance") == 0) {
        return ok && u && u->has_handler && finding->has_location && u->handler_rva == finding->representative_rva;
    }
    if (strcmp(code, "placement_exec_nonexec_handler_combo") == 0) {
        return (ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_EXECUTE)) ||
               (ok && report_handler_section_nonexec(img, u));
    }
    if (strcmp(code, "placement_integrity_combo") == 0) {
        bool placement = (ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_EXECUTE)) ||
                         (ok && report_handler_section_nonexec(img, u));
        bool integrity = !ok || r->unwind_rva == 0 || r->unwind_rva >= img->size_of_image ||
                         (u && ((u->anomalies & report_non_abi_anomaly_mask()) != 0));
        return placement || integrity;
    }
    if (strcmp(code, "writable_metadata_handler_combo") == 0) {
        return (ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_WRITE)) ||
               (ok && report_handler_section_writable(img, u));
    }
    if (strcmp(code, "reuse_dominance_combo") == 0) {
        return finding->has_location && r->unwind_rva == finding->representative_rva;
    }
    return false;
}

static size_t evidence_record_count(const HeuristicFinding* finding,
                                    const PeImage* img,
                                    const RuntimeFunction* rf,
                                    const UnwindSummary* us,
                                    const bool* us_ok,
                                    size_t n) {
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        if (evidence_record_matches(finding, img, rf, us, us_ok, n, i)) count++;
    }
    return count;
}

static void evidence_reason_append(char* out, size_t out_size, const char* clause) {
    if (!out || out_size == 0 || !clause || !clause[0]) return;
    size_t used = strlen(out);
    if (used >= out_size - 1u) return;
    (void)snprintf(out + used, out_size - used, "%s%s",
                   used ? "; " : "", clause);
}

static void evidence_record_reason_ru(const HeuristicFinding* finding,
                                      const PeImage* img,
                                      const RuntimeFunction* rf,
                                      const UnwindSummary* us,
                                      const bool* us_ok,
                                      size_t n,
                                      size_t index,
                                      char* out,
                                      size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!finding || !rf || index >= n) {
        snprintf(out, out_size, "Запись evidence недоступна.");
        return;
    }
    const RuntimeFunction* r = &rf[index];
    const UnwindSummary* u = us ? &us[index] : NULL;
    bool ok = us_ok ? us_ok[index] : false;
    const char* code = finding->code;

    if (strcmp(code, "invalid_ranges") == 0) {
        snprintf(out, out_size, "EndAddress не больше BeginAddress: begin=0x%08x, end=0x%08x.",
                 (unsigned)r->begin_rva, (unsigned)r->end_rva);
    } else if (strcmp(code, "rf_oob") == 0) {
        snprintf(out, out_size, "Диапазон функции выходит за SizeOfImage: begin=0x%08x, end=0x%08x, SizeOfImage=0x%08x.",
                 (unsigned)r->begin_rva, (unsigned)r->end_rva, (unsigned)(img ? img->size_of_image : 0u));
    } else if (strcmp(code, "unwind_rva_oob") == 0) {
        snprintf(out, out_size, "UnwindInfoAddress не указывает на допустимую область image: unwind=0x%08x, SizeOfImage=0x%08x.",
                 (unsigned)r->unwind_rva, (unsigned)(img ? img->size_of_image : 0u));
    } else if (strcmp(code, "rf_unsorted") == 0) {
        snprintf(out, out_size, "BeginAddress текущей записи меньше BeginAddress предыдущей записи .pdata.");
    } else if (strcmp(code, "rf_overlaps") == 0) {
        snprintf(out, out_size, "Диапазон функции пересекается с другой записью RUNTIME_FUNCTION, что создает неоднозначность для ControlPc.");
    } else if (strcmp(code, "duplicate_begin") == 0) {
        snprintf(out, out_size, "BeginAddress повторяется в другой записи RUNTIME_FUNCTION.");
    } else if (strcmp(code, "unwind_parse_fail") == 0) {
        snprintf(out, out_size, "UNWIND_INFO не разобран: failed_field=%s%s%s.",
                 (u && u->diagnostic_field[0]) ? u->diagnostic_field : "-",
                 (u && u->parse_error[0]) ? "; parse_error=" : "",
                 (u && u->parse_error[0]) ? u->parse_error : "");
    } else if (strcmp(code, "unwind_anomalies") == 0) {
        snprintf(out, out_size, "UNWIND_INFO разобран, но содержит внутренние аномалии: bitmask=0x%08x.",
                 (unsigned)(u ? u->anomalies : 0u));
    } else if (strcmp(code, "unwind_in_exec_section") == 0) {
        snprintf(out, out_size, "UNWIND_INFO расположен в секции с правом исполнения.");
    } else if (strcmp(code, "unwind_unusual_section") == 0) {
        snprintf(out, out_size, "UNWIND_INFO расположен вне обычных metadata-секций .xdata/.rdata/.pdata.");
    } else if (strcmp(code, "unwind_writable_section") == 0) {
        snprintf(out, out_size, "UNWIND_INFO расположен в секции с правом записи.");
    } else if (strcmp(code, "handler_nonexec_section") == 0) {
        snprintf(out, out_size, "Handler RVA не разрешается в исполняемую секцию.");
    } else if (strcmp(code, "handler_writable_section") == 0) {
        snprintf(out, out_size, "Handler RVA указывает в секцию с правом записи.");
    } else if (strcmp(code, "placement_exec_nonexec_handler_combo") == 0) {
        if (ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_EXECUTE)) {
            evidence_reason_append(out, out_size, "UNWIND_INFO расположен в исполняемой секции");
        }
        if (ok && report_handler_section_nonexec(img, u)) {
            evidence_reason_append(out, out_size, "handler RVA не разрешается в исполняемую секцию");
        }
    } else if (strcmp(code, "placement_integrity_combo") == 0) {
        if (ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_EXECUTE)) {
            evidence_reason_append(out, out_size, "UNWIND_INFO расположен в исполняемой секции");
        }
        if (ok && report_handler_section_nonexec(img, u)) {
            evidence_reason_append(out, out_size, "handler RVA не разрешается в исполняемую секцию");
        }
        if (!ok) evidence_reason_append(out, out_size, "структурный разбор UNWIND_INFO завершился ошибкой");
        if (r->unwind_rva == 0 || (img && r->unwind_rva >= img->size_of_image)) {
            evidence_reason_append(out, out_size, "UnwindInfoAddress находится вне допустимой области image");
        }
        if (u && (u->anomalies & report_non_abi_anomaly_mask()) != 0u) {
            evidence_reason_append(out, out_size, "в UNWIND_INFO зафиксирована внутренняя аномалия");
        }
    } else if (strcmp(code, "writable_metadata_handler_combo") == 0) {
        if (ok && report_unwind_section_has_flag(img, r->unwind_rva, IMAGE_SCN_MEM_WRITE)) {
            evidence_reason_append(out, out_size, "UNWIND_INFO расположен в секции с правом записи");
        }
        if (ok && report_handler_section_writable(img, u)) {
            evidence_reason_append(out, out_size, "handler RVA указывает в секцию с правом записи");
        }
    } else if (strcmp(code, "reuse_dominance_combo") == 0) {
        snprintf(out, out_size,
                 "Запись использует доминирующий UnwindInfoAddress; второй компонент корреляции раскрыт отдельным finding handler_dominance.");
    } else if (strcmp(code, "unwind_reuse_strong") == 0 || strcmp(code, "unwind_reuse_moderate") == 0) {
        snprintf(out, out_size, "Запись использует доминирующий UnwindInfoAddress, участвующий в признаке повторного использования metadata.");
    } else if (strcmp(code, "handler_dominance") == 0) {
        snprintf(out, out_size, "Запись использует доминирующий HandlerRVA, участвующий в признаке концентрации ссылок на один обработчик.");
    } else if (!ok && u && u->parse_error[0]) {
        snprintf(out, out_size, "Связанная запись имеет ошибку разбора UNWIND_INFO: %s.", u->parse_error);
    } else {
        snprintf(out, out_size, "Запись связана с representative RVA данного finding-а.");
    }
}

static const char* finding_rule_text(const char* code) {
    if (!code) return "Код признака отсутствует, поэтому отчет не может сопоставить его с правилом.";
    if (strcmp(code, "pe_section_raw_oob") == 0) return "Raw-диапазон каждой секции должен лежать внутри файла: PointerToRawData + SizeOfRawData <= размер файла.";
    if (strcmp(code, "pe_section_virtual_oob") == 0) return "Virtual-диапазон каждой секции должен лежать внутри загруженного образа: VirtualAddress + max(VirtualSize, SizeOfRawData) <= SizeOfImage.";
    if (strcmp(code, "pe_section_raw_overlap") == 0) return "Raw-диапазоны секций не должны пересекаться, иначе один участок файла получает двух владельцев.";
    if (strcmp(code, "pe_section_virtual_overlap") == 0) return "Virtual-диапазоны секций не должны пересекаться, иначе один RVA неоднозначно относится сразу к нескольким областям image.";
    if (strcmp(code, "pe_section_misaligned") == 0) return "Инварианты PE-выравнивания должны выполняться: FileAlignment, SectionAlignment, заголовки и секции должны быть согласованы.";
    if (strcmp(code, "pe_exception_directory_oob") == 0) return "Exception Directory должна либо корректно отсутствовать как RVA=0 и Size=0, либо целиком помещаться в SizeOfImage.";
    if (strcmp(code, "no_runtime_functions") == 0) return "Для нетривиального x64-образа с исполняемым кодом обычно ожидаются записи RUNTIME_FUNCTION для non-leaf функций.";
    if (strcmp(code, "invalid_ranges") == 0) return "Каждая запись RUNTIME_FUNCTION должна описывать положительный диапазон: EndAddress должен быть больше BeginAddress.";
    if (strcmp(code, "rf_oob") == 0) return "Диапазон BeginAddress/EndAddress каждой RUNTIME_FUNCTION должен находиться внутри SizeOfImage.";
    if (strcmp(code, "unwind_rva_oob") == 0) return "UnwindInfoAddress каждой RUNTIME_FUNCTION должен указывать на доступную UNWIND_INFO внутри image.";
    if (strcmp(code, "rf_unsorted") == 0) return "Таблица RUNTIME_FUNCTION должна быть отсортирована по BeginAddress, чтобы поиск по ControlPc был однозначным.";
    if (strcmp(code, "rf_overlaps") == 0) return "Диапазоны RUNTIME_FUNCTION не должны пересекаться, потому что один RVA кода должен иметь одну unwind-запись.";
    if (strcmp(code, "duplicate_begin") == 0) return "Разные записи RUNTIME_FUNCTION не должны повторно использовать один и тот же BeginAddress.";
    if (strcmp(code, "unwind_parse_fail") == 0) return "UNWIND_INFO должна структурно разбираться по формату x64 unwind без обрыва и выхода за границы.";
    if (strcmp(code, "unwind_anomalies") == 0) return "Поля UNWIND_INFO и unwind-коды должны соответствовать кодировке Microsoft x64 unwind и ограничениям ABI.";
    if (strcmp(code, "unwind_reuse_strong") == 0) return "Массовое повторное использование одного UnwindInfoAddress многими функциями нетипично и требует подтверждения другими признаками.";
    if (strcmp(code, "unwind_reuse_moderate") == 0) return "Умеренное повторное использование UnwindInfoAddress становится доказательством только при наличии другого статического сигнала.";
    if (strcmp(code, "handler_dominance") == 0) return "Один handler target не должен доминировать над большой группой защищенных функций без понятного runtime/compiler-объяснения.";
    if (strcmp(code, "unwind_in_exec_section") == 0) return "UNWIND_INFO не должна размещаться в исполняемой секции кода.";
    if (strcmp(code, "unwind_unusual_section") == 0) return "UNWIND_INFO обычно лежит в metadata-секциях вроде .xdata, .rdata или .pdata.";
    if (strcmp(code, "unwind_writable_section") == 0) return "UNWIND_INFO обычно должна быть read-only metadata, а не writable-областью.";
    if (strcmp(code, "handler_nonexec_section") == 0) return "Exception handler должен указывать на исполняемый код.";
    if (strcmp(code, "handler_writable_section") == 0) return "Exception handler в writable-памяти нетипичен для обычного compiler-produced образа.";
    if (strcmp(code, "placement_exec_nonexec_handler_combo") == 0) return "Подозрительное размещение unwind metadata и handler в non-executable области усиливают друг друга как единый комбо-признак.";
    if (strcmp(code, "placement_integrity_combo") == 0) return "Подозрительное размещение metadata вместе с ошибками целостности unwind/table усиливает итоговый вывод.";
    if (strcmp(code, "reuse_dominance_combo") == 0) return "Повторное использование UnwindInfo и доминирующий handler вместе похожи на dispatcher-style схему.";
    if (strcmp(code, "writable_metadata_handler_combo") == 0) return "Writable unwind metadata и writable handler targets вместе образуют более сильный признак подозрительного размещения.";
    return "Эвристическое правило определяется кодом найденного признака.";
}

static const char* finding_expected_text(const char* code) {
    if (!code) return "Признак должен иметь известный код и достаточно контекста для объяснения.";
    if (strcmp(code, "pe_section_raw_oob") == 0) return "Для каждой секции с raw-данными должно выполняться raw_end <= размер файла.";
    if (strcmp(code, "pe_section_virtual_oob") == 0) return "Для каждой секции должно выполняться virtual_end <= SizeOfImage.";
    if (strcmp(code, "pe_section_raw_overlap") == 0) return "Raw-интервалы секций должны быть непересекающимися или пустыми.";
    if (strcmp(code, "pe_section_virtual_overlap") == 0) return "Virtual-интервалы секций должны быть непересекающимися.";
    if (strcmp(code, "pe_section_misaligned") == 0) return "Заголовки, SizeOfImage, ImageBase и raw/virtual адреса секций должны выполнять правила PE-выравнивания.";
    if (strcmp(code, "pe_exception_directory_oob") == 0) return "Exception Directory должна корректно отсутствовать или иметь валидный читаемый диапазон [RVA, RVA+Size).";
    if (strcmp(code, "no_runtime_functions") == 0) return "x64-код со stack frame, сохранением nonvolatile регистров, handlers или вызовами обычно имеет .pdata записи.";
    if (strcmp(code, "invalid_ranges") == 0) return "Для каждой RUNTIME_FUNCTION должно выполняться BeginAddress < EndAddress.";
    if (strcmp(code, "rf_oob") == 0) return "BeginAddress и EndAddress должны разрешаться внутри загруженного image.";
    if (strcmp(code, "unwind_rva_oob") == 0) return "UnwindInfoAddress должен быть RVA внутри image и должен мапиться в байты файла при статическом чтении.";
    if (strcmp(code, "rf_unsorted") == 0) return "Записи должны идти по возрастанию BeginAddress.";
    if (strcmp(code, "rf_overlaps") == 0) return "После сортировки EndAddress предыдущей записи должен быть <= BeginAddress следующей.";
    if (strcmp(code, "duplicate_begin") == 0) return "Каждый BeginAddress должен идентифицировать одну запись function table.";
    if (strcmp(code, "unwind_parse_fail") == 0) return "Version, Flags, CountOfCodes, массив unwind-кодов, padding и tail-данные должны разбираться без усечения.";
    if (strcmp(code, "unwind_anomalies") == 0) return "Unwind opcodes, operands, code offsets, chained info и handler data должны быть внутренне согласованы.";
    if (strcmp(code, "unwind_reuse_strong") == 0) return "Большинство функций должны иметь собственную UNWIND_INFO или делить ее только в небольших compiler-plausible шаблонах.";
    if (strcmp(code, "unwind_reuse_moderate") == 0) return "Reuse должен оставаться ниже умеренного порога, если нет понятного benign compiler/runtime объяснения.";
    if (strcmp(code, "handler_dominance") == 0) return "Handler references должны распределяться согласно обычным language/runtime структурам или объясняться известными runtime helpers.";
    if (strcmp(code, "unwind_in_exec_section") == 0) return "UNWIND_INFO должна лежать в non-executable metadata, обычно .xdata/.rdata/.pdata.";
    if (strcmp(code, "unwind_unusual_section") == 0) return "UNWIND_INFO должна находиться в секции, роль которой соответствует read-only exception/unwind metadata.";
    if (strcmp(code, "unwind_writable_section") == 0) return "Секция с UNWIND_INFO обычно должна быть readable и не должна быть writable/executable.";
    if (strcmp(code, "handler_nonexec_section") == 0) return "Handler RVA должен разрешаться в executable-секцию.";
    if (strcmp(code, "handler_writable_section") == 0) return "Handler RVA должен указывать на executable-код без неожиданного writable-права.";
    if (strcmp(code, "placement_exec_nonexec_handler_combo") == 0) return "Placement-признаки не должны одновременно усиливать друг друга по unwind metadata и handler targets.";
    if (strcmp(code, "placement_integrity_combo") == 0) return "Placement-признаки не должны совпадать с parse/OOB/integrity-проблемами.";
    if (strcmp(code, "reuse_dominance_combo") == 0) return "Reuse-признаки не должны совпадать с одним dominant handler target без доброкачественного объяснения.";
    if (strcmp(code, "writable_metadata_handler_combo") == 0) return "Writable metadata и writable handler targets не должны вместе встречаться в нормальном compiler output.";
    return "Наблюдаемое состояние должно удовлетворять соответствующему PE/unwind-инварианту.";
}

static const char* finding_impact_text(const char* code) {
    if (!code) return "Для неизвестного признака отсутствует заранее заданная интерпретационная модель; наблюдение подлежит отдельной ручной верификации аналитиком.";
    if (strncmp(code, "pe_section_", 11) == 0 || strcmp(code, "pe_exception_directory_oob") == 0) return "Такое нарушение способно исказить преобразование RVA в file offset, сделать evidence chain неоднозначной либо указать на поврежденную или намеренно искаженную PE-разметку.";
    if (strcmp(code, "no_runtime_functions") == 0) return "Для non-leaf кода отсутствие function table снижает полноту stack walking; leaf-only характер образа или специальный формат должны подтверждаться отдельным анализом.";
    if (strcmp(code, "invalid_ranges") == 0 || strcmp(code, "rf_oob") == 0 || strcmp(code, "rf_unsorted") == 0 || strcmp(code, "rf_overlaps") == 0 || strcmp(code, "duplicate_begin") == 0) return "Function table может перестать давать уникальную и надежную карту от instruction RVA к unwind metadata.";
    if (strcmp(code, "unwind_rva_oob") == 0) return "Windows или эмуляция unwind может не найти metadata функции, из-за чего ломается virtual unwind и восстановление стека.";
    if (strcmp(code, "unwind_parse_fail") == 0 || strcmp(code, "unwind_anomalies") == 0) return "Virtual unwind может вычислить неверный caller context, оборваться раньше времени или скрыть реальный exception/handler path.";
    if (strcmp(code, "unwind_reuse_strong") == 0 || strcmp(code, "unwind_reuse_moderate") == 0) return "Сильный metadata reuse может указывать на синтетическую или dispatcher-oriented разметку, особенно при совпадении с другими признаками.";
    if (strcmp(code, "handler_dominance") == 0) return "Один handler, контролирующий много функций, может указывать на централизованный exception dispatch, обфускацию или защитную логику.";
    if (strcmp(code, "unwind_in_exec_section") == 0 || strcmp(code, "unwind_unusual_section") == 0 || strcmp(code, "unwind_writable_section") == 0) return "Нетипичное placement metadata снижает доверие к unwind map и может указывать на нестандартную разметку, packing или protected code.";
    if (strcmp(code, "handler_nonexec_section") == 0 || strcmp(code, "handler_writable_section") == 0) return "Handler target с неожиданными правами делает exception dispatch небезопасным, неоднозначным или похожим на защитную схему.";
    if (strstr(code, "_combo") != NULL) return "Агрегированная оценка учитывает взаимно подтвержденные признаки как более значимые, чем изолированные слабые сигналы.";
    return "Признак влияет на доверие к PE/unwind-анализу и подлежит сопоставлению с соседними структурами отчета.";
}

typedef struct {
    const char* code;
    const char* title;
    const char* meaning;
    const char* next_step;
} FindingPresentationRu;

static const FindingPresentationRu FINDING_PRESENTATIONS_RU[] = {
    {"pe_section_raw_oob", "Raw-диапазон секции выходит за границы файла",
     "PointerToRawData и SizeOfRawData задают физический диапазон секции. Его выход за размер файла означает, что заявленные байты отсутствуют и не могут быть безопасно использованы при последующем разборе.",
     "Сопоставить PointerToRawData, SizeOfRawData и фактический размер файла; определить первое недоступное смещение и секционную запись, задающую некорректный диапазон."},
    {"pe_section_virtual_oob", "Виртуальный диапазон секции выходит за SizeOfImage",
     "Секция описывает RVA-область за пределами загружаемого PE-образа. Такая разметка нарушает единую систему координат, на которой основаны переходы от RVA к секции и file offset.",
     "Проверить VirtualAddress, VirtualSize, SizeOfRawData и SizeOfImage; установить, является ли причиной повреждение секционной таблицы либо несогласованное значение SizeOfImage."},
    {"pe_section_raw_overlap", "Физические диапазоны секций пересекаются",
     "Один участок входного файла одновременно объявлен содержимым нескольких секций. В результате происхождение байтов и преобразование file offset в секционный контекст становятся неоднозначными.",
     "Сопоставить пары [PointerToRawData, PointerToRawData + SizeOfRawData) и зафиксировать точный интервал пересечения, характеристики и назначение обеих секций."},
    {"pe_section_virtual_overlap", "Виртуальные диапазоны секций пересекаются",
     "Один RVA относится сразу к нескольким секциям PE. Это лишает section map однозначности и снижает достоверность определения прав доступа и владельца UNWIND_INFO либо handler target.",
     "Сопоставить RVA-интервалы конфликтующих секций, определить область пересечения и проверить ее фактическое отображение загрузчиком."},
    {"pe_section_misaligned", "Нарушены инварианты выравнивания PE",
     "Значения FileAlignment, SectionAlignment, SizeOfHeaders, SizeOfImage либо координаты секций не образуют согласованную PE-разметку. Ошибка может влиять на вычисление границ и преобразование адресов.",
     "Проверить каждое alignment-поле и остаток деления соответствующих raw/virtual координат; локализовать конкретный заголовок или секцию, нарушающую правило."},
    {"pe_exception_directory_oob", "Exception Directory недоступна или структурно некорректна",
     "Каталог исключений отсутствует неполной парой RVA/Size, не отображается в доступные байты либо выходит за границы image. Поэтому массив RUNTIME_FUNCTION нельзя считать надежно определенным.",
     "Сопоставить RVA и Size каталога с SizeOfImage, section map и file offset; проверить кратность доступной части размеру 12-байтовой записи RUNTIME_FUNCTION."},
    {"no_runtime_functions", "RUNTIME_FUNCTION не обнаружены",
     "В исполняемом PE32+ AMD64-образе отсутствует статическая таблица функций. Это может быть допустимо для leaf-only кода, но не подтверждает такую природу образа автоматически.",
     "Установить наличие non-leaf функций, стековых кадров, сохранения nonvolatile-регистров и динамической регистрации function table; только после этого классифицировать отсутствие .pdata."},
    {"invalid_ranges", "Диапазон RUNTIME_FUNCTION не имеет положительной длины",
     "В одной или нескольких записях EndAddress не больше BeginAddress. Такая запись не задает корректный полуинтервал функции и не может однозначно покрывать ControlPc.",
     "Сопоставить BeginAddress и EndAddress каждой evidence-записи с SizeOfImage, соседними записями .pdata и границами машинного кода."},
    {"rf_oob", "Диапазон RUNTIME_FUNCTION выходит за SizeOfImage",
     "BeginAddress либо EndAddress находится вне виртуальных границ PE-образа. Function table ссылается на область, которая не принадлежит заявленному image.",
     "Проверить координаты evidence-записи относительно SizeOfImage и исполняемых секций; определить, какое поле формирует выход за границу."},
    {"unwind_rva_oob", "UnwindInfoAddress не разрешается в доступную UNWIND_INFO",
     "RUNTIME_FUNCTION содержит нулевой либо выходящий за границы UnwindInfoAddress. Статический слой не может связать функцию с корректно читаемой unwind metadata.",
     "Проследить цепочку .pdata entry -> UnwindInfoAddress -> секция -> file offset и установить точную точку, на которой адрес перестает разрешаться."},
    {"rf_unsorted", "Нарушена сортировка RUNTIME_FUNCTION по BeginAddress",
     "Порядок записей в Exception Directory не является возрастающим по BeginAddress. Это нарушает ожидаемую организацию function table и может влиять на поиск записи по ControlPc.",
     "Сопоставить текущую и предыдущую .pdata-записи в каждой зафиксированной инверсии; исключить ошибку извлечения границ каталога."},
    {"rf_overlaps", "Диапазоны RUNTIME_FUNCTION пересекаются",
     "Несколько function entries покрывают общий RVA-интервал. Для ControlPc внутри пересечения возникает неоднозначное соответствие между кодом и unwind metadata.",
     "Исследовать обе записи каждой конфликтующей пары, их UnwindInfoAddress и фактические границы функций в машинном коде."},
    {"duplicate_begin", "Несколько RUNTIME_FUNCTION имеют одинаковый BeginAddress",
     "Одна начальная координата функции связана с несколькими записями .pdata. Это может означать дублирование либо конфликтующие описания одной области кода.",
     "Сопоставить все записи с повторяющимся BeginAddress, их EndAddress и UnwindInfoAddress; определить, эквивалентны ли они или задают противоречащие metadata."},
    {"unwind_parse_fail", "Структурный разбор UNWIND_INFO завершился ошибкой",
     "Header, массив UNWIND_CODE, operand slots, padding либо tail невозможно прочитать полностью и безопасно. Поля после точки отказа не используются как достоверные данные.",
     "Исследовать failed_field, file offset, ожидаемый и доступный размер, число slots и сохраненный byte dump; не интерпретировать handler или chain за границей достоверно прочитанной области."},
    {"unwind_anomalies", "UNWIND_INFO содержит внутреннее нарушение",
     "Структура прочитана, однако версия, opcode/OpInfo, CodeOffset, порядок кодов, frame-поля, chain либо ABI-ограничения не согласуются с проверяемой моделью x64 unwind.",
     "Определить конкретные anomaly bits, сопоставить их с полями UNWIND_INFO и вручную проверить кодировку операции, дополнительные slots, padding и tail."},
    {"unwind_reuse_strong", "Выявлено массовое повторное использование UNWIND_INFO",
     "Большая доля функций ссылается на один UnwindInfoAddress. Наблюдение является контекстной эвристикой: оно допускает compiler/runtime-объяснение, но может отражать синтетическую централизованную разметку.",
     "Сгруппировать evidence-записи по UnwindInfoAddress, сравнить прологи и назначение функций, затем установить, объясняется ли повторное использование единым корректным шаблоном."},
    {"handler_dominance", "Один handler target доминирует в выборке функций",
     "Значительная доля функций с обработчиком ссылается на один HandlerRVA. Это может соответствовать стандартному language runtime либо централизованной dispatcher-схеме.",
     "Идентифицировать handler target, секцию и права доступа; сопоставить связанные функции и language-specific data, чтобы отделить стандартный runtime helper от нестандартной маршрутизации."},
    {"unwind_reuse_moderate", "Умеренное повторное использование UNWIND_INFO подтверждено контекстом",
     "Доля повторного использования сама по себе недостаточна для finding, однако в данном образце она совпала с другим статическим сигналом и поэтому включена в совокупную оценку.",
     "Проверить группу функций с доминирующим UnwindInfoAddress и отдельно верифицировать тот признак, который повысил доказательную значимость reuse-наблюдения."},
    {"unwind_in_exec_section", "UNWIND_INFO размещена в исполняемой секции",
     "Данные x64 unwind находятся в секции с правом исполнения. Это нетипичное совмещение кода и metadata повышает риск ошибочной классификации содержимого и требует контекстной проверки.",
     "Сопоставить RVA, file offset, характеристики секции и соседние байты; определить, объясняется ли размещение особенностями linker/runtime либо является намеренным смешением кода и данных."},
    {"unwind_unusual_section", "UNWIND_INFO размещена вне типичных metadata-секций",
     "Имя и роль секции не соответствуют ожидаемым .xdata/.rdata/.pdata-подобным областям. Название секции не является нормативным требованием, поэтому finding имеет контекстный характер.",
     "Оценить права секции, тип соседних данных, linker/compiler provenance и корректность полного RVA-to-file-offset mapping; не делать вывод только по имени секции."},
    {"unwind_writable_section", "UNWIND_INFO размещена в секции с правом записи",
     "Unwind metadata находится в изменяемой области. Статическое содержимое может не совпадать с состоянием памяти во время выполнения, особенно при наличии loader, JIT или protector-логики.",
     "Сопоставить права секции на диске и в памяти; при допустимом изолированном запуске проверить, изменяются ли соответствующие bytes до возникновения исключения."},
    {"handler_nonexec_section", "HandlerRVA не указывает на исполняемую секцию",
     "Адрес обработчика из UNWIND_INFO не разрешается в область с execute-правом либо не принадлежит известной секции. Такой target не соответствует обычной статической модели вызова handler-кода.",
     "Проследить HandlerRVA через section map, проверить права и фактические bytes по адресу; учесть возможное изменение memory protection только как гипотезу до динамического подтверждения."},
    {"handler_writable_section", "HandlerRVA указывает в секцию с правом записи",
     "Обработчик размещен в области, допускающей изменение содержимого. Это не доказывает вмешательство, но снижает устойчивость статической интерпретации handler target.",
     "Сопоставить HandlerRVA с правами секции, кодом обработчика и runtime memory protection; проверить, изменяется ли target при выполнении."},
    {"placement_exec_nonexec_handler_combo", "Корреляция: исполняемая unwind metadata и неисполняемый handler",
     "Одновременно зафиксированы два нетипичных placement-условия: UNWIND_INFO в executable-секции и handler target вне executable-секции. Совместное наблюдение сильнее каждого условия по отдельности.",
     "Раздельно верифицировать evidence-записи обоих частных признаков, затем сопоставить, относятся ли они к одной функции или единой схеме размещения."},
    {"placement_integrity_combo", "Корреляция: нетипичное размещение и нарушение целостности",
     "Placement-сигнал совпал с ошибкой чтения UNWIND_INFO, внутренней аномалией либо некорректным UnwindInfoAddress. Комбинация связывает контекст размещения с наблюдаемым структурным нарушением.",
     "Для каждой evidence-записи установить, какой placement-компонент и какое integrity-условие выполнены; подтвердить их по section map, диагностическому полю и byte evidence."},
    {"reuse_dominance_combo", "Корреляция: повторное использование UNWIND_INFO и доминирующий handler",
     "Централизация UnwindInfoAddress совпала с концентрацией HandlerRVA. Такая связка совместима как со стандартным runtime-шаблоном, так и с dispatcher-oriented организацией, поэтому требует идентификации handler-а.",
     "Сравнить группу с доминирующим UnwindInfoAddress с группой handler_dominance, определить их пересечение и проверить семантику общего обработчика."},
    {"writable_metadata_handler_combo", "Корреляция: изменяемая unwind metadata и изменяемый handler target",
     "UNWIND_INFO и связанные handler targets одновременно находятся в writable-секциях. Это повышает вероятность того, что статическая карта может изменяться в runtime.",
     "Сопоставить evidence-записи обоих writable-признаков и, при разрешенной динамической проверке, сравнить bytes и memory protection до и после инициализации процесса."},
};

static const FindingPresentationRu* finding_presentation_ru(const char* code) {
    if (!code) return NULL;
    for (size_t i = 0; i < sizeof(FINDING_PRESENTATIONS_RU) / sizeof(FINDING_PRESENTATIONS_RU[0]); i++) {
        if (strcmp(code, FINDING_PRESENTATIONS_RU[i].code) == 0) {
            return &FINDING_PRESENTATIONS_RU[i];
        }
    }
    return NULL;
}

static const char* finding_title_ru(const char* code) {
    const FindingPresentationRu* presentation = finding_presentation_ru(code);
    return presentation ? presentation->title : "Эвристический признак";
}

static const char* finding_meaning_ru(const char* code) {
    const FindingPresentationRu* presentation = finding_presentation_ru(code);
    return presentation
        ? presentation->meaning
        : "Код finding-а не сопоставлен с зарегистрированной интерпретационной моделью; вывод требует отдельной ручной верификации аналитиком.";
}

static const char* finding_why_it_matters_ru(const char* code) {
    return finding_impact_text(code);
}

static const char* finding_next_step_ru(const char* code) {
    const FindingPresentationRu* presentation = finding_presentation_ru(code);
    return presentation
        ? presentation->next_step
        : "Сопоставить исходный код finding-а с таблицей функций, секционной картой, байтами входного файла и воспроизводимым результатом ручной проверки.";
}

static bool finding_is_pe_level(const HeuristicFinding* finding) {
    return finding && strncmp(finding->code, "pe_", 3) == 0;
}

static size_t finding_related_function_index(const HeuristicFinding* finding,
                                             const RuntimeFunction* rf,
                                             const UnwindSummary* us,
                                             const bool* us_ok,
                                             size_t n) {
    if (!finding || !finding->has_location || !rf || finding_is_pe_level(finding)) {
        return (size_t)-1;
    }
    uint32_t rva = finding->representative_rva;
    for (size_t i = 0; i < n; i++) {
        if (rf[i].unwind_rva == rva) return i;
        if (rf[i].begin_rva == rva) return i;
        if (rf[i].begin_rva <= rva && rva < rf[i].end_rva) return i;
        if (us && us_ok && us_ok[i] && us[i].has_handler && us[i].handler_rva == rva) return i;
        if (us && us_ok && us_ok[i] && us[i].has_chain &&
            us[i].chain.begin_rva <= rva && rva < us[i].chain.end_rva) {
            return i;
        }
    }
    return (size_t)-1;
}

static void finding_observed_text(const HeuristicFinding* finding,
                                  const PeImage* img,
                                  const RuntimeFunction* rf,
                                  const UnwindSummary* us,
                                  const bool* us_ok,
                                  size_t n,
                                  char* out,
                                  size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!finding) {
        snprintf(out, out_size, "Объект finding не передан.");
        return;
    }

    size_t related = finding_related_function_index(finding, rf, us, us_ok, n);
    if (strstr(finding->code, "_combo") != NULL) {
        size_t evidence_records = evidence_record_count(finding, img, rf, us, us_ok, n);
        if (finding->has_location) {
            uint32_t file_off = 0;
            bool has_file_off = pe_rva_to_fileoff(img, finding->representative_rva, &file_off);
            const PeSection* section = pe_find_section_for_rva(img, finding->representative_rva);
            char permissions[4] = "---";
            char file_offset_text[32];
            if (section) section_permissions(section->characteristics, permissions);
            if (has_file_off) snprintf(file_offset_text, sizeof(file_offset_text), "0x%08x", (unsigned)file_off);
            else snprintf(file_offset_text, sizeof(file_offset_text), "не мапится в файл");
            snprintf(out, out_size,
                     "Тип наблюдения: агрегированный корреляционный признак; число частных структурных срабатываний: %zu; число записей-доказательств: %zu; representative RVA: 0x%08x; file offset: %s; секция: %s; права: %s",
                     finding->affected_count,
                     evidence_records,
                     (unsigned)finding->representative_rva,
                     file_offset_text,
                     section ? section->name : "-",
                     permissions);
        } else {
            snprintf(out, out_size,
                     "Тип наблюдения: агрегированный корреляционный признак; число частных структурных срабатываний: %zu; число записей-доказательств: %zu; единый representative RVA не определен",
                     finding->affected_count,
                     evidence_records);
        }
        return;
    }
    if (finding->has_location) {
        uint32_t file_off = 0;
        bool has_file_off = pe_rva_to_fileoff(img, finding->representative_rva, &file_off);
        const PeSection* section = pe_find_section_for_rva(img, finding->representative_rva);
        char permissions[4] = "---";
        char file_offset_text[32];
        char characteristics_text[32];
        if (section) section_permissions(section->characteristics, permissions);
        if (has_file_off) snprintf(file_offset_text, sizeof(file_offset_text), "0x%08x", (unsigned)file_off);
        else snprintf(file_offset_text, sizeof(file_offset_text), "не_мапится_в_файл");
        if (section) snprintf(characteristics_text, sizeof(characteristics_text), "0x%08x", (unsigned)section->characteristics);
        else snprintf(characteristics_text, sizeof(characteristics_text), "нет");
        snprintf(out, out_size,
                 "Число зафиксированных нарушений: %zu; representative RVA: 0x%08x; file offset: %s; секция: %s; характеристики секции: %s; права: %s; связанная функция: %s",
                 finding->affected_count,
                 (unsigned)finding->representative_rva,
                 file_offset_text,
                 section ? section->name : "-",
                 characteristics_text,
                 permissions,
                 related != (size_t)-1 ? "найдена" : "не_сопоставлена");
        if (related != (size_t)-1) {
            size_t len = strlen(out);
            snprintf(out + len, out_size > len ? out_size - len : 0,
                     "; координаты функции: index=%zu, begin=0x%08x, end=0x%08x, unwind=0x%08x",
                     related,
                     (unsigned)rf[related].begin_rva,
                     (unsigned)rf[related].end_rva,
                     (unsigned)rf[related].unwind_rva);
        }
    } else {
        snprintf(out, out_size,
                 "Число зафиксированных нарушений: %zu; единый representative RVA для данного наблюдения не определен",
                 finding->affected_count);
    }
}

static uint32_t runtime_function_size(const RuntimeFunction* r) {
    if (!r || r->end_rva < r->begin_rva) return 0;
    return r->end_rva - r->begin_rva;
}

static bool csv_cell(StrBuf* out, const char* s) {
    if (!out || !s) return false;
    bool need_q = false;
    for (const char* p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') { need_q = true; break; }
    }
    if (!need_q) return sb_append(out, s);

    if (!sb_appendn(out, "\"", 1)) return false;
    for (const char* p = s; *p; p++) {
        if (*p == '"' && !sb_appendn(out, "\"", 1)) return false;
        if (!sb_appendn(out, p, 1)) return false;
    }
    return sb_appendn(out, "\"", 1);
}

static bool build_unwind_comment(const UnwindSummary* u, StrBuf* sb) {
    sb->len = 0;
    if (sb->s) sb->s[0] = 0;

    char fbuf[64];
    unwind_flags_to_string(u->flags, fbuf);

    sb_appendf(sb, "UNWIND v%u flags=%s prolog=%u stack=%uB frame=%s+%u ",
               (unsigned)u->version, fbuf, (unsigned)u->prolog_size,
               (unsigned)u->fixed_stack_bytes,
               (u->frame_reg ? unwind_reg_name(u->frame_reg) : "-"),
               (unsigned)(u->frame_off * 16u));

    sb_append(sb, "saved_gp=[");
    append_regmask(sb, u->saved_nonvol_mask, false);
    sb_append(sb, "] saved_xmm=[");
    append_regmask(sb, u->saved_xmm_mask, true);
    sb_append(sb, "]");

    if (u->has_handler) sb_appendf(sb, " handler_rva=0x%08x", (unsigned)u->handler_rva);
    if (u->has_chain) {
        sb_appendf(sb, " chain_to=[0x%08x..0x%08x] u=0x%08x",
                   (unsigned)u->chain.begin_rva,
                   (unsigned)u->chain.end_rva,
                   (unsigned)u->chain.unwind_rva);
    }

    if (u->anomalies) {
        sb_append(sb, " anomalies=");
        anomalies_to_str(sb, u->anomalies);
    }
    return sb_ok(sb);
}

void report_print_brief(const char* path, const PeImage* img, size_t rf_count) {
    printf("File: %s\n", path);
    printf("Machine: 0x%04x (AMD64)\n", (unsigned)img->machine);
    printf("ImageBase: 0x%llx\n", (unsigned long long)img->image_base);
    printf("SizeOfImage: 0x%x\n", (unsigned)img->size_of_image);
    printf("SizeOfHeaders: 0x%x  Sections: %zu\n",
           (unsigned)img->size_of_headers, img->num_sections);
    printf("Exception Directory: RVA=0x%08x Size=0x%x\n", (unsigned)img->exception_rva, (unsigned)img->exception_size);
    printf("RUNTIME_FUNCTION entries: %zu\n", rf_count);
}

bool report_write_csv(const char* path,
                      const PeImage* img,
                      const RuntimeFunction* rf,
                      const UnwindSummary* us,
                      const bool* us_ok,
                      size_t n,
                      bool ghidra_mode,
                      StrBuf* err) {
    (void)img;
    if (!path || (!rf && n) || (!us && n) || (!us_ok && n)) {
        sb_append(err, "Invalid arguments for CSV report.\n");
        return false;
    }

    StrBuf output = {0};
    StrBuf comment = {0};
    if (!sb_init(&output, 8192) || !sb_init(&comment, 512)) {
        sb_free(&comment);
        sb_free(&output);
        sb_append(err, "OOM.\n");
        return false;
    }

    if (ghidra_mode) {
        sb_append(&output, "begin_rva,end_rva,name,comment\n");
        for (size_t i = 0; i < n; i++) {
            const RuntimeFunction* r = &rf[i];
            const UnwindSummary* u = &us[i];

            char name[64];
            snprintf(name, sizeof(name), "sub_%08X", (unsigned)r->begin_rva);

            if (us_ok[i]) build_unwind_comment(u, &comment);
            else {
                comment.len = 0;
                if (comment.s) comment.s[0] = 0;
                sb_append(&comment, "UNWIND parse failed");
                if (u->parse_error[0]) sb_appendf(&comment, ": %s", u->parse_error);
            }

            char a[32], b[32];
            snprintf(a, sizeof(a), "0x%08X", (unsigned)r->begin_rva);
            snprintf(b, sizeof(b), "0x%08X", (unsigned)r->end_rva);

            csv_cell(&output, a); sb_appendn(&output, ",", 1);
            csv_cell(&output, b); sb_appendn(&output, ",", 1);
            csv_cell(&output, name); sb_appendn(&output, ",", 1);
            csv_cell(&output, comment.s ? comment.s : "");
            sb_appendn(&output, "\n", 1);
        }
    } else {
        sb_append(&output,
                  "index,begin_rva,end_rva,size,unwind_rva,unwind_ver,"
                  "unwind_flags,prolog_size,fixed_stack,frame_reg,frame_off,"
                  "handler_rva,has_chain,anomalies,parse_error\n");
        for (size_t i = 0; i < n; i++) {
            const RuntimeFunction* r = &rf[i];
            const UnwindSummary* u = &us[i];
            char fbuf[64];
            unwind_flags_to_string(u->flags, fbuf);

            sb_appendf(&output, "%zu,0x%08X,0x%08X,%u,0x%08X,",
                       i, (unsigned)r->begin_rva, (unsigned)r->end_rva,
                       (unsigned)runtime_function_size(r),
                       (unsigned)r->unwind_rva);

            if (!us_ok[i]) {
                sb_appendf(&output, "NA,NA,NA,NA,NA,NA,NA,0,0x%08X,",
                           (unsigned)u->anomalies);
                csv_cell(&output, u->parse_error);
                sb_appendn(&output, "\n", 1);
                continue;
            }

            sb_appendf(&output, "%u,%s,%u,%u,%s,%u,0x%08X,%u,0x%08X,",
                       (unsigned)u->version, fbuf, (unsigned)u->prolog_size,
                       (unsigned)u->fixed_stack_bytes,
                       (u->frame_reg ? unwind_reg_name(u->frame_reg) : "-"),
                       (unsigned)(u->frame_off * 16u),
                       (unsigned)u->handler_rva,
                       (unsigned)(u->has_chain ? 1u : 0u),
                       (unsigned)u->anomalies);
            csv_cell(&output, "");
            sb_appendn(&output, "\n", 1);
        }
    }

    bool ok = sb_ok(&output) && sb_ok(&comment);
    if (ok) ok = file_write_atomic(path, output.s, output.len);
    sb_free(&comment);
    sb_free(&output);
    if (!ok) sb_appendf(err, "Failed while building or writing CSV: %s\n", path);
    return ok;
}

static size_t valid_utf8_sequence_length(const unsigned char* s, size_t remaining) {
    if (!s || remaining == 0) return 0;
    if (s[0] < 0x80u) return 1;
    if (s[0] >= 0xc2u && s[0] <= 0xdfu) {
        return remaining >= 2 && s[1] >= 0x80u && s[1] <= 0xbfu ? 2 : 0;
    }
    if (s[0] == 0xe0u) {
        return remaining >= 3 && s[1] >= 0xa0u && s[1] <= 0xbfu &&
               s[2] >= 0x80u && s[2] <= 0xbfu ? 3 : 0;
    }
    if ((s[0] >= 0xe1u && s[0] <= 0xecu) || (s[0] >= 0xeeu && s[0] <= 0xefu)) {
        return remaining >= 3 && s[1] >= 0x80u && s[1] <= 0xbfu &&
               s[2] >= 0x80u && s[2] <= 0xbfu ? 3 : 0;
    }
    if (s[0] == 0xedu) {
        return remaining >= 3 && s[1] >= 0x80u && s[1] <= 0x9fu &&
               s[2] >= 0x80u && s[2] <= 0xbfu ? 3 : 0;
    }
    if (s[0] == 0xf0u) {
        return remaining >= 4 && s[1] >= 0x90u && s[1] <= 0xbfu &&
               s[2] >= 0x80u && s[2] <= 0xbfu &&
               s[3] >= 0x80u && s[3] <= 0xbfu ? 4 : 0;
    }
    if (s[0] >= 0xf1u && s[0] <= 0xf3u) {
        return remaining >= 4 && s[1] >= 0x80u && s[1] <= 0xbfu &&
               s[2] >= 0x80u && s[2] <= 0xbfu &&
               s[3] >= 0x80u && s[3] <= 0xbfu ? 4 : 0;
    }
    if (s[0] == 0xf4u) {
        return remaining >= 4 && s[1] >= 0x80u && s[1] <= 0x8fu &&
               s[2] >= 0x80u && s[2] <= 0xbfu &&
               s[3] >= 0x80u && s[3] <= 0xbfu ? 4 : 0;
    }
    return 0;
}

static void json_escape(StrBuf* sb, const char* s) {
    if (!s) return;
    size_t length = strlen(s);
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '\\': sb_append(sb, "\\\\"); break;
            case '"':  sb_append(sb, "\\\""); break;
            case '\n': sb_append(sb, "\\n"); break;
            case '\r': sb_append(sb, "\\r"); break;
            case '\t': sb_append(sb, "\\t"); break;
            default:
                if (c < 0x20) sb_appendf(sb, "\\u%04x", (unsigned)c);
                else if (c < 0x80) sb_appendn(sb, &s[i], 1);
                else {
                    size_t sequence = valid_utf8_sequence_length(
                        (const unsigned char*)&s[i], length - i);
                    if (sequence) {
                        sb_appendn(sb, &s[i], sequence);
                        i += sequence - 1;
                    } else {
                        sb_appendf(sb, "\\u%04x", (unsigned)c);
                    }
                }
        }
    }
}

static void json_key(StrBuf* sb, const char* k) {
    sb_append(sb, "\"");
    json_escape(sb, k);
    sb_append(sb, "\":");
}

static void json_string(StrBuf* sb, const char* s) {
    sb_append(sb, "\"");
    json_escape(sb, s ? s : "");
    sb_append(sb, "\"");
}

static void json_string_field(StrBuf* sb, const char* k, const char* v, bool trailing_comma) {
    json_key(sb, k);
    json_string(sb, v);
    if (trailing_comma) sb_append(sb, ",");
}

static void json_bool_field(StrBuf* sb, const char* k, bool v, bool trailing_comma) {
    json_key(sb, k);
    sb_append(sb, v ? "true" : "false");
    if (trailing_comma) sb_append(sb, ",");
}


static void json_nullable_hex32(StrBuf* sb, bool has_value, uint32_t value) {
    if (has_value) sb_appendf(sb, "\"0x%08x\"", (unsigned)value);
    else sb_append(sb, "null");
}

static void json_nullable_count(StrBuf* sb, bool has_value, uint32_t value) {
    if (has_value) sb_appendf(sb, "%u", (unsigned)value);
    else sb_append(sb, "null");
}

static void bytes_to_hex(const uint8_t* bytes, size_t count, char* out, size_t out_size) {
    static const char hex[] = "0123456789abcdef";
    if (!out || out_size == 0) return;
    size_t pos = 0;
    for (size_t i = 0; i < count && bytes && pos + 3 < out_size; i++) {
        if (i > 0) out[pos++] = ' ';
        out[pos++] = hex[(bytes[i] >> 4) & 0x0f];
        out[pos++] = hex[bytes[i] & 0x0f];
    }
    out[pos] = '\0';
}

static void json_unwind_diagnostic(StrBuf* sb, const UnwindSummary* u) {
    char bytes_hex[UNWIND_DIAG_MAX_BYTES * 3u + 1u];
    bytes_hex[0] = '\0';
    if (u && u->diagnostic_has_bytes) {
        bytes_to_hex(u->diagnostic_bytes, u->diagnostic_bytes_count, bytes_hex, sizeof(bytes_hex));
    }
    sb_append(sb, "{");
    json_string_field(sb, "failed_field", u ? u->diagnostic_field : "", true);
    json_key(sb, "failure_file_offset");
    json_nullable_hex32(sb, u && u->diagnostic_has_file_offset, u ? u->diagnostic_file_offset : 0u);
    sb_append(sb, ",");
    json_key(sb, "expected_size");
    json_nullable_count(sb, u && u->diagnostic_has_size, u ? u->diagnostic_expected_size : 0u);
    sb_append(sb, ",");
    json_key(sb, "available_size");
    json_nullable_count(sb, u && u->diagnostic_has_size, u ? u->diagnostic_available_size : 0u);
    sb_append(sb, ",");
    json_key(sb, "expected_slots");
    json_nullable_count(sb, u && u->diagnostic_has_slots, u ? u->diagnostic_expected_slots : 0u);
    sb_append(sb, ",");
    json_key(sb, "available_slots");
    json_nullable_count(sb, u && u->diagnostic_has_slots, u ? u->diagnostic_available_slots : 0u);
    sb_append(sb, ",");
    json_key(sb, "bytes_file_offset");
    json_nullable_hex32(sb, u && u->diagnostic_has_bytes, u ? u->diagnostic_bytes_file_offset : 0u);
    sb_append(sb, ",");
    json_string_field(sb, "bytes_hex", (u && u->diagnostic_has_bytes) ? bytes_hex : "", true);
    json_key(sb, "bytes_count");
    sb_appendf(sb, "%u,", (unsigned)(u ? u->diagnostic_bytes_count : 0u));
    json_key(sb, "chain_path");
    sb_append(sb, "[");
    if (u) {
        for (uint8_t i = 0; i < u->chain_path_count; i++) {
            if (i) sb_append(sb, ",");
            sb_appendf(sb, "\"0x%08x\"", (unsigned)u->chain_path[i]);
        }
    }
    sb_append(sb, "],");
    json_bool_field(sb, "chain_loop_detected", u && u->chain_loop_detected, true);
    json_key(sb, "chain_loop_rva");
    json_nullable_hex32(sb, u && u->chain_loop_detected, u ? u->chain_loop_rva : 0u);
    sb_append(sb, "}");
}

static void json_finding_evidence_record(StrBuf* sb,
                                         const HeuristicFinding* finding,
                                         const PeImage* img,
                                         const RuntimeFunction* rf,
                                         const UnwindSummary* us,
                                         const bool* us_ok,
                                         size_t n,
                                         size_t index) {
    const RuntimeFunction* r = (rf && index < n) ? &rf[index] : NULL;
    const UnwindSummary* u = (us && index < n) ? &us[index] : NULL;
    const PeSection* unwind_section = r ? pe_find_section_for_rva(img, r->unwind_rva) : NULL;
    const PeSection* handler_section = (u && u->has_handler) ? pe_find_section_for_rva(img, u->handler_rva) : NULL;
    uint32_t pdata_rva = 0;
    uint32_t pdata_file_offset = 0;
    uint32_t unwind_file_offset = 0;
    uint32_t handler_file_offset = 0;
    bool has_pdata_rva = pdata_entry_rva_for_index(img, index, &pdata_rva);
    bool has_pdata_file_offset = pdata_entry_fileoff_for_index(img, index, &pdata_file_offset);
    bool has_unwind_file_offset = r && pe_rva_to_fileoff(img, r->unwind_rva, &unwind_file_offset);
    bool has_handler_file_offset = u && u->has_handler && pe_rva_to_fileoff(img, u->handler_rva, &handler_file_offset);
    char unwind_permissions[4] = "---";
    char handler_permissions[4] = "---";
    char reason[512];
    if (unwind_section) section_permissions(unwind_section->characteristics, unwind_permissions);
    if (handler_section) section_permissions(handler_section->characteristics, handler_permissions);
    evidence_record_reason_ru(finding, img, rf, us, us_ok, n, index, reason, sizeof(reason));

    sb_append(sb, "{");
    json_key(sb, "runtime_function_index"); sb_appendf(sb, "%zu,", index);
    json_key(sb, "pdata_entry_rva"); json_nullable_hex32(sb, has_pdata_rva, pdata_rva); sb_append(sb, ",");
    json_key(sb, "pdata_entry_file_offset"); json_nullable_hex32(sb, has_pdata_file_offset, pdata_file_offset); sb_append(sb, ",");
    json_key(sb, "runtime_function_entry_size"); sb_appendf(sb, "%u,", REPORT_RUNTIME_FUNCTION_ENTRY_SIZE);
    json_key(sb, "function_begin_rva"); json_nullable_hex32(sb, r != NULL, r ? r->begin_rva : 0u); sb_append(sb, ",");
    json_key(sb, "function_end_rva"); json_nullable_hex32(sb, r != NULL, r ? r->end_rva : 0u); sb_append(sb, ",");
    json_key(sb, "function_size"); sb_appendf(sb, "%u,", (unsigned)(r ? runtime_function_size(r) : 0u));
    json_string_field(sb, "function_begin_section", r ? section_name_or_dash(img, r->begin_rva) : "-", true);
    json_key(sb, "unwind_rva"); json_nullable_hex32(sb, r != NULL, r ? r->unwind_rva : 0u); sb_append(sb, ",");
    json_string_field(sb, "unwind_section", r ? section_name_or_dash(img, r->unwind_rva) : "-", true);
    json_key(sb, "unwind_file_offset"); json_nullable_hex32(sb, has_unwind_file_offset, unwind_file_offset); sb_append(sb, ",");
    json_string_field(sb, "unwind_section_permissions", unwind_permissions, true);
    json_key(sb, "handler_rva"); json_nullable_hex32(sb, u && u->has_handler, u ? u->handler_rva : 0u); sb_append(sb, ",");
    json_string_field(sb, "handler_section", (u && u->has_handler) ? section_name_or_dash(img, u->handler_rva) : "-", true);
    json_key(sb, "handler_file_offset"); json_nullable_hex32(sb, has_handler_file_offset, handler_file_offset); sb_append(sb, ",");
    json_string_field(sb, "handler_section_permissions", handler_permissions, true);
    json_bool_field(sb, "unwind_ok", us_ok && index < n ? us_ok[index] : false, true);
    json_string_field(sb, "parse_error", u ? u->parse_error : "", true);
    json_string_field(sb, "failed_field", u ? u->diagnostic_field : "", true);
    json_string_field(sb, "reason_ru", reason, true);
    json_key(sb, "diagnostic");
    json_unwind_diagnostic(sb, u);
    sb_append(sb, "}");
}

static void json_finding_evidence_records(StrBuf* sb,
                                          const HeuristicFinding* finding,
                                          const PeImage* img,
                                          const RuntimeFunction* rf,
                                          const UnwindSummary* us,
                                          const bool* us_ok,
                                          size_t n) {
    size_t total = evidence_record_count(finding, img, rf, us, us_ok, n);
    size_t written = 0;
    json_key(sb, "evidence_records_total"); sb_appendf(sb, "%zu,", total);
    json_key(sb, "evidence_records_limit"); sb_appendf(sb, "%u,", REPORT_EVIDENCE_RECORD_LIMIT_JSON);
    json_key(sb, "evidence_records_truncated"); sb_append(sb, total > REPORT_EVIDENCE_RECORD_LIMIT_JSON ? "true," : "false,");
    json_key(sb, "evidence_records");
    sb_append(sb, "[");
    for (size_t i = 0; i < n && written < REPORT_EVIDENCE_RECORD_LIMIT_JSON; i++) {
        if (!evidence_record_matches(finding, img, rf, us, us_ok, n, i)) continue;
        if (written) sb_append(sb, ",");
        json_finding_evidence_record(sb, finding, img, rf, us, us_ok, n, i);
        written++;
    }
    sb_append(sb, "]");
}

static void json_finding_evidence_chain(StrBuf* sb,
                                        const HeuristicFinding* finding,
                                        const PeImage* img,
                                        const RuntimeFunction* rf,
                                        const UnwindSummary* us,
                                        const bool* us_ok,
                                        size_t n) {
    size_t related = finding_related_function_index(finding, rf, us, us_ok, n);
    const RuntimeFunction* related_rf = (related != (size_t)-1) ? &rf[related] : NULL;
    const UnwindSummary* related_us = (related != (size_t)-1 && us) ? &us[related] : NULL;
    const PeSection* unwind_section = related_rf ? pe_find_section_for_rva(img, related_rf->unwind_rva) : NULL;
    uint32_t exception_file_offset = 0;
    uint32_t pdata_entry_rva = 0;
    uint32_t pdata_entry_file_offset = 0;
    uint32_t unwind_file_offset = 0;
    bool has_exception_file_offset = img && pe_rva_to_fileoff(img, img->exception_rva, &exception_file_offset);
    bool has_pdata_entry_rva = related != (size_t)-1 && pdata_entry_rva_for_index(img, related, &pdata_entry_rva);
    bool has_pdata_entry_file_offset = related != (size_t)-1 && pdata_entry_fileoff_for_index(img, related, &pdata_entry_file_offset);
    bool has_unwind_file_offset = related_rf && pe_rva_to_fileoff(img, related_rf->unwind_rva, &unwind_file_offset);
    char permissions[4] = "---";
    if (unwind_section) section_permissions(unwind_section->characteristics, permissions);

    sb_append(sb, "{");
    json_key(sb, "exception_directory_rva");
    sb_appendf(sb, "\"0x%08x\",", (unsigned)(img ? img->exception_rva : 0u));
    json_key(sb, "exception_directory_size");
    sb_appendf(sb, "\"0x%x\",", (unsigned)(img ? img->exception_size : 0u));
    json_key(sb, "exception_directory_file_offset");
    json_nullable_hex32(sb, has_exception_file_offset, exception_file_offset);
    sb_append(sb, ",");
    json_key(sb, "runtime_function_index");
    if (related != (size_t)-1) sb_appendf(sb, "%zu,", related);
    else sb_append(sb, "null,");
    json_key(sb, "runtime_function_entry_size"); sb_appendf(sb, "%u,", REPORT_RUNTIME_FUNCTION_ENTRY_SIZE);
    json_key(sb, "pdata_entry_rva");
    json_nullable_hex32(sb, has_pdata_entry_rva, pdata_entry_rva);
    sb_append(sb, ",");
    json_key(sb, "pdata_entry_file_offset");
    json_nullable_hex32(sb, has_pdata_entry_file_offset, pdata_entry_file_offset);
    sb_append(sb, ",");
    json_key(sb, "function_begin_rva");
    json_nullable_hex32(sb, related_rf != NULL, related_rf ? related_rf->begin_rva : 0u);
    sb_append(sb, ",");
    json_key(sb, "function_end_rva");
    json_nullable_hex32(sb, related_rf != NULL, related_rf ? related_rf->end_rva : 0u);
    sb_append(sb, ",");
    json_key(sb, "unwind_rva");
    json_nullable_hex32(sb, related_rf != NULL, related_rf ? related_rf->unwind_rva : 0u);
    sb_append(sb, ",");
    json_string_field(sb, "unwind_section", related_rf ? section_name_or_dash(img, related_rf->unwind_rva) : "-", true);
    json_key(sb, "unwind_file_offset");
    json_nullable_hex32(sb, has_unwind_file_offset, unwind_file_offset);
    sb_append(sb, ",");
    json_string_field(sb, "unwind_section_permissions", permissions, true);
    json_string_field(sb, "failed_field", related_us ? related_us->diagnostic_field : "", false);
    sb_append(sb, "}");
}

static void json_heuristic_families(StrBuf* sb, uint32_t mask) {
    sb_append(sb, "[");
    bool first = true;
    uint32_t bits[] = {
        HEF_TABLE_INTEGRITY,
        HEF_UNWIND_INTEGRITY,
        HEF_METADATA_PLACEMENT,
        HEF_UNWIND_REUSE,
        HEF_HANDLER_DOMINANCE
    };
    for (size_t i = 0; i < sizeof(bits)/sizeof(bits[0]); i++) {
        if (!(mask & bits[i])) continue;
        if (!first) sb_append(sb, ",");
        json_string(sb, heuristics_evidence_family_name(bits[i]));
        first = false;
    }
    sb_append(sb, "]");
}

static unsigned dynamic_signal_count(const DynamicReport* dr) {
    unsigned n = 0;
    if (!dr) return 0;
    if (dr->unwind_handler_hits) n++;
    if (dr->veh_hits || dr->veh_registrations) n++;
    if (dr->vch_hits || dr->vch_registrations) n++;
    if (dr->uef_hits || dr->uef_set_calls) n++;
    if (dr->rtl_add_function_table_calls || dr->rtl_install_function_table_cb_calls) n++;
    if (dr->second_chance_seen) n++;
    return n;
}

static bool dynamic_session_complete(const DynamicReport* dr) {
    return dr &&
           dr->ran &&
           dr->ok &&
           !dr->timed_out &&
           dr->target_exited &&
           dr->instrumentation_complete;
}

static bool has_static_dynamic_correlation(const HeuristicReport* hr, const DynamicReport* dr) {
    bool suspicious_static_handler_context = false;
    if (!hr || !dynamic_session_complete(dr)) return false;
    suspicious_static_handler_context =
        (hr->handler_nonexec_section > 0) ||
        (hr->handler_writable_section > 0) ||
        ((hr->evidence_families_mask & HEF_HANDLER_DOMINANCE) != 0u);
    if (suspicious_static_handler_context && (dr->unwind_handler_hits || dr->veh_hits || dr->vch_hits || dr->uef_hits)) return true;
    if ((hr->unwind_exec_section || hr->unwind_unusual_section || hr->unwind_writable_section ||
         hr->handler_nonexec_section || hr->handler_writable_section) &&
        (dr->rtl_add_function_table_calls || dr->rtl_install_function_table_cb_calls)) return true;
    return false;
}


static const char* runtime_evidence_level(const DynamicReport* dr) {
    if (!dr || !dr->ran) return "none";
    unsigned strong = 0, medium = 0, weak = 0;
    if (dr->unwind_handler_hits || dr->veh_hits || dr->vch_hits || dr->uef_hits) strong++;
    if (dr->rtl_add_function_table_calls || dr->rtl_install_function_table_cb_calls) medium++;
    if (dr->second_chance_seen) medium++;
    if (dr->veh_registrations || dr->vch_registrations || dr->uef_set_calls || dr->first_chance_seen) weak++;
    const char* level = "none";
    if (strong >= 1 && medium >= 1) level = "strong";
    else if (strong >= 1 || medium >= 2) level = "medium";
    else if (medium >= 1 || weak >= 1) level = "weak";
    if (!dynamic_session_complete(dr) && strcmp(level, "none") != 0) return "weak";
    return level;
}

static const char* case_strength(const HeuristicReport* hr, const DynamicReport* dr, bool correlated) {
    const char* static_lvl = (hr && hr->evidence_level[0]) ? hr->evidence_level : "none";
    const char* runtime_lvl = runtime_evidence_level(dr);
    bool static_strong = strcmp(static_lvl, "strong") == 0;
    bool static_medium = strcmp(static_lvl, "medium") == 0;
    bool static_weak = strcmp(static_lvl, "weak") == 0;
    bool runtime_strong = strcmp(runtime_lvl, "strong") == 0;
    bool runtime_medium = strcmp(runtime_lvl, "medium") == 0;
    bool runtime_weak = strcmp(runtime_lvl, "weak") == 0;

    if (correlated && (static_strong || runtime_strong)) return "strong_correlated_case";
    if (correlated && (static_medium || runtime_medium)) return "medium_correlated_case";
    if (static_strong || runtime_strong) return "strong_unconfirmed_case";
    if (static_medium || runtime_medium) return "medium_case";
    if (static_weak || runtime_weak) return "weak_case";
    return "no_case";
}

typedef struct AssessmentSummary {
    bool correlated;
    unsigned dynamic_signals;
    double final_confidence;
    const char* final_verdict;
    const char* static_evidence_level;
    const char* runtime_evidence_level;
    const char* strength;
} AssessmentSummary;

static AssessmentSummary assessment_summary(const HeuristicReport* hr,
                                            const DynamicReport* dr) {
    AssessmentSummary summary;
    summary.correlated = has_static_dynamic_correlation(hr, dr);
    summary.dynamic_signals = dynamic_signal_count(dr);
    summary.final_confidence = hr ? hr->confidence : 0.10;
    summary.final_verdict = "no_strong_correlated_evidence";
    summary.static_evidence_level = hr ? hr->evidence_level : "none";
    summary.runtime_evidence_level = runtime_evidence_level(dr);
    summary.strength = case_strength(hr, dr, summary.correlated);

    if (dynamic_session_complete(dr) && summary.dynamic_signals) {
        summary.final_confidence += 0.10;
    }
    if (summary.correlated) summary.final_confidence += 0.10;
    if (summary.final_confidence > 0.98) summary.final_confidence = 0.98;

    if (hr) {
        if (hr->score >= 70) {
            summary.final_verdict = summary.correlated
                ? "high_suspicion_correlated"
                : "high_suspicion_static";
        } else if (hr->score >= 40) {
            summary.final_verdict = summary.correlated
                ? "moderate_suspicion_correlated"
                : "moderate_suspicion_static";
        } else if (hr->score >= 15) {
            summary.final_verdict = summary.correlated
                ? "low_suspicion_correlated"
                : "low_suspicion_static";
        } else if (dynamic_session_complete(dr) && summary.dynamic_signals) {
            summary.final_verdict = "runtime_signals_only";
        }
    } else if (dynamic_session_complete(dr) && summary.dynamic_signals) {
        summary.final_verdict = "runtime_signals_only";
    }
    return summary;
}

static bool heuristics_has_finding_code(const HeuristicReport* hr, const char* code) {
    if (!hr || !code) return false;
    for (size_t i = 0; i < hr->finding_count; i++) {
        if (strcmp(hr->findings[i].code, code) == 0) return true;
    }
    return false;
}

static bool heuristics_has_family(const HeuristicReport* hr, const char* family) {
    if (!hr || !family) return false;
    for (size_t i = 0; i < hr->finding_count; i++) {
        if (strcmp(hr->findings[i].family, family) == 0) return true;
    }
    return false;
}

typedef struct ManualValidationSteps {
    const char* items[16];
    size_t count;
} ManualValidationSteps;

static ManualValidationSteps collect_manual_validation_steps(const HeuristicReport* hr,
                                                              const DynamicReport* dr) {
    ManualValidationSteps steps;
    memset(&steps, 0, sizeof(steps));
#define ADD_STEP(txt) do { \
    if (steps.count < sizeof(steps.items) / sizeof(steps.items[0])) { \
        steps.items[steps.count++] = (txt); \
    } \
} while (0)
    if (hr) {
        if (hr->rf_invalid_ranges || hr->rf_oob || hr->rf_unwind_oob || hr->rf_overlaps) {
            ADD_STEP("Верификация целостности .pdata: записи RUNTIME_FUNCTION сопоставляются по BeginAddress; Begin/End/Unwind RVA проверяются на принадлежность допустимому диапазону SizeOfImage.");
        }
        if (hr->unwind_parse_fail || hr->unwind_anomalies || heuristics_has_family(hr, "unwind_integrity")) {
            ADD_STEP("Побайтовая верификация UNWIND_INFO: сопоставляются Version, Flags, CountOfCodes, tail layout и decoded prolog actions с фактическим прологом функции в дизассемблере.");
        }
        if (hr->unwind_unusual_section || hr->unwind_exec_section || hr->unwind_writable_section || heuristics_has_family(hr, "metadata_placement")) {
            ADD_STEP("Анализ секции размещения unwind metadata: фиксируются RVA, raw offset и permissions; placement сопоставляется с benign compiler layout и признаками redirected/manual layout.");
        }
        if (hr->handler_nonexec_section) {
            ADD_STEP("Дизассемблерная верификация handler target: подтверждается execute permission; landing bytes классифицируются как handler, thunk либо non-code blob.");
        }
        if (hr->unwind_writable_section || hr->handler_writable_section) {
            ADD_STEP("Оценка writable unwind metadata или writable handler targets: проверяется наличие JIT/runtime-обоснования; при его отсутствии placement коррелируется с runtime memory protections.");
        }
        if (heuristics_has_finding_code(hr, "handler_dominance") || heuristics_has_family(hr, "handler_dominance")) {
            ADD_STEP("Исследование dominant handler target: несколько referencing functions сопоставляются между собой для разграничения normal runtime helper и central dispatcher.");
        }
        if (hr->mitigation_count > 0) {
            ADD_STEP("Перед итоговой интерпретацией учитываются weakening rules: для текущего evidence set должны быть исключены доброкачественные объяснения.");
        }
    }
    if (dr) {
        if (dr->rtl_add_function_table_calls || dr->rtl_install_function_table_cb_calls) {
            ADD_STEP("Фиксация аргументов RtlAddFunctionTable / RtlInstallFunctionTableCallback: runtime table contents сопоставляются с module/section mapping.");
        }
        if (dr->veh_registrations || dr->vch_registrations || dr->uef_set_calls) {
            ADD_STEP("Для каждой регистрации VEH/VCH/UEF фиксируется target address; трассировка от registered routine используется для разграничения benign runtime hook и exception interceptor.");
        }
        if (dr->veh_hits || dr->vch_hits || dr->uef_hits) {
            ADD_STEP("Трассировка от handler hit используется для восстановления module/section transitions непосредственно после exception dispatch point.");
        }
        if (dr->unwind_handler_hits) {
            ADD_STEP("Достигнутый unwind handler сопоставляется с known language/runtime handlers и с dispatcher/interceptor path, на который могут ссылаться protected functions.");
        }
    }
    if ((!dr || dynamic_signal_count(dr) == 0) && hr && (hr->score > 0 || hr->finding_count > 0)) {
        ADD_STEP("Повторный запуск исследуемого образца с --dynamic на representative exception path используется для получения runtime corroboration.");
    }
#undef ADD_STEP
    return steps;
}

static void json_manual_validation_steps(StrBuf* sb, const HeuristicReport* hr, const DynamicReport* dr) {
    ManualValidationSteps steps = collect_manual_validation_steps(hr, dr);
    sb_append(sb, "[");
    for (size_t i = 0; i < steps.count; i++) {
        if (i) sb_append(sb, ",");
        json_string(sb, steps.items[i]);
    }
    sb_append(sb, "]");
}

void report_print_heuristics(const HeuristicReport* hr) {
    if (!hr) return;
    printf("\n[Heuristic Analysis] Suspicion score: %d / 100\n", hr->score);
    printf("  base_weight_sum=%d  score_cap_applied=%s\n",
           hr->score_weight_sum, hr->score_weight_sum > 100 ? "yes" : "no");
    printf("  suspicion=%.3f  confidence=%.3f  verdict=%s  manual_review=%s\n",
           hr->suspicion, hr->confidence,
           hr->verdict[0] ? hr->verdict : "-",
           hr->requires_manual_review ? "yes" : "no");
    printf("  total=%zu  invalid_ranges=%zu  oob=%zu  unwind_oob=%zu\n",
           hr->total, hr->rf_invalid_ranges, hr->rf_oob, hr->rf_unwind_oob);
    printf("  unsorted=%zu  overlaps=%zu  duplicate_begins=%zu  unwind_parse_fail=%zu  unwind_anom=%zu\n",
           hr->rf_unsorted, hr->rf_overlaps, hr->rf_duplicate_begins,
           hr->unwind_parse_fail, hr->unwind_anomalies);
    printf("  strict_abi_warnings=%zu\n", hr->unwind_abi_warnings);
    printf("  unwind_unusual_section=%zu  unwind_exec_section=%zu  unwind_writable_section=%zu\n",
           hr->unwind_unusual_section, hr->unwind_exec_section, hr->unwind_writable_section);
    printf("  handler_nonexec_section=%zu  handler_writable_section=%zu\n",
           hr->handler_nonexec_section, hr->handler_writable_section);
    printf("  unwind_reuse_ratio=%.3f  unwind_unique_ratio=%.3f\n",
           hr->unwind_reuse_ratio, hr->unwind_unique_ratio);
    if (hr->handler_count) {
        printf("  handler_count=%zu  handler_reuse_ratio=%.3f\n",
               hr->handler_count, hr->handler_reuse_ratio);
    }
    printf("  evidence_families=%zu  findings=%zu\n",
           heuristics_evidence_family_count(hr->evidence_families_mask), hr->finding_count);
    printf("Findings:\n%s\n", hr->details.s ? hr->details.s : "");
}

static bool report_metadata_valid(const ReportMetadata* metadata) {
    if (!metadata ||
        !metadata->tool_version || metadata->tool_version[0] == '\0' ||
        !metadata->report_schema_version ||
        strcmp(metadata->report_schema_version, EHUA_REPORT_SCHEMA_VERSION) != 0 ||
        !metadata->generated_at_utc || metadata->generated_at_utc[0] == '\0' ||
        !metadata->input_sha256 || strlen(metadata->input_sha256) != 64u ||
        !metadata->command_line ||
        !metadata->build_compiler || metadata->build_compiler[0] == '\0' ||
        !metadata->build_platform || metadata->build_platform[0] == '\0' ||
        !metadata->build_mode ||
        (strcmp(metadata->build_mode, "debug") != 0 &&
         strcmp(metadata->build_mode, "release") != 0) ||
        metadata->max_chain_depth < 1u ||
        metadata->max_chain_depth > 16u) {
        return false;
    }
    for (size_t i = 0; i < 64u; i++) {
        const char c = metadata->input_sha256[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    if (strlen(metadata->generated_at_utc) != 20u ||
        metadata->generated_at_utc[4] != '-' ||
        metadata->generated_at_utc[7] != '-' ||
        metadata->generated_at_utc[10] != 'T' ||
        metadata->generated_at_utc[13] != ':' ||
        metadata->generated_at_utc[16] != ':' ||
        metadata->generated_at_utc[19] != 'Z') {
        return false;
    }
    for (size_t i = 0; i < 19u; i++) {
        if (i == 4u || i == 7u || i == 10u || i == 13u || i == 16u) continue;
        if (metadata->generated_at_utc[i] < '0' ||
            metadata->generated_at_utc[i] > '9') {
            return false;
        }
    }
    return true;
}

static bool report_model_valid(const PeImage* img,
                               const HeuristicReport* hr,
                               const DynamicReport* dr) {
    if (!img || (img->num_sections && !img->sections)) return false;
    if (hr && (hr->finding_count > HEURISTICS_MAX_FINDINGS ||
               hr->mitigation_count > HEURISTICS_MAX_MITIGATIONS)) {
        return false;
    }
    if (hr && (hr->score_weight_sum < 0 ||
               hr->score != (hr->score_weight_sum > 100 ? 100 : hr->score_weight_sum))) {
        return false;
    }
    if (dr && (dr->event_count > DYNAMIC_MAX_EVENTS ||
               dr->trace_count > sizeof(dr->trace) / sizeof(dr->trace[0]) ||
               dr->trace_steps > sizeof(dr->trace) / sizeof(dr->trace[0]))) {
        return false;
    }
    if (dr && dr->instrumentation_complete &&
        (dr->module_refresh_failures ||
         dr->module_list_truncations ||
         dr->breakpoint_set_failures ||
         dr->breakpoint_capacity_drops ||
         dr->pending_rearm_failures ||
         dr->breakpoint_rearm_failures ||
         dr->dropped_events)) {
        return false;
    }
    return true;
}

bool report_write_input_validation_json(const char* path,
                                        const char* input_path,
                                        const PeInputValidation* validation,
                                        const char* parser_diagnostic,
                                        const ReportMetadata* metadata,
                                        StrBuf* err) {
    if (!path || !input_path || !validation ||
        !report_metadata_valid(metadata) || !err) {
        if (err) sb_append(err, "Invalid arguments for input-validation JSON report.\n");
        return false;
    }

    StrBuf sb;
    if (!sb_init(&sb, 8192)) {
        sb_append(err, "OOM.\n");
        return false;
    }
    sb_append(&sb, "{");
    json_string_field(&sb, "report_type", "pe_input_validation", true);
    json_string_field(&sb, "input", input_path, true);
    json_key(&sb, "report_metadata");
    sb_append(&sb, "{");
    json_string_field(&sb, "schema_version", metadata->report_schema_version, true);
    json_string_field(&sb, "tool_version", metadata->tool_version, true);
    json_string_field(&sb, "generated_at_utc", metadata->generated_at_utc, true);
    json_string_field(&sb, "input_sha256", metadata->input_sha256, true);
    json_key(&sb, "input_size"); sb_appendf(&sb, "%llu,", (unsigned long long)metadata->input_size);
    json_string_field(&sb, "command_line", metadata->command_line, true);
    json_string_field(&sb, "build_compiler", metadata->build_compiler, true);
    json_string_field(&sb, "build_platform", metadata->build_platform, true);
    json_string_field(&sb, "build_mode", metadata->build_mode, true);
    json_bool_field(&sb, "strict_abi", metadata->strict_abi, true);
    json_bool_field(&sb, "follow_chain", metadata->follow_chain, true);
    json_key(&sb, "max_chain_depth");
    sb_appendf(&sb, "%u", (unsigned)metadata->max_chain_depth);
    sb_append(&sb, "},");

    json_key(&sb, "input_validation");
    sb_append(&sb, "{");
    json_bool_field(&sb, "accepted", validation->accepted, true);
    json_key(&sb, "passed_count"); sb_appendf(&sb, "%zu,", validation->passed_count);
    json_key(&sb, "failed_count"); sb_appendf(&sb, "%zu,", validation->failed_count);
    json_key(&sb, "not_evaluated_count"); sb_appendf(&sb, "%zu,", validation->not_evaluated_count);
    json_string_field(&sb, "parser_diagnostic", parser_diagnostic ? parser_diagnostic : "", true);
    json_key(&sb, "checks");
    sb_append(&sb, "[");
    for (size_t i = 0; i < PE_INPUT_CHECK_COUNT; i++) {
        const PeInputCheck* check = &validation->checks[i];
        if (i) sb_append(&sb, ",");
        sb_append(&sb, "{");
        json_string_field(&sb, "code", pe_input_check_code((PeInputCheckCode)i), true);
        json_string_field(&sb, "title_ru", pe_input_check_title_ru((PeInputCheckCode)i), true);
        json_string_field(&sb, "status", pe_input_check_status_name(check->status), true);
        json_key(&sb, "file_offset");
        if (check->has_file_range) sb_appendf(&sb, "%zu,", check->file_offset);
        else sb_append(&sb, "null,");
        json_key(&sb, "byte_length");
        if (check->has_file_range) sb_appendf(&sb, "%zu,", check->byte_length);
        else sb_append(&sb, "null,");
        json_key(&sb, "observed_value");
        if (check->has_observed_value) {
            sb_appendf(&sb, "\"0x%llx\",", (unsigned long long)check->observed_value);
        } else {
            sb_append(&sb, "null,");
        }
        json_string_field(&sb, "requirement_ru", pe_input_check_requirement_ru((PeInputCheckCode)i), true);
        json_string_field(&sb, "detail", check->detail, false);
        sb_append(&sb, "}");
    }
    sb_append(&sb, "]}}");

    bool ok = sb_ok(&sb) && file_write_atomic(path, sb.s, sb.len);
    if (!ok) {
        sb_appendf(err, "%s: %s\n",
                   sb_ok(&sb) ? "Failed to write input-validation JSON" : "OOM while building input-validation JSON",
                   path);
    }
    sb_free(&sb);
    return ok;
}

bool report_write_json_ex(const char* path,
                       const char* input_path,
                       const PeImage* img,
                       const RuntimeFunction* rf,
                       const UnwindSummary* us,
                       const bool* us_ok,
                       size_t n,
                       const HeuristicReport* hr,
                       const DynamicReport* dr,
                       const ReportMetadata* metadata,
                       StrBuf* err) {
    if (!path || !input_path || (!rf && n) || (!us && n) || (!us_ok && n) ||
        !report_model_valid(img, hr, dr) || !report_metadata_valid(metadata)) {
        sb_append(err, "Invalid arguments or metadata for JSON report.\n");
        return false;
    }

    StrBuf sb;
    if (!sb_init(&sb, 8192)) { sb_append(err, "OOM.\n"); return false; }
    StrBuf comment;
    if (!sb_init(&comment, 512)) { sb_free(&sb); sb_append(err, "OOM.\n"); return false; }
    StrBuf anom;
    if (!sb_init(&anom, 128)) { sb_free(&comment); sb_free(&sb); sb_append(err, "OOM.\n"); return false; }

    sb_append(&sb, "{");
    json_string_field(&sb, "input", input_path, true);
    json_key(&sb, "report_metadata");
    sb_append(&sb, "{");
    json_string_field(&sb, "schema_version", metadata->report_schema_version, true);
    json_string_field(&sb, "tool_version", metadata->tool_version, true);
    json_string_field(&sb, "generated_at_utc", metadata->generated_at_utc, true);
    json_string_field(&sb, "input_sha256", metadata->input_sha256, true);
    json_key(&sb, "input_size"); sb_appendf(&sb, "%llu,", (unsigned long long)metadata->input_size);
    json_string_field(&sb, "command_line", metadata->command_line, true);
    json_string_field(&sb, "build_compiler", metadata->build_compiler, true);
    json_string_field(&sb, "build_platform", metadata->build_platform, true);
    json_string_field(&sb, "build_mode", metadata->build_mode, true);
    json_bool_field(&sb, "strict_abi", metadata->strict_abi, true);
    json_bool_field(&sb, "follow_chain", metadata->follow_chain, true);
    json_key(&sb, "max_chain_depth");
    sb_appendf(&sb, "%u", (unsigned)metadata->max_chain_depth);
    sb_append(&sb, "},");
    json_key(&sb, "image_base"); sb_appendf(&sb, "\"0x%llx\",", (unsigned long long)img->image_base);
    json_key(&sb, "size_of_image"); sb_appendf(&sb, "\"0x%x\",", (unsigned)img->size_of_image);
    json_key(&sb, "size_of_headers"); sb_appendf(&sb, "\"0x%x\",", (unsigned)img->size_of_headers);
    json_key(&sb, "section_alignment"); sb_appendf(&sb, "\"0x%x\",", (unsigned)img->section_alignment);
    json_key(&sb, "file_alignment"); sb_appendf(&sb, "\"0x%x\",", (unsigned)img->file_alignment);
    json_key(&sb, "exception_directory");
    sb_appendf(&sb, "{\"rva\":\"0x%08x\",\"size\":\"0x%x\"}",
               (unsigned)img->exception_rva, (unsigned)img->exception_size);
    sb_append(&sb, ",");
    json_key(&sb, "pe_validation");
    sb_append(&sb, "{");
    json_key(&sb, "section_raw_oob"); sb_appendf(&sb, "%zu,", img->section_raw_oob);
    json_key(&sb, "section_virtual_oob"); sb_appendf(&sb, "%zu,", img->section_virtual_oob);
    json_key(&sb, "section_raw_overlaps"); sb_appendf(&sb, "%zu,", img->section_raw_overlaps);
    json_key(&sb, "section_virtual_overlaps"); sb_appendf(&sb, "%zu,", img->section_virtual_overlaps);
    json_key(&sb, "section_misaligned"); sb_appendf(&sb, "%zu,", img->section_misaligned);
    json_bool_field(&sb, "exception_directory_oob", img->exception_directory_oob, false);
    sb_append(&sb, "},");
    json_key(&sb, "sections");
    sb_append(&sb, "[");
    for (size_t i = 0; i < img->num_sections; i++) {
        const PeSection* section = &img->sections[i];
        if (i) sb_append(&sb, ",");
        sb_append(&sb, "{");
        json_string_field(&sb, "name", section->name, true);
        json_key(&sb, "virtual_address"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)section->virtual_address);
        json_key(&sb, "virtual_size"); sb_appendf(&sb, "\"0x%x\",", (unsigned)section->virtual_size);
        json_key(&sb, "raw_offset"); sb_appendf(&sb, "\"0x%x\",", (unsigned)section->raw_ptr);
        json_key(&sb, "raw_size"); sb_appendf(&sb, "\"0x%x\",", (unsigned)section->raw_size);
        json_key(&sb, "characteristics"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)section->characteristics);
        json_bool_field(&sb, "readable", (section->characteristics & IMAGE_SCN_MEM_READ) != 0, true);
        json_bool_field(&sb, "writable", (section->characteristics & IMAGE_SCN_MEM_WRITE) != 0, true);
        json_bool_field(&sb, "executable", (section->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0, false);
        sb_append(&sb, "}");
    }
    sb_append(&sb, "],");

    if (hr) {
        json_key(&sb, "heuristic_analysis");
        sb_append(&sb, "{");
        json_key(&sb, "score"); sb_appendf(&sb, "%d,", hr->score);
        json_key(&sb, "score_weight_sum"); sb_appendf(&sb, "%d,", hr->score_weight_sum);
        json_key(&sb, "suspicion"); sb_appendf(&sb, "%.6f,", hr->suspicion);
        json_key(&sb, "confidence"); sb_appendf(&sb, "%.6f,", hr->confidence);
        json_bool_field(&sb, "requires_manual_review", hr->requires_manual_review, true);
        json_string_field(&sb, "verdict", hr->verdict, true);
        json_string_field(&sb, "evidence_level", hr->evidence_level, true);
        json_key(&sb, "weak_finding_count"); sb_appendf(&sb, "%zu,", hr->weak_finding_count);
        json_key(&sb, "medium_finding_count"); sb_appendf(&sb, "%zu,", hr->medium_finding_count);
        json_key(&sb, "strong_finding_count"); sb_appendf(&sb, "%zu,", hr->strong_finding_count);
        json_key(&sb, "total"); sb_appendf(&sb, "%zu,", hr->total);
        json_key(&sb, "pe_section_raw_oob"); sb_appendf(&sb, "%zu,", hr->pe_section_raw_oob);
        json_key(&sb, "pe_section_virtual_oob"); sb_appendf(&sb, "%zu,", hr->pe_section_virtual_oob);
        json_key(&sb, "pe_section_raw_overlaps"); sb_appendf(&sb, "%zu,", hr->pe_section_raw_overlaps);
        json_key(&sb, "pe_section_virtual_overlaps"); sb_appendf(&sb, "%zu,", hr->pe_section_virtual_overlaps);
        json_key(&sb, "pe_section_misaligned"); sb_appendf(&sb, "%zu,", hr->pe_section_misaligned);
        json_bool_field(&sb, "pe_exception_directory_oob", hr->pe_exception_directory_oob, true);
        json_key(&sb, "rf_invalid_ranges"); sb_appendf(&sb, "%zu,", hr->rf_invalid_ranges);
        json_key(&sb, "rf_oob"); sb_appendf(&sb, "%zu,", hr->rf_oob);
        json_key(&sb, "rf_unwind_oob"); sb_appendf(&sb, "%zu,", hr->rf_unwind_oob);
        json_key(&sb, "rf_unsorted"); sb_appendf(&sb, "%zu,", hr->rf_unsorted);
        json_key(&sb, "rf_overlaps"); sb_appendf(&sb, "%zu,", hr->rf_overlaps);
        json_key(&sb, "rf_duplicate_begins"); sb_appendf(&sb, "%zu,", hr->rf_duplicate_begins);
        json_key(&sb, "unwind_parse_fail"); sb_appendf(&sb, "%zu,", hr->unwind_parse_fail);
        json_key(&sb, "unwind_anomalies"); sb_appendf(&sb, "%zu,", hr->unwind_anomalies);
        json_key(&sb, "unwind_abi_warnings"); sb_appendf(&sb, "%zu,", hr->unwind_abi_warnings);
        json_key(&sb, "unwind_unusual_section"); sb_appendf(&sb, "%zu,", hr->unwind_unusual_section);
        json_key(&sb, "unwind_exec_section"); sb_appendf(&sb, "%zu,", hr->unwind_exec_section);
        json_key(&sb, "unwind_writable_section"); sb_appendf(&sb, "%zu,", hr->unwind_writable_section);
        json_key(&sb, "handler_nonexec_section"); sb_appendf(&sb, "%zu,", hr->handler_nonexec_section);
        json_key(&sb, "handler_writable_section"); sb_appendf(&sb, "%zu,", hr->handler_writable_section);
        json_key(&sb, "unwind_reuse_ratio"); sb_appendf(&sb, "%.6f,", hr->unwind_reuse_ratio);
        json_key(&sb, "unwind_unique_ratio"); sb_appendf(&sb, "%.6f,", hr->unwind_unique_ratio);
        json_key(&sb, "handler_count"); sb_appendf(&sb, "%zu,", hr->handler_count);
        json_key(&sb, "handler_reuse_ratio"); sb_appendf(&sb, "%.6f,", hr->handler_reuse_ratio);
        json_key(&sb, "evidence_family_count"); sb_appendf(&sb, "%zu,", heuristics_evidence_family_count(hr->evidence_families_mask));
        json_key(&sb, "evidence_families"); json_heuristic_families(&sb, hr->evidence_families_mask); sb_append(&sb, ",");
        json_key(&sb, "findings");
        sb_append(&sb, "[");
        for (size_t i = 0; i < hr->finding_count; i++) {
            const HeuristicFinding* finding = &hr->findings[i];
            const PeSection* location_section = NULL;
            uint32_t file_offset = 0;
            bool has_file_offset = false;
            char permissions[4] = "---";
            char observed[1024];
            size_t related_function = finding_related_function_index(finding, rf, us, us_ok, n);
            if (finding->has_location) {
                location_section = pe_find_section_for_rva(img, finding->representative_rva);
                has_file_offset = pe_rva_to_fileoff(img, finding->representative_rva, &file_offset);
                if (location_section) {
                    section_permissions(location_section->characteristics, permissions);
                }
            }
            finding_observed_text(finding, img, rf, us, us_ok, n, observed, sizeof(observed));
            if (i) sb_append(&sb, ",");
            sb_append(&sb, "{");
            json_string_field(&sb, "code", finding->code, true);
            json_string_field(&sb, "family", finding->family, true);
            json_string_field(&sb, "severity", finding->severity, true);
            json_string_field(&sb, "message", finding->message, true);
            json_string_field(&sb, "title_ru", finding_title_ru(finding->code), true);
            json_string_field(&sb, "meaning_ru", finding_meaning_ru(finding->code), true);
            json_string_field(&sb, "why_it_matters_ru", finding_why_it_matters_ru(finding->code), true);
            json_string_field(&sb, "what_to_check_next_ru", finding_next_step_ru(finding->code), true);
            json_key(&sb, "affected_count"); sb_appendf(&sb, "%zu,", finding->affected_count);
            json_key(&sb, "representative_rva");
            if (finding->has_location) {
                sb_appendf(&sb, "\"0x%08x\",", (unsigned)finding->representative_rva);
            } else {
                sb_append(&sb, "null,");
            }
            json_string_field(
                &sb,
                "representative_section",
                finding->has_location
                    ? section_name_or_dash(img, finding->representative_rva)
                    : "-",
                true);
            json_key(&sb, "representative_file_offset");
            if (has_file_offset) {
                sb_appendf(&sb, "\"0x%08x\",", (unsigned)file_offset);
            } else {
                sb_append(&sb, "null,");
            }
            json_key(&sb, "representative_section_characteristics");
            if (location_section) {
                sb_appendf(&sb, "\"0x%08x\",", (unsigned)location_section->characteristics);
            } else {
                sb_append(&sb, "null,");
            }
            json_string_field(&sb, "representative_section_permissions", permissions, true);
            json_key(&sb, "related_function_index");
            if (related_function != (size_t)-1) sb_appendf(&sb, "%zu,", related_function);
            else sb_append(&sb, "null,");
            json_key(&sb, "related_function_begin_rva");
            if (related_function != (size_t)-1) sb_appendf(&sb, "\"0x%08x\",", (unsigned)rf[related_function].begin_rva);
            else sb_append(&sb, "null,");
            json_key(&sb, "related_function_end_rva");
            if (related_function != (size_t)-1) sb_appendf(&sb, "\"0x%08x\",", (unsigned)rf[related_function].end_rva);
            else sb_append(&sb, "null,");
            json_key(&sb, "related_function_unwind_rva");
            if (related_function != (size_t)-1) sb_appendf(&sb, "\"0x%08x\",", (unsigned)rf[related_function].unwind_rva);
            else sb_append(&sb, "null,");
            json_string_field(&sb, "rule", finding_rule_text(finding->code), true);
            json_string_field(&sb, "observed", observed, true);
            json_string_field(&sb, "expected", finding_expected_text(finding->code), true);
            json_string_field(&sb, "impact", finding_impact_text(finding->code), true);
            json_key(&sb, "evidence_chain");
            json_finding_evidence_chain(&sb, finding, img, rf, us, us_ok, n);
            sb_append(&sb, ",");
            json_finding_evidence_records(&sb, finding, img, rf, us, us_ok, n);
            sb_append(&sb, "}");
        }
        sb_append(&sb, "],");
        json_key(&sb, "weakening_rules_applied");
        sb_append(&sb, "[");
        for (size_t i = 0; i < hr->mitigation_count; i++) {
            if (i) sb_append(&sb, ",");
            sb_append(&sb, "{");
            json_string_field(&sb, "code", hr->mitigations[i].code, true);
            json_string_field(&sb, "message", hr->mitigations[i].message, false);
            sb_append(&sb, "}");
        }
        sb_append(&sb, "],");
        json_key(&sb, "weakening_rule_count"); sb_appendf(&sb, "%zu,", hr->mitigation_count);
        json_string_field(&sb, "details", hr->details.s ? hr->details.s : "", false);
        sb_append(&sb, "},");
    }

    if (dr) {
        json_key(&sb, "dynamic_validation");
        sb_append(&sb, "{");
        json_bool_field(&sb, "enabled", dr->enabled, true);
        json_bool_field(&sb, "ran", dr->ran, true);
        json_bool_field(&sb, "ok", dr->ok, true);
        json_bool_field(&sb, "timed_out", dr->timed_out, true);
        json_bool_field(&sb, "target_exited", dr->target_exited, true);
        json_key(&sb, "target_exit_code"); sb_appendf(&sb, "%u,", (unsigned)dr->target_exit_code);
        json_key(&sb, "timeout_ms"); sb_appendf(&sb, "%u,", (unsigned)dr->timeout_ms);
        json_key(&sb, "trace_steps"); sb_appendf(&sb, "%u,", (unsigned)dr->trace_steps);
        json_bool_field(&sb, "instrumentation_complete", dr->instrumentation_complete, true);
        json_key(&sb, "modules_observed_peak"); sb_appendf(&sb, "%u,", (unsigned)dr->modules_observed_peak);
        json_key(&sb, "module_refresh_failures"); sb_appendf(&sb, "%u,", (unsigned)dr->module_refresh_failures);
        json_key(&sb, "module_list_truncations"); sb_appendf(&sb, "%u,", (unsigned)dr->module_list_truncations);
        json_key(&sb, "unwind_handlers_discovered"); sb_appendf(&sb, "%u,", (unsigned)dr->unwind_handlers_discovered);
        json_key(&sb, "breakpoint_set_attempts"); sb_appendf(&sb, "%u,", (unsigned)dr->breakpoint_set_attempts);
        json_key(&sb, "breakpoint_set_failures"); sb_appendf(&sb, "%u,", (unsigned)dr->breakpoint_set_failures);
        json_key(&sb, "breakpoint_capacity_drops"); sb_appendf(&sb, "%u,", (unsigned)dr->breakpoint_capacity_drops);
        json_key(&sb, "pending_rearm_failures"); sb_appendf(&sb, "%u,", (unsigned)dr->pending_rearm_failures);
        json_key(&sb, "breakpoint_rearm_failures"); sb_appendf(&sb, "%u,", (unsigned)dr->breakpoint_rearm_failures);
        json_key(&sb, "exceptions_seen"); sb_appendf(&sb, "%u,", (unsigned)dr->exceptions_seen);
        json_key(&sb, "first_chance_seen"); sb_appendf(&sb, "%u,", (unsigned)dr->first_chance_seen);
        json_key(&sb, "second_chance_seen"); sb_appendf(&sb, "%u,", (unsigned)dr->second_chance_seen);
        json_key(&sb, "unwind_handler_bp_set"); sb_appendf(&sb, "%u,", (unsigned)dr->unwind_handler_bp_set);
        json_key(&sb, "unwind_handler_hits"); sb_appendf(&sb, "%u,", (unsigned)dr->unwind_handler_hits);
        json_key(&sb, "veh_registrations"); sb_appendf(&sb, "%u,", (unsigned)dr->veh_registrations);
        json_key(&sb, "veh_hits"); sb_appendf(&sb, "%u,", (unsigned)dr->veh_hits);
        json_key(&sb, "vch_registrations"); sb_appendf(&sb, "%u,", (unsigned)dr->vch_registrations);
        json_key(&sb, "vch_hits"); sb_appendf(&sb, "%u,", (unsigned)dr->vch_hits);
        json_key(&sb, "uef_set_calls"); sb_appendf(&sb, "%u,", (unsigned)dr->uef_set_calls);
        json_key(&sb, "uef_hits"); sb_appendf(&sb, "%u,", (unsigned)dr->uef_hits);
        json_key(&sb, "rtl_add_function_table_calls"); sb_appendf(&sb, "%u,", (unsigned)dr->rtl_add_function_table_calls);
        json_key(&sb, "rtl_install_function_table_cb_calls"); sb_appendf(&sb, "%u,", (unsigned)dr->rtl_install_function_table_cb_calls);
        json_key(&sb, "dynamic_signal_count"); sb_appendf(&sb, "%u,", dynamic_signal_count(dr));
        json_key(&sb, "dropped_events"); sb_appendf(&sb, "%u,", (unsigned)dr->dropped_events);
        json_string_field(&sb, "details", dr->details.s ? dr->details.s : "", true);
        json_key(&sb, "events");
        sb_append(&sb, "[");
        for (uint32_t i = 0; i < dr->event_count; i++) {
            const DynamicEvent* event = &dr->events[i];
            if (i) sb_append(&sb, ",");
            sb_append(&sb, "{");
            json_string_field(&sb, "type", event->type, true);
            json_string_field(&sb, "module", event->module, true);
            json_key(&sb, "thread_id"); sb_appendf(&sb, "%u,", (unsigned)event->thread_id);
            json_key(&sb, "exception_code"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)event->exception_code);
            json_bool_field(&sb, "first_chance", event->first_chance, true);
            json_key(&sb, "address"); sb_appendf(&sb, "\"0x%llx\",", (unsigned long long)event->address);
            json_key(&sb, "arg0"); sb_appendf(&sb, "\"0x%llx\",", (unsigned long long)event->arg0);
            json_key(&sb, "arg1"); sb_appendf(&sb, "\"0x%llx\",", (unsigned long long)event->arg1);
            json_key(&sb, "arg2"); sb_appendf(&sb, "\"0x%llx\",", (unsigned long long)event->arg2);
            json_key(&sb, "arg3"); sb_appendf(&sb, "\"0x%llx\"", (unsigned long long)event->arg3);
            sb_append(&sb, "}");
        }
        sb_append(&sb, "],");
        json_key(&sb, "trace");
        sb_append(&sb, "[");
        for (uint32_t i = 0; i < dr->trace_count; i++) {
            if (i) sb_append(&sb, ",");
            sb_appendf(&sb, "\"0x%llx\"", (unsigned long long)dr->trace[i]);
        }
        sb_append(&sb, "]");
        sb_append(&sb, "},");
    }

    if (hr || dr) {
        AssessmentSummary summary = assessment_summary(hr, dr);

        json_key(&sb, "assessment");
        sb_append(&sb, "{");
        json_string_field(&sb, "final_verdict", summary.final_verdict, true);
        json_key(&sb, "final_confidence"); sb_appendf(&sb, "%.6f,", summary.final_confidence);
        json_string_field(&sb, "static_evidence_level", summary.static_evidence_level, true);
        json_string_field(&sb, "runtime_evidence_level", summary.runtime_evidence_level, true);
        json_string_field(&sb, "case_strength", summary.strength, true);
        json_bool_field(&sb, "static_dynamic_correlation", summary.correlated, true);
        json_key(&sb, "dynamic_signal_count"); sb_appendf(&sb, "%u,", summary.dynamic_signals);
        json_key(&sb, "weakening_rule_count"); sb_appendf(&sb, "%zu,", hr ? hr->mitigation_count : 0u);
        json_key(&sb, "manual_validation_steps"); json_manual_validation_steps(&sb, hr, dr);
        sb_append(&sb, "},");
    }

    json_key(&sb, "functions");
    sb_append(&sb, "[");
    for (size_t i = 0; i < n; i++) {
        if (i) sb_append(&sb, ",");
        if (us_ok[i]) build_unwind_comment(&us[i], &comment);
        else {
            comment.len = 0;
            if (comment.s) comment.s[0] = 0;
            sb_append(&comment, "UNWIND parse failed");
            if (us[i].parse_error[0]) sb_appendf(&comment, ": %s", us[i].parse_error);
        }
        anom.len = 0; if (anom.s) anom.s[0] = 0; anomalies_to_str(&anom, us[i].anomalies);

        sb_append(&sb, "{");
        json_key(&sb, "index"); sb_appendf(&sb, "%zu,", i);
        {
            uint32_t pdata_entry_rva = 0;
            uint32_t pdata_entry_file_offset = 0;
            bool has_pdata_entry_rva = pdata_entry_rva_for_index(img, i, &pdata_entry_rva);
            bool has_pdata_entry_file_offset = pdata_entry_fileoff_for_index(img, i, &pdata_entry_file_offset);
            json_key(&sb, "pdata_entry_rva");
            json_nullable_hex32(&sb, has_pdata_entry_rva, pdata_entry_rva);
            sb_append(&sb, ",");
            json_key(&sb, "pdata_entry_file_offset");
            json_nullable_hex32(&sb, has_pdata_entry_file_offset, pdata_entry_file_offset);
            sb_append(&sb, ",");
            json_key(&sb, "runtime_function_entry_size"); sb_appendf(&sb, "%u,", REPORT_RUNTIME_FUNCTION_ENTRY_SIZE);
        }
        json_key(&sb, "begin_rva"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)rf[i].begin_rva);
        json_key(&sb, "end_rva"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)rf[i].end_rva);
        json_key(&sb, "size"); sb_appendf(&sb, "%u,", (unsigned)runtime_function_size(&rf[i]));
        json_key(&sb, "begin_section"); json_string(&sb, section_name_or_dash(img, rf[i].begin_rva)); sb_append(&sb, ",");
        json_key(&sb, "unwind_rva"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)rf[i].unwind_rva);
        json_key(&sb, "unwind_section"); json_string(&sb, section_name_or_dash(img, rf[i].unwind_rva)); sb_append(&sb, ",");
        json_bool_field(&sb, "unwind_ok", us_ok[i], true);
        json_string_field(&sb, "unwind_error", us[i].parse_error, true);
        json_key(&sb, "unwind");
        sb_append(&sb, "{");
        json_key(&sb, "version"); sb_appendf(&sb, "%u,", (unsigned)us[i].version);
        json_key(&sb, "flags"); sb_appendf(&sb, "%u,", (unsigned)us[i].flags);
        json_key(&sb, "prolog_size"); sb_appendf(&sb, "%u,", (unsigned)us[i].prolog_size);
        json_key(&sb, "count_codes"); sb_appendf(&sb, "%u,", (unsigned)us[i].count_codes);
        json_key(&sb, "fixed_stack_bytes"); sb_appendf(&sb, "%u,", (unsigned)us[i].fixed_stack_bytes);
        json_key(&sb, "frame_reg"); json_string(&sb, (us[i].frame_reg ? unwind_reg_name(us[i].frame_reg) : "-")); sb_append(&sb, ",");
        json_key(&sb, "frame_off"); sb_appendf(&sb, "%u,", (unsigned)(us[i].frame_off * 16u));
        json_bool_field(&sb, "has_handler", us[i].has_handler, true);
        json_key(&sb, "handler_rva"); sb_appendf(&sb, "\"0x%08x\",", (unsigned)us[i].handler_rva);
        json_key(&sb, "handler_section"); json_string(&sb, us[i].has_handler ? section_name_or_dash(img, us[i].handler_rva) : "-"); sb_append(&sb, ",");
        json_bool_field(&sb, "has_chain", us[i].has_chain, true);
        json_key(&sb, "anomalies"); sb_appendf(&sb, "%u,", (unsigned)us[i].anomalies);
        json_string_field(&sb, "anomalies_text", anom.s ? anom.s : "0", true);
        json_key(&sb, "chain");
        if (us[i].has_chain) {
            sb_appendf(&sb, "{\"begin_rva\":\"0x%08x\",\"end_rva\":\"0x%08x\",\"unwind_rva\":\"0x%08x\"}",
                       (unsigned)us[i].chain.begin_rva,
                       (unsigned)us[i].chain.end_rva,
                       (unsigned)us[i].chain.unwind_rva);
        } else {
            sb_append(&sb, "null");
        }
        sb_append(&sb, ",");
        json_key(&sb, "diagnostic");
        json_unwind_diagnostic(&sb, &us[i]);
        sb_append(&sb, "},");
        json_string_field(&sb, "comment", comment.s ? comment.s : "", false);
        sb_append(&sb, "}");
    }
    sb_append(&sb, "]}");

    bool ok = sb_ok(&sb) && sb_ok(&comment) && sb_ok(&anom);
    if (ok) ok = file_write_atomic(path, sb.s, sb.len);
    if (!ok) {
        sb_appendf(err, "%s: %s\n",
                   sb_ok(&sb) && sb_ok(&comment) && sb_ok(&anom)
                       ? "Failed to write JSON"
                       : "Out of memory while building JSON report",
                   path);
    }

    sb_free(&anom);
    sb_free(&comment);
    sb_free(&sb);
    return ok;
}

static void html_escape(StrBuf* sb, const char* text) {
    if (!text) return;
    size_t length = strlen(text);
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)text[i];
        switch (c) {
            case '&': sb_append(sb, "&amp;"); break;
            case '<': sb_append(sb, "&lt;"); break;
            case '>': sb_append(sb, "&gt;"); break;
            case '"': sb_append(sb, "&quot;"); break;
            case '\'': sb_append(sb, "&#39;"); break;
            default:
                if (c < 0x80) {
                    sb_appendn(sb, &text[i], 1);
                } else {
                    size_t sequence = valid_utf8_sequence_length(
                        (const unsigned char*)&text[i], length - i);
                    if (sequence) {
                        sb_appendn(sb, &text[i], sequence);
                        i += sequence - 1;
                    } else {
                        sb_appendf(sb, "&#x%02x;", (unsigned)c);
                    }
                }
                break;
        }
    }
}

static void html_text_cell(StrBuf* sb, const char* text) {
    sb_append(sb, "<td>");
    html_escape(sb, text ? text : "");
    sb_append(sb, "</td>");
}

static const char* input_check_status_ru(PeInputCheckStatus status) {
    switch (status) {
        case PE_INPUT_CHECK_PASSED: return "пройдена";
        case PE_INPUT_CHECK_FAILED: return "нарушена";
        default: return "не проверена";
    }
}

bool report_write_input_validation_html(const char* path,
                                        const char* input_path,
                                        const PeInputValidation* validation,
                                        const char* parser_diagnostic,
                                        const ReportMetadata* metadata,
                                        StrBuf* err) {
    if (!path || !input_path || !validation ||
        !report_metadata_valid(metadata) || !err) {
        if (err) sb_append(err, "Invalid arguments for input-validation HTML report.\n");
        return false;
    }

    StrBuf sb;
    if (!sb_init(&sb, 16384)) {
        sb_append(err, "OOM.\n");
        return false;
    }
    sb_append(&sb, "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">");
    sb_append(&sb, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    sb_append(&sb, "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none';style-src 'unsafe-inline';base-uri 'none';form-action 'none'\">");
    sb_append(&sb, "<title>Результат входного контроля PE-образа</title><style>");
    sb_append(&sb,
        ":root{--bg:#edf3f6;--panel:#fff;--text:#172532;--muted:#586a78;--line:#ced9df;--accent:#08747c;--ok:#167052;--danger:#b4233a}"
        "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}"
        "main{width:100%;max-width:1500px;margin:auto;padding:30px}h1{margin:0 0 7px;font-size:30px}h2{margin:0 0 13px;font-size:20px}"
        ".muted{color:var(--muted)}.panel{min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:21px;margin-bottom:18px;box-shadow:0 6px 22px rgba(31,52,68,.07)}"
        ".hero{border-top:4px solid var(--accent)}.status{display:inline-block;border:1px solid var(--danger);color:var(--danger);border-radius:999px;padding:4px 11px;font-weight:700}"
        ".cards{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:10px;margin-top:18px}.card{border:1px solid var(--line);border-radius:9px;padding:12px;background:#f5f9fa}.card b{display:block;font-size:22px}"
        ".table-wrap{max-width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{padding:10px 12px;border-right:1px solid var(--line);border-bottom:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#e5f0f3}tr:last-child td{border-bottom:0}th:last-child,td:last-child{border-right:0}"
        ".passed{color:var(--ok);font-weight:700}.failed{color:var(--danger);font-weight:700}.not-evaluated{color:var(--muted);font-weight:700}code,pre{font-family:SFMono-Regular,Consolas,monospace}code{background:#e8f4f4;color:#00656a;padding:2px 5px;border-radius:5px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#102332;color:#edf7f8;padding:15px;border-radius:9px}"
        "footer{color:var(--muted);padding:2px 0 20px}@media(max-width:800px){main{padding:15px}.cards{grid-template-columns:1fr 1fr}table{min-width:900px}}"
    );
    sb_append(&sb, "</style></head><body><main>");
    sb_append(&sb, "<section class=\"panel hero\"><h1>Результат входного контроля PE-образа</h1>");
    sb_append(&sb, "<span class=\"status\">Входной файл отклонён</span><p class=\"muted\">");
    html_escape(&sb, input_path);
    sb_append(&sb, "</p><div class=\"cards\">");
    sb_appendf(&sb, "<div class=\"card\"><span>Нарушено проверок</span><b>%zu</b></div>", validation->failed_count);
    sb_appendf(&sb, "<div class=\"card\"><span>Пройдено проверок</span><b>%zu</b></div>", validation->passed_count);
    sb_appendf(&sb, "<div class=\"card\"><span>Не проверено</span><b>%zu</b></div>", validation->not_evaluated_count);
    sb_appendf(&sb, "<div class=\"card\"><span>Размер файла</span><b>%llu B</b></div>", (unsigned long long)metadata->input_size);
    sb_append(&sb, "</div></section>");

    sb_append(&sb, "<section class=\"panel\"><h2>Результаты проверок</h2><p class=\"muted\">Статус «не проверена» означает, что координаты соответствующего поля нельзя установить после нарушения предшествующей структуры.</p>");
    sb_append(&sb, "<div class=\"table-wrap\"><table><colgroup><col style=\"width:18%\"><col style=\"width:11%\"><col style=\"width:16%\"><col style=\"width:15%\"><col style=\"width:40%\"></colgroup>");
    sb_append(&sb, "<thead><tr><th>Проверка</th><th>Статус</th><th>Диапазон файла</th><th>Значение</th><th>Критерий и диагностические данные</th></tr></thead><tbody>");
    for (size_t i = 0; i < PE_INPUT_CHECK_COUNT; i++) {
        const PeInputCheck* check = &validation->checks[i];
        const char* status_class = check->status == PE_INPUT_CHECK_PASSED ? "passed" :
                                   check->status == PE_INPUT_CHECK_FAILED ? "failed" : "not-evaluated";
        sb_append(&sb, "<tr><td><b>");
        html_escape(&sb, pe_input_check_title_ru((PeInputCheckCode)i));
        sb_append(&sb, "</b><br><code>");
        html_escape(&sb, pe_input_check_code((PeInputCheckCode)i));
        sb_appendf(&sb, "</code></td><td class=\"%s\">", status_class);
        html_escape(&sb, input_check_status_ru(check->status));
        sb_append(&sb, "</td><td>");
        if (check->has_file_range) {
            sb_appendf(&sb, "offset=<code>0x%zx</code><br>size=<code>%zu B</code>",
                       check->file_offset, check->byte_length);
        } else {
            sb_append(&sb, "-");
        }
        sb_append(&sb, "</td><td>");
        if (check->has_observed_value) {
            sb_appendf(&sb, "<code>0x%llx</code>", (unsigned long long)check->observed_value);
        } else {
            sb_append(&sb, "-");
        }
        sb_append(&sb, "</td><td>");
        html_escape(&sb, pe_input_check_requirement_ru((PeInputCheckCode)i));
        if (check->detail[0]) {
            sb_append(&sb, "<br><span class=\"muted\">");
            html_escape(&sb, check->detail);
            sb_append(&sb, "</span>");
        }
        sb_append(&sb, "</td></tr>");
    }
    sb_append(&sb, "</tbody></table></div></section>");

    sb_append(&sb, "<section class=\"panel\"><h2>Диагностика синтаксического разбора</h2><pre>");
    html_escape(&sb, parser_diagnostic ? parser_diagnostic : "");
    sb_append(&sb, "</pre></section><section class=\"panel\"><h2>Идентификация входного файла</h2>");
    sb_append(&sb, "<div class=\"table-wrap\"><table><tbody><tr><th>SHA-256</th><td><code>");
    html_escape(&sb, metadata->input_sha256);
    sb_append(&sb, "</code></td></tr><tr><th>Время формирования (UTC)</th><td>");
    html_escape(&sb, metadata->generated_at_utc);
    sb_append(&sb, "</td></tr><tr><th>Командная строка</th><td><code>");
    html_escape(&sb, metadata->command_line);
    sb_append(&sb, "</code></td></tr></tbody></table></div></section><footer>EH/Unwind Analyzer</footer></main></body></html>");

    bool ok = sb_ok(&sb) && file_write_atomic(path, sb.s, sb.len);
    if (!ok) {
        sb_appendf(err, "%s: %s\n",
                   sb_ok(&sb) ? "Failed to write input-validation HTML" : "OOM while building input-validation HTML",
                   path);
    }
    sb_free(&sb);
    return ok;
}

static void html_hex32_cell(StrBuf* sb, uint32_t value) {
    sb_appendf(sb, "<td><code>0x%08x</code></td>", (unsigned)value);
}

static void html_hex64_cell(StrBuf* sb, uint64_t value) {
    sb_appendf(sb, "<td><code>0x%llx</code></td>", (unsigned long long)value);
}

static void html_frame_saved_cell(StrBuf* sb, const UnwindSummary* u) {
    sb_append(sb, "<td class=\"register-cell\">");
    if (!u) {
        sb_append(sb, "-</td>");
        return;
    }
    sb_appendf(sb, "<div class=\"register-row\"><span class=\"register-label\">Stack</span><span class=\"register-value\"><code>%u B</code></span></div>",
               (unsigned)u->fixed_stack_bytes);
    sb_append(sb, "<div class=\"register-row\"><span class=\"register-label\">Frame</span><span class=\"register-value\">");
    if (u->frame_reg) {
        sb_appendf(sb, "<code>%s+%u</code>",
                   unwind_reg_name(u->frame_reg),
                   (unsigned)(u->frame_off * 16u));
    } else {
        sb_append(sb, "-");
    }
    sb_appendf(sb, "</span></div><div class=\"register-row\"><span class=\"register-label\">PUSH_NONVOL</span><span class=\"register-value\"><code>%u</code></span></div>",
               (unsigned)u->pushed_nonvol_count);
    sb_append(sb, "<div class=\"register-row\"><span class=\"register-label\">Сохранённые GPR</span><span class=\"register-value\">");
    if (u->saved_nonvol_mask) {
        bool first = true;
        for (uint8_t reg = 0; reg < 16; reg++) {
            if ((u->saved_nonvol_mask & (uint16_t)(1u << reg)) == 0u) continue;
            if (!first) sb_append(sb, " ");
            sb_append(sb, "<code>");
            html_escape(sb, unwind_reg_name(reg));
            sb_append(sb, "</code>");
            first = false;
        }
    } else {
        sb_append(sb, "-");
    }
    sb_append(sb, "</span></div><div class=\"register-row\"><span class=\"register-label\">Сохранённые XMM</span><span class=\"register-value\">");
    if (u->saved_xmm_mask) {
        bool first = true;
        for (uint8_t reg = 0; reg < 16; reg++) {
            if ((u->saved_xmm_mask & (uint16_t)(1u << reg)) == 0u) continue;
            if (!first) sb_append(sb, " ");
            sb_appendf(sb, "<code>XMM%u</code>", (unsigned)reg);
            first = false;
        }
    } else {
        sb_append(sb, "-");
    }
    sb_append(sb, "</span></div></td>");
}

static void html_handler_chain_cell(StrBuf* sb, const UnwindSummary* u) {
    sb_append(sb, "<td class=\"handler-cell\">");
    if (!u) {
        sb_append(sb, "-</td>");
        return;
    }
    if (u->has_handler) {
        sb_appendf(sb, "<div class=\"register-row\"><span class=\"register-label\">Handler RVA</span><span class=\"register-value\"><code>0x%08x</code></span></div>",
                   (unsigned)u->handler_rva);
    } else if (u->has_chain) {
        sb_appendf(sb, "<div class=\"register-row\"><span class=\"register-label\">Chain range</span><span class=\"register-value\"><code>0x%08x</code><br><code>0x%08x</code></span></div>"
                       "<div class=\"register-row\"><span class=\"register-label\">Unwind RVA</span><span class=\"register-value\"><code>0x%08x</code></span></div>",
                   (unsigned)u->chain.begin_rva,
                   (unsigned)u->chain.end_rva,
                   (unsigned)u->chain.unwind_rva);
    } else {
        sb_append(sb, "-");
    }
    sb_append(sb, "</td>");
}

static const char* html_issue_class(bool issue) {
    return issue ? "warn" : "ok";
}

static void html_metric_row(StrBuf* sb,
                            const char* group,
                            const char* check,
                            const char* value,
                            bool issue,
                            const char* meaning) {
    sb_append(sb, "<tr>");
    html_text_cell(sb, group);
    html_text_cell(sb, check);
    sb_appendf(sb, "<td><b class=\"%s\">", html_issue_class(issue));
    html_escape(sb, value ? value : "");
    sb_append(sb, "</b></td><td class=\"wrap\">");
    html_escape(sb, meaning ? meaning : "");
    sb_append(sb, "</td></tr>");
}

static void html_count_metric_row(StrBuf* sb,
                                  const char* group,
                                  const char* check,
                                  size_t value,
                                  const char* meaning) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%zu", value);
    html_metric_row(sb, group, check, buf, value != 0, meaning);
}

static void html_bool_metric_row(StrBuf* sb,
                                 const char* group,
                                 const char* check,
                                 bool value,
                                 const char* meaning) {
    html_metric_row(sb, group, check, value ? "да" : "нет", value, meaning);
}

static void html_ratio_metric_row(StrBuf* sb,
                                  const char* group,
                                  const char* check,
                                  double value,
                                  const char* meaning) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%.3f", value);
    html_metric_row(sb, group, check, buf, false, meaning);
}

static void html_evidence_families_metric_row(StrBuf* sb, const HeuristicReport* hr) {
    char buf[256];
    const uint32_t bits[] = {
        HEF_TABLE_INTEGRITY,
        HEF_UNWIND_INTEGRITY,
        HEF_METADATA_PLACEMENT,
        HEF_UNWIND_REUSE,
        HEF_HANDLER_DOMINANCE
    };
    buf[0] = '\0';
    if (hr) {
        for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
            if ((hr->evidence_families_mask & bits[i]) == 0u) continue;
            if (buf[0] != '\0') strncat(buf, ", ", sizeof(buf) - strlen(buf) - 1u);
            strncat(buf, heuristics_evidence_family_name(bits[i]), sizeof(buf) - strlen(buf) - 1u);
        }
    }
    if (buf[0] == '\0') snprintf(buf, sizeof(buf), "%s", "нет активных семейств");
    html_metric_row(sb, "Оценка доказательств", "Активные семейства признаков", buf,
                    hr && hr->evidence_families_mask != 0u,
                    "Показывает, из каких независимых групп признаков складывается доказательная база.");
}
static const char* html_score_class(const HeuristicReport* hr) {
    if (!hr) return "neutral";
    if (hr->score >= 70) return "danger";
    if (hr->score >= 40) return "warn";
    return "ok";
}

static const char* html_level_class(const char* level) {
    if (!level) return "neutral";
    if (strcmp(level, "strong") == 0) return "danger";
    if (strcmp(level, "medium") == 0) return "warn";
    if (strcmp(level, "weak") == 0) return "neutral";
    if (strcmp(level, "none") == 0) return "ok";
    return "neutral";
}

static const char* ru_yes_no(bool value) {
    return value ? "да" : "нет";
}

static bool dynamic_platform_unsupported(const DynamicReport* dr) {
    return dr && !dr->ran && dr->details.s &&
           strstr(dr->details.s, "Dynamic mode is supported only on Windows.") != NULL;
}

static const char* ru_status_text(const DynamicReport* dr) {
    if (!dr) return "не запрашивалась";
    if (dynamic_platform_unsupported(dr)) return "запрошена, недоступна на текущей ОС";
    if (dr->timed_out) return "тайм-аут";
    if (!dr->ran) return "запрошена, не выполнена";
    return dr->ok ? "завершена" : "ошибка";
}

static const char* dynamic_status_class(const DynamicReport* dr) {
    if (!dr) return "neutral";
    if (dr->ran && dr->ok && !dr->timed_out) return "ok";
    if (dynamic_platform_unsupported(dr) || dr->timed_out || !dr->ok) return "warn";
    return "neutral";
}

static const char* ru_level_text(const char* value) {
    if (!value) return "-";
    if (strcmp(value, "strong") == 0) return "сильный";
    if (strcmp(value, "medium") == 0) return "средний";
    if (strcmp(value, "weak") == 0) return "слабый";
    if (strcmp(value, "none") == 0) return "нет";
    return value;
}

static const char* ru_severity_text(const char* value) {
    if (!value) return "-";
    if (strcmp(value, "critical") == 0) return "критическая";
    if (strcmp(value, "high") == 0) return "высокая";
    if (strcmp(value, "medium") == 0) return "средняя";
    if (strcmp(value, "low") == 0) return "низкая";
    if (strcmp(value, "info") == 0) return "информационная";
    return value;
}

static const char* ru_family_text(const char* value) {
    if (!value) return "-";
    if (strcmp(value, "table_integrity") == 0) return "целостность PE и таблицы функций";
    if (strcmp(value, "unwind_integrity") == 0) return "целостность UNWIND_INFO";
    if (strcmp(value, "metadata_placement") == 0) return "размещение metadata и handlers";
    if (strcmp(value, "unwind_reuse") == 0) return "повторное использование unwind metadata";
    if (strcmp(value, "handler_dominance") == 0) return "концентрация ссылок на handler";
    return value;
}

static const char* ru_family_short_text(const char* value) {
    if (!value) return "-";
    if (strcmp(value, "table_integrity") == 0) return "целостность таблиц";
    if (strcmp(value, "unwind_integrity") == 0) return "целостность UNWIND_INFO";
    if (strcmp(value, "metadata_placement") == 0) return "размещение метаданных";
    if (strcmp(value, "unwind_reuse") == 0) return "повторное использование";
    if (strcmp(value, "handler_dominance") == 0) return "доминирование обработчика";
    return value;
}

static const char* ru_verdict_text(const char* value) {
    if (!value) return "-";
    if (strcmp(value, "high_suspicion") == 0) return "высокая подозрительность";
    if (strcmp(value, "moderate_suspicion") == 0) return "умеренная подозрительность";
    if (strcmp(value, "low_suspicion") == 0) return "низкая подозрительность";
    if (strcmp(value, "no_strong_static_anomalies") == 0) return "сильные статические аномалии не обнаружены";
    if (strcmp(value, "high_suspicion_correlated") == 0) return "высокая подозрительность с динамическим подтверждением";
    if (strcmp(value, "high_suspicion_static") == 0) return "высокая статическая подозрительность";
    if (strcmp(value, "moderate_suspicion_correlated") == 0) return "умеренная подозрительность с динамическим подтверждением";
    if (strcmp(value, "moderate_suspicion_static") == 0) return "умеренная статическая подозрительность";
    if (strcmp(value, "low_suspicion_correlated") == 0) return "низкая подозрительность с динамическим подтверждением";
    if (strcmp(value, "low_suspicion_static") == 0) return "низкая статическая подозрительность";
    if (strcmp(value, "runtime_signals_only") == 0) return "обнаружены только динамические сигналы";
    if (strcmp(value, "no_strong_correlated_evidence") == 0) return "сильная корреляция не обнаружена";
    return value;
}

static const char* ru_case_strength_text(const char* value) {
    if (!value) return "-";
    if (strcmp(value, "strong_correlated_case") == 0) return "сильная, с корреляцией";
    if (strcmp(value, "medium_correlated_case") == 0) return "средняя, с корреляцией";
    if (strcmp(value, "strong_unconfirmed_case") == 0) return "сильная, без динамического подтверждения";
    if (strcmp(value, "medium_case") == 0) return "средняя";
    if (strcmp(value, "weak_case") == 0) return "слабая";
    if (strcmp(value, "no_case") == 0) return "значимых признаков нет";
    return value;
}

static void html_append_manual_step_ru(StrBuf* sb, const char* step) {
    if (!step) return;
    html_escape(sb, step);
}

static void html_append_finding_message_ru(StrBuf* sb, const HeuristicFinding* finding) {
    if (!finding || !finding->code[0]) return;
    const char* code = finding->code;
    size_t n = finding->affected_count;
    if (strcmp(code, "pe_section_raw_oob") == 0) {
        sb_append(sb, "Raw-диапазон секции PE выходит за границы файла.");
    } else if (strcmp(code, "pe_section_virtual_oob") == 0) {
        sb_append(sb, "Virtual-диапазон секции PE выходит за пределы SizeOfImage.");
    } else if (strcmp(code, "pe_section_raw_overlap") == 0) {
        sb_append(sb, "Raw-диапазоны секций PE пересекаются.");
    } else if (strcmp(code, "pe_section_virtual_overlap") == 0) {
        sb_append(sb, "Virtual-диапазоны секций PE пересекаются.");
    } else if (strcmp(code, "pe_section_misaligned") == 0) {
        sb_append(sb, "Обнаружена секция PE с нарушением выравнивания.");
    } else if (strcmp(code, "pe_exception_directory_oob") == 0) {
        sb_append(sb, "Exception directory поврежден, неполон, недоступен для чтения или выходит за допустимые границы.");
    } else if (strcmp(code, "no_runtime_functions") == 0) {
        sb_append(sb, "Записи RUNTIME_FUNCTION не найдены; это допустимо для leaf-only image, однако характер кода подлежит отдельному подтверждению.");
    } else if (strcmp(code, "invalid_ranges") == 0) {
        sb_appendf(sb, "Обнаружены записи RUNTIME_FUNCTION с некорректным диапазоном Begin/End: %zu.", n);
    } else if (strcmp(code, "rf_oob") == 0) {
        sb_appendf(sb, "Диапазоны RUNTIME_FUNCTION выходят за пределы SizeOfImage: %zu.", n);
    } else if (strcmp(code, "unwind_rva_oob") == 0) {
        sb_appendf(sb, "UnwindInfoRVA отсутствует или выходит за допустимые границы: %zu.", n);
    } else if (strcmp(code, "rf_unsorted") == 0) {
        sb_appendf(sb, "Таблица RUNTIME_FUNCTION не отсортирована по BeginAddress: %zu.", n);
    } else if (strcmp(code, "rf_overlaps") == 0) {
        sb_appendf(sb, "Диапазоны RUNTIME_FUNCTION пересекаются: %zu.", n);
    } else if (strcmp(code, "duplicate_begin") == 0) {
        sb_appendf(sb, "Несколько записей RUNTIME_FUNCTION используют один и тот же BeginAddress: %zu.", n);
    } else if (strcmp(code, "unwind_parse_fail") == 0) {
        sb_appendf(sb, "Ошибки разбора UNWIND_INFO: %zu.", n);
    } else if (strcmp(code, "unwind_anomalies") == 0) {
        sb_appendf(sb, "Аномалии UNWIND_INFO (version/opcode/chain/ABI и др.): %zu.", n);
    } else if (strcmp(code, "unwind_reuse_strong") == 0) {
        sb_appendf(sb, "Сильное повторное использование UNWIND_INFO: максимальное число записей, ссылающихся на один UnwindInfoRVA, равно %zu.", n);
    } else if (strcmp(code, "handler_dominance") == 0) {
        sb_appendf(sb, "Один handler target доминирует: максимальное число записей, ссылающихся на один HandlerRVA, равно %zu.", n);
    } else if (strcmp(code, "unwind_reuse_moderate") == 0) {
        sb_appendf(sb, "Умеренное повторное использование UNWIND_INFO подтверждается другим статическим признаком: максимальное число записей, ссылающихся на один UnwindInfoRVA, равно %zu.", n);
    } else if (strcmp(code, "unwind_in_exec_section") == 0) {
        sb_appendf(sb, "UNWIND_INFO расположен в executable-секции: %zu.", n);
    } else if (strcmp(code, "unwind_unusual_section") == 0) {
        sb_appendf(sb, "UNWIND_INFO расположен в необычной секции, отличной от .xdata/.rdata/.pdata: %zu.", n);
    } else if (strcmp(code, "unwind_writable_section") == 0) {
        sb_appendf(sb, "UNWIND_INFO расположен в writable-секции: %zu.", n);
    } else if (strcmp(code, "handler_nonexec_section") == 0) {
        sb_appendf(sb, "Exception handler RVA указывает в non-executable или неизвестную секцию: %zu.", n);
    } else if (strcmp(code, "handler_writable_section") == 0) {
        sb_appendf(sb, "Exception handler RVA указывает в writable-секцию: %zu.", n);
    } else if (strcmp(code, "placement_exec_nonexec_handler_combo") == 0) {
        sb_append(sb, "Unwind metadata в executable-секции совпадает с handler targets в non-executable/unknown секции; такую комбинацию сложнее объяснить доброкачественно.");
    } else if (strcmp(code, "placement_integrity_combo") == 0) {
        sb_append(sb, "Подозрительное размещение metadata подтверждается проблемами целостности UNWIND_INFO / UnwindInfoRVA; вместе эти признаки сильнее, чем по отдельности.");
    } else if (strcmp(code, "reuse_dominance_combo") == 0) {
        sb_append(sb, "Активное повторное использование UNWIND_INFO совпадает с dominant handler target, что похоже на централизованный dispatcher-style metadata reuse.");
    } else if (strcmp(code, "writable_metadata_handler_combo") == 0) {
        sb_append(sb, "Writable unwind metadata совпадает с writable handler targets; такая комбинация нетипична для обычных compiler-produced images и требует внимательной проверки.");
    } else {
        html_escape(sb, finding->message);
    }
}

static void html_append_unwind_diagnostic_inline(StrBuf* sb, const UnwindSummary* u) {
    if (!u) return;
    if (!u->diagnostic_field[0] && !u->diagnostic_has_size && !u->diagnostic_has_slots &&
        !u->diagnostic_has_bytes && u->chain_path_count == 0) {
        return;
    }
    char bytes_hex[UNWIND_DIAG_MAX_BYTES * 3u + 1u];
    bytes_hex[0] = '\0';
    if (u->diagnostic_has_bytes) {
        bytes_to_hex(u->diagnostic_bytes, u->diagnostic_bytes_count, bytes_hex, sizeof(bytes_hex));
    }
    sb_append(sb, "<br><b>Диагностические данные</b>: ");
    if (u->diagnostic_field[0]) {
        sb_append(sb, "failed_field=<code class=\"code-wrap\">");
        html_escape(sb, u->diagnostic_field);
        sb_append(sb, "</code>; ");
    }
    if (u->diagnostic_has_file_offset) {
        sb_appendf(sb, "file_offset=<code>0x%08x</code>; ", (unsigned)u->diagnostic_file_offset);
    }
    if (u->diagnostic_has_size) {
        sb_appendf(sb, "expected_size=%u; available_size=%u; ",
                   (unsigned)u->diagnostic_expected_size,
                   (unsigned)u->diagnostic_available_size);
    }
    if (u->diagnostic_has_slots) {
        sb_appendf(sb, "expected_slots=%u; available_slots=%u; ",
                   (unsigned)u->diagnostic_expected_slots,
                   (unsigned)u->diagnostic_available_slots);
    }
    if (u->diagnostic_has_bytes) {
        sb_append(sb, "bytes@<code>");
        sb_appendf(sb, "0x%08x", (unsigned)u->diagnostic_bytes_file_offset);
        sb_append(sb, "</code>=<code class=\"code-wrap\">");
        html_escape(sb, bytes_hex);
        sb_append(sb, "</code>; ");
    }
    if (u->chain_path_count > 0) {
        sb_append(sb, "chain_path=<code class=\"code-wrap\">");
        for (uint8_t i = 0; i < u->chain_path_count; i++) {
            if (i) sb_append(sb, " -&gt; ");
            sb_appendf(sb, "0x%08x", (unsigned)u->chain_path[i]);
        }
        sb_append(sb, "</code>");
        if (u->chain_loop_detected) {
            sb_appendf(sb, "; loop_rva=<code>0x%08x</code>", (unsigned)u->chain_loop_rva);
        }
    }
}

static bool html_unwind_has_key_diagnostic(bool ok, const UnwindSummary* u) {
    if (!u) return !ok;
    return !ok || u->anomalies != 0 || u->diagnostic_field[0] ||
           u->diagnostic_has_size || u->diagnostic_has_slots ||
           u->diagnostic_has_bytes || u->chain_loop_detected ||
           u->chain_path_count > 0;
}

static const char* html_key_diagnostic_interpretation_ru(bool ok, const UnwindSummary* u) {
    if (!u) return "Запись подлежит ручной верификации аналитиком: сводные данные недоступны.";
    if (strstr(u->diagnostic_field, "CountOfCodes / UWOP operand slots") != NULL) {
        return "CountOfCodes не покрывает все operand slots текущей UWOP-операции; дальнейшее чтение tail, handler RVA или chained info из этой структуры ненадежно.";
    }
    if (strstr(u->diagnostic_field, "UnwindInfoAddress") != NULL) {
        return "RUNTIME_FUNCTION ссылается на UNWIND_INFO, который не удалось сопоставить с байтами image; unwind-карта функции недостоверна.";
    }
    if (strstr(u->diagnostic_field, "Version") != NULL) {
        return "Версия UNWIND_INFO не поддерживается форматом анализатора; интерпретация последующих полей остановлена.";
    }
    if (strstr(u->diagnostic_field, "UNWIND_CODE") != NULL) {
        return "Массив UNWIND_CODE не может быть прочитан целиком; восстановление stack frame по этой записи ненадежно.";
    }
    if (u->chain_loop_detected) {
        return "CHAININFO образует цикл; следование цепочке может не завершиться без защитного ограничения глубины.";
    }
    if (!ok) {
        return "UNWIND_INFO не прошел структурный разбор; выводы по handler и stack frame должны считаться предварительными.";
    }
    if (u->anomalies) {
        return "UNWIND_INFO прочитан, но содержит внутренние аномалии; требуется ручная сверка аналитиком с кодом функции и соседними metadata.";
    }
    return "Запись содержит диагностические данные, требующие ручной сверки аналитиком.";
}

static void html_append_key_diagnostic_reason(StrBuf* sb, bool ok, const UnwindSummary* u) {
    if (!u) {
        sb_append(sb, "summary недоступен");
        return;
    }
    bool wrote = false;
    if (!ok && u->parse_error[0]) {
        html_escape(sb, u->parse_error);
        wrote = true;
    }
    if (u->anomalies) {
        StrBuf anom = {0};
        if (sb_init(&anom, 128)) {
            anomalies_to_str(&anom, u->anomalies);
            if (wrote) sb_append(sb, "; ");
            html_escape(sb, anom.s ? anom.s : "");
            wrote = true;
            sb_free(&anom);
        }
    }
    if (!wrote && u->diagnostic_field[0]) {
        html_escape(sb, u->diagnostic_field);
        wrote = true;
    }
    if (!wrote) sb_append(sb, "диагностическое предупреждение");
}

static void html_append_key_diagnostic_data(StrBuf* sb, const UnwindSummary* u) {
    if (!u) {
        sb_append(sb, "-");
        return;
    }
    bool wrote = false;
    char bytes_hex[UNWIND_DIAG_MAX_BYTES * 3u + 1u];
    bytes_hex[0] = '\0';
    if (u->diagnostic_has_bytes) {
        bytes_to_hex(u->diagnostic_bytes, u->diagnostic_bytes_count, bytes_hex, sizeof(bytes_hex));
    }
    if (u->diagnostic_field[0]) {
        sb_append(sb, "failed_field=<code class=\"code-wrap\">");
        html_escape(sb, u->diagnostic_field);
        sb_append(sb, "</code>");
        wrote = true;
    }
    if (u->diagnostic_has_file_offset) {
        if (wrote) sb_append(sb, "<br>");
        sb_appendf(sb, "file_offset=<code>0x%08x</code>", (unsigned)u->diagnostic_file_offset);
        wrote = true;
    }
    if (u->diagnostic_has_size) {
        if (wrote) sb_append(sb, "<br>");
        sb_appendf(sb, "expected_size=%u; available_size=%u",
                   (unsigned)u->diagnostic_expected_size,
                   (unsigned)u->diagnostic_available_size);
        wrote = true;
    }
    if (u->diagnostic_has_slots) {
        if (wrote) sb_append(sb, "<br>");
        sb_appendf(sb, "expected_slots=%u; available_slots=%u",
                   (unsigned)u->diagnostic_expected_slots,
                   (unsigned)u->diagnostic_available_slots);
        wrote = true;
    }
    if (u->diagnostic_has_bytes) {
        if (wrote) sb_append(sb, "<br>");
        sb_appendf(sb, "bytes@<code>0x%08x</code>=<code class=\"code-wrap\">",
                   (unsigned)u->diagnostic_bytes_file_offset);
        html_escape(sb, bytes_hex);
        sb_append(sb, "</code>");
        wrote = true;
    }
    if (u->chain_path_count > 0) {
        if (wrote) sb_append(sb, "<br>");
        sb_append(sb, "chain_path=<code class=\"code-wrap\">");
        for (uint8_t i = 0; i < u->chain_path_count; i++) {
            if (i) sb_append(sb, " -&gt; ");
            sb_appendf(sb, "0x%08x", (unsigned)u->chain_path[i]);
        }
        sb_append(sb, "</code>");
        if (u->chain_loop_detected) {
            sb_appendf(sb, "; loop_rva=<code>0x%08x</code>", (unsigned)u->chain_loop_rva);
        }
        wrote = true;
    }
    if (!wrote) sb_append(sb, "-");
}

static void html_append_key_diagnostics_panel(StrBuf* sb,
                                              const PeImage* img,
                                              const RuntimeFunction* rf,
                                              const UnwindSummary* us,
                                              const bool* us_ok,
                                              size_t n) {
    if (!sb || (!rf && n) || (!us && n) || (!us_ok && n)) return;
    size_t diagnostic_count = 0;
    for (size_t i = 0; i < n; i++) {
        if (html_unwind_has_key_diagnostic(us_ok[i], &us[i])) diagnostic_count++;
    }
    if (diagnostic_count == 0) return;

    sb_append(sb, "<section class=\"panel\" id=\"structural-diagnostics\"><h2>Ключевые структурные диагностики</h2>");
    sb_append(sb, "<p class=\"muted\">Локализуются записи RUNTIME_FUNCTION с нарушенным инвариантом или ошибкой разбора UNWIND_INFO. Координаты .pdata, диапазон функции, UnwindInfoAddress, поле ошибки и доступные байты образуют проверяемую цепочку PE -&gt; Exception Directory -&gt; .pdata -&gt; UNWIND_INFO -&gt; нарушение.</p>");
    sb_append(sb, "<div class=\"table-wrap\"><table class=\"diagnostics-table\">"
                  "<colgroup><col style=\"width:13%\"><col style=\"width:12%\"><col style=\"width:11%\">"
                  "<col style=\"width:12%\"><col style=\"width:16%\"><col style=\"width:18%\">"
                  "<col style=\"width:18%\"></colgroup><thead><tr>"
                  "<th>Запись .pdata</th><th>Диапазон функции</th><th>UnwindInfo RVA</th><th>Размещение метаданных</th>"
                  "<th>Основание фиксации</th><th>Диагностические данные</th><th>Аналитическая интерпретация</th>"
                  "</tr></thead><tbody>");

    for (size_t i = 0; i < n; i++) {
        const UnwindSummary* u = &us[i];
        if (!html_unwind_has_key_diagnostic(us_ok[i], u)) continue;
        uint32_t file_offset = 0;
        uint32_t pdata_entry_rva = 0;
        uint32_t pdata_entry_file_offset = 0;
        bool has_file_offset = pe_rva_to_fileoff(img, rf[i].unwind_rva, &file_offset);
        bool has_pdata_entry_rva = pdata_entry_rva_for_index(img, i, &pdata_entry_rva);
        bool has_pdata_entry_file_offset = pdata_entry_fileoff_for_index(img, i, &pdata_entry_file_offset);
        const char* row_class = us_ok[i] ? "warn" : "danger";
        sb_append(sb, "<tr>");
        sb_appendf(sb, "<td class=\"diagnostic-cell\"><div class=\"diagnostic-field\"><span>Индекс записи</span><b class=\"%s\">%zu</b></div>", row_class, i);
        if (has_pdata_entry_rva) sb_appendf(sb, "<div class=\"diagnostic-field\"><span>.pdata RVA</span><code>0x%08x</code></div>", (unsigned)pdata_entry_rva);
        if (has_pdata_entry_file_offset) sb_appendf(sb, "<div class=\"diagnostic-field\"><span>File offset</span><code>0x%08x</code></div>", (unsigned)pdata_entry_file_offset);
        sb_append(sb, "</td>");
        sb_appendf(sb, "<td class=\"diagnostic-cell\"><div class=\"diagnostic-field\"><span>Begin RVA</span><code>0x%08x</code></div>"
                       "<div class=\"diagnostic-field\"><span>End RVA</span><code>0x%08x</code></div></td>",
                   (unsigned)rf[i].begin_rva, (unsigned)rf[i].end_rva);
        sb_appendf(sb, "<td class=\"diagnostic-cell\"><div class=\"diagnostic-field\"><span>RVA</span><code>0x%08x</code></div></td>",
                   (unsigned)rf[i].unwind_rva);
        sb_append(sb, "<td class=\"diagnostic-cell\"><div class=\"diagnostic-field\"><span>Секция</span>");
        html_escape(sb, section_name_or_dash(img, rf[i].unwind_rva));
        sb_append(sb, "</div><div class=\"diagnostic-field\"><span>File offset</span>");
        if (has_file_offset) sb_appendf(sb, "<code>0x%08x</code>", (unsigned)file_offset);
        else sb_append(sb, "не мапится");
        sb_append(sb, "</div>");
        sb_append(sb, "</td><td class=\"wrap\">");
        html_append_key_diagnostic_reason(sb, us_ok[i], u);
        sb_append(sb, "</td><td class=\"wrap\">");
        html_append_key_diagnostic_data(sb, u);
        sb_append(sb, "</td><td class=\"wrap\">");
        html_escape(sb, html_key_diagnostic_interpretation_ru(us_ok[i], u));
        sb_append(sb, "</td></tr>");
    }

    sb_append(sb, "</tbody></table></div></section>");
}

static void html_append_finding_chain_ru(StrBuf* sb,
                                         const HeuristicFinding* finding,
                                         const PeImage* img,
                                         const RuntimeFunction* rf,
                                         const UnwindSummary* us,
                                         const bool* us_ok,
                                         size_t n) {
    size_t related = finding_related_function_index(finding, rf, us, us_ok, n);
    sb_append(sb, "<br><b>Доказательная трассировка</b>: ");
    sb_appendf(sb, "PE -&gt; Exception Directory <code>0x%08x + 0x%x</code>",
               (unsigned)(img ? img->exception_rva : 0u),
               (unsigned)(img ? img->exception_size : 0u));
    if (related == (size_t)-1) {
        sb_append(sb, " -&gt; связанная RUNTIME_FUNCTION не сопоставлена");
        return;
    }
    uint32_t pdata_entry_rva = 0;
    uint32_t pdata_entry_file_offset = 0;
    uint32_t file_offset = 0;
    bool has_pdata_entry_rva = pdata_entry_rva_for_index(img, related, &pdata_entry_rva);
    bool has_pdata_entry_file_offset = pdata_entry_fileoff_for_index(img, related, &pdata_entry_file_offset);
    bool has_file_offset = pe_rva_to_fileoff(img, rf[related].unwind_rva, &file_offset);
    const PeSection* section = pe_find_section_for_rva(img, rf[related].unwind_rva);
    char permissions[4] = "---";
    if (section) section_permissions(section->characteristics, permissions);
    sb_appendf(sb, " -&gt; RUNTIME_FUNCTION[%zu] <code>0x%08x..0x%08x</code>",
               related, (unsigned)rf[related].begin_rva, (unsigned)rf[related].end_rva);
    if (has_pdata_entry_rva) sb_appendf(sb, " (.pdata RVA <code>0x%08x</code>", (unsigned)pdata_entry_rva);
    if (has_pdata_entry_file_offset) sb_appendf(sb, ", file_offset <code>0x%08x</code>", (unsigned)pdata_entry_file_offset);
    if (has_pdata_entry_rva) sb_append(sb, ")");
    sb_appendf(sb, " -&gt; UnwindInfoAddress <code>0x%08x</code>", (unsigned)rf[related].unwind_rva);
    sb_append(sb, " -&gt; section <code>");
    html_escape(sb, section ? section->name : "не определена");
    sb_append(sb, "</code>");
    if (section) sb_appendf(sb, " rights=<code>%s</code>", permissions);
    else sb_append(sb, " rights=<code>не определены</code>");
    if (has_file_offset) sb_appendf(sb, " file_offset=<code>0x%08x</code>", (unsigned)file_offset);
    if (us) html_append_unwind_diagnostic_inline(sb, &us[related]);
}

static void html_append_finding_evidence_records(StrBuf* sb,
                                                 const HeuristicFinding* finding,
                                                 const PeImage* img,
                                                 const RuntimeFunction* rf,
                                                 const UnwindSummary* us,
                                                 const bool* us_ok,
                                                 size_t n) {
    size_t total = evidence_record_count(finding, img, rf, us, us_ok, n);
    size_t written = 0;
    if (!sb || total == 0) {
        sb_append(sb, "<br><b>Evidence-записи</b>: для данного finding-а не формируется перечень отдельных RUNTIME_FUNCTION entries, поскольку наблюдение является агрегатным либо относится к PE-разметке в целом.");
        return;
    }
    sb_appendf(sb, "<br><b>Evidence-записи</b>: %zu", total);
    if (total > REPORT_EVIDENCE_RECORD_LIMIT_HTML) {
        sb_appendf(sb, " (лимит записей в HTML: %u; полный перечень сохранен в JSON-поле evidence_records)", REPORT_EVIDENCE_RECORD_LIMIT_HTML);
    }
    sb_append(sb, "<div class=\"table-wrap\" style=\"margin-top:8px\"><table class=\"evidence-table\">"
                  "<colgroup><col style=\"width:7%\"><col style=\"width:17%\"><col style=\"width:18%\">"
                  "<col style=\"width:25%\"><col style=\"width:13%\"><col style=\"width:20%\"></colgroup><thead><tr>"
                  "<th>Индекс записи</th><th>Положение entry в .pdata</th><th>Диапазон функции</th>"
                  "<th>UnwindInfoAddress</th><th>Секция / права</th><th>Основание включения</th>"
                  "</tr></thead><tbody>");
    for (size_t i = 0; i < n && written < REPORT_EVIDENCE_RECORD_LIMIT_HTML; i++) {
        if (!evidence_record_matches(finding, img, rf, us, us_ok, n, i)) continue;
        uint32_t pdata_rva = 0;
        uint32_t pdata_file_offset = 0;
        uint32_t unwind_file_offset = 0;
        bool has_pdata_rva = pdata_entry_rva_for_index(img, i, &pdata_rva);
        bool has_pdata_file_offset = pdata_entry_fileoff_for_index(img, i, &pdata_file_offset);
        bool has_unwind_file_offset = pe_rva_to_fileoff(img, rf[i].unwind_rva, &unwind_file_offset);
        const PeSection* section = pe_find_section_for_rva(img, rf[i].unwind_rva);
        char permissions[4] = "---";
        char reason[512];
        if (section) section_permissions(section->characteristics, permissions);
        evidence_record_reason_ru(finding, img, rf, us, us_ok, n, i, reason, sizeof(reason));

        sb_append(sb, "<tr>");
        sb_appendf(sb, "<td><code>[%zu]</code></td>", i);
        sb_append(sb, "<td class=\"wrap\">");
        if (has_pdata_rva) sb_appendf(sb, "RVA=<code>0x%08x</code>", (unsigned)pdata_rva);
        else sb_append(sb, "RVA=-");
        if (has_pdata_file_offset) sb_appendf(sb, "<br>file_offset=<code>0x%08x</code>", (unsigned)pdata_file_offset);
        else sb_append(sb, "<br>file_offset=не мапится");
        sb_appendf(sb, "<br>size=%u B", REPORT_RUNTIME_FUNCTION_ENTRY_SIZE);
        sb_append(sb, "</td>");
        sb_appendf(sb, "<td><code>0x%08x..0x%08x</code></td>",
                   (unsigned)rf[i].begin_rva, (unsigned)rf[i].end_rva);
        sb_appendf(sb, "<td class=\"wrap\"><code>0x%08x</code>", (unsigned)rf[i].unwind_rva);
        if (has_unwind_file_offset) sb_appendf(sb, "<br>file_offset=<code>0x%08x</code>", (unsigned)unwind_file_offset);
        else sb_append(sb, "<br>file_offset=не мапится");
        if (us && us[i].diagnostic_field[0]) {
            sb_append(sb, "<br>failed_field=<code class=\"code-wrap\">");
            html_escape(sb, us[i].diagnostic_field);
            sb_append(sb, "</code>");
        }
        sb_append(sb, "</td><td class=\"wrap\">section=<code>");
        html_escape(sb, section ? section->name : "не определена");
        sb_append(sb, "</code>");
        if (section) sb_appendf(sb, "<br>rights=<code>%s</code>", permissions);
        else sb_append(sb, "<br>rights=<code>не определены</code>");
        sb_append(sb, "</td><td class=\"wrap\">");
        html_escape(sb, reason);
        sb_append(sb, "</td></tr>");
        written++;
    }
    sb_append(sb, "</tbody></table></div>");
}

static void html_append_finding_evidence_block(StrBuf* sb,
                                               const HeuristicFinding* finding,
                                               const PeImage* img,
                                               const RuntimeFunction* rf,
                                               const UnwindSummary* us,
                                               const bool* us_ok,
                                               size_t n) {
    char observed[1024];
    const char* code = finding ? finding->code : NULL;
    finding_observed_text(finding, img, rf, us, us_ok, n, observed, sizeof(observed));
    sb_append(sb, "<div style=\"margin-top:8px;padding-top:8px;border-top:1px solid var(--line)\"><b>Аналитическая формулировка</b>: ");
    html_escape(sb, finding_title_ru(code));
    sb_append(sb, "<br><b>Техническое основание</b>: ");
    html_escape(sb, finding_meaning_ru(code));
    sb_append(sb, "<br><b>Проверяемый инвариант</b>: ");
    html_escape(sb, finding_rule_text(code));
    sb_append(sb, "<br><b>Зафиксированное наблюдение</b>: ");
    html_escape(sb, observed);
    sb_append(sb, "<br><b>Ожидаемое состояние</b>: ");
    html_escape(sb, finding_expected_text(code));
    sb_append(sb, "<br><b>Аналитическое значение</b>: ");
    html_escape(sb, finding_why_it_matters_ru(code));
    sb_append(sb, "<br><b>Рекомендуемая ручная верификация</b>: ");
    html_escape(sb, finding_next_step_ru(code));
    html_append_finding_chain_ru(sb, finding, img, rf, us, us_ok, n);
    html_append_finding_evidence_records(sb, finding, img, rf, us, us_ok, n);
    sb_append(sb, "</div>");
}

static void html_append_mitigation_message_ru(StrBuf* sb, const char* code, const char* message) {
    if (!code) {
        html_escape(sb, message);
    } else if (strcmp(code, "single_signal_only") == 0) {
        sb_append(sb, "Вклад сформирован одним не-сильным признаком; как самостоятельное доказательство он имеет ограниченную диагностическую силу.");
    } else if (strcmp(code, "small_sample_size") == 0) {
        sb_append(sb, "Очень маленькая выборка .pdata может завышать доли; уверенность снижена до появления большего числа функций.");
    } else if (strcmp(code, "placement_only_signal") == 0) {
        sb_append(sb, "Аномалии только по placement могут встречаться в необычных, но доброкачественных layout; требуется ручная верификация контекста размещения аналитиком.");
    } else if (strcmp(code, "single_family_only") == 0) {
        sb_append(sb, "Признаки относятся только к одному семейству; перед сильным выводом желательно cross-layer corroboration.");
    } else {
        html_escape(sb, message);
    }
}


static const HeuristicFinding* html_find_finding_by_code(const HeuristicReport* hr,
                                                         const char* code) {
    if (!hr || !code) return NULL;
    for (size_t i = 0; i < hr->finding_count; i++) {
        if (strcmp(hr->findings[i].code, code) == 0) return &hr->findings[i];
    }
    return NULL;
}

static const char* html_matrix_status_class(bool active, const char* severity) {
    if (!active) return "ok";
    if (severity && (strcmp(severity, "critical") == 0 || strcmp(severity, "high") == 0)) return "danger";
    if (severity && strcmp(severity, "medium") == 0) return "warn";
    return "neutral";
}

static void html_heuristic_matrix_row(StrBuf* sb,
                                      size_t number,
                                      const HeuristicReport* hr,
                                      const char* code,
                                      const char* family,
                                      const char* default_severity,
                                      bool active,
                                      const char* value) {
    const HeuristicFinding* finding = html_find_finding_by_code(hr, code);
    if (finding) active = true;
    const char* severity = (finding && finding->severity[0]) ? finding->severity : default_severity;
    const char* status_class = html_matrix_status_class(active, severity);

    sb_append(sb, "<tr>");
    sb_appendf(sb, "<td>%zu</td>", number);
    if (finding) {
        sb_append(sb, "<td><a class=\"finding-link\" href=\"#finding-");
        html_escape(sb, code);
        sb_append(sb, "\"><code>");
        html_escape(sb, code);
        sb_append(sb, "</code><span>подробности</span></a></td>");
    } else {
        html_text_cell(sb, code);
    }
    sb_append(sb, "<td class=\"wrap\">");
    html_escape(sb, ru_family_short_text(family));
    sb_append(sb, "<br><code>");
    html_escape(sb, family);
    sb_append(sb, "</code></td>");
    html_text_cell(sb, ru_severity_text(severity));
    sb_appendf(sb, "<td><b class=\"%s\">%s</b></td>", status_class,
               active ? "да" : "нет");
    sb_appendf(sb, "<td><b class=\"%s\">", active ? status_class : "ok");
    html_escape(sb, value ? value : "-");
    sb_append(sb, "</b></td>");
    if (finding) {
        sb_appendf(sb, "<td><b class=\"%s\">+%d</b></td>", status_class,
                   heuristics_finding_score_contribution(hr, code));
    } else {
        sb_append(sb, "<td>0</td>");
    }
    if (finding && finding->has_location) html_hex32_cell(sb, finding->representative_rva);
    else sb_append(sb, "<td>-</td>");
    sb_append(sb, "<td class=\"wrap\">");
    html_escape(sb, finding_rule_text(code));
    sb_append(sb, "</td></tr>");
}

static void html_heuristic_matrix_count_row(StrBuf* sb,
                                            size_t* number,
                                            const HeuristicReport* hr,
                                            const char* code,
                                            const char* family,
                                            const char* default_severity,
                                            size_t count) {
    char value[64];
    snprintf(value, sizeof(value), "%zu", count);
    html_heuristic_matrix_row(sb, (*number)++, hr, code, family, default_severity,
                              count != 0, value);
}

static void html_heuristic_matrix_bool_row(StrBuf* sb,
                                           size_t* number,
                                           const HeuristicReport* hr,
                                           const char* code,
                                           const char* family,
                                           const char* default_severity,
                                           bool flag) {
    html_heuristic_matrix_row(sb, (*number)++, hr, code, family, default_severity,
                              flag, flag ? "да" : "нет");
}

static void html_heuristic_matrix_ratio_row(StrBuf* sb,
                                            size_t* number,
                                            const HeuristicReport* hr,
                                            const char* code,
                                            const char* family,
                                            const char* default_severity,
                                            double ratio,
                                            const char* label) {
    char value[96];
    (void)label;
    snprintf(value, sizeof(value), "%.3f", ratio);
    html_heuristic_matrix_row(sb, (*number)++, hr, code, family, default_severity,
                              html_find_finding_by_code(hr, code) != NULL, value);
}

static void html_heuristic_matrix_combo_row(StrBuf* sb,
                                            size_t* number,
                                            const HeuristicReport* hr,
                                            const char* code,
                                            const char* family,
                                            const char* default_severity) {
    bool active = html_find_finding_by_code(hr, code) != NULL;
    html_heuristic_matrix_row(sb, (*number)++, hr, code, family, default_severity,
                              active, active ? "выполнены" : "не выполнены");
}

static void html_append_static_heuristic_matrix(StrBuf* sb,
                                                const HeuristicReport* hr,
                                                size_t runtime_function_count) {
    if (!hr) return;
    sb_append(sb, "<details class=\"panel\" id=\"heuristic-matrix\" open><summary>Матрица покрытия 27 эвристических признаков</summary><div class=\"details-content\">");
    sb_appendf(sb, "<p class=\"muted\">Матрица отражает состояние всех 27 правил. Колонка «Базовый вес» показывает вес отдельного признака до применения верхней границы итоговой шкалы. Сумма базовых весов активных признаков составляет <b>%d</b>; итоговый Score вычислен как min(%d, 100) = <b>%d</b>. В колонке «Нарушение» значение <b class=\"warn\">да</b> означает наличие соответствующего наблюдения, значение <b class=\"ok\">нет</b> - отсутствие нарушения данного класса в анализируемом образце.</p>",
               hr->score_weight_sum, hr->score_weight_sum, hr->score);
    sb_append(sb, "<div class=\"table-wrap\"><table class=\"heuristic-matrix-table\">"
                  "<colgroup><col style=\"width:4%\"><col style=\"width:20%\"><col style=\"width:16%\">"
                  "<col style=\"width:8%\"><col style=\"width:7%\"><col style=\"width:12%\">"
                  "<col style=\"width:7%\"><col style=\"width:9%\"><col style=\"width:17%\"></colgroup><thead><tr>"
                  "<th>#</th><th>Код признака</th><th>Семейство</th><th>Базовая важность</th>"
                  "<th class=\"matrix-status-head\">Нарушение</th><th>Значение</th><th>Базовый вес</th><th>RVA</th><th>Проверяемый инвариант</th>"
                  "</tr></thead><tbody>");

    size_t number = 1;
    html_heuristic_matrix_count_row(sb, &number, hr, "pe_section_raw_oob", "table_integrity", "high", hr->pe_section_raw_oob);
    html_heuristic_matrix_count_row(sb, &number, hr, "pe_section_virtual_oob", "table_integrity", "high", hr->pe_section_virtual_oob);
    html_heuristic_matrix_count_row(sb, &number, hr, "pe_section_raw_overlap", "table_integrity", "medium", hr->pe_section_raw_overlaps);
    html_heuristic_matrix_count_row(sb, &number, hr, "pe_section_virtual_overlap", "table_integrity", "high", hr->pe_section_virtual_overlaps);
    html_heuristic_matrix_count_row(sb, &number, hr, "pe_section_misaligned", "table_integrity", "medium", hr->pe_section_misaligned);
    html_heuristic_matrix_bool_row(sb, &number, hr, "pe_exception_directory_oob", "table_integrity", "high", hr->pe_exception_directory_oob);

    bool no_runtime_active = html_find_finding_by_code(hr, "no_runtime_functions") != NULL;
    char runtime_value[64];
    snprintf(runtime_value, sizeof(runtime_value), "%zu", runtime_function_count);
    html_heuristic_matrix_row(sb, number++, hr, "no_runtime_functions", "table_integrity", "medium",
                              no_runtime_active, no_runtime_active ? "0 записей" : runtime_value);

    html_heuristic_matrix_count_row(sb, &number, hr, "invalid_ranges", "table_integrity", "medium", hr->rf_invalid_ranges);
    html_heuristic_matrix_count_row(sb, &number, hr, "rf_oob", "table_integrity", "medium", hr->rf_oob);
    html_heuristic_matrix_count_row(sb, &number, hr, "unwind_rva_oob", "table_integrity", "medium", hr->rf_unwind_oob);
    html_heuristic_matrix_count_row(sb, &number, hr, "rf_unsorted", "table_integrity", "medium", hr->rf_unsorted);
    html_heuristic_matrix_count_row(sb, &number, hr, "rf_overlaps", "table_integrity", "high", hr->rf_overlaps);
    html_heuristic_matrix_count_row(sb, &number, hr, "duplicate_begin", "table_integrity", "medium", hr->rf_duplicate_begins);

    html_heuristic_matrix_count_row(sb, &number, hr, "unwind_parse_fail", "unwind_integrity", "medium", hr->unwind_parse_fail);
    html_heuristic_matrix_count_row(sb, &number, hr, "unwind_anomalies", "unwind_integrity", "medium", hr->unwind_anomalies);

    html_heuristic_matrix_ratio_row(sb, &number, hr, "unwind_reuse_strong", "unwind_reuse", "high", hr->unwind_reuse_ratio, "reuse_ratio");
    html_heuristic_matrix_ratio_row(sb, &number, hr, "unwind_reuse_moderate", "unwind_reuse", "medium", hr->unwind_reuse_ratio, "reuse_ratio");
    html_heuristic_matrix_ratio_row(sb, &number, hr, "handler_dominance", "handler_dominance", "medium", hr->handler_reuse_ratio, "handler_ratio");

    html_heuristic_matrix_count_row(sb, &number, hr, "unwind_in_exec_section", "metadata_placement", "high", hr->unwind_exec_section);
    html_heuristic_matrix_count_row(sb, &number, hr, "unwind_unusual_section", "metadata_placement", "medium", hr->unwind_unusual_section);
    html_heuristic_matrix_count_row(sb, &number, hr, "unwind_writable_section", "metadata_placement", "medium", hr->unwind_writable_section);
    html_heuristic_matrix_count_row(sb, &number, hr, "handler_nonexec_section", "metadata_placement", "high", hr->handler_nonexec_section);
    html_heuristic_matrix_count_row(sb, &number, hr, "handler_writable_section", "metadata_placement", "medium", hr->handler_writable_section);

    html_heuristic_matrix_combo_row(sb, &number, hr, "placement_exec_nonexec_handler_combo", "metadata_placement", "high");
    html_heuristic_matrix_combo_row(sb, &number, hr, "placement_integrity_combo", "unwind_integrity", "medium");
    html_heuristic_matrix_combo_row(sb, &number, hr, "reuse_dominance_combo", "unwind_reuse", "medium");
    html_heuristic_matrix_combo_row(sb, &number, hr, "writable_metadata_handler_combo", "metadata_placement", "high");

    sb_append(sb, "</tbody></table></div></div></details>");
}

static void html_append_static_coverage_panel(StrBuf* sb,
                                              const HeuristicReport* hr,
                                              size_t runtime_function_count) {
    if (!hr) return;
    sb_append(sb, "<details class=\"panel\" id=\"static-coverage\"><summary>Полная контрольная карта статического анализа</summary><div class=\"details-content\">");
    sb_append(sb, "<p class=\"muted\">Карта сводит результаты проверки PE, Exception Directory, RUNTIME_FUNCTION, UNWIND_INFO, размещения metadata и адресов handlers. Ноль означает, что проверка выполнена, но нарушение соответствующего класса не обнаружено.</p>");
    sb_append(sb, "<div class=\"table-wrap\"><table><thead><tr>"
                  "<th>Слой анализа</th><th>Метрика / инвариант</th><th>Значение</th><th>Аналитическая интерпретация</th>"
                  "</tr></thead><tbody>");

    html_count_metric_row(sb, "PE layout", "Section raw OOB", hr->pe_section_raw_oob,
                          "Raw-диапазоны секций не должны выходить за границы входного файла.");
    html_count_metric_row(sb, "PE layout", "Section virtual OOB", hr->pe_section_virtual_oob,
                          "Virtual-диапазоны секций должны укладываться в SizeOfImage.");
    html_count_metric_row(sb, "PE layout", "Raw overlaps", hr->pe_section_raw_overlaps,
                          "Физические диапазоны секций в файле не должны пересекаться.");
    html_count_metric_row(sb, "PE layout", "Virtual overlaps", hr->pe_section_virtual_overlaps,
                          "RVA-диапазоны секций не должны давать неоднозначную карту image.");
    html_count_metric_row(sb, "PE layout", "Alignment issues", hr->pe_section_misaligned,
                          "Проверяется согласованность alignment-полей и секционных границ.");
    html_bool_metric_row(sb, "PE layout", "Exception Directory OOB", hr->pe_exception_directory_oob,
                         "Exception Directory должна указывать на читаемый массив RUNTIME_FUNCTION.");

    char runtime_function_count_text[64];
    snprintf(runtime_function_count_text, sizeof(runtime_function_count_text), "%zu", runtime_function_count);
    html_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "RUNTIME_FUNCTION total",
                    runtime_function_count_text, false,
                    "Количество записей RUNTIME_FUNCTION, извлеченных из Exception Directory и переданных в статический эвристический слой.");
    html_count_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "Invalid ranges", hr->rf_invalid_ranges,
                          "BeginAddress должен быть меньше EndAddress.");
    html_count_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "Function range OOB", hr->rf_oob,
                          "Begin/End функции должны находиться внутри image.");
    html_count_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "UnwindInfo RVA OOB", hr->rf_unwind_oob,
                          "UnwindInfoAddress должен мапиться в допустимые байты UNWIND_INFO.");
    html_count_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "Unsorted entries", hr->rf_unsorted,
                          "Таблица должна быть отсортирована по BeginAddress.");
    html_count_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "Overlapping ranges", hr->rf_overlaps,
                          "Пересечение диапазонов делает выбор записи для ControlPc неоднозначным.");
    html_count_metric_row(sb, ".pdata / RUNTIME_FUNCTION", "Duplicate BeginAddress", hr->rf_duplicate_begins,
                          "Повтор BeginAddress может скрывать конфликтующие описания одной функции.");

    html_count_metric_row(sb, ".xdata / UNWIND_INFO", "Parse failures", hr->unwind_parse_fail,
                          "UNWIND_INFO должна разбираться без обрыва header, codes, padding, tail и chain.");
    html_count_metric_row(sb, ".xdata / UNWIND_INFO", "Internal anomalies", hr->unwind_anomalies,
                          "Проверяются opcode, operands, CountOfCodes, chain flags, frame fields и sanity rules.");
    html_count_metric_row(sb, ".xdata / UNWIND_INFO", "ABI warnings", hr->unwind_abi_warnings,
                          "Формальные предупреждения ABI отделены от критических ошибок разбора.");

    html_count_metric_row(sb, "Metadata placement", "Unusual unwind section", hr->unwind_unusual_section,
                          "UNWIND_INFO обычно ожидается в .xdata/.rdata-подобной read-only области.");
    html_count_metric_row(sb, "Metadata placement", "Executable unwind section", hr->unwind_exec_section,
                          "Исполняемое размещение metadata повышает риск смешения кода и данных.");
    html_count_metric_row(sb, "Metadata placement", "Writable unwind section", hr->unwind_writable_section,
                          "Writable metadata может быть изменена runtime-ом или loader/protector-логикой.");
    html_count_metric_row(sb, "Handler targets", "Handler in non-executable section", hr->handler_nonexec_section,
                          "Handler RVA должен разрешаться в исполняемый код.");
    html_count_metric_row(sb, "Handler targets", "Handler in writable section", hr->handler_writable_section,
                          "Writable handler target требует отдельного объяснения и dynamic-проверки.");

    html_ratio_metric_row(sb, "Reuse / dominance", "Unwind reuse ratio", hr->unwind_reuse_ratio,
                          "Доля функций, указывающих на самый часто повторяющийся UnwindInfoRVA.");
    html_ratio_metric_row(sb, "Reuse / dominance", "Unwind unique ratio", hr->unwind_unique_ratio,
                          "Доля уникальных UnwindInfoRVA среди всех RUNTIME_FUNCTION.");
    char handler_count_text[64];
    snprintf(handler_count_text, sizeof(handler_count_text), "%zu", hr->handler_count);
    html_metric_row(sb, "Reuse / dominance", "Handler count", handler_count_text, false,
                    "Количество функций/записей, для которых найден handler target; само по себе это контекст, а не аномалия.");
    html_ratio_metric_row(sb, "Reuse / dominance", "Handler reuse ratio", hr->handler_reuse_ratio,
                          "Доля самого доминирующего handler среди функций с handler target.");

    html_count_metric_row(sb, "Оценка доказательств", "Слабые признаки", hr->weak_finding_count,
                          "Количество слабых признаков после применения системы эвристических правил.");
    html_count_metric_row(sb, "Оценка доказательств", "Признаки средней значимости", hr->medium_finding_count,
                          "Количество признаков средней значимости, влияющих на итоговую оценку и уверенность вывода.");
    html_count_metric_row(sb, "Оценка доказательств", "Сильные признаки", hr->strong_finding_count,
                          "Количество сильных признаков, несущих основную доказательную нагрузку.");
    html_evidence_families_metric_row(sb, hr);
    html_count_metric_row(sb, "Оценка доказательств", "Правила снижения уверенности", hr->mitigation_count,
                          "Количество правил, снизивших уверенность вследствие доброкачественных объяснений или недостаточного объёма контекста.");

    sb_append(sb, "</tbody></table></div></div></details>");
}

static const char* dynamic_event_type_ru(const char* type) {
    if (!type) return "неизвестное runtime-событие";
    if (strcmp(type, "exception") == 0) return "исключение";
    if (strcmp(type, "unwind_handler_hit") == 0) return "попадание в handler из UNWIND_INFO";
    if (strcmp(type, "veh_registration") == 0) return "регистрация VEH";
    if (strcmp(type, "veh_hit") == 0 || strcmp(type, "veh_handler_hit") == 0) return "попадание в VEH";
    if (strcmp(type, "vch_registration") == 0) return "регистрация VCH";
    if (strcmp(type, "vch_hit") == 0 || strcmp(type, "vch_handler_hit") == 0) return "попадание в VCH";
    if (strcmp(type, "uef_registration") == 0) return "установка UnhandledExceptionFilter";
    if (strcmp(type, "uef_hit") == 0 || strcmp(type, "uef_handler_hit") == 0) return "попадание в UnhandledExceptionFilter";
    if (strcmp(type, "rtl_add_function_table") == 0) return "регистрация runtime function table";
    if (strcmp(type, "rtl_install_function_table_callback") == 0) return "регистрация callback-based runtime function table";
    if (strcmp(type, "process_exit") == 0) return "завершение процесса";
    if (strcmp(type, "timeout") == 0) return "тайм-аут динамической сессии";
    return type;
}

static const char* dynamic_event_meaning_ru(const char* type) {
    if (!type) return "Событие подлежит сопоставлению с журналом выполнения и контекстом процесса.";
    if (strcmp(type, "exception") == 0) return "Процесс сгенерировал исключение; для интерпретации оцениваются first/second chance status и дальнейший маршрут обработки.";
    if (strcmp(type, "unwind_handler_hit") == 0) return "Исполнение дошло до handler, указанного в UNWIND_INFO; это runtime-подтверждение handler path.";
    if (strcmp(type, "veh_registration") == 0) return "Процесс зарегистрировал vectored exception handler через AddVectoredExceptionHandler.";
    if (strcmp(type, "veh_hit") == 0 || strcmp(type, "veh_handler_hit") == 0) return "Зарегистрированный VEH фактически получил управление во время обработки исключения.";
    if (strcmp(type, "vch_registration") == 0) return "Процесс зарегистрировал vectored continue handler через AddVectoredContinueHandler.";
    if (strcmp(type, "vch_hit") == 0 || strcmp(type, "vch_handler_hit") == 0) return "Зарегистрированный VCH фактически получил управление.";
    if (strcmp(type, "uef_registration") == 0) return "Процесс заменил top-level unhandled exception filter; это может быть обычной runtime-логикой или перехватом исключений.";
    if (strcmp(type, "uef_hit") == 0 || strcmp(type, "uef_handler_hit") == 0) return "UnhandledExceptionFilter фактически получил управление после исключения.";
    if (strcmp(type, "rtl_add_function_table") == 0) return "Процесс добавил RUNTIME_FUNCTION table во время выполнения; unwind-карта меняется уже после загрузки файла.";
    if (strcmp(type, "rtl_install_function_table_callback") == 0) return "Процесс установил callback, который может выдавать function table динамически; статическая .pdata уже не описывает всю картину.";
    if (strcmp(type, "process_exit") == 0) return "Процесс завершился; exit code помогает понять, дошла ли программа до штатного конца.";
    if (strcmp(type, "timeout") == 0) return "Динамическая сессия достигла лимита --timeout-ms; найденные события остаются полезными, но отсутствие других событий нельзя считать доказательством их отсутствия.";
    return "Событие сохранено как динамическое доказательство и требует ручного сопоставления аналитиком с журналом выполнения.";
}

static void html_append_dynamic_event_arguments(StrBuf* sb, const DynamicEvent* event) {
    if (!sb || !event) return;
    const char* type = event->type;
    if (strcmp(type, "veh_registration") == 0 || strcmp(type, "vch_registration") == 0) {
        sb_appendf(sb, "FirstHandler=%llu<br>Handler=<code>0x%llx</code>",
                   (unsigned long long)event->arg0,
                   (unsigned long long)event->arg1);
    } else if (strcmp(type, "uef_registration") == 0) {
        sb_appendf(sb, "Filter=<code>0x%llx</code>", (unsigned long long)event->arg0);
    } else if (strcmp(type, "rtl_add_function_table") == 0) {
        sb_appendf(sb,
                   "FunctionTable=<code>0x%llx</code><br>EntryCount=%llu<br>BaseAddress=<code>0x%llx</code>",
                   (unsigned long long)event->arg0,
                   (unsigned long long)event->arg1,
                   (unsigned long long)event->arg2);
    } else if (strcmp(type, "rtl_install_function_table_callback") == 0) {
        sb_appendf(sb,
                   "TableIdentifier=<code>0x%llx</code><br>BaseAddress=<code>0x%llx</code><br>Length=%llu<br>Callback=<code>0x%llx</code>",
                   (unsigned long long)event->arg0,
                   (unsigned long long)event->arg1,
                   (unsigned long long)event->arg2,
                   (unsigned long long)event->arg3);
    } else if (strcmp(type, "process_exit") == 0) {
        sb_appendf(sb, "ExitCode=%llu (<code>0x%llx</code>)",
                   (unsigned long long)event->arg0,
                   (unsigned long long)event->arg0);
    } else if (strcmp(type, "timeout") == 0) {
        sb_appendf(sb, "LimitMs=%llu", (unsigned long long)event->arg0);
    } else {
        sb_append(sb, "-");
    }
}

static void html_dynamic_evidence_row(StrBuf* sb,
                                      const char* signal,
                                      const char* observed,
                                      const char* rule,
                                      const char* interpretation) {
    sb_append(sb, "<tr><td class=\"wrap\">");
    html_escape(sb, signal);
    sb_append(sb, "</td><td class=\"wrap\">");
    html_escape(sb, observed);
    sb_append(sb, "</td><td class=\"wrap\">");
    html_escape(sb, rule);
    sb_append(sb, "</td><td class=\"wrap\">");
    html_escape(sb, interpretation);
    sb_append(sb, "</td></tr>");
}

static void html_append_dynamic_evidence_table(StrBuf* sb, const DynamicReport* dr) {
    if (!dr) return;
    sb_append(sb, "<h2 style=\"margin-top:18px\">Runtime evidence динамического слоя</h2>"
                  "<div class=\"table-wrap\"><table class=\"dynamic-evidence\"><thead><tr>"
                  "<th>Сигнал</th><th>Наблюдение</th><th>Объект проверки</th><th>Интерпретация</th>"
                  "</tr></thead><tbody>");

    if (!dr->ran) {
        if (dynamic_platform_unsupported(dr)) {
            html_dynamic_evidence_row(
                sb,
                "Динамическая проверка запрошена, но недоступна на текущей ОС",
                "Команда содержит --dynamic, однако collector использует Windows Debug API и не может выполниться на macOS/Linux.",
                "Сбор событий VEH/VCH/UEF, handler hit и runtime function table требует Windows x64.",
                "Отчёт содержит статический результат и явно фиксирует отсутствие динамических данных.");
        } else {
            html_dynamic_evidence_row(
                sb,
                "Динамическая проверка не выполнена",
                "Параметр --dynamic не использовался или runtime-сессия не стартовала.",
                "Runtime evidence формируется только при запуске target под отладчиком.",
                "Итоговая оценка не содержит динамического подтверждения.");
        }
    } else {
        bool any_signal = false;
        if (dr->rtl_add_function_table_calls || dr->rtl_install_function_table_cb_calls) {
            char observed[256];
            snprintf(observed, sizeof(observed),
                     "RtlAddFunctionTable: %u; callback: %u",
                     (unsigned)dr->rtl_add_function_table_calls,
                     (unsigned)dr->rtl_install_function_table_cb_calls);
            html_dynamic_evidence_row(
                sb,
                "Runtime function tables",
                observed,
                "Регистрация unwind/function table во время выполнения.",
                "Статическая .pdata может описывать не всю runtime-карту; допустимые причины включают JIT и системный runtime.");
            any_signal = true;
        }
        if (dr->veh_registrations || dr->vch_registrations || dr->uef_set_calls) {
            char observed[256];
            snprintf(observed, sizeof(observed),
                     "VEH: %u; VCH: %u; UEF: %u",
                     (unsigned)dr->veh_registrations,
                     (unsigned)dr->vch_registrations,
                     (unsigned)dr->uef_set_calls);
            html_dynamic_evidence_row(
                sb,
                "Регистрация exception handlers",
                observed,
                "Регистрация обработчиков через системные API.",
                "Наблюдение подтверждает runtime-слой обработки исключений, не представленный только структурами PE/.pdata.");
            any_signal = true;
        }
        if (dr->unwind_handler_hits || dr->veh_hits || dr->vch_hits || dr->uef_hits) {
            char observed[256];
            snprintf(observed, sizeof(observed),
                     "Unwind: %u; VEH: %u; VCH: %u; UEF: %u",
                     (unsigned)dr->unwind_handler_hits,
                     (unsigned)dr->veh_hits,
                     (unsigned)dr->vch_hits,
                     (unsigned)dr->uef_hits);
            html_dynamic_evidence_row(
                sb,
                "Фактические попадания в handlers",
                observed,
                "Фактическое достижение зарегистрированных или unwind-связанных handlers.",
                "Handler не только зарегистрирован, но и получил управление в данной сессии.");
            any_signal = true;
        }
        if (dr->exceptions_seen || dr->first_chance_seen || dr->second_chance_seen) {
            char observed[256];
            snprintf(observed, sizeof(observed),
                     "Всего: %u; first-chance: %u; second-chance: %u",
                     (unsigned)dr->exceptions_seen,
                     (unsigned)dr->first_chance_seen,
                     (unsigned)dr->second_chance_seen);
            html_dynamic_evidence_row(
                sb,
                "Поток исключений",
                observed,
                "Наличие исключений и стадия first-chance/second-chance.",
                "События позволяют сопоставить регистрацию handlers с фактическим маршрутом dispatch/unwind.");
            any_signal = true;
        }
        if (dr->timed_out || !dr->instrumentation_complete || dr->module_refresh_failures ||
            dr->module_list_truncations || dr->breakpoint_set_failures ||
            dr->breakpoint_capacity_drops || dr->pending_rearm_failures ||
            dr->breakpoint_rearm_failures || dr->dropped_events) {
            char observed[384];
            snprintf(observed, sizeof(observed),
                     "Тайм-аут: %s; полное покрытие: %s; ошибки модулей: %u; усечения: %u; ошибки breakpoint: %u; потеряно событий: %u",
                     dr->timed_out ? "да" : "нет",
                     dr->instrumentation_complete ? "да" : "нет",
                     (unsigned)dr->module_refresh_failures,
                     (unsigned)dr->module_list_truncations,
                     (unsigned)dr->breakpoint_set_failures,
                     (unsigned)dr->dropped_events);
            html_dynamic_evidence_row(
                sb,
                "Качество динамической сессии",
                observed,
                "Полнота установки breakpoint, обновления модулей и регистрации событий.",
                "Предупреждения сохраняют достоверность записанных событий, но снижают полноту динамических доказательств.");
            any_signal = true;
        }
        if (!any_signal) {
            html_dynamic_evidence_row(
                sb,
                "Runtime-сигналы не обнаружены",
                "Количество категорий: 0.",
                "Runtime-регистрации, handler hits, исключения и API динамических таблиц.",
                "В данной сессии динамические сигналы не зафиксированы; вывод учитывает границы покрытия.");
        }
    }
    sb_append(sb, "</tbody></table></div>");
}

static bool html_trace_addr_to_rva(const PeImage* img,
                                   const DynamicReport* dr,
                                   uint64_t addr,
                                   uint32_t* out_rva,
                                   const char** out_base_kind) {
    if (!img || !dr || !out_rva) return false;

    uint64_t base = 0;
    const char* base_kind = NULL;
    if (dr->runtime_image_base) {
        base = dr->runtime_image_base;
        base_kind = "runtime image base";
    } else if (img->image_base) {
        base = img->image_base;
        base_kind = "PE ImageBase";
    } else {
        return false;
    }

    if (addr < base) return false;
    uint64_t delta = addr - base;
    if (delta > 0xffffffffull) return false;
    if (img->size_of_image && delta >= (uint64_t)img->size_of_image) return false;

    *out_rva = (uint32_t)delta;
    if (out_base_kind) *out_base_kind = base_kind;
    return true;
}

static void html_append_trace_interpretation(StrBuf* sb,
                                             uint32_t index,
                                             uint64_t addr,
                                             bool mapped,
                                             uint32_t rva,
                                             const PeSection* section,
                                             const char* base_kind,
                                             bool has_prev,
                                             uint64_t prev_addr,
                                             bool prev_mapped,
                                             const PeSection* prev_section) {
    if (!sb) return;

    if (index == 0) {
        html_escape(sb, "Старт трассировки после handler hit. ");
    } else if (has_prev && prev_mapped != mapped) {
        if (mapped) {
            html_escape(sb, "Возврат в адресное пространство основного PE image. ");
        } else {
            html_escape(sb, "Переход за пределы основного PE image. ");
        }
    } else if (has_prev) {
        if (addr >= prev_addr) {
            uint64_t delta = addr - prev_addr;
            if (delta <= 0x10ull && mapped && prev_mapped && section == prev_section) {
                sb_appendf(sb, "Линейное продвижение в том же участке: RIP +0x%llx. ",
                           (unsigned long long)delta);
            } else {
                sb_appendf(sb, "Нелинейное смещение относительно предыдущего адреса: RIP +0x%llx. ",
                           (unsigned long long)delta);
            }
        } else {
            uint64_t delta = prev_addr - addr;
            sb_appendf(sb, "Обратное смещение относительно предыдущего адреса: RIP -0x%llx. ",
                       (unsigned long long)delta);
        }
    } else {
        sb_appendf(sb, "Точка трассировки #%u. ", (unsigned)index);
    }

    if (mapped && section) {
        char perms[4] = "---";
        section_permissions(section->characteristics, perms);
        sb_appendf(
            sb,
            "VA переводится в RVA 0x%08x относительно %s; секция %s, права %s. ",
            (unsigned)rva,
            base_kind ? base_kind : "image base",
            section->name,
            perms);
        if (section->characteristics & IMAGE_SCN_MEM_EXECUTE) {
            html_escape(
                sb,
                "Статус: исполняемая область основного модуля.");
        } else {
            html_escape(
                sb,
                "Статус: секция без execute-права; требуется проверка фактической memory protection.");
        }
    } else if (mapped) {
        sb_appendf(
            sb,
            "VA переводится в RVA 0x%08x относительно %s, но секция не определена. ",
            (unsigned)rva,
            base_kind ? base_kind : "image base");
        html_escape(
            sb,
            "Статус: section context не установлен.");
    } else {
        html_escape(
            sb,
            "VA не переводится в RVA основного PE image. Статус: адрес требует сопоставления со списком загруженных модулей или runtime memory map.");
    }
}

static bool trace_segment_same(const PeImage* img,
                               const DynamicReport* dr,
                               uint64_t a,
                               uint64_t b) {
    uint32_t arva = 0, brva = 0;
    const char* akind = NULL;
    const char* bkind = NULL;
    bool amapped = html_trace_addr_to_rva(img, dr, a, &arva, &akind);
    bool bmapped = html_trace_addr_to_rva(img, dr, b, &brva, &bkind);
    if (amapped != bmapped) return false;
    if (!amapped) return true;
    return pe_find_section_for_rva(img, arva) == pe_find_section_for_rva(img, brva);
}

static void html_append_trace_segment_row(StrBuf* sb,
                                          const PeImage* img,
                                          const DynamicReport* dr,
                                          uint32_t first,
                                          uint32_t last) {
    uint64_t start_addr = dr->trace[first];
    uint64_t end_addr = dr->trace[last];
    uint32_t rva = 0;
    const char* base_kind = NULL;
    bool mapped = html_trace_addr_to_rva(img, dr, start_addr, &rva, &base_kind);
    const PeSection* section = mapped ? pe_find_section_for_rva(img, rva) : NULL;

    sb_append(sb, "<tr>");
    sb_appendf(sb, "<td>%u..%u</td>", (unsigned)first, (unsigned)last);
    sb_append(sb, "<td><code>");
    sb_appendf(sb, "0x%llx", (unsigned long long)start_addr);
    if (first != last) {
        sb_append(sb, " .. ");
        sb_appendf(sb, "0x%llx", (unsigned long long)end_addr);
    }
    sb_append(sb, "</code></td>");
    if (mapped && section) {
        char perms[4] = "---";
        section_permissions(section->characteristics, perms);
        sb_append(sb, "<td>");
        html_escape(sb, section->name);
        sb_appendf(sb, " / <code>%s</code></td>", perms);
    } else if (mapped) {
        sb_append(sb, "<td>основной image, секция не определена</td>");
    } else {
        sb_append(sb, "<td>вне основного image</td>");
    }
    sb_append(sb, "<td class=\"wrap\">");
    if (mapped && section && (section->characteristics & IMAGE_SCN_MEM_EXECUTE)) {
        html_escape(sb, "Участок объясняется статической картой основного модуля: адреса переводятся в RVA и попадают в исполняемую секцию. Практический следующий шаг - сверить эти RVA с дизассемблированным кодом вокруг handler route.");
    } else if (mapped && section) {
        html_escape(sb, "Участок находится внутри основного image, но не в исполняемой секции. Это не доказывает ошибку само по себе, однако требует проверки прав секции и фактической защиты памяти во время выполнения.");
    } else if (mapped) {
        html_escape(sb, "Участок переводится в RVA основного image, но не получает однозначный section context. Для строгой интерпретации нужна сверка section table и runtime memory map.");
    } else {
        html_escape(sb, "Участок не объясняется статической картой основного PE image. Отчет фиксирует только факт выхода из этой карты; принадлежность адресов следует устанавливать по списку загруженных модулей или runtime memory map.");
    }
    sb_append(sb, "</td></tr>");
}

static void html_append_dynamic_trace_table(StrBuf* sb,
                                            const PeImage* img,
                                            const DynamicReport* dr) {
    if (!sb || !dr) return;

    sb_append(sb, "<h2 style=\"margin-top:18px\">RIP trace после handler hit</h2>"
                  "<p class=\"muted\">Фиксируется ограниченная последовательность RIP после достижения обработчика. Это не полная трассировка: collector сохраняет первые VA, необходимые для анализа ближайшего маршрута исполнения.</p>");

    sb_append(sb, "<div class=\"cards trace-cards\">");
    sb_appendf(sb, "<div class=\"card\">Запрошенный бюджет trace<b>%u</b></div>",
               (unsigned)dr->trace_steps);
    sb_appendf(sb, "<div class=\"card\">Записано RIP-адресов<b class=\"%s\">%u</b></div>",
               dr->trace_count ? "ok" : "neutral",
               (unsigned)dr->trace_count);
    sb_append(sb, "<div class=\"card\">Runtime ImageBase<b style=\"font-size:16px\"><code>");
    if (dr->runtime_image_base) sb_appendf(sb, "0x%llx", (unsigned long long)dr->runtime_image_base);
    else sb_append(sb, "не зафиксирован");
    sb_append(sb, "</code></b></div></div>");

    if (!dr->trace_count) {
        sb_append(sb, "<p class=\"empty\">RIP trace не записан. Обычно это означает, что trace_steps=0, handler hit не произошел, dynamic mode не дошел до точки трассировки или сессия завершилась раньше сбора single-step адресов.</p>");
        return;
    }

    sb_append(sb, "<h3>Сводка участков RIP trace</h3>"
                  "<p class=\"muted\">Последовательные RIP группируются по отношению к основной PE-карте: адреса внутри image отделяются от адресов, требующих сопоставления с runtime memory map.</p>"
                  "<div class=\"table-wrap\"><table><thead><tr>"
                  "<th>Индексы</th><th>Диапазон VA</th><th>Контекст</th><th>Вывод для анализа</th>"
                  "</tr></thead><tbody>");
    uint32_t seg_first = 0;
    for (uint32_t i = 1; i < dr->trace_count; i++) {
        if (!trace_segment_same(img, dr, dr->trace[i - 1u], dr->trace[i])) {
            html_append_trace_segment_row(sb, img, dr, seg_first, i - 1u);
            seg_first = i;
        }
    }
    html_append_trace_segment_row(sb, img, dr, seg_first, dr->trace_count - 1u);
    sb_append(sb, "</tbody></table></div>");

    sb_append(sb, "<h3>Детальная таблица RIP trace</h3>"
                  "<p class=\"muted\">Для каждого наблюдения приводятся VA, вычисленный RVA, секция и изменение RIP относительно предыдущей точки.</p>");
    sb_append(sb, "<div class=\"table-wrap\"><table><thead><tr>"
                  "<th>#</th><th>RIP / VA</th><th>RVA в основном image</th><th>Секция</th><th>Интерпретация</th>"
                  "</tr></thead><tbody>");
    for (uint32_t i = 0; i < dr->trace_count; i++) {
        uint64_t addr = dr->trace[i];
        uint32_t rva = 0;
        const char* base_kind = NULL;
        bool mapped = html_trace_addr_to_rva(img, dr, addr, &rva, &base_kind);
        const PeSection* section = mapped ? pe_find_section_for_rva(img, rva) : NULL;
        bool has_prev = i > 0;
        uint64_t prev_addr = has_prev ? dr->trace[i - 1u] : 0u;
        uint32_t prev_rva = 0;
        const char* prev_base_kind = NULL;
        bool prev_mapped = has_prev &&
            html_trace_addr_to_rva(img, dr, prev_addr, &prev_rva, &prev_base_kind);
        const PeSection* prev_section = prev_mapped ? pe_find_section_for_rva(img, prev_rva) : NULL;

        sb_append(sb, "<tr>");
        sb_appendf(sb, "<td>%u</td>", (unsigned)i);
        html_hex64_cell(sb, addr);
        if (mapped) html_hex32_cell(sb, rva);
        else sb_append(sb, "<td>-</td>");
        html_text_cell(sb, section ? section->name : "-");
        sb_append(sb, "<td class=\"wrap\">");
        html_append_trace_interpretation(
            sb, i, addr, mapped, rva, section, base_kind, has_prev, prev_addr, prev_mapped, prev_section);
        sb_append(sb, "</td></tr>");
    }
    sb_append(sb, "</tbody></table></div>");
}

bool report_write_html(const char* path,
                       const char* input_path,
                       const PeImage* img,
                       const RuntimeFunction* rf,
                       const UnwindSummary* us,
                       const bool* us_ok,
                       size_t n,
                       const HeuristicReport* hr,
                       const DynamicReport* dr,
                       const ReportMetadata* metadata,
                       StrBuf* err) {
    if (!path || !input_path || (!rf && n) || (!us && n) || (!us_ok && n) ||
        !report_model_valid(img, hr, dr) || !report_metadata_valid(metadata)) {
        sb_append(err, "Invalid arguments or metadata for HTML report.\n");
        return false;
    }

    StrBuf sb = {0};
    StrBuf anomalies = {0};
    if (!sb_init(&sb, 32768) ||
        !sb_init(&anomalies, 128)) {
        sb_free(&anomalies);
        sb_free(&sb);
        sb_append(err, "OOM.\n");
        return false;
    }

    const char* tool_version = metadata->tool_version;
    const char* generated_at = metadata->generated_at_utc;
    const char* schema_version = metadata->report_schema_version;
    const char* input_hash = metadata->input_sha256;
    const char* build_platform = metadata->build_platform;
    const char* build_compiler = metadata->build_compiler;
    const char* build_mode = metadata->build_mode;
    size_t parse_failures = 0;
    size_t anomaly_count = 0;
    size_t abi_warning_count = 0;
    for (size_t i = 0; i < n; i++) {
        if (!us_ok[i]) parse_failures++;
        if ((us[i].anomalies & report_non_abi_anomaly_mask()) != 0u) anomaly_count++;
        if ((us[i].anomalies & report_abi_anomaly_mask()) != 0u) abi_warning_count++;
    }
    AssessmentSummary top_summary = assessment_summary(hr, dr);

    sb_append(&sb, "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">");
    sb_append(&sb, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    sb_append(&sb, "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none';"
                   "style-src 'unsafe-inline';script-src 'unsafe-inline';img-src 'none';"
                   "base-uri 'none';form-action 'none'\">");
    sb_append(&sb, "<title>Отчет EH/Unwind Analyzer - ");
    html_escape(&sb, input_path ? input_path : "");
    sb_append(&sb, "</title><style>");
    sb_append(&sb,
        ":root{color-scheme:light;--bg:#edf3f6;--panel:#ffffff;--panel2:#f5f9fa;"
        "--text:#172532;--muted:#586a78;--line:#ced9df;--accent:#08747c;"
        "--ok:#167052;--warn:#9a6510;--danger:#b4233a;--shadow:0 6px 22px rgba(31,52,68,.07)}"
        "*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);"
        "font:15px/1.58 system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}"
        "main{width:100%;max-width:1720px;min-width:0;margin:auto;padding:30px}h1{margin:0;font-size:30px;letter-spacing:-.02em}"
        "h2{margin:0 0 13px;font-size:20px}h3{margin:24px 0 12px;font-size:17px}"
        "p{margin:7px 0}.muted{color:var(--muted);max-width:1180px}"
        ".hero,.panel{min-width:0;max-width:100%;background:var(--panel);border:1px solid var(--line);border-radius:13px;"
        "padding:21px;margin-bottom:18px;box-shadow:var(--shadow)}"
        ".hero{background:linear-gradient(135deg,#ffffff 0%,#eefafb 100%);border-top:4px solid var(--accent)}"
        ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:11px;"
        "margin:18px 0;align-items:stretch}.card{background:var(--panel2);border:1px solid var(--line);"
        "border-radius:9px;padding:13px 14px;display:flex;flex-direction:column;justify-content:space-between;min-height:96px}"
        ".card b{display:block;font-size:21px;margin-top:8px}.card-note{display:block;color:var(--muted);font-size:12px;margin-top:3px}"
        ".ok{color:var(--ok)}.warn{color:var(--warn)}.danger{color:var(--danger)}"
        ".neutral{color:var(--accent)}.badge{display:inline-block;border:1px solid currentColor;"
        "border-radius:999px;padding:2px 8px;font-size:12px;font-weight:650}.grid{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:18px}"
        ".table-wrap{width:100%;max-width:100%;min-width:0;overflow-x:auto;overflow-y:visible;"
        "border:1px solid var(--line);border-radius:9px;background:#fff;overscroll-behavior-x:none}"
        "table{width:100%;min-width:100%;border-collapse:collapse;line-height:1.42}th,td{padding:10px 12px;"
        "border-bottom:1px solid #dbe3e8;text-align:left;vertical-align:top}"
        "th+th,td+td{border-left:1px solid #e1e8ec}"
        "th{position:sticky;top:0;background:#e8f0f3;color:#304757;z-index:1;font-size:13px;"
        "line-height:1.35;vertical-align:middle;overflow-wrap:normal;word-break:normal}"
        "tr:last-child td{border-bottom:0}tr:hover td{background:#f4f8fa}"
        "code{color:#075d65;background:#edf5f6;border-radius:4px;padding:1px 4px;white-space:nowrap}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f8fa;"
        "border:1px solid var(--line);border-radius:8px;padding:13px;color:#273b49}"
        ".meta{display:grid;grid-template-columns:max-content 1fr;gap:5px 14px;"
        "overflow-wrap:anywhere}.meta dt{color:var(--muted)}.meta dd{margin:0;min-width:0}"
        ".meta dd code{white-space:normal;overflow-wrap:anywhere;word-break:break-word}"
        ".command-block{margin:0}.command-block summary{color:#075d65;font-weight:650;cursor:pointer}"
        ".command-block code{display:block;margin-top:8px;padding:8px 10px;line-height:1.45}"
        ".toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap}"
        "input{min-width:280px;max-width:100%;background:#fff;color:var(--text);"
        "border:1px solid #aebdc7;border-radius:7px;padding:9px 11px}"
        ".empty{color:var(--muted);font-style:italic}.wrap{white-space:normal;min-width:0;max-width:none;"
        "overflow-wrap:break-word;word-break:normal;hyphens:none}"
        ".code-wrap{white-space:normal;overflow-wrap:normal;word-break:normal}"
        "details.panel>summary{font-size:19px;font-weight:700;cursor:pointer;list-style-position:inside}");
    sb_append(&sb,
        ".details-content{margin-top:14px}.panel>p.muted,.details-content>p.muted{width:100%;max-width:none;"
        "margin:0 0 16px;padding:0 0 10px;border-bottom:1px solid #e2e9ed;text-align:left;text-wrap:pretty;hyphens:none}"
        ".finding-body>p{max-width:none;text-align:left;text-wrap:pretty;hyphens:none}"
        ".dynamic-evidence{width:100%;min-width:980px;table-layout:fixed}.dynamic-evidence th:nth-child(1){width:18%}"
        ".dynamic-evidence th:nth-child(2){width:22%}.dynamic-evidence th:nth-child(3){width:25%}"
        ".dynamic-evidence th:nth-child(4){width:35%}.dynamic-evidence .wrap{min-width:0;max-width:none;overflow-wrap:break-word}"
        ".assessment-cards,.dynamic-metrics,.trace-cards{grid-template-columns:repeat(3,minmax(0,1fr))}"
        ".runtime-table{width:100%;min-width:100%;table-layout:fixed}"
        ".runtime-table th,.runtime-table td{min-width:0;overflow-wrap:normal;word-break:normal}"
        ".runtime-table .wrap{min-width:0;max-width:none}"
        ".runtime-table .code-wrap{display:block;margin-top:4px;white-space:normal;overflow-wrap:anywhere;word-break:break-word}"
        ".register-cell,.field-cell,.handler-cell{min-width:0;max-width:none}"
        ".register-row{display:grid;grid-template-columns:104px minmax(0,1fr);gap:10px;align-items:start;padding:3px 0}"
        ".field-cell .register-row{grid-template-columns:1fr;gap:2px}"
        ".register-cell .register-row{grid-template-columns:132px minmax(0,1fr)}"
        ".handler-cell .register-row{grid-template-columns:1fr;gap:3px}"
        ".register-row+.register-row{border-top:1px dotted #d8e2e7}.register-label{color:var(--muted);font-size:12px}"
        ".register-value{min-width:0;overflow-wrap:normal;word-break:normal;text-align:left}.register-value code{display:inline-block;margin:0 3px 2px 0}"
        ".metric-card{justify-content:flex-start}.metric-list{display:grid;grid-template-columns:minmax(0,1fr) max-content;"
        "gap:5px 12px;margin:10px 0 0;line-height:1.35}.metric-list dt{color:var(--muted);min-width:0}"
        ".metric-list dd{margin:0;font-weight:700;text-align:right}.metric-list div{display:contents}");
    sb_append(&sb,
        ".diagnostics-table{width:100%;min-width:100%;table-layout:fixed}.evidence-table{width:100%;min-width:100%;table-layout:fixed}"
        ".diagnostics-table th,.diagnostics-table td{min-width:0}"
        ".diagnostics-table th{overflow-wrap:break-word;word-break:normal}"
        ".diagnostic-cell{min-width:0}.diagnostic-field{min-width:0;padding:3px 0}"
        ".diagnostic-field+.diagnostic-field{border-top:1px dotted #d8e2e7}"
        ".diagnostic-field>span{display:block;color:var(--muted);font-size:12px;margin-bottom:2px}"
        ".diagnostic-field code{display:inline-block;max-width:100%;white-space:nowrap}"
        ".diagnostics-table .code-wrap{white-space:normal;overflow-wrap:anywhere;word-break:break-word}"
        ".heuristic-matrix-table{width:100%;min-width:100%;table-layout:fixed}"
        ".heuristic-matrix-table th:first-child{text-align:left;white-space:nowrap}"
        ".heuristic-matrix-table td:first-child{text-align:center;white-space:nowrap}"
        ".heuristic-matrix-table th,.heuristic-matrix-table td{min-width:0;overflow-wrap:normal;word-break:normal}"
        ".heuristic-matrix-table thead th{height:58px;padding:10px 12px;text-align:left;vertical-align:middle;line-height:1.25;hyphens:none}"
        ".heuristic-matrix-table th:nth-child(5){white-space:nowrap;text-align:left}"
        ".heuristic-matrix-table td:nth-child(5){white-space:nowrap;text-align:left}"
        ".heuristic-matrix-table thead th.matrix-status-head{text-align:left;padding-left:12px;padding-right:8px}"
        ".heuristic-matrix-table td:nth-child(6){overflow-wrap:anywhere;word-break:break-word}"
        ".heuristic-matrix-table .finding-link{display:block;min-width:0}"
        ".heuristic-matrix-table .finding-link code{display:block;white-space:normal;overflow-wrap:anywhere;word-break:break-word}"
        ".heuristic-matrix-table .finding-link span{display:block;margin-top:4px}"
        ".diagnostics-table .wrap,.evidence-table .wrap{min-width:0;max-width:none;overflow-wrap:break-word;word-break:normal}"
        ".diagnostics-table code,.evidence-table code,.heuristic-matrix-table code,.runtime-table code{max-width:100%}"
        ".finding-list{display:grid;gap:10px;min-width:0}"
        ".finding-detail{min-width:0;max-width:100%;border:1px solid var(--line);border-radius:9px;background:#fbfdfe;scroll-margin-top:16px}"
        ".finding-detail:target{border-color:var(--accent);box-shadow:0 0 0 3px rgba(8,116,124,.12)}"
        ".finding-detail>summary{display:flex;align-items:center;gap:10px;flex-wrap:wrap;cursor:pointer;"
        "padding:12px 14px;font-weight:650}.finding-detail>summary span:first-child{flex:1;min-width:260px}"
        ".finding-detail>summary>code{max-width:100%;white-space:normal;overflow-wrap:anywhere;word-break:break-word}"
        ".finding-body{min-width:0;max-width:100%;padding:0 14px 14px;border-top:1px solid var(--line);overflow-wrap:break-word}"
        ".report-nav{display:flex;gap:8px;flex-wrap:wrap;margin-top:15px}.report-nav a{color:#075d65;"
        "text-decoration:none;border:1px solid #aac8cc;background:#f4fbfb;border-radius:999px;padding:5px 10px}"
        ".report-nav a:hover{background:#e3f5f5}.finding-link{display:inline-flex;align-items:center;gap:6px;"
        "color:#075d65;text-decoration:none}.finding-link span{font-size:12px;font-weight:650}.finding-link:hover span{text-decoration:underline}"
        "footer{text-align:center;color:var(--muted);padding:12px}"
        "@media(min-width:701px){.table-wrap{overflow-x:clip}}"
        "@media(max-width:700px){main{padding:12px}.hero,.panel{padding:15px}.meta{grid-template-columns:1fr}"
        ".grid{grid-template-columns:1fr}.assessment-cards,.dynamic-metrics,.trace-cards{grid-template-columns:1fr}"
        ".dynamic-evidence{min-width:760px}.runtime-table{min-width:1180px}.diagnostics-table{min-width:1100px}"
        ".evidence-table{min-width:980px}.heuristic-matrix-table{min-width:1180px}}"
        "@media print{body{background:#fff}main{max-width:none;padding:0}.hero,.panel{box-shadow:none;break-inside:avoid}"
        "details:not([open])>*:not(summary){display:block}.report-nav,.toolbar{display:none}th{position:static}}");
    sb_append(&sb, "</style></head><body><main>");

    sb_append(&sb, "<section class=\"hero\"><h1>EH/Unwind Analyzer</h1><p class=\"muted\">");
    html_escape(&sb, input_path ? input_path : "");
    sb_append(&sb, "</p><div class=\"cards\">");
    sb_appendf(&sb, "<div class=\"card\">Записи RUNTIME_FUNCTION<b>%zu</b></div>", n);
    sb_appendf(&sb, "<div class=\"card\">Ошибки разбора<b class=\"%s\">%zu</b></div>",
               parse_failures ? "danger" : "ok", parse_failures);
    sb_appendf(&sb, "<div class=\"card\">Структурные аномалии UNWIND_INFO<b class=\"%s\">%zu</b></div>",
               anomaly_count ? "warn" : "ok", anomaly_count);
    sb_appendf(&sb, "<div class=\"card\">Предупреждения x64 ABI<b class=\"%s\">%zu</b></div>",
               abi_warning_count ? "warn" : "ok", abi_warning_count);
    if (hr) {
        sb_appendf(&sb, "<div class=\"card\">Эвристические признаки<b class=\"%s\">%zu</b></div>",
                   hr->finding_count ? "warn" : "ok", hr->finding_count);
        sb_appendf(&sb, "<div class=\"card\">Статическая оценка<b class=\"%s\">%d / 100</b><span class=\"card-note\">Сумма базовых весов: %d</span></div>",
                   html_score_class(hr), hr->score, hr->score_weight_sum);
    } else {
        sb_append(&sb, "<div class=\"card\">Эвристические признаки<b class=\"neutral\" style=\"font-size:16px\">не запускалась</b></div>");
        sb_append(&sb, "<div class=\"card\">Статическая оценка<b class=\"neutral\" style=\"font-size:16px\">не запускалась</b></div>");
    }
    if (hr || dr) {
        sb_append(&sb, "<div class=\"card\">Итоговый вывод<b class=\"");
        sb_append(&sb, hr ? html_score_class(hr) : html_level_class(top_summary.runtime_evidence_level));
        sb_append(&sb, "\" style=\"font-size:16px\">");
        html_escape(&sb, ru_verdict_text(top_summary.final_verdict));
        sb_append(&sb, "</b></div>");
        sb_append(&sb, "<div class=\"card\">Статика / динамика<b style=\"font-size:16px\">");
        html_escape(&sb, ru_level_text(top_summary.static_evidence_level));
        sb_append(&sb, " / ");
        html_escape(&sb, ru_level_text(top_summary.runtime_evidence_level));
        sb_append(&sb, "</b></div>");
        if (!dr) {
            sb_append(&sb, "<div class=\"card\">Динамические сигналы (категории)<b class=\"neutral\" style=\"font-size:16px\">не запускалась</b></div>");
        } else if (dynamic_platform_unsupported(dr)) {
            sb_append(&sb, "<div class=\"card\">Динамические сигналы (категории)<b class=\"warn\" style=\"font-size:16px\">нет данных</b></div>");
        } else {
            sb_appendf(&sb, "<div class=\"card\">Динамические сигналы (категории)<b class=\"%s\">%u</b></div>",
                       html_level_class(top_summary.runtime_evidence_level),
                       top_summary.dynamic_signals);
        }
        sb_appendf(&sb, "<div class=\"card\">Уверенность итоговой оценки<b>%.0f%%</b></div>",
                   top_summary.final_confidence * 100.0);
    }
    sb_append(&sb, "<div class=\"card\">Динамическая проверка<b class=\"");
    sb_append(&sb, dynamic_status_class(dr));
    sb_append(&sb, "\" style=\"font-size:16px\">");
    html_escape(&sb, ru_status_text(dr));
    sb_append(&sb, "</b></div></div>");

    sb_append(&sb, "<dl class=\"meta\"><dt>Сформировано</dt><dd>");
    html_escape(&sb, generated_at);
    sb_append(&sb, "</dd><dt>Версия инструмента / схема отчёта</dt><dd>");
    html_escape(&sb, tool_version);
    sb_append(&sb, " / ");
    html_escape(&sb, schema_version);
    sb_append(&sb, "</dd><dt>SHA-256</dt><dd><code>");
    html_escape(&sb, input_hash);
    sb_append(&sb, "</code></dd><dt>Сборка</dt><dd>");
    html_escape(&sb, build_platform);
    sb_append(&sb, " / ");
    html_escape(&sb, build_compiler);
    sb_append(&sb, " / ");
    html_escape(&sb, build_mode);
    sb_append(&sb, "</dd><dt>Параметры анализа</dt><dd>");
    sb_appendf(&sb, "строгая проверка ABI x64: %s; обработка цепочек CHAININFO: %s; предельная глубина цепочки: %u",
               ru_yes_no(metadata->strict_abi),
               ru_yes_no(metadata->follow_chain),
               (unsigned)metadata->max_chain_depth);
    sb_appendf(&sb, "</dd><dt>Размер файла</dt><dd>%llu B</dd><dt>Команда запуска</dt><dd>"
                    "<details class=\"command-block\"><summary>Показать полную команду</summary><code>",
               (unsigned long long)metadata->input_size);
    html_escape(&sb, metadata->command_line);
    sb_append(&sb, "</code></details>");
    sb_append(&sb, "</dd></dl><nav class=\"report-nav\" aria-label=\"Разделы отчета\">"
                   "<a href=\"#pe-map\">PE-карта</a>");
    if (hr || dr) sb_append(&sb, "<a href=\"#assessment\">Итоговая оценка</a>");
    if (hr) {
        sb_append(&sb, "<a href=\"#findings\">Аналитические заключения</a>"
                       "<a href=\"#heuristic-matrix\">27 признаков</a>");
    }
    if (dr) sb_append(&sb, "<a href=\"#dynamic-analysis\">Динамика</a>");
    sb_append(&sb, "<a href=\"#runtime-functions\">RUNTIME_FUNCTION</a></nav></section>");

    sb_append(&sb, "<div class=\"grid\" id=\"pe-map\"><section class=\"panel\"><h2>Паспорт PE-образа</h2><p class=\"muted\">Ключевые поля PE задают границы образа и систему преобразования VA, RVA и file offset.</p><dl class=\"meta\">");
    sb_appendf(&sb,
        "<dt>ImageBase</dt><dd><code>0x%llx</code></dd>"
        "<dt>SizeOfImage</dt><dd><code>0x%x</code></dd>"
        "<dt>SizeOfHeaders</dt><dd><code>0x%x</code></dd>"
        "<dt>Exception directory</dt><dd><code>0x%08x + 0x%x</code></dd>"
        "<dt>SectionAlignment / FileAlignment</dt><dd><code>0x%x / 0x%x</code></dd></dl></section>",
        (unsigned long long)img->image_base, (unsigned)img->size_of_image,
        (unsigned)img->size_of_headers, (unsigned)img->exception_rva,
        (unsigned)img->exception_size, (unsigned)img->section_alignment,
        (unsigned)img->file_alignment);
    sb_append(&sb, "<section class=\"panel\"><h2>Структурные инварианты PE</h2><p class=\"muted\">Проверяются границы и пересечения секций, выравнивание и доступность Exception Directory. Результат определяет доверие к последующим преобразованиям адресов.</p><dl class=\"meta\">");
    sb_appendf(&sb,
        "<dt>Raw-диапазоны вне файла</dt><dd>%zu</dd><dt>Virtual-диапазоны вне image</dt><dd>%zu</dd>"
        "<dt>Пересечения raw</dt><dd>%zu</dd><dt>Пересечения virtual</dt><dd>%zu</dd>"
        "<dt>Невыровненные секции</dt><dd>%zu</dd><dt>Exception directory OOB</dt><dd>%s</dd>"
        "</dl></section></div>",
        img->section_raw_oob, img->section_virtual_oob, img->section_raw_overlaps,
        img->section_virtual_overlaps, img->section_misaligned,
        ru_yes_no(img->exception_directory_oob));

    sb_append(&sb, "<section class=\"panel\"><h2>Секционная карта</h2><p class=\"muted\">Таблица связывает RVA с диапазонами файла и правами R/W/X; по ней определяется размещение UNWIND_INFO и обработчиков.</p><div class=\"table-wrap\"><table>"
                   "<thead><tr><th>Имя</th><th>VirtualAddress</th><th>VirtualSize</th>"
                   "<th>Raw offset</th><th>Raw size</th><th>Права</th></tr></thead><tbody>");
    for (size_t i = 0; i < img->num_sections; i++) {
        const PeSection* section = &img->sections[i];
        char permissions[4];
        permissions[0] = (section->characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-';
        permissions[1] = (section->characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
        permissions[2] = (section->characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
        permissions[3] = '\0';
        sb_append(&sb, "<tr>");
        html_text_cell(&sb, section->name);
        html_hex32_cell(&sb, section->virtual_address);
        html_hex32_cell(&sb, section->virtual_size);
        html_hex32_cell(&sb, section->raw_ptr);
        html_hex32_cell(&sb, section->raw_size);
        html_text_cell(&sb, permissions);
        sb_append(&sb, "</tr>");
    }
    sb_append(&sb, "</tbody></table></div></section>");

    if (hr || dr) {
        AssessmentSummary summary = assessment_summary(hr, dr);
        ManualValidationSteps steps = collect_manual_validation_steps(hr, dr);
        sb_append(&sb, "<section class=\"panel\" id=\"assessment\"><h2>Сводная оценка</h2><p class=\"muted\">Объединяет статические findings, динамические сигналы и уверенность для ранжирования отклонений и определения приоритета ручной проверки.</p><div class=\"cards assessment-cards\">");
        sb_append(&sb, "<div class=\"card\">Вывод<b style=\"font-size:16px\">");
        html_escape(&sb, ru_verdict_text(summary.final_verdict));
        sb_append(&sb, "</b></div><div class=\"card\">Сила доказательств<b style=\"font-size:16px\">");
        html_escape(&sb, ru_case_strength_text(summary.strength));
        sb_appendf(&sb,
            "</b></div><div class=\"card\">Уверенность итоговой оценки<b>%.0f%%</b></div>"
            "<div class=\"card\">Статика / динамика<b style=\"font-size:16px\">",
            summary.final_confidence * 100.0);
        html_escape(&sb, ru_level_text(summary.static_evidence_level));
        sb_append(&sb, " / ");
        html_escape(&sb, ru_level_text(summary.runtime_evidence_level));
        sb_appendf(&sb,
            "</b></div><div class=\"card\">Корреляция слоев<b class=\"%s\" "
            "style=\"font-size:16px\">%s</b></div>",
            summary.correlated ? "ok" : "neutral",
            ru_yes_no(summary.correlated));
        if (!dr) {
            sb_append(&sb, "<div class=\"card\">Динамические сигналы (категории)<b class=\"neutral\" style=\"font-size:16px\">не запускалась</b></div></div>");
        } else if (dynamic_platform_unsupported(dr)) {
            sb_append(&sb, "<div class=\"card\">Динамические сигналы (категории)<b class=\"warn\" style=\"font-size:16px\">нет данных</b></div></div>");
        } else {
            sb_appendf(&sb, "<div class=\"card\">Динамические сигналы (категории)<b>%u</b></div></div>",
                       summary.dynamic_signals);
        }
        if (steps.count) {
            sb_append(&sb, "<h2 style=\"margin-top:18px\">Программа ручной верификации</h2><ol>");
            for (size_t i = 0; i < steps.count; i++) {
                sb_append(&sb, "<li>");
                html_append_manual_step_ru(&sb, steps.items[i]);
                sb_append(&sb, "</li>");
            }
            sb_append(&sb, "</ol>");
        }
        sb_append(&sb, "</section>");
    }

    html_append_key_diagnostics_panel(&sb, img, rf, us, us_ok, n);

    if (hr) {
        sb_append(&sb, "<section class=\"panel\" id=\"findings\"><h2>Результаты статического анализа</h2><p class=\"muted\">"
                       "Таблица перечисляет активные признаки и установленный для каждого из них базовый вес; карточки ниже раскрывают инвариант, наблюдение, координаты и доказательства. Finding (аналитическое наблюдение) не является автоматическим выводом о вредоносности.</p>");
        if (hr->finding_count == 0) {
            sb_append(&sb, "<p class=\"empty\">Статически значимые аналитические заключения по заданной системе эвристических правил не сформированы.</p>");
        } else {
            sb_append(&sb, "<div class=\"table-wrap\"><table><thead><tr><th>Важность</th>"
                           "<th>Признак</th><th>Семейство</th><th>Базовый вес</th><th>Объем наблюдения</th><th>Representative RVA</th>"
                           "<th>Секция</th></tr></thead><tbody>");
            for (size_t i = 0; i < hr->finding_count; i++) {
                const HeuristicFinding* finding = &hr->findings[i];
                size_t evidence_records = evidence_record_count(finding, img, rf, us, us_ok, n);
                sb_append(&sb, "<tr>");
                html_text_cell(&sb, ru_severity_text(finding->severity));
                sb_append(&sb, "<td class=\"wrap\"><b>");
                html_escape(&sb, finding_title_ru(finding->code));
                sb_append(&sb, "</b><br><code>");
                html_escape(&sb, finding->code);
                sb_append(&sb, "</code></td><td class=\"wrap\">");
                html_escape(&sb, ru_family_text(finding->family));
                sb_append(&sb, "<br><code>");
                html_escape(&sb, finding->family);
                sb_appendf(&sb, "</code></td><td><b>+%d</b></td><td class=\"wrap\">",
                           heuristics_finding_score_contribution(hr, finding->code));
                if (strstr(finding->code, "_combo") != NULL) {
                    sb_appendf(&sb, "Число частных срабатываний: %zu<br>Число записей-доказательств: %zu",
                               finding->affected_count, evidence_records);
                } else {
                    sb_appendf(&sb, "Число нарушений: %zu", finding->affected_count);
                    if (evidence_records != finding->affected_count && evidence_records != 0) {
                        sb_appendf(&sb, "<br>Число записей-доказательств: %zu", evidence_records);
                    }
                }
                sb_append(&sb, "</td>");
                if (finding->has_location) html_hex32_cell(&sb, finding->representative_rva);
                else sb_append(&sb, "<td>-</td>");
                html_text_cell(&sb, finding->has_location
                                      ? section_name_or_dash(img, finding->representative_rva)
                                      : "-");
                sb_append(&sb, "</tr>");
            }
            sb_append(&sb, "</tbody></table></div>");
            sb_append(&sb, "<h3>Доказательные карточки</h3><div class=\"finding-list\">");
            for (size_t i = 0; i < hr->finding_count; i++) {
                const HeuristicFinding* finding = &hr->findings[i];
                sb_append(&sb, "<details class=\"finding-detail\" id=\"finding-");
                html_escape(&sb, finding->code);
                sb_append(&sb, "\"");
                if (i == 0) sb_append(&sb, " open");
                sb_append(&sb, "><summary><span>");
                html_escape(&sb, finding_title_ru(finding->code));
                sb_append(&sb, "</span><code>");
                html_escape(&sb, finding->code);
                sb_append(&sb, "</code><span class=\"badge ");
                sb_append(&sb, html_matrix_status_class(true, finding->severity));
                sb_append(&sb, "\">");
                html_escape(&sb, ru_severity_text(finding->severity));
                sb_append(&sb, "</span></summary><div class=\"finding-body\"><p>");
                html_append_finding_message_ru(&sb, finding);
                sb_append(&sb, "</p>");
                html_append_finding_evidence_block(&sb, finding, img, rf, us, us_ok, n);
                sb_append(&sb, "</div></details>");
            }
            sb_append(&sb, "</div>");
        }
        if (hr->mitigation_count) {
            sb_append(&sb, "<h2 style=\"margin-top:18px\">Факторы снижения уверенности</h2><div class=\"table-wrap\">"
                           "<table><thead><tr><th>Код</th><th>Аналитическое пояснение</th></tr></thead><tbody>");
            for (size_t i = 0; i < hr->mitigation_count; i++) {
                sb_append(&sb, "<tr>");
                html_text_cell(&sb, hr->mitigations[i].code);
                sb_append(&sb, "<td class=\"wrap\">");
                html_append_mitigation_message_ru(&sb, hr->mitigations[i].code, hr->mitigations[i].message);
                sb_append(&sb, "</td></tr>");
            }
            sb_append(&sb, "</tbody></table></div>");
        }
        sb_append(&sb, "</section>");
        html_append_static_heuristic_matrix(&sb, hr, n);
        html_append_static_coverage_panel(&sb, hr, n);
    }

    if (dr) {
        sb_append(&sb, "<section class=\"panel\" id=\"dynamic-analysis\"><h2>Динамическая проверка</h2><p class=\"muted\">Показывает исключения, достижения handlers, регистрации VEH/VCH/UEF, вызовы API динамических function tables и полноту инструментирования. Наблюдения дополняют, но не заменяют статическую карту.</p><div class=\"cards dynamic-metrics\">");
        sb_append(&sb, "<div class=\"card\">Статус сессии<b class=\"");
        sb_append(&sb, dynamic_status_class(dr));
        sb_append(&sb, "\" style=\"font-size:16px\">");
        html_escape(&sb, ru_status_text(dr));
        sb_append(&sb, "</b></div>");
        sb_appendf(&sb, "<div class=\"card\">Исключения<b>%u</b></div>",
                   (unsigned)dr->exceptions_seen);
        sb_appendf(&sb, "<div class=\"card\">Попадания в handler<b>%u</b></div>",
                   (unsigned)(dr->unwind_handler_hits + dr->veh_hits + dr->vch_hits + dr->uef_hits));
        sb_appendf(&sb, "<div class=\"card\">Вызовы runtime-таблиц<b>%u</b></div>",
                   (unsigned)(dr->rtl_add_function_table_calls +
                              dr->rtl_install_function_table_cb_calls));
        sb_appendf(&sb, "<div class=\"card\">Потерянные события<b class=\"%s\">%u</b></div>",
                   dr->dropped_events ? "warn" : "ok", (unsigned)dr->dropped_events);
        sb_appendf(&sb, "<div class=\"card\">Инструментация завершена<b class=\"%s\">%s</b></div>",
                   dr->instrumentation_complete ? "ok" : "warn",
                   ru_yes_no(dr->instrumentation_complete));
        sb_appendf(&sb, "<div class=\"card metric-card\"><span>Точки останова обработчиков</span><dl class=\"metric-list\">"
                        "<div><dt>Обнаружено handlers</dt><dd>%u</dd></div>"
                        "<div><dt>Установлено breakpoint</dt><dd>%u</dd></div></dl></div>",
                   (unsigned)dr->unwind_handlers_discovered,
                   (unsigned)dr->unwind_handler_bp_set);
        sb_appendf(&sb, "<div class=\"card metric-card\"><span>Состояние breakpoint</span><dl class=\"metric-list\">"
                        "<div><dt>Попытки установки</dt><dd>%u</dd></div>"
                        "<div><dt>Ошибки установки</dt><dd class=\"%s\">%u</dd></div>"
                        "<div><dt>Пропуски по ёмкости</dt><dd class=\"%s\">%u</dd></div>"
                        "<div><dt>Ошибки перевзвода</dt><dd class=\"%s\">%u</dd></div></dl></div>",
                   (unsigned)dr->breakpoint_set_attempts,
                   dr->breakpoint_set_failures ? "warn" : "ok",
                   (unsigned)dr->breakpoint_set_failures,
                   dr->breakpoint_capacity_drops ? "warn" : "ok",
                   (unsigned)dr->breakpoint_capacity_drops,
                   (dr->pending_rearm_failures || dr->breakpoint_rearm_failures) ? "warn" : "ok",
                   (unsigned)(dr->pending_rearm_failures + dr->breakpoint_rearm_failures));
        sb_appendf(&sb, "<div class=\"card metric-card\"><span>Покрытие модулей</span><dl class=\"metric-list\">"
                        "<div><dt>Наблюдалось одновременно</dt><dd>%u</dd></div>"
                        "<div><dt>Ошибки обновления</dt><dd class=\"%s\">%u</dd></div>"
                        "<div><dt>Усечения списка</dt><dd class=\"%s\">%u</dd></div></dl></div>",
                   (unsigned)dr->modules_observed_peak,
                   dr->module_refresh_failures ? "warn" : "ok",
                   (unsigned)dr->module_refresh_failures,
                   dr->module_list_truncations ? "warn" : "ok",
                   (unsigned)dr->module_list_truncations);
        sb_append(&sb, "</div>");
        html_append_dynamic_evidence_table(&sb, dr);
        html_append_dynamic_trace_table(&sb, img, dr);
        if (dr->event_count) {
            sb_append(&sb, "<div class=\"table-wrap\"><table><thead><tr><th>Тип</th><th>Русское название</th><th>Модуль</th>"
                           "<th>Thread</th><th>Exception</th><th>Chance</th><th>Address</th>"
                           "<th>Параметры события</th><th>Аналитическая интерпретация</th>"
                           "</tr></thead><tbody>");
            for (uint32_t i = 0; i < dr->event_count; i++) {
                const DynamicEvent* event = &dr->events[i];
                sb_append(&sb, "<tr>");
                html_text_cell(&sb, event->type);
                html_text_cell(&sb, dynamic_event_type_ru(event->type));
                html_text_cell(&sb, event->module);
                sb_appendf(&sb, "<td>%u</td>", (unsigned)event->thread_id);
                html_hex32_cell(&sb, event->exception_code);
                html_text_cell(&sb, event->first_chance ? "first" : "second / n/a");
                html_hex64_cell(&sb, event->address);
                sb_append(&sb, "<td class=\"wrap\">");
                html_append_dynamic_event_arguments(&sb, event);
                sb_append(&sb, "</td>");
                sb_append(&sb, "<td class=\"wrap\">");
                html_escape(&sb, dynamic_event_meaning_ru(event->type));
                sb_append(&sb, "</td>");
                sb_append(&sb, "</tr>");
            }
            sb_append(&sb, "</tbody></table></div>");
        } else {
            sb_append(&sb, "<p class=\"empty\">Динамические события не записаны.</p>");
        }
        if (dr->details.s && dr->details.len) {
            sb_append(&sb, "<h2 style=\"margin-top:18px\">Журнал выполнения</h2><pre>");
            html_escape(&sb, dr->details.s);
            sb_append(&sb, "</pre>");
        }
        sb_append(&sb, "</section>");
    }

    sb_append(&sb, "<section class=\"panel\" id=\"runtime-functions\"><h2>Таблица RUNTIME_FUNCTION</h2><p class=\"muted\">Карта .pdata связывает диапазон кода с UNWIND_INFO, параметрами стека, регистрами, handler/chain и диагностикой. Таблица локализует запись, сформировавшую finding.</p><div class=\"toolbar\">"
                   "<input id=\"function-filter\" type=\"search\" placeholder=\"Фильтр по RVA, секции, флагу или ошибке\">"
                   "<span id=\"function-count\" class=\"muted\"></span></div>"
                   "<div class=\"table-wrap\"><table id=\"functions\" class=\"runtime-table\">"
                   "<colgroup><col style=\"width:4%\"><col style=\"width:14%\"><col style=\"width:11%\">"
                   "<col style=\"width:7%\"><col style=\"width:8%\"><col style=\"width:10%\">"
                   "<col style=\"width:17%\"><col style=\"width:9%\"><col style=\"width:20%\"></colgroup>"
                   "<thead><tr><th>#</th><th>Диапазон функции</th><th>Размещение UNWIND_INFO</th>"
                   "<th>Статус</th><th>Version и flags</th><th>Prolog / CountOfCodes</th>"
                   "<th>Stack, frame и сохранённые регистры</th><th>Handler и CHAININFO</th>"
                   "<th>Аномалии / ошибка</th></tr></thead><tbody>");
    for (size_t i = 0; i < n; i++) {
        char flags[64];
        unwind_flags_to_string(us[i].flags, flags);
        anomalies.len = 0;
        if (anomalies.s) anomalies.s[0] = '\0';
        anomalies_to_str(&anomalies, us[i].anomalies);
        sb_append(&sb, "<tr>");
        sb_appendf(&sb, "<td>%zu</td>", i);
        sb_appendf(&sb, "<td class=\"field-cell\"><div class=\"register-row\"><span class=\"register-label\">Begin RVA</span><span class=\"register-value\"><code>0x%08x</code></span></div>"
                        "<div class=\"register-row\"><span class=\"register-label\">End RVA</span><span class=\"register-value\"><code>0x%08x</code></span></div>"
                        "<div class=\"register-row\"><span class=\"register-label\">Размер</span><span class=\"register-value\"><code>%u B</code></span></div>"
                        "<div class=\"register-row\"><span class=\"register-label\">Секция кода</span><span class=\"register-value\">",
                   (unsigned)rf[i].begin_rva,
                   (unsigned)rf[i].end_rva,
                   (unsigned)runtime_function_size(&rf[i]));
        html_escape(&sb, section_name_or_dash(img, rf[i].begin_rva));
        sb_append(&sb, "</span></div></td>");
        sb_appendf(&sb, "<td class=\"field-cell\"><div class=\"register-row\"><span class=\"register-label\">Unwind RVA</span><span class=\"register-value\"><code>0x%08x</code></span></div>"
                        "<div class=\"register-row\"><span class=\"register-label\">Секция</span><span class=\"register-value\">",
                   (unsigned)rf[i].unwind_rva);
        html_escape(&sb, section_name_or_dash(img, rf[i].unwind_rva));
        sb_append(&sb, "</span></div></td>");
        sb_append(&sb, us_ok[i] ? "<td class=\"ok\">OK</td>" : "<td class=\"danger\">Ошибка</td>");
        sb_appendf(&sb, "<td class=\"field-cell\"><div class=\"register-row\"><span class=\"register-label\">Version</span><span class=\"register-value\"><code>%u</code></span></div>"
                        "<div class=\"register-row\"><span class=\"register-label\">Flags</span><span class=\"register-value\"><code>",
                   (unsigned)us[i].version);
        html_escape(&sb, flags);
        sb_append(&sb, "</code></span></div></td>");
        sb_appendf(&sb, "<td class=\"field-cell\"><div class=\"register-row\"><span class=\"register-label\">SizeOfProlog</span><span class=\"register-value\"><code>%u B</code></span></div>"
                        "<div class=\"register-row\"><span class=\"register-label\">CountOfCodes</span><span class=\"register-value\"><code>%u</code></span></div></td>",
                   (unsigned)us[i].prolog_size,
                   (unsigned)us[i].count_codes);
        html_frame_saved_cell(&sb, &us[i]);
        html_handler_chain_cell(&sb, &us[i]);
        sb_append(&sb, "<td class=\"wrap\">");
        if (us[i].anomalies) html_escape(&sb, anomalies.s);
        if (us[i].anomalies && us[i].parse_error[0]) sb_append(&sb, "; ");
        html_escape(&sb, us[i].parse_error);
        if (!us[i].anomalies && !us[i].parse_error[0]) sb_append(&sb, "-");
        html_append_unwind_diagnostic_inline(&sb, &us[i]);
        sb_append(&sb, "</td></tr>");
    }
    sb_append(&sb, "</tbody></table></div></section>");

    sb_append(&sb,
        "<footer>EH/Unwind Analyzer</footer></main><script>"
        "(()=>{const q=document.getElementById('function-filter');"
        "for(const wrap of document.querySelectorAll('.table-wrap'))wrap.scrollLeft=0;"
        "const rows=[...document.querySelectorAll('#functions tbody tr')];"
        "const out=document.getElementById('function-count');"
        "function run(){const needle=q.value.trim().toLowerCase();let shown=0;"
        "for(const row of rows){const visible=!needle||row.textContent.toLowerCase().includes(needle);"
        "row.hidden=!visible;if(visible)shown++;}out.textContent=`${shown} из ${rows.length}`;}"
        "function openFinding(){const id=location.hash.slice(1);if(!id.startsWith('finding-'))return;"
        "const target=document.getElementById(id);if(target&&target.tagName==='DETAILS')target.open=true;}"
        "q.addEventListener('input',run);window.addEventListener('hashchange',openFinding);run();openFinding();})();"
        "</script></body></html>");

    bool ok = sb_ok(&sb) && sb_ok(&anomalies);
    if (ok) ok = file_write_atomic(path, sb.s, sb.len);
    if (!ok) {
        sb_appendf(err, "%s: %s\n",
                   sb_ok(&sb) && sb_ok(&anomalies)
                       ? "Failed to write HTML"
                       : "Out of memory while building HTML report",
                   path);
    }
    sb_free(&anomalies);
    sb_free(&sb);
    return ok;
}
