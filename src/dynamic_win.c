#include "dynamic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifdef _WIN32

#include <windows.h>
#include <tlhelp32.h>

/* MinGW exposes exception_code as a compatibility macro. */
#ifdef exception_code
#undef exception_code
#endif

/* -------------------------------------------------------------------------- */

typedef struct ModInfo {
    char name[MAX_PATH];
    uint64_t base;
    uint64_t size;
} ModInfo;

typedef struct ModList {
    ModInfo mods[128];
    size_t count;
    bool truncated;
} ModList;

static void mods_init(ModList* ml) { if (ml) memset(ml, 0, sizeof(*ml)); }

static const char* basename_lower(const char* path) {
    const char* base = path;
    for (const char* p = path; *p; p++) {
        if (*p == '\\' || *p == '/') base = p + 1;
    }
    return base;
}

static void strlower_inplace(char* s) {
    for (; s && *s; s++) {
        if (*s >= 'A' && *s <= 'Z') *s = (char)(*s - 'A' + 'a');
    }
}

static void mods_add(ModList* ml, const char* name, uint64_t base, uint64_t size) {
    if (!ml || !name) return;
    if (ml->count >= sizeof(ml->mods)/sizeof(ml->mods[0])) {
        ml->truncated = true;
        return;
    }
    ModInfo* m = &ml->mods[ml->count++];
    strncpy(m->name, name, sizeof(m->name)-1);
    m->name[sizeof(m->name)-1] = 0;
    strlower_inplace(m->name);
    m->base = base;
    m->size = size;
}

static const ModInfo* mods_find(const ModList* ml, const char* name) {
    if (!ml || !name) return NULL;
    char tmp[MAX_PATH];
    strncpy(tmp, name, sizeof(tmp)-1);
    tmp[sizeof(tmp)-1] = 0;
    strlower_inplace(tmp);
    for (size_t i = 0; i < ml->count; i++) {
        if (strcmp(ml->mods[i].name, tmp) == 0) return &ml->mods[i];
    }
    return NULL;
}

static const ModInfo* mods_find_by_addr(const ModList* ml, uint64_t addr) {
    if (!ml) return NULL;
    for (size_t i = 0; i < ml->count; i++) {
        uint64_t b = ml->mods[i].base;
        uint64_t e = ml->mods[i].size > UINT64_MAX - b
            ? UINT64_MAX
            : b + ml->mods[i].size;
        if (addr >= b && addr < e) return &ml->mods[i];
    }
    return NULL;
}

static bool mods_refresh_toolhelp(ModList* ml, DWORD pid) {
    if (!ml) return false;
    ml->count = 0;
    ml->truncated = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32 me;
    memset(&me, 0, sizeof(me));
    me.dwSize = sizeof(me);
    if (!Module32First(snap, &me)) {
        CloseHandle(snap);
        return false;
    }
    do {
        const char* base = basename_lower(me.szModule);
        mods_add(ml, base, (uint64_t)(uintptr_t)me.modBaseAddr, (uint64_t)me.modBaseSize);
    } while (Module32Next(snap, &me));

    CloseHandle(snap);
    return true;
}

static bool mods_refresh_accounted(ModList* ml, DWORD pid, DynamicReport* dr) {
    if (!mods_refresh_toolhelp(ml, pid)) {
        if (dr) {
            dr->module_refresh_failures++;
            dr->instrumentation_complete = false;
        }
        return false;
    }
    if (dr) {
        if (ml->count > dr->modules_observed_peak) {
            dr->modules_observed_peak = (uint32_t)ml->count;
        }
        if (ml->truncated) {
            dr->module_list_truncations++;
            dr->instrumentation_complete = false;
        }
    }
    return true;
}

/* -------------------------------------------------------------------------- */

typedef enum BpKind {
    BP_UNWIND_HANDLER       = 1u << 0,
    BP_API_ADD_VEH          = 1u << 1,
    BP_API_ADD_VCH          = 1u << 2,
    BP_API_SET_UEF          = 1u << 3,
    BP_API_RTL_ADD_FT       = 1u << 4,
    BP_API_RTL_INSTALL_FTCB = 1u << 5,
    BP_CUSTOM_VEH_HANDLER   = 1u << 6,
    BP_CUSTOM_VCH_HANDLER   = 1u << 7,
    BP_CUSTOM_UEF           = 1u << 8
} BpKind;

typedef struct Breakpoint {
    uint64_t addr;
    uint8_t  orig;
    bool     armed;
    bool     rearm_pending;
    uint32_t kinds;
} Breakpoint;

typedef struct BpList {
    Breakpoint bps[512];
    size_t count;
} BpList;

static void bps_init(BpList* bl) { if (bl) memset(bl, 0, sizeof(*bl)); }

static Breakpoint* bps_find(BpList* bl, uint64_t addr) {
    if (!bl) return NULL;
    for (size_t i = 0; i < bl->count; i++) {
        if (bl->bps[i].addr == addr) return &bl->bps[i];
    }
    return NULL;
}

static bool write_one_byte(HANDLE hProcess, uint64_t addr, uint8_t val, StrBuf* err) {
    SIZE_T nw = 0;
    uint8_t b = val;
    if (WriteProcessMemory(hProcess, (LPVOID)(uintptr_t)addr, &b, 1, &nw) && nw == 1) {
        FlushInstructionCache(hProcess, (LPCVOID)(uintptr_t)addr, 1);
        return true;
    }
    DWORD werr = GetLastError();

    /* Retry with temporary RWX. Some targets map code pages RX. */
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, (LPVOID)(uintptr_t)addr, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        if (err) sb_appendf(err,
            "WriteProcessMemory failed at 0x%llx (err=%lu) and VirtualProtectEx failed (err=%lu)\n",
            (unsigned long long)addr, (unsigned long)werr, (unsigned long)GetLastError());
        return false;
    }

    nw = 0;
    if (!WriteProcessMemory(hProcess, (LPVOID)(uintptr_t)addr, &b, 1, &nw) || nw != 1) {
        DWORD werr2 = GetLastError();
        DWORD tmp = 0;
        VirtualProtectEx(hProcess, (LPVOID)(uintptr_t)addr, 1, oldProt, &tmp);
        if (err) sb_appendf(err,
            "WriteProcessMemory failed at 0x%llx after VirtualProtectEx (err=%lu)\n",
            (unsigned long long)addr, (unsigned long)werr2);
        return false;
    }

    FlushInstructionCache(hProcess, (LPCVOID)(uintptr_t)addr, 1);
    DWORD tmp = 0;
    VirtualProtectEx(hProcess, (LPVOID)(uintptr_t)addr, 1, oldProt, &tmp);
    return true;
}

static bool bp_set(HANDLE hProcess, Breakpoint* bp, StrBuf* err) {
    SIZE_T nread = 0;
    uint8_t b = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)bp->addr, &b, 1, &nread) || nread != 1) {
        if (err) sb_appendf(err, "ReadProcessMemory failed at 0x%llx (err=%lu)\n",
                            (unsigned long long)bp->addr, (unsigned long)GetLastError());
        return false;
    }
    bp->orig = b;
    if (!write_one_byte(hProcess, bp->addr, 0xCC, err)) return false;
    bp->armed = true;
    bp->rearm_pending = false;
    return true;
}

static bool bp_clear(HANDLE hProcess, Breakpoint* bp, StrBuf* err) {
    if (!bp || !bp->armed) return true;
    if (!write_one_byte(hProcess, bp->addr, bp->orig, err)) return false;
    bp->armed = false;
    return true;
}

static bool bp_add_and_arm(BpList* bl, HANDLE hProcess, uint64_t addr, BpKind kind, StrBuf* err) {
    if (!bl) return false;

    Breakpoint* ex = bps_find(bl, addr);
    if (ex) {
        ex->kinds |= (uint32_t)kind;
        if (ex->armed || ex->rearm_pending) return true;
        return bp_set(hProcess, ex, err);
    }

    if (bl->count >= sizeof(bl->bps)/sizeof(bl->bps[0])) return false;
    Breakpoint* bp = &bl->bps[bl->count];
    memset(bp, 0, sizeof(*bp));
    bp->addr = addr;
    bp->kinds = (uint32_t)kind;

    if (!bp_set(hProcess, bp, err)) return false;
    bl->count++;
    return true;
}

/* -------------------------------------------------------------------------- */
/* Log each breakpoint's target address, module and installed INT3 byte (0xCC). */

static const char* bp_kind_name(BpKind k); /* forward */
static void dr_append(DynamicReport* dr, const char* fmt, ...); /* forward */

static bool bp_peek_byte(HANDLE hProcess, uint64_t addr, uint8_t* outb, StrBuf* err) {
    if (!outb) return false;
    SIZE_T nr = 0;
    uint8_t b = 0;
    if (ReadProcessMemory(hProcess, (LPCVOID)(uintptr_t)addr, &b, 1, &nr) && nr == 1) {
        *outb = b;
        return true;
    }
    if (err) sb_appendf(err, "ReadProcessMemory peek failed at 0x%llx (err=%lu)\n",
                        (unsigned long long)addr, (unsigned long)GetLastError());
    return false;
}

static void format_bp_location(const ModList* mods, uint64_t addr, char* out, size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = 0;
    const ModInfo* mi = mods ? mods_find_by_addr(mods, addr) : NULL;
    if (mi) {
        snprintf(out, outsz, "%s+0x%llx (0x%llx)",
                 mi->name,
                 (unsigned long long)(addr - mi->base),
                 (unsigned long long)addr);
    } else {
        snprintf(out, outsz, "0x%llx", (unsigned long long)addr);
    }
}

/* Log the self-check in dr->details only on the first placement attempt per address. */
static bool bp_add_and_arm_selfcheck(BpList* bl,
                                    HANDLE hProcess,
                                    const ModList* mods,
                                    DynamicReport* dr,
                                    uint64_t addr,
                                    BpKind kind,
                                    const char* what,
                                    StrBuf* err) {
    if (!bl) return false;

    Breakpoint* existing = bps_find(bl, addr);
    bool first_time = (existing == NULL);
    bool capacity_exhausted =
        first_time && bl->count >= sizeof(bl->bps) / sizeof(bl->bps[0]);
    if (dr && first_time) dr->breakpoint_set_attempts++;

    StrBuf te; sb_init(&te, 256);
    bool ok = bp_add_and_arm(bl, hProcess, addr, kind, &te);

    if (dr && !ok) {
        dr->breakpoint_set_failures++;
        if (capacity_exhausted) dr->breakpoint_capacity_drops++;
        dr->instrumentation_complete = false;
    }

    if (dr && first_time) {
        char loc[192];
        format_bp_location(mods, addr, loc, sizeof(loc));

        uint8_t cur = 0xFF;
        StrBuf peek_err; sb_init(&peek_err, 128);
        bool peek_ok = bp_peek_byte(hProcess, addr, &cur, &peek_err);

        if (ok) {
            if (peek_ok) {
                dr_append(dr, "[SelfCheck] BP set %-22s %-40s at %s : OK (byte=0x%02x)%s\n",
                          bp_kind_name(kind),
                          (what ? what : ""),
                          loc,
                          (unsigned)cur,
                          (cur == 0xCC ? "" : " [WARN: not INT3]"));
            } else {
                dr_append(dr, "[SelfCheck] BP set %-22s %-40s at %s : OK (peek failed: %s)\n",
                          bp_kind_name(kind), (what ? what : ""), loc,
                          (peek_err.s ? peek_err.s : "unknown"));
            }
        } else {
            dr_append(dr, "[SelfCheck] BP set %-22s %-40s at %s : FAIL%s%s",
                      bp_kind_name(kind),
                      (what ? what : ""),
                      loc,
                      (te.len ? " : " : "\n"),
                      (te.len ? te.s : "\n"));
        }

        sb_free(&peek_err);
    }

    if (!ok && err && te.len) sb_append(err, te.s);
    sb_free(&te);
    return ok;
}


/* -------------------------------------------------------------------------- */

/* Pending breakpoint re-arming must be tracked per-thread.
   With multiple threads, a single global pending pointer can cause lost rearms. */
typedef struct PendingRearmEntry {
    DWORD tid;
    Breakpoint* bp;
} PendingRearmEntry;

typedef struct PendingRearmList {
    PendingRearmEntry e[64];
} PendingRearmList;

static void pending_rearm_init(PendingRearmList* pr) {
    if (!pr) return;
    memset(pr, 0, sizeof(*pr));
}

static bool pending_rearm_set(PendingRearmList* pr, DWORD tid, Breakpoint* bp) {
    if (!pr || !bp) return false;
    /* overwrite existing */
    for (size_t i = 0; i < sizeof(pr->e)/sizeof(pr->e[0]); i++) {
        if (pr->e[i].bp && pr->e[i].tid == tid) {
            pr->e[i].bp = bp;
            return true;
        }
    }
    /* take a free slot */
    for (size_t i = 0; i < sizeof(pr->e)/sizeof(pr->e[0]); i++) {
        if (!pr->e[i].bp) {
            pr->e[i].tid = tid;
            pr->e[i].bp = bp;
            return true;
        }
    }
    return false;
}

static Breakpoint* pending_rearm_take(PendingRearmList* pr, DWORD tid) {
    if (!pr) return NULL;
    for (size_t i = 0; i < sizeof(pr->e)/sizeof(pr->e[0]); i++) {
        if (pr->e[i].bp && pr->e[i].tid == tid) {
            Breakpoint* bp = pr->e[i].bp;
            pr->e[i].bp = NULL;
            pr->e[i].tid = 0;
            return bp;
        }
    }
    return NULL;
}

static HANDLE open_event_thread(DWORD tid) {
    return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
}

static void close_event_thread(HANDLE h) {
    if (h) CloseHandle(h);
}

static void dr_append(DynamicReport* dr, const char* fmt, ...) {
    if (!dr) return;
    va_list ap;
    va_start(ap, fmt);
    /* Reuse sb_appendf's variadic through vsnprintf into temp */
    char tmp[1024];
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    tmp[sizeof(tmp)-1] = 0;
    sb_append(&dr->details, tmp);
}

static void dynamic_event_add(DynamicReport* dr,
                              const ModList* mods,
                              const char* type,
                              DWORD thread_id,
                              uint64_t address,
                              uint32_t exception_code,
                              bool first_chance,
                              uint64_t arg0,
                              uint64_t arg1,
                              uint64_t arg2,
                              uint64_t arg3) {
    if (!dr || !type) return;
    if (dr->event_count >= DYNAMIC_MAX_EVENTS) {
        dr->dropped_events++;
        dr->instrumentation_complete = false;
        return;
    }

    DynamicEvent* event = &dr->events[dr->event_count++];
    memset(event, 0, sizeof(*event));
    snprintf(event->type, sizeof(event->type), "%s", type);
    const ModInfo* module = mods_find_by_addr(mods, address);
    if (module) snprintf(event->module, sizeof(event->module), "%s", module->name);
    event->thread_id = (uint32_t)thread_id;
    event->exception_code = exception_code;
    event->first_chance = first_chance;
    event->address = address;
    event->arg0 = arg0;
    event->arg1 = arg1;
    event->arg2 = arg2;
    event->arg3 = arg3;
}

void dynamic_report_init(DynamicReport* dr) {
    if (!dr) return;
    memset(dr, 0, sizeof(*dr));
    dr->enabled = true;
    dr->instrumentation_complete = true;
    sb_init(&dr->details, 2048);
}

void dynamic_report_free(DynamicReport* dr) {
    if (!dr) return;
    sb_free(&dr->details);
    memset(dr, 0, sizeof(*dr));
}

static bool append_backslashes(StrBuf* out, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!sb_appendn(out, "\\", 1)) return false;
    }
    return true;
}

/* Quote one argument according to the Windows C runtime command-line rules. */
static bool append_cmd_arg(StrBuf* out, const char* arg) {
    if (!out || !arg) return false;
    bool quote = (*arg == '\0') || strpbrk(arg, " \t\"") != NULL;
    if (!quote) return sb_append(out, arg);
    if (!sb_appendn(out, "\"", 1)) return false;

    const char* p = arg;
    while (*p) {
        size_t backslashes = 0;
        while (*p == '\\') {
            backslashes++;
            p++;
        }
        if (*p == '"') {
            if (!append_backslashes(out, backslashes * 2u + 1u)) return false;
            if (!sb_appendn(out, "\"", 1)) return false;
            p++;
        } else if (*p == '\0') {
            if (!append_backslashes(out, backslashes * 2u)) return false;
        } else {
            if (!append_backslashes(out, backslashes)) return false;
            if (!sb_appendn(out, p, 1)) return false;
            p++;
        }
    }
    return sb_appendn(out, "\"", 1);
}

/* Build a command line for CreateProcessA while preserving target arguments. */
static bool build_cmdline(const char* path, const char* const* argv, int argc, StrBuf* out) {
    if (!path || !out) return false;
    out->len = 0;
    if (out->s) out->s[0] = 0;

    if (!append_cmd_arg(out, path)) return false;

    for (int i = 0; i < argc; i++) {
        const char* a = argv[i];
        if (!a || !sb_appendn(out, " ", 1) || !append_cmd_arg(out, a)) return false;
    }
    return true;
}

/* Resolve a symbol to (real module basename, offset) in *this* process.
   Important: many APIs are forwarded (e.g. kernel32 -> kernelbase). */
typedef struct LocalProcLoc {
    char mod_name[MAX_PATH]; /* lower-case basename, e.g. kernelbase.dll */
    uint64_t offset;
} LocalProcLoc;

static bool local_proc_loc(const char* preferred_mod, const char* sym, LocalProcLoc* out) {
    if (!preferred_mod || !sym || !out) return false;
    memset(out, 0, sizeof(*out));

    HMODULE hPref = GetModuleHandleA(preferred_mod);
    if (!hPref) return false;

    FARPROC p = GetProcAddress(hPref, sym);
    if (!p) return false;

    HMODULE hReal = NULL;
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)p, &hReal) || !hReal) {
        hReal = hPref;
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

    char path[MAX_PATH];
    memset(path, 0, sizeof(path));
    if (!GetModuleFileNameA(hReal, path, (DWORD)sizeof(path))) {
        strncpy(out->mod_name, preferred_mod, sizeof(out->mod_name)-1);
        out->mod_name[sizeof(out->mod_name)-1] = 0;
        strlower_inplace(out->mod_name);
    } else {
        const char* base = basename_lower(path);
        strncpy(out->mod_name, base, sizeof(out->mod_name)-1);
        out->mod_name[sizeof(out->mod_name)-1] = 0;
        strlower_inplace(out->mod_name);
    }

    out->offset = (uint64_t)(uintptr_t)p - (uint64_t)(uintptr_t)hReal;
    return true;
}

static bool add_api_bps_if_ready(BpList* bl, HANDLE hProcess, const ModList* mods, DynamicReport* dr, StrBuf* err) {
    if (!bl || !mods) return false;

    const struct {
        const char* preferred_mod;
        const char* sym;
        BpKind kind;
    } apis[] = {
        {"kernel32.dll", "AddVectoredExceptionHandler", BP_API_ADD_VEH},
        {"kernel32.dll", "AddVectoredContinueHandler", BP_API_ADD_VCH},
        {"kernel32.dll", "SetUnhandledExceptionFilter", BP_API_SET_UEF},
        {"ntdll.dll",    "RtlAddFunctionTable", BP_API_RTL_ADD_FT},
        {"ntdll.dll",    "RtlInstallFunctionTableCallback", BP_API_RTL_INSTALL_FTCB},
    };

    for (size_t i = 0; i < sizeof(apis)/sizeof(apis[0]); i++) {
        LocalProcLoc loc;
        if (!local_proc_loc(apis[i].preferred_mod, apis[i].sym, &loc)) continue;

        const ModInfo* m = mods_find(mods, loc.mod_name);
        if (!m) {
            if (dr) dr_append(dr, "[Dynamic] API %s resolved to %s but module not present in target yet\n",
                              apis[i].sym, loc.mod_name);
            continue;
        }

        uint64_t bp_addr = m->base + loc.offset;
        {
            char what[320];
            snprintf(what, sizeof(what), "%s!%s", loc.mod_name, apis[i].sym);
            if (!bp_add_and_arm_selfcheck(bl, hProcess, mods, dr, bp_addr, apis[i].kind, what, err)) {
                if (dr) dr_append(dr, "[Dynamic] failed to set API breakpoint %s at 0x%llx\n",
                                  what, (unsigned long long)bp_addr);
            }
        }
    }

    return true;
}


static const char* bp_kind_name(BpKind k) {
    switch (k) {
        case BP_UNWIND_HANDLER: return "unwind_handler";
        case BP_API_ADD_VEH: return "api_add_veh";
        case BP_API_ADD_VCH: return "api_add_vch";
        case BP_API_SET_UEF: return "api_set_uef";
        case BP_API_RTL_ADD_FT: return "api_rtl_add_ft";
        case BP_API_RTL_INSTALL_FTCB: return "api_rtl_install_ftcb";
        case BP_CUSTOM_VEH_HANDLER: return "veh_handler";
        case BP_CUSTOM_VCH_HANDLER: return "vch_handler";
        case BP_CUSTOM_UEF: return "uef_handler";
        default: return "bp";
    }
}

static void add_trace(DynamicReport* dr, uint64_t rip) {
    if (!dr) return;
    if (dr->trace_count >= (uint32_t)(sizeof(dr->trace)/sizeof(dr->trace[0]))) return;
    dr->trace[dr->trace_count++] = rip;
}

static void start_trace(DynamicReport* dr,
                        uint32_t trace_steps,
                        DWORD tid,
                        uint64_t rip,
                        bool* tracing,
                        DWORD* trace_tid,
                        uint32_t* trace_left) {
    if (!dr || !tracing || !trace_tid || !trace_left ||
        trace_steps == 0 || dr->trace_count != 0) {
        return;
    }

    uint32_t budget = trace_steps > 256u ? 256u : trace_steps;
    add_trace(dr, rip);
    *trace_left = budget - 1u;
    *tracing = *trace_left > 0;
    *trace_tid = *tracing ? tid : 0;
}

static void addr_to_loc(const PeImage* img, uint64_t base, uint64_t addr, char* out, size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = 0;
    if (!img || addr < base) {
        snprintf(out, outsz, "0x%llx", (unsigned long long)addr);
        return;
    }
    uint32_t rva = (uint32_t)(addr - base);
    const PeSection* s = pe_find_section_for_rva(img, rva);
    if (s) snprintf(out, outsz, "0x%llx (rva=0x%08x sec=%s)", (unsigned long long)addr, (unsigned)rva, s->name);
    else snprintf(out, outsz, "0x%llx (rva=0x%08x)", (unsigned long long)addr, (unsigned)rva);
}

/* -------------------------------------------------------------------------- */

bool dynamic_collect_windows(const char* pe_path,
                            const char* const* child_argv,
                            int child_argc,
                            const PeImage* img,
                            const RuntimeFunction* rf,
                            const UnwindSummary* us,
                            const bool* us_ok,
                            size_t rf_count,
                            uint32_t timeout_ms,
                            uint32_t trace_steps,
                            DynamicReport* out,
                            StrBuf* err) {
    if (!out || !err || !pe_path || !img) return false;
    if (rf_count > 0 && (!rf || !us || !us_ok)) return false;

    dynamic_report_init(out);
    if (!sb_ok(&out->details)) {
        sb_append(err, "Out of memory (dynamic report buffer).\n");
        return false;
    }
    out->enabled = true;
    out->timeout_ms = timeout_ms;
    out->trace_steps = trace_steps > 256u ? 256u : trace_steps;

    StrBuf cmd;
    if (!sb_init(&cmd, 1024)) {
        sb_append(err, "Out of memory (command line buffer).\n");
        return false;
    }
    if (!build_cmdline(pe_path, child_argv, child_argc, &cmd)) {
        sb_append(err, "Failed to build command line.\n");
        sb_free(&cmd);
        return false;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    /*
     * Do not use CREATE_SUSPENDED.
     *
     * The Windows Debug API event stream must start immediately after
     * CreateProcess. On some configurations,
     * creating the debuggee suspended can result in no debug events
     * being delivered (no CREATE_PROCESS_DEBUG_EVENT), which causes
     * a deadlock (the tool waits forever, never resumes the thread).
     */
    DWORD flags = DEBUG_ONLY_THIS_PROCESS;

    if (!CreateProcessA(NULL, cmd.s, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
        sb_appendf(err, "CreateProcess failed (err=%lu)\n", GetLastError());
        sb_free(&cmd);
        return false;
    }

    out->ran = true;

    HANDLE hProcess = pi.hProcess;
    DWORD pid = pi.dwProcessId;

    ModList mods;
    mods_init(&mods);

    BpList bps;
    bps_init(&bps);

    /* Collect unique handler RVAs from static parse. */
    uint32_t* handler_rvas = (uint32_t*)calloc(rf_count ? rf_count : 1, sizeof(uint32_t));
    if (!handler_rvas) {
        sb_append(err, "Out of memory (handler RVA list).\n");
        TerminateProcess(hProcess, 0);
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        sb_free(&cmd);
        return false;
    }
    size_t handler_count = 0;
    for (size_t i = 0; i < rf_count; i++) {
        if (!us_ok[i] || !us[i].has_handler) continue;
        uint32_t hr = us[i].handler_rva;
        bool seen = false;
        for (size_t j = 0; j < handler_count; j++) {
            if (handler_rvas[j] == hr) { seen = true; break; }
        }
        if (!seen) handler_rvas[handler_count++] = hr;
    }
    out->unwind_handlers_discovered = (uint32_t)handler_count;

    DEBUG_EVENT ev;
    bool got_create = false;
    bool debug_loop_ok = true;
    bool process_exited = false;
    bool timed_out = false;
    uint64_t base_main = 0;

    bool initial_break_ignored = false;

    uint64_t start = GetTickCount64();

    PendingRearmList pending;
    pending_rearm_init(&pending);
    bool tracing = false;
    uint32_t trace_left = 0;
    DWORD trace_tid = 0;

    /* Let debug loop run */
    for (;;) {
        uint64_t elapsed = GetTickCount64() - start;
        if (elapsed > timeout_ms) {
            dr_append(out, "[Dynamic] timeout reached (%u ms)\n", timeout_ms);
            dynamic_event_add(out, &mods, "timeout", 0, 0, 0, false, timeout_ms, 0, 0, 0);
            timed_out = true;
            break;
        }

        if (!WaitForDebugEvent(&ev, 100)) {
            DWORD werr = GetLastError();
            if (werr == ERROR_SEM_TIMEOUT) {
                continue;
            }
            dr_append(out, "[Dynamic] WaitForDebugEvent failed (err=%lu)\n", (unsigned long)werr);
            sb_appendf(err, "WaitForDebugEvent failed (err=%lu)\n", (unsigned long)werr);
            debug_loop_ok = false;
            break;
        }

        DWORD cont = DBG_CONTINUE;
        bool finish_after_continue = false;

        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            got_create = true;
            base_main = (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage;
            out->runtime_image_base = base_main;
            dr_append(out, "[Dynamic] CREATE_PROCESS pid=%lu base=0x%llx\n", (unsigned long)pid, (unsigned long long)base_main);

            /* refresh module list and add API breakpoints */
            (void)mods_refresh_accounted(&mods, pid, out);
            add_api_bps_if_ready(&bps, hProcess, &mods, out, err);

            /* Set breakpoints on handlers referenced in UNWIND_INFO */
            for (size_t i = 0; i < handler_count; i++) {
                uint64_t a = base_main + (uint64_t)handler_rvas[i];
                char what[96];
                snprintf(what, sizeof(what), "unwind_handler_rva=0x%08lx", (unsigned long)handler_rvas[i]);
                if (bp_add_and_arm_selfcheck(&bps, hProcess, &mods, out, a, BP_UNWIND_HANDLER, what, err)) {
                    out->unwind_handler_bp_set++;
                } else {
                    /* best effort: ignore failures (some handlers could be invalid/outside main image) */
                }
            }

            /* Process continues after ContinueDebugEvent(). */
            CloseHandle(ev.u.CreateProcessInfo.hFile);
        }
        else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            /* Refresh the module list before setting API breakpoints. */
            (void)mods_refresh_accounted(&mods, pid, out);
            add_api_bps_if_ready(&bps, hProcess, &mods, out, err);
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        }
        else if (ev.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
            (void)mods_refresh_accounted(&mods, pid, out);
        }
        else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            dr_append(out, "[Dynamic] EXIT_PROCESS code=%lu\n", (unsigned long)ev.u.ExitProcess.dwExitCode);
            process_exited = true;
            out->target_exited = true;
            out->target_exit_code = (uint32_t)ev.u.ExitProcess.dwExitCode;
            dynamic_event_add(
                out, &mods, "process_exit", ev.dwThreadId, 0, 0, false,
                ev.u.ExitProcess.dwExitCode, 0, 0, 0);
            finish_after_continue = true;
        }
        else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            uint64_t addr = (uint64_t)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;

            if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
                bool first_chance = ev.u.Exception.dwFirstChance != 0;
                out->exceptions_seen++;
                if (first_chance) out->first_chance_seen++;
                else out->second_chance_seen++;
                dr_append(out, "[Dynamic] exception 0x%08lx at 0x%llx (%s chance)\n",
                          (unsigned long)code,
                          (unsigned long long)addr,
                          first_chance ? "first" : "second");
                dynamic_event_add(
                    out, &mods, "exception", ev.dwThreadId, addr, (uint32_t)code,
                    first_chance, 0, 0, 0, 0);
                /* Preserve the target's normal exception-dispatch flow. */
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }

            if (code == EXCEPTION_BREAKPOINT) {
                Breakpoint* bp = bps_find(&bps, addr);
                if (!bp && !initial_break_ignored) {
                    /* Ignore the debugger's system initial breakpoint only when it is not ours. */
                    initial_break_ignored = true;
                    cont = DBG_CONTINUE;
                } else if (!bp) {
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                } else {
                    bool bp_prepared = bp_clear(hProcess, bp, err);
                    if (bp_prepared) {
                        bp->rearm_pending = true;
                        bp_prepared = pending_rearm_set(&pending, ev.dwThreadId, bp);
                        if (!bp_prepared) {
                            bp->rearm_pending = false;
                            out->pending_rearm_failures++;
                            out->instrumentation_complete = false;
                        }
                    }
                    if (!bp_prepared) {
                        dr_append(out, "[Dynamic] failed to prepare breakpoint rearm at 0x%llx\n",
                                  (unsigned long long)addr);
                        debug_loop_ok = false;
                        finish_after_continue = true;
                        cont = DBG_CONTINUE;
                    } else {
                        HANDLE hEvThread = open_event_thread(ev.dwThreadId);
                        if (!hEvThread) {
                            dr_append(out, "[Dynamic] OpenThread failed tid=%lu (err=%lu)\n",
                                      (unsigned long)ev.dwThreadId, (unsigned long)GetLastError());
                            debug_loop_ok = false;
                            finish_after_continue = true;
                            cont = DBG_CONTINUE;
                        } else {
                            CONTEXT ctx;
                            memset(&ctx, 0, sizeof(ctx));
                            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

                            if (!GetThreadContext(hEvThread, &ctx)) {
                                dr_append(out, "[Dynamic] GetThreadContext failed tid=%lu (err=%lu)\n",
                                          (unsigned long)ev.dwThreadId, (unsigned long)GetLastError());
                                close_event_thread(hEvThread);
                                debug_loop_ok = false;
                                finish_after_continue = true;
                                cont = DBG_CONTINUE;
                            } else {
                                /* RIP points to INT3+1; rewind */
                                ctx.Rip = (DWORD64)addr;
                                ctx.EFlags |= 0x100; /* Trap flag */

                                /* handle API breaks: capture handler pointers */
                                if (bp->kinds & BP_API_ADD_VEH) {
                                    uint64_t first = (uint64_t)ctx.Rcx;
                                    uint64_t handler = (uint64_t)ctx.Rdx;
                                    out->veh_registrations++;
                                    dr_append(out, "[Dynamic] AddVectoredExceptionHandler first=%llu handler=0x%llx\n",
                                              (unsigned long long)first, (unsigned long long)handler);
                                    dynamic_event_add(
                                        out, &mods, "veh_registration", ev.dwThreadId, addr, 0, false,
                                        first, handler, 0, 0);
                                    if (handler) {
                                        (void)mods_refresh_accounted(&mods, pid, out);
                                        (void)bp_add_and_arm_selfcheck(
                                            &bps, hProcess, &mods, out, handler,
                                            BP_CUSTOM_VEH_HANDLER, "custom_veh_handler", err);
                                    }
                                }
                                if (bp->kinds & BP_API_ADD_VCH) {
                                    uint64_t first = (uint64_t)ctx.Rcx;
                                    uint64_t handler = (uint64_t)ctx.Rdx;
                                    out->vch_registrations++;
                                    dr_append(out, "[Dynamic] AddVectoredContinueHandler first=%llu handler=0x%llx\n",
                                              (unsigned long long)first, (unsigned long long)handler);
                                    dynamic_event_add(
                                        out, &mods, "vch_registration", ev.dwThreadId, addr, 0, false,
                                        first, handler, 0, 0);
                                    if (handler) {
                                        (void)mods_refresh_accounted(&mods, pid, out);
                                        (void)bp_add_and_arm_selfcheck(
                                            &bps, hProcess, &mods, out, handler,
                                            BP_CUSTOM_VCH_HANDLER, "custom_vch_handler", err);
                                    }
                                }
                                if (bp->kinds & BP_API_SET_UEF) {
                                    out->uef_set_calls++;
                                    uint64_t handler = (uint64_t)ctx.Rcx;
                                    dr_append(out, "[Dynamic] SetUnhandledExceptionFilter handler=0x%llx\n",
                                              (unsigned long long)handler);
                                    dynamic_event_add(
                                        out, &mods, "uef_registration", ev.dwThreadId, addr, 0, false,
                                        handler, 0, 0, 0);
                                    if (handler) {
                                        (void)mods_refresh_accounted(&mods, pid, out);
                                        (void)bp_add_and_arm_selfcheck(
                                            &bps, hProcess, &mods, out, handler,
                                            BP_CUSTOM_UEF, "custom_uef_handler", err);
                                    }
                                }
                                if (bp->kinds & BP_API_RTL_ADD_FT) {
                                    uint64_t table = (uint64_t)ctx.Rcx;
                                    uint64_t count = (uint64_t)ctx.Rdx;
                                    uint64_t baseaddr = (uint64_t)ctx.R8;
                                    out->rtl_add_function_table_calls++;
                                    dr_append(
                                        out,
                                        "[Dynamic] RtlAddFunctionTable table=0x%llx count=%llu base=0x%llx\n",
                                        (unsigned long long)table,
                                        (unsigned long long)count,
                                        (unsigned long long)baseaddr);
                                    dynamic_event_add(
                                        out, &mods, "rtl_add_function_table",
                                        ev.dwThreadId, addr, 0, false,
                                        table, count, baseaddr, 0);
                                }
                                if (bp->kinds & BP_API_RTL_INSTALL_FTCB) {
                                    uint64_t table_id = (uint64_t)ctx.Rcx;
                                    uint64_t baseaddr = (uint64_t)ctx.Rdx;
                                    uint64_t length = (uint64_t)ctx.R8;
                                    uint64_t callback = (uint64_t)ctx.R9;
                                    out->rtl_install_function_table_cb_calls++;
                                    dr_append(
                                        out,
                                        "[Dynamic] RtlInstallFunctionTableCallback id=0x%llx base=0x%llx length=%llu callback=0x%llx\n",
                                        (unsigned long long)table_id,
                                        (unsigned long long)baseaddr,
                                        (unsigned long long)length,
                                        (unsigned long long)callback);
                                    dynamic_event_add(
                                        out, &mods, "rtl_install_function_table_callback",
                                        ev.dwThreadId, addr, 0, false,
                                        table_id, baseaddr, length, callback);
                                }
                                if (bp->kinds & BP_UNWIND_HANDLER) {
                                    out->unwind_handler_hits++;
                                    char loc[128];
                                    addr_to_loc(img, base_main, addr, loc, sizeof(loc));
                                    dr_append(out, "[Dynamic] hit unwind handler at %s\n", loc);
                                    dynamic_event_add(
                                        out, &mods, "unwind_handler_hit",
                                        ev.dwThreadId, addr, 0, false, 0, 0, 0, 0);
                                    start_trace(
                                        out, out->trace_steps, ev.dwThreadId,
                                        (uint64_t)ctx.Rip,
                                        &tracing, &trace_tid, &trace_left);
                                }
                                if (bp->kinds & BP_CUSTOM_VEH_HANDLER) {
                                    out->veh_hits++;
                                    dr_append(out, "[Dynamic] hit vectored exception handler 0x%llx\n", (unsigned long long)addr);
                                    dynamic_event_add(
                                        out, &mods, "veh_handler_hit",
                                        ev.dwThreadId, addr, 0, false, 0, 0, 0, 0);
                                    start_trace(
                                        out, out->trace_steps, ev.dwThreadId,
                                        (uint64_t)ctx.Rip,
                                        &tracing, &trace_tid, &trace_left);
                                }
                                if (bp->kinds & BP_CUSTOM_VCH_HANDLER) {
                                    out->vch_hits++;
                                    dr_append(out, "[Dynamic] hit vectored continue handler 0x%llx\n", (unsigned long long)addr);
                                    dynamic_event_add(
                                        out, &mods, "vch_handler_hit",
                                        ev.dwThreadId, addr, 0, false, 0, 0, 0, 0);
                                    start_trace(
                                        out, out->trace_steps, ev.dwThreadId,
                                        (uint64_t)ctx.Rip,
                                        &tracing, &trace_tid, &trace_left);
                                }
                                if (bp->kinds & BP_CUSTOM_UEF) {
                                    out->uef_hits++;
                                    dr_append(out, "[Dynamic] hit unhandled exception filter 0x%llx\n", (unsigned long long)addr);
                                    dynamic_event_add(
                                        out, &mods, "uef_handler_hit",
                                        ev.dwThreadId, addr, 0, false, 0, 0, 0, 0);
                                    start_trace(
                                        out, out->trace_steps, ev.dwThreadId,
                                        (uint64_t)ctx.Rip,
                                        &tracing, &trace_tid, &trace_left);
                                }

                                if (!SetThreadContext(hEvThread, &ctx)) {
                                    dr_append(out, "[Dynamic] SetThreadContext failed tid=%lu (err=%lu)\n",
                                              (unsigned long)ev.dwThreadId,
                                              (unsigned long)GetLastError());
                                    debug_loop_ok = false;
                                    finish_after_continue = true;
                                }
                                close_event_thread(hEvThread);
                                cont = DBG_CONTINUE;
                            }
                        }
                    }
                }
            }
            else if (code == EXCEPTION_SINGLE_STEP) {
                /* Re-arm the breakpoint after executing original instruction (per-thread). */
                Breakpoint* pr_bp = pending_rearm_take(&pending, ev.dwThreadId);
                if (pr_bp) {
                    StrBuf te; sb_init(&te, 128);
                    if (!bp_set(hProcess, pr_bp, &te)) {
                        out->breakpoint_rearm_failures++;
                        out->instrumentation_complete = false;
                        dr_append(out, "[Dynamic] failed to re-arm breakpoint at 0x%llx: %s",
                                  (unsigned long long)pr_bp->addr,
                                  te.s ? te.s : "unknown error\n");
                        debug_loop_ok = false;
                        finish_after_continue = true;
                    }
                    sb_free(&te);
                }

                HANDLE hEvThread = open_event_thread(ev.dwThreadId);
                if (!hEvThread) {
                    dr_append(out, "[Dynamic] OpenThread failed tid=%lu (err=%lu)\n",
                              (unsigned long)ev.dwThreadId, (unsigned long)GetLastError());
                    debug_loop_ok = false;
                    finish_after_continue = true;
                    cont = DBG_CONTINUE;
                } else {
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

                    if (!GetThreadContext(hEvThread, &ctx)) {
                        dr_append(out, "[Dynamic] GetThreadContext failed tid=%lu (err=%lu)\n",
                                  (unsigned long)ev.dwThreadId, (unsigned long)GetLastError());
                        close_event_thread(hEvThread);
                        debug_loop_ok = false;
                        finish_after_continue = true;
                        cont = DBG_CONTINUE;
                    } else {
                        if (tracing && trace_left && ev.dwThreadId == trace_tid) {
                            add_trace(out, (uint64_t)ctx.Rip);
                            trace_left--;
                            /* keep trap flag */
                            ctx.EFlags |= 0x100;
                            if (trace_left == 0) {
                                tracing = false;
                                trace_tid = 0;
                                ctx.EFlags &= ~0x100u;
                                dr_append(out, "[Dynamic] trace collected: %u steps\n", (unsigned)out->trace_count);
                            }
                        } else {
                            /* stop single-stepping */
                            ctx.EFlags &= ~0x100u;
                        }
                        if (!SetThreadContext(hEvThread, &ctx)) {
                            dr_append(out, "[Dynamic] SetThreadContext failed tid=%lu (err=%lu)\n",
                                      (unsigned long)ev.dwThreadId,
                                      (unsigned long)GetLastError());
                            debug_loop_ok = false;
                            finish_after_continue = true;
                        }
                        close_event_thread(hEvThread);
                        cont = DBG_CONTINUE;
                    }
                }
            }

        }
        else if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
            Breakpoint* pr_bp = pending_rearm_take(&pending, ev.dwThreadId);
            if (pr_bp) {
                StrBuf te;
                sb_init(&te, 128);
                if (!bp_set(hProcess, pr_bp, &te)) {
                    out->breakpoint_rearm_failures++;
                    out->instrumentation_complete = false;
                    dr_append(out, "[Dynamic] failed to re-arm breakpoint after thread exit: %s",
                              te.s ? te.s : "unknown error\n");
                    debug_loop_ok = false;
                    finish_after_continue = true;
                }
                sb_free(&te);
            }
            if (tracing && trace_tid == ev.dwThreadId) {
                tracing = false;
                trace_tid = 0;
                trace_left = 0;
            }
        }

        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)) {
            DWORD cerr = GetLastError();
            dr_append(out, "[Dynamic] ContinueDebugEvent failed (err=%lu)\n", (unsigned long)cerr);
            sb_appendf(err, "ContinueDebugEvent failed (err=%lu)\n", (unsigned long)cerr);
            debug_loop_ok = false;
            break;
        }
        if (finish_after_continue) break;
    }

    out->timed_out = timed_out;
    out->target_exited = process_exited;
    out->ok = got_create && debug_loop_ok && !timed_out;
    if (!sb_ok(&out->details)) {
        out->ok = false;
        sb_append(err, "Out of memory while building dynamic details.\n");
    }

    /* Cleanup: remove breakpoints */
    for (size_t i = 0; i < bps.count; i++) {
        bp_clear(hProcess, &bps.bps[i], NULL);
    }

    /*
     * Terminate only when the target did not exit by itself. A debuggee may
     * not signal its process handle until the debugger continues the queued
     * exit event, so drain cleanup events instead of waiting a fixed 5 s.
     */
    if (!process_exited && TerminateProcess(hProcess, 0)) {
        uint64_t cleanup_deadline = GetTickCount64() + 1000u;
        while (WaitForSingleObject(hProcess, 0) != WAIT_OBJECT_0 &&
               GetTickCount64() < cleanup_deadline) {
            DEBUG_EVENT cleanup_event;
            if (!WaitForDebugEvent(&cleanup_event, 50)) {
                if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
                break;
            }

            if (cleanup_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT &&
                cleanup_event.u.CreateProcessInfo.hFile) {
                CloseHandle(cleanup_event.u.CreateProcessInfo.hFile);
            } else if (cleanup_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
                       cleanup_event.u.LoadDll.hFile) {
                CloseHandle(cleanup_event.u.LoadDll.hFile);
            }

            bool cleanup_exited =
                cleanup_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
            if (!ContinueDebugEvent(
                    cleanup_event.dwProcessId,
                    cleanup_event.dwThreadId,
                    DBG_CONTINUE)) {
                break;
            }
            if (cleanup_exited) break;
        }
        (void)WaitForSingleObject(hProcess, 100);
    }

    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);

    free(handler_rvas);
    sb_free(&cmd);

    if (!out->ok) {
        if (timed_out) {
            sb_appendf(err, "Dynamic session timed out after %u ms.\n", timeout_ms);
        } else if (!got_create) {
            sb_append(err, "Dynamic session failed before CREATE_PROCESS_DEBUG_EVENT.\n");
        } else {
            sb_append(err, "Dynamic session failed inside the debug event loop.\n");
        }
        return false;
    }
    return true;
}

#else /* !_WIN32 */

void dynamic_report_init(DynamicReport* dr) {
    if (!dr) return;
    memset(dr, 0, sizeof(*dr));
    dr->enabled = false;
    sb_init(&dr->details, 256);
    sb_append(&dr->details, "Dynamic mode is supported only on Windows.\n");
}

void dynamic_report_free(DynamicReport* dr) {
    if (!dr) return;
    sb_free(&dr->details);
    memset(dr, 0, sizeof(*dr));
}

bool dynamic_collect_windows(const char* pe_path,
                            const char* const* child_argv,
                            int child_argc,
                            const PeImage* img,
                            const RuntimeFunction* rf,
                            const UnwindSummary* us,
                            const bool* us_ok,
                            size_t rf_count,
                            uint32_t timeout_ms,
                            uint32_t trace_steps,
                            DynamicReport* out,
                            StrBuf* err) {
    (void)pe_path; (void)child_argv; (void)child_argc; (void)img; (void)rf; (void)us; (void)us_ok; (void)rf_count;
    (void)timeout_ms; (void)trace_steps;
    dynamic_report_init(out);
    if (!out || !sb_ok(&out->details)) {
        sb_append(err, "Out of memory (dynamic report buffer).\n");
        return false;
    }
    out->enabled = true;
    out->timeout_ms = timeout_ms;
    out->trace_steps = trace_steps > 256u ? 256u : trace_steps;
    sb_append(err, "Dynamic mode is supported only on Windows.\n");
    return false;
}

#endif
