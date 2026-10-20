#include <windows.h>
#include <stdio.h>

static LONG WINAPI DynVehPassthrough(struct _EXCEPTION_POINTERS* e) {
    if (!e || !e->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    printf("[dyn_vch] VEH pass-through, code=0x%08lx\n", (unsigned long)e->ExceptionRecord->ExceptionCode);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI DynVchHandler(struct _EXCEPTION_POINTERS* e) {
    if (!e || !e->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    printf("[dyn_vch] VCH hit, code=0x%08lx\n", (unsigned long)e->ExceptionRecord->ExceptionCode);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI DynUefFallback(struct _EXCEPTION_POINTERS* e) {
    unsigned long code = 0UL;
    if (e && e->ExceptionRecord) code = (unsigned long)e->ExceptionRecord->ExceptionCode;
    printf("[dyn_vch] UEF fallback hit, code=0x%08lx\n", code);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
    printf("[dyn_vch] install VEH+VCH+UEF and raise exception\n");
    fflush(stdout);
    PVOID hv = AddVectoredExceptionHandler(1, DynVehPassthrough);
    PVOID hc = AddVectoredContinueHandler(1, DynVchHandler);
    SetUnhandledExceptionFilter(DynUefFallback);
    RaiseException(0xE0000102UL, 0, 0, NULL);
    if (hc) RemoveVectoredContinueHandler(hc);
    if (hv) RemoveVectoredExceptionHandler(hv);
    printf("[dyn_vch] done\n");
    return 0;
}
