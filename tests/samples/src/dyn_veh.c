#include <windows.h>
#include <stdio.h>

static LONG WINAPI DynVehHandler(struct _EXCEPTION_POINTERS* e) {
    if (!e || !e->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    printf("[dyn_veh] VEH hit, code=0x%08lx\n", (unsigned long)e->ExceptionRecord->ExceptionCode);
    fflush(stdout);
    if (e->ExceptionRecord->ExceptionCode == 0xE0000101UL) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    printf("[dyn_veh] install VEH + raise exception\n");
    fflush(stdout);
    PVOID h = AddVectoredExceptionHandler(1, DynVehHandler);
    RaiseException(0xE0000101UL, 0, 0, NULL);
    if (h) RemoveVectoredExceptionHandler(h);
    printf("[dyn_veh] done\n");
    return 0;
}

