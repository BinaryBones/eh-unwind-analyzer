#include <windows.h>
#include <stdio.h>

static LONG WINAPI DynUef(struct _EXCEPTION_POINTERS* e) {
    unsigned long code = 0UL;
    if (e && e->ExceptionRecord) code = (unsigned long)e->ExceptionRecord->ExceptionCode;
    printf("[dyn_uef] UEF hit, code=0x%08lx\n", code);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
    printf("[dyn_uef] set UEF and raise unhandled exception\n");
    fflush(stdout);
    SetUnhandledExceptionFilter(DynUef);
    RaiseException(0xE0000103UL, 0, 0, NULL);
    printf("[dyn_uef] after RaiseException (unexpected under debugger)\n");
    return 0;
}

