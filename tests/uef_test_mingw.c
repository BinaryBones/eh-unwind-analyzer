#include <windows.h>
#include <stdio.h>

static LONG WINAPI MyUef(struct _EXCEPTION_POINTERS* e) {
    unsigned long code = 0UL;
    if (e && e->ExceptionRecord) code = (unsigned long)e->ExceptionRecord->ExceptionCode;
    printf("[uef_test_mingw] unhandled exception filter hit code=0x%08lx\n", code);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
    printf("[uef_test_mingw] setting UEF then raising unhandled exception...\n");
    SetUnhandledExceptionFilter(MyUef);
    fflush(stdout);
    RaiseException(0xE0000003UL, 0, 0, NULL);
    printf("[uef_test_mingw] after RaiseException (unexpected under debugger)\n");
    return 0;
}
