#include <windows.h>
#include <stdio.h>

static LONG WINAPI MyUef(struct _EXCEPTION_POINTERS* e) {
    unsigned long code = 0UL;
    if (e && e->ExceptionRecord) {
        code = (unsigned long)e->ExceptionRecord->ExceptionCode;
    }
    printf("[uef_test] unhandled exception filter hit code=0x%08lx\n", code);
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
    printf("[uef_test] setting UEF then raising unhandled exception...\n");
    SetUnhandledExceptionFilter(MyUef);
    fflush(stdout);
    RaiseException(0xE0000003UL, 0, 0, NULL);
    return 0;
}
