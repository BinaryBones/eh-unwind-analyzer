#include <windows.h>
#include <stdio.h>

static LONG WINAPI MyVeh(struct _EXCEPTION_POINTERS* e) {
    (void)e;
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI MyVch(struct _EXCEPTION_POINTERS* e) {
    unsigned long code = 0UL;
    if (e && e->ExceptionRecord) {
        code = (unsigned long)e->ExceptionRecord->ExceptionCode;
    }
    printf("[vch_test] vectored continue handler hit code=0x%08lx\n", code);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI MyUef(struct _EXCEPTION_POINTERS* e) {
    (void)e;
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
    printf("[vch_test] installing VEH, VCH and UEF...\n");
    PVOID veh = AddVectoredExceptionHandler(1, MyVeh);
    PVOID vch = AddVectoredContinueHandler(1, MyVch);
    SetUnhandledExceptionFilter(MyUef);
    fflush(stdout);
    RaiseException(0xE0000102UL, 0, 0, NULL);
    if (vch) RemoveVectoredContinueHandler(vch);
    if (veh) RemoveVectoredExceptionHandler(veh);
    return 0;
}
