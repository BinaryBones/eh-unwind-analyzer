#include <windows.h>
#include <stdio.h>

static LONG WINAPI MyVeh(struct _EXCEPTION_POINTERS* e) {
    if (!e || !e->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    printf("[veh_test_mingw] vectored handler hit code=0x%08lx\n",
           (unsigned long)e->ExceptionRecord->ExceptionCode);
    if (e->ExceptionRecord->ExceptionCode == 0xE0000002UL) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    printf("[veh_test_mingw] installing VEH then raising continuable exception...\n");
    PVOID h = AddVectoredExceptionHandler(1, MyVeh);
    printf("[veh_test_mingw] handler handle=%p\n", h);
    RaiseException(0xE0000002UL, 0, 0, NULL);
    if (h) RemoveVectoredExceptionHandler(h);
    printf("[veh_test_mingw] done\n");
    return 0;
}
