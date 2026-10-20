#include <windows.h>
#include <stdio.h>

static LONG WINAPI MyVeh(struct _EXCEPTION_POINTERS* e) {
    (void)e;
    printf("[veh_test] vectored handler hit\n");
    return EXCEPTION_CONTINUE_SEARCH; /* let normal SEH continue */
}

int main(void) {
    printf("[veh_test] installing VEH then raising exception...\n");
    PVOID h = AddVectoredExceptionHandler(1, MyVeh);
    printf("[veh_test] handler handle=%p\n", h);
    __try {
        RaiseException(0xE0000002, 0, 0, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[veh_test] __except ran\n");
    }
    if (h) RemoveVectoredExceptionHandler(h);
    printf("[veh_test] done\n");
    return 0;
}
