#include <windows.h>
#include <stdio.h>

int main(void) {
    printf("[seh_test] raising exception inside __try/__except...\n");
    __try {
        RaiseException(0xE0000001, 0, 0, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[seh_test] caught exception in __except\n");
    }
    printf("[seh_test] done\n");
    return 0;
}
