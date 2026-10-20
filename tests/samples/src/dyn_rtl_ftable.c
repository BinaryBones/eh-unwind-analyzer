#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef BOOLEAN (WINAPI *PFN_RTL_ADD_FUNCTION_TABLE)(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount,
    DWORD64 BaseAddress
);

typedef BOOLEAN (WINAPI *PFN_RTL_INSTALL_FUNCTION_TABLE_CALLBACK)(
    DWORD64 TableIdentifier,
    DWORD64 BaseAddress,
    DWORD Length,
    PGET_RUNTIME_FUNCTION_CALLBACK Callback,
    PVOID Context,
    PCWSTR OutOfProcessCallbackDll
);

static PRUNTIME_FUNCTION CALLBACK DummyCallback(
    DWORD64 ControlPc,
    PVOID Context
) {
    (void)ControlPc;
    (void)Context;
    return NULL;
}

int main(void) {
    printf("[dyn_rtl_ftable] resolve and call RtlAddFunctionTable / RtlInstallFunctionTableCallback\n");
    fflush(stdout);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[dyn_rtl_ftable] ntdll not found\n");
        return 1;
    }

    PFN_RTL_ADD_FUNCTION_TABLE pAdd = (PFN_RTL_ADD_FUNCTION_TABLE)GetProcAddress(ntdll, "RtlAddFunctionTable");
    PFN_RTL_INSTALL_FUNCTION_TABLE_CALLBACK pInstall =
        (PFN_RTL_INSTALL_FUNCTION_TABLE_CALLBACK)GetProcAddress(ntdll, "RtlInstallFunctionTableCallback");

    if (pAdd) {
        RUNTIME_FUNCTION rf[1];
        memset(rf, 0, sizeof(rf));
        rf[0].BeginAddress = 0;
        rf[0].EndAddress = 1;
        rf[0].UnwindData = 0;
        BOOLEAN ok = pAdd(rf, 1, (DWORD64)(uintptr_t)GetModuleHandleA(NULL));
        printf("[dyn_rtl_ftable] RtlAddFunctionTable called, ret=%d\n", (int)ok);
        fflush(stdout);
    } else {
        printf("[dyn_rtl_ftable] RtlAddFunctionTable not resolved\n");
        fflush(stdout);
    }

    if (pInstall) {
        BOOLEAN ok2 = pInstall(
            ((DWORD64)0x12345000u) | 0x3ull,
            (DWORD64)(uintptr_t)GetModuleHandleA(NULL),
            0x1000u,
            DummyCallback,
            NULL,
            NULL
        );
        printf("[dyn_rtl_ftable] RtlInstallFunctionTableCallback called, ret=%d\n", (int)ok2);
        fflush(stdout);
    } else {
        printf("[dyn_rtl_ftable] RtlInstallFunctionTableCallback not resolved\n");
        fflush(stdout);
    }

    return 0;
}
