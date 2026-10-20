#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef BOOLEAN (WINAPI *RtlAddFunctionTableFn)(
    PRUNTIME_FUNCTION,
    DWORD,
    DWORD64
);

typedef BOOLEAN (WINAPI *RtlInstallFunctionTableCallbackFn)(
    DWORD64,
    DWORD64,
    DWORD,
    PGET_RUNTIME_FUNCTION_CALLBACK,
    PVOID,
    PCWSTR
);

static PRUNTIME_FUNCTION CALLBACK DummyCallback(DWORD64 control_pc, PVOID context) {
    (void)control_pc;
    (void)context;
    return NULL;
}

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 1;

    RtlAddFunctionTableFn add_table =
        (RtlAddFunctionTableFn)GetProcAddress(ntdll, "RtlAddFunctionTable");
    RtlInstallFunctionTableCallbackFn install_callback =
        (RtlInstallFunctionTableCallbackFn)GetProcAddress(
            ntdll, "RtlInstallFunctionTableCallback");
    if (!add_table || !install_callback) return 2;

    RUNTIME_FUNCTION table[1];
    memset(table, 0, sizeof(table));
    table[0].EndAddress = 1;
    (void)add_table(table, 1, (DWORD64)(uintptr_t)GetModuleHandleA(NULL));
    (void)install_callback(
        0x12345003ull,
        (DWORD64)(uintptr_t)GetModuleHandleA(NULL),
        0x1000u,
        DummyCallback,
        NULL,
        NULL);
    printf("[rtl_ftable_test] function-table APIs called\n");
    return 0;
}
