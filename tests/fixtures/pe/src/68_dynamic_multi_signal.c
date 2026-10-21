#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef BOOLEAN (WINAPI *PFN_RTL_ADD_FUNCTION_TABLE)(PRUNTIME_FUNCTION,DWORD,DWORD64);
static LONG WINAPI MultiVeh(struct _EXCEPTION_POINTERS* e){if(e&&e->ExceptionRecord&&e->ExceptionRecord->ExceptionCode==0xE0000202UL)return EXCEPTION_CONTINUE_EXECUTION;return EXCEPTION_CONTINUE_SEARCH;}
static LONG WINAPI MultiVch(struct _EXCEPTION_POINTERS* e){(void)e;return EXCEPTION_CONTINUE_SEARCH;}
static LONG WINAPI MultiUef(struct _EXCEPTION_POINTERS* e){(void)e;return EXCEPTION_EXECUTE_HANDLER;}
int main(void){AddVectoredExceptionHandler(1,MultiVeh);AddVectoredContinueHandler(1,MultiVch);SetUnhandledExceptionFilter(MultiUef);HMODULE ntdll=GetModuleHandleA("ntdll.dll");if(ntdll){PFN_RTL_ADD_FUNCTION_TABLE p=(PFN_RTL_ADD_FUNCTION_TABLE)GetProcAddress(ntdll,"RtlAddFunctionTable");if(p){RUNTIME_FUNCTION rf[1];memset(rf,0,sizeof(rf));rf[0].BeginAddress=0;rf[0].EndAddress=1;rf[0].UnwindData=0;p(rf,1,(DWORD64)(uintptr_t)GetModuleHandleA(NULL));}}RaiseException(0xE0000202UL,0,0,NULL);return 0;}
