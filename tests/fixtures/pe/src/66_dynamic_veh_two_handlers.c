#include <windows.h>
#include <stdio.h>
static LONG WINAPI FirstVeh(struct _EXCEPTION_POINTERS* e){(void)e;printf("[dyn_veh_two] first VEH pass\n");fflush(stdout);return EXCEPTION_CONTINUE_SEARCH;}
static LONG WINAPI SecondVeh(struct _EXCEPTION_POINTERS* e){if(e&&e->ExceptionRecord&&e->ExceptionRecord->ExceptionCode==0xE0000201UL){printf("[dyn_veh_two] second VEH handles\n");fflush(stdout);return EXCEPTION_CONTINUE_EXECUTION;}return EXCEPTION_CONTINUE_SEARCH;}
int main(void){PVOID h1=AddVectoredExceptionHandler(1,FirstVeh);PVOID h2=AddVectoredExceptionHandler(1,SecondVeh);RaiseException(0xE0000201UL,0,0,NULL);if(h2)RemoveVectoredExceptionHandler(h2);if(h1)RemoveVectoredExceptionHandler(h1);return 0;}
