#include <windows.h>
#include <stdio.h>
static LONG WINAPI RemovedVeh(struct _EXCEPTION_POINTERS* e){(void)e;return EXCEPTION_CONTINUE_SEARCH;}
int main(void){printf("[dyn_veh_remove] register then remove, no exception\n");fflush(stdout);PVOID h=AddVectoredExceptionHandler(1,RemovedVeh);if(h)RemoveVectoredExceptionHandler(h);return 0;}
