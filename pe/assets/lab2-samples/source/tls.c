/* Lab 2 bonus sample: a TLS callback runs before main. */
#include <windows.h>
#include <stdio.h>
static void NTAPI on_tls(PVOID h, DWORD reason, PVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) OutputDebugStringA("TLS callback: I run before main!\n");
}
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_ptr")
#pragma const_seg(".CRT$XLB")
extern const PIMAGE_TLS_CALLBACK tls_callback_ptr;
const PIMAGE_TLS_CALLBACK tls_callback_ptr = on_tls;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback_ptr")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK tls_callback_ptr = on_tls;
#pragma data_seg()
#endif
int main(void) { MessageBoxA(NULL, "Hello from main", "FII RE Lab 2", MB_OK); return 0; }
