/* Small DLL used in Lab 2: three named exports and one exported only by ordinal (see mathlib.def). */
#include <windows.h>
static int g_ready = 0;
__declspec(dllexport) int Add(int a, int b) { return a + b; }
__declspec(dllexport) void Init(void) { g_ready = 1; }
__declspec(dllexport) int Run(int x) { return g_ready ? x * 2 : -1; }
int Hidden(int x) { return x ^ 0x5A; }
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) { (void)h; (void)reason; (void)r; return TRUE; }
