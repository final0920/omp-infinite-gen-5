/* Owned compiler/producer control; no upstream sample source or bytes. */
#include <windows.h>
__declspec(dllexport) __declspec(noinline)
unsigned __int64 __fastcall ig5_modern_add64(unsigned __int64 x, unsigned __int64 y) {
    return x + y;
}
__declspec(noreturn) void __cdecl ig5_owned_entry(void) {
    volatile unsigned __int64 result = ig5_modern_add64(1, 2);
    ExitProcess((UINT)result);
}
