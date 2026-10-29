/* Own deterministic functions compiled independently; no upstream target code. */
#include <windows.h>
#include <intrin.h>
#ifndef IG5_OWNED_CASE
#error IG5_OWNED_CASE must identify the compiled fixture
#endif
__declspec(dllexport) __declspec(noinline)
unsigned __int64 __fastcall ig5_modern_leaf(unsigned __int64 x, unsigned __int64 y) {
#if IG5_OWNED_CASE == 0
    return _rotl64(x, (int)y) ^ (x + y);
#elif IG5_OWNED_CASE == 1
    return (__int64)x > (__int64)y ? x : y;
#elif IG5_OWNED_CASE == 2
    return (unsigned int)(((unsigned int)x ^ (unsigned int)y) + 99u) * 143u;
#else
#error Unknown owned case
#endif
}
__declspec(noreturn) void __cdecl ig5_owned_entry(void) {
    volatile unsigned __int64 result = ig5_modern_leaf(1, 2);
    ExitProcess((UINT)result);
}
