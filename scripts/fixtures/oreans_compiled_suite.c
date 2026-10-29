/* Own scalar business functions; external SDK only marks protected regions. */
#include <windows.h>
#include <intrin.h>
#include "ThemidaSDK.h"
#if !defined(IG5_OWNED_CASE) || !defined(IG5_OWNED_VM)
#error Explicit owned case and SDK VM marker are required
#endif
#if IG5_OWNED_VM == 0
#define IG5_VM_START VM_TIGER_WHITE_START
#define IG5_VM_END VM_TIGER_WHITE_END
#elif IG5_OWNED_VM == 1
#define IG5_VM_START VM_TIGER_RED_START
#define IG5_VM_END VM_TIGER_RED_END
#elif IG5_OWNED_VM == 2
#define IG5_VM_START VM_TIGER_BLACK_START
#define IG5_VM_END VM_TIGER_BLACK_END
#else
#error Unknown owned VM marker
#endif
__declspec(dllexport) __declspec(noinline)
unsigned __int64 __fastcall ig5_oreans_leaf(unsigned __int64 x, unsigned __int64 y) {
    /* Volatile store keeps pure arithmetic between opaque SDK calls at /O2. */
    volatile unsigned __int64 result;
    IG5_VM_START
#if IG5_OWNED_CASE == 0
    result = _rotl64(x, (int)y) ^ (x + y);
#elif IG5_OWNED_CASE == 1
    result = (__int64)x > (__int64)y ? x : y;
#elif IG5_OWNED_CASE == 2
    result = (unsigned int)(((unsigned int)x ^ (unsigned int)y) + 99u) * 143u;
#else
#error Unknown owned case
#endif
    IG5_VM_END
    return result;
}
__declspec(noreturn) void __cdecl ig5_owned_entry(void) {
    volatile unsigned __int64 result = ig5_oreans_leaf(1, 2);
    ExitProcess((UINT)result);
}
