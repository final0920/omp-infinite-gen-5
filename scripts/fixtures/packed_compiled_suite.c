/* Owned branch/round controls. The exported compression data enlarges the
 * input for LZMA testing; it is not evidence of business-logic complexity. */
#include <windows.h>
#include <intrin.h>
#ifndef IG5_OWNED_CASE
#error IG5_OWNED_CASE is required
#endif
__declspec(dllexport) const unsigned char ig5_owned_compression_data[65536] = { 'I', 'G', '5' };
__declspec(dllexport) __declspec(noinline)
unsigned __int64 __fastcall ig5_packed_leaf(unsigned __int64 x, unsigned __int64 y) {
#if IG5_OWNED_CASE == 0
    volatile unsigned __int64 result;
    if ((x ^ y) & 1u) result = (x + y) ^ 0xd6e8feb86659fd93ui64;
    else result = (x ^ y) + 0x9e3779b97f4a7c15ui64;
    return result;
#elif IG5_OWNED_CASE == 1
    volatile unsigned __int64 state = x;
    unsigned int i;
    for (i = 0; i < 8; ++i)
        state = _rotl64(state + y + i, 7) ^ (y * 0x9e3779b97f4a7c15ui64);
    return state;
#else
#error Unknown owned case
#endif
}
__declspec(noreturn) void __cdecl ig5_owned_entry(void) {
    volatile unsigned __int64 result = ig5_packed_leaf(1, 2);
    ExitProcess((UINT)result);
}
