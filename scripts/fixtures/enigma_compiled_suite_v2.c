/* OWN classic-VM controls with a debugger rendezvous outside the VM region.
 * Business formulas/round count/marker region match v1. No protector bytes or
 * license checks are patched. The rendezvous is part of the compiled harness. */
#include <windows.h>
#include <intrin.h>
__declspec(dllimport) void __stdcall EP_Marker(const char *name);
#ifndef IG5_OWNED_CASE
#error IG5_OWNED_CASE is required
#endif
__declspec(dllexport) __declspec(noinline) void ig5_enigma_debug_ready(void) {
    __debugbreak();
}
__declspec(dllexport) __declspec(noinline)
unsigned __int64 __fastcall ig5_enigma_leaf(unsigned __int64 x, unsigned __int64 y) {
    volatile unsigned __int64 state;
    EP_Marker("vm_begin");
#if IG5_OWNED_CASE == 0
    if ((x ^ y) & 1u) state = (x + y) ^ 0xd6e8feb86659fd93ui64;
    else state = (x ^ y) + 0x9e3779b97f4a7c15ui64;
#elif IG5_OWNED_CASE == 1
    unsigned int i;
    state = x;
    for (i = 0; i < 8; ++i)
        state = _rotl64(state + y + i, 7) ^ (y * 0x9e3779b97f4a7c15ui64);
#else
#error Unknown owned case
#endif
    EP_Marker("vm_end");
    return state;
}
__declspec(noreturn) void __cdecl ig5_owned_entry(void) {
    ig5_enigma_debug_ready();
    volatile unsigned __int64 result = ig5_enigma_leaf(1, 2);
    ExitProcess((UINT)result);
}
