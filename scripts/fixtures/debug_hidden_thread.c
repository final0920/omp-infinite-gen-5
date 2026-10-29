/* OWN diagnostic fixture, not a devirtualization benchmark. The main thread
 * hides itself using the documented NT ABI; a visible helper produces a trap.
 * The debugger can then read the paused main thread without modifying it. */
#include <windows.h>
#include <intrin.h>
__declspec(dllimport) LONG NTAPI NtSetInformationThread(HANDLE, ULONG, PVOID, ULONG);
__declspec(dllexport) volatile LONG ig5_owned_hide_status = -1;
static DWORD WINAPI ig5_owned_visible_observer(LPVOID unused) {
    (void)unused;
    Sleep(100);
    __debugbreak();
    Sleep(INFINITE);
    return 0;
}
__declspec(noreturn) void __cdecl ig5_owned_entry(void) {
    ig5_owned_hide_status = NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
    HANDLE thread = CreateThread(NULL, 0, ig5_owned_visible_observer, NULL, 0, NULL);
    if (!thread) ExitProcess(2);
    WaitForSingleObject(thread, INFINITE);
    ExitProcess(0);
}
