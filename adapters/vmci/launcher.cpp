// Fixed local guest-service launcher. No target, command or path arguments.
#include <windows.h>
#include <cwchar>
#include <string>
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    WCHAR file[32768] = {};
    DWORD count = GetModuleFileNameW(nullptr, file, 32768);
    if (!count || count >= 32768) return 1;
    WCHAR* slash = wcsrchr(file, L'\\');
    if (!slash) return 1;
    *slash = 0;
    const std::wstring root(file);
    const std::wstring python = root + L"\\runtimes\\x64dbg\\python\\pythonw.exe";
    const std::wstring script = root + L"\\adapters\\vmci\\guest.py";
    std::wstring command = L"\"" + python + L"\" -I -B -X utf8 \"" + script + L"\"";
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(python.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, root.c_str(), &startup, &process)) {
        MessageBoxW(nullptr, L"Could not start the fixed IG5 guest service.", L"IG5 guest launcher", MB_OK | MB_ICONERROR);
        return 1;
    }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return 0;
}
