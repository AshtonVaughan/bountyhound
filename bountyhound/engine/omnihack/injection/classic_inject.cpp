/*
 * Classic DLL Injection via CreateRemoteThread
 * Compile: g++ -o classic_inject.exe classic_inject.cpp -lkernel32
 */
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD GetProcessIdByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

bool InjectDLL(DWORD processId, const std::wstring& dllPath) {
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::wcerr << L"[-] Failed to open process: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"[+] Opened process handle: 0x" << std::hex << (DWORD_PTR)hProcess << std::endl;

    // Allocate memory in target process
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, pathSize,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemotePath) {
        std::wcerr << L"[-] VirtualAllocEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] Allocated memory at: 0x" << std::hex << (DWORD_PTR)pRemotePath << std::endl;

    // Write DLL path to allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath.c_str(),
                           pathSize, &bytesWritten)) {
        std::wcerr << L"[-] WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] Wrote " << std::dec << bytesWritten << L" bytes" << std::endl;

    // Get address of LoadLibraryW
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
        hKernel32, "LoadLibraryW");

    if (!pLoadLibrary) {
        std::wcerr << L"[-] Failed to get LoadLibraryW address" << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] LoadLibraryW at: 0x" << std::hex << (DWORD_PTR)pLoadLibrary << std::endl;

    // Create remote thread
    DWORD threadId;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary,
                                        pRemotePath, 0, &threadId);

    if (!hThread) {
        std::wcerr << L"[-] CreateRemoteThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] Created remote thread: TID " << std::dec << threadId << std::endl;

    // Wait for thread to complete
    WaitForSingleObject(hThread, INFINITE);

    // Get exit code (module base address)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    if (exitCode == 0) {
        std::wcerr << L"[-] DLL failed to load in target process" << std::endl;
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::wcout << L"[+] DLL loaded at: 0x" << std::hex << exitCode << std::endl;

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::wcout << L"[+] Injection successful!" << std::endl;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcout << L"Usage: classic_inject.exe <process_name> <dll_path>" << std::endl;
        std::wcout << L"Example: classic_inject.exe FortniteClient-Win64-Shipping.exe payload.dll" << std::endl;
        return 1;
    }

    std::wstring processName = argv[1];
    std::wstring dllPath = argv[2];

    // Get full DLL path
    wchar_t fullPath[MAX_PATH];
    GetFullPathNameW(dllPath.c_str(), MAX_PATH, fullPath, NULL);
    dllPath = fullPath;

    // Check if DLL exists
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"[-] DLL not found: " << dllPath << std::endl;
        return 1;
    }

    // Get process ID
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        std::wcerr << L"[-] Process not found: " << processName << std::endl;
        return 1;
    }

    std::wcout << L"[+] Target process: " << processName << L" (PID: " << pid << L")" << std::endl;
    std::wcout << L"[+] DLL path: " << dllPath << std::endl;

    // Inject
    if (InjectDLL(pid, dllPath)) {
        return 0;
    }

    return 1;
}
