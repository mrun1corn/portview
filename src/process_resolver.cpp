#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "process_resolver.h"
#include "utils.h"
#include <psapi.h>

std::string GetProcessName(DWORD pid) {
    static std::unordered_map<DWORD, std::string> cache;
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return it->second;
    }

    if (pid == 0) {
        return "System Idle Process";
    } else if (pid == 4) {
        return "System";
    }

    std::string processName = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            std::wstring wpath(path);
            size_t lastSlash = wpath.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                std::wstring wname = wpath.substr(lastSlash + 1);
                processName = WStringToString(wname);
            } else {
                processName = WStringToString(wpath);
            }
        }
        CloseHandle(hProcess);
    }
    cache[pid] = processName;
    return processName;
}

std::wstring GetProcessImagePath(DWORD pid) {
    if (pid == 0 || pid == 4) return L"";
    std::wstring pathStr = L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            pathStr = path;
        }
        CloseHandle(hProcess);
    }
    return pathStr;
}
