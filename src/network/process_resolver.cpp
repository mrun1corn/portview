#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include "network/process_resolver.h"
#include "core/utils.h"
#include <psapi.h>
#include <mutex>
#include <unordered_map>

namespace {
std::mutex g_procCacheMutex;
std::unordered_map<DWORD, std::string> g_procNameCache;
std::unordered_map<DWORD, std::wstring> g_procPathCache;
} // namespace

std::string ProcessResolver::GetProcessName(DWORD pid) {
    if (pid == 0) {
        return "System Idle Process";
    }
    if (pid == 4) {
        return "System";
    }

    {
        std::lock_guard<std::mutex> lock(g_procCacheMutex);
        auto it = g_procNameCache.find(pid);
        if (it != g_procNameCache.end()) {
            return it->second;
        }
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

    {
        std::lock_guard<std::mutex> lock(g_procCacheMutex);
        g_procNameCache[pid] = processName;
    }

    return processName;
}

std::wstring ProcessResolver::GetProcessImagePath(DWORD pid) {
    if (pid == 0 || pid == 4) {
        return L"";
    }

    {
        std::lock_guard<std::mutex> lock(g_procCacheMutex);
        auto it = g_procPathCache.find(pid);
        if (it != g_procPathCache.end()) {
            return it->second;
        }
    }

    std::wstring appPath = L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            appPath = path;
        }
        CloseHandle(hProcess);
    }

    {
        std::lock_guard<std::mutex> lock(g_procCacheMutex);
        g_procPathCache[pid] = appPath;
    }

    return appPath;
}

void ProcessResolver::EvictPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(g_procCacheMutex);
    g_procNameCache.erase(pid);
    g_procPathCache.erase(pid);
}

void ProcessResolver::ClearCache() {
    std::lock_guard<std::mutex> lock(g_procCacheMutex);
    g_procNameCache.clear();
    g_procPathCache.clear();
}
