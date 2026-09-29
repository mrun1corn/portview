#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>

class ProcessResolver {
public:
    static std::string GetProcessName(DWORD pid);
    static std::wstring GetProcessImagePath(DWORD pid);
};

inline std::string GetProcessName(DWORD pid) {
    return ProcessResolver::GetProcessName(pid);
}

inline std::wstring GetProcessImagePath(DWORD pid) {
    return ProcessResolver::GetProcessImagePath(pid);
}
