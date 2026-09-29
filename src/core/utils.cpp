#include "core/utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstdio>
#include <iostream>
#include <algorithm>

ScopedWinsock::ScopedWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
        initialized_ = true;
    } else {
        std::cerr << "Failed to initialize Winsock.\n";
    }
}

ScopedWinsock::~ScopedWinsock() {
    if (initialized_) {
        WSACleanup();
        initialized_ = false;
    }
}

ScopedCom::ScopedCom(DWORD coInit) {
    hr_ = CoInitializeEx(NULL, coInit);
}

ScopedCom::~ScopedCom() {
    if (SUCCEEDED(hr_)) {
        CoUninitialize();
    }
}

void ProcessSummaryRow::finalize(int uniquePortsCount) {
    portsCount = uniquePortsCount;
    sentStr = (sentBytes > 0) ? FormatBytes(sentBytes) : "-";
    recvStr = (recvBytes > 0) ? FormatBytes(recvBytes) : "-";
    ramStr = (ramBytes > 0) ? FormatBytes(ramBytes) : "-";
    if (cpuPercent > 0.0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f%%", cpuPercent);
        cpuStr = buf;
    } else {
        cpuStr = "0.0%";
    }
}

std::string TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
}

std::string IpToString(DWORD ipAddress) {
    IN_ADDR inAddr;
    inAddr.S_un.S_addr = ipAddress;
    char ipStr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &inAddr, ipStr, sizeof(ipStr))) {
        return ipStr;
    }
    return "0.0.0.0";
}

std::string FormatBytes(ULONG64 bytes) {
    double num = static_cast<double>(bytes);
    constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    while (num >= 1024.0 && unitIndex < 4) {
        num /= 1024.0;
        unitIndex++;
    }
    char buf[64];
    if (unitIndex == 0) {
        std::snprintf(buf, sizeof(buf), "%llu B", bytes);
    } else {
        std::snprintf(buf, sizeof(buf), "%.1f %s", num, units[unitIndex]);
    }
    return buf;
}

std::string FormatSpeed(double bytesPerSec) {
    if (bytesPerSec < 0.0) return "-";
    if (bytesPerSec == 0.0) return "0 B/s";
    double num = bytesPerSec;
    constexpr const char* units[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
    int unitIndex = 0;
    while (num >= 1024.0 && unitIndex < 4) {
        num /= 1024.0;
        unitIndex++;
    }
    char buf[64];
    if (unitIndex == 0) {
        std::snprintf(buf, sizeof(buf), "%d B/s", static_cast<int>(bytesPerSec));
    } else {
        std::snprintf(buf, sizeof(buf), "%.1f %s", num, units[unitIndex]);
    }
    return buf;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return "";
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

std::string PadOrTrim(std::string str, int targetWidth) {
    if (targetWidth <= 0) return "";
    size_t width = static_cast<size_t>(targetWidth);
    if (str.length() < width) {
        str.append(width - str.length(), ' ');
    } else if (str.length() > width) {
        str = str.substr(0, width);
    }
    return str;
}

bool IsElevated() {
    bool elevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = (elevation.TokenIsElevated != 0);
        }
        CloseHandle(hToken);
    }
    return elevated;
}

bool CopyToClipboard(const std::string& text) {
    if (text.empty()) return false;
    if (!OpenClipboard(NULL)) return false;
    EmptyClipboard();
    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hGlob) {
        CloseClipboard();
        return false;
    }
    char* pBuf = static_cast<char*>(GlobalLock(hGlob));
    if (pBuf) {
        std::memcpy(pBuf, text.c_str(), text.size() + 1);
        GlobalUnlock(hGlob);
        SetClipboardData(CF_TEXT, hGlob);
    }
    CloseClipboard();
    return true;
}
