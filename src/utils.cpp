#include "utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <stdio.h>

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
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    while (num >= 1024.0 && unitIndex < 4) {
        num /= 1024.0;
        unitIndex++;
    }
    char buf[64];
    if (unitIndex == 0) {
        sprintf(buf, "%d B", static_cast<int>(bytes));
    } else {
        sprintf(buf, "%.1f %s", num, units[unitIndex]);
    }
    return buf;
}

std::string FormatSpeed(double bytesPerSec) {
    if (bytesPerSec < 0) return "-";
    if (bytesPerSec == 0) return "0 B/s";
    double num = bytesPerSec;
    const char* units[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
    int unitIndex = 0;
    while (num >= 1024.0 && unitIndex < 4) {
        num /= 1024.0;
        unitIndex++;
    }
    char buf[64];
    if (unitIndex == 0) {
        sprintf(buf, "%d B/s", static_cast<int>(bytesPerSec));
    } else {
        sprintf(buf, "%.1f %s", num, units[unitIndex]);
    }
    return buf;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}
bool IsElevated() {
    bool elevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    return elevated;
}

