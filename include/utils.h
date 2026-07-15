#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include "firewall.h" // For FirewallStatus

std::string TcpStateToString(DWORD state);
std::string IpToString(DWORD ipAddress);
std::string FormatBytes(ULONG64 bytes);
std::string FormatSpeed(double bytesPerSec);
std::string WStringToString(const std::wstring& wstr);

struct ConnectionRow {
    std::string proto;
    u_short localPort;
    std::string remoteAddr;
    std::string state;
    DWORD pid;
    std::string procName;
    std::string sentStr;
    std::string recvStr;
    ULONG64 sentBytesVal;
    ULONG64 recvBytesVal;
    ULONG64 totalBytes;
    FirewallStatus fwStatus;
};
bool IsElevated();
