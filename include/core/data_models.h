#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <string>

enum FirewallStatus {
    FW_STATUS_NONE,      // No rule (default blocked)
    FW_STATUS_ALLOWED,   // Explicitly allowed
    FW_STATUS_BLOCKED    // Explicitly blocked
};

struct PreviousBytes {
    ULONG64 sentBytes = 0;
    ULONG64 recvBytes = 0;
    DWORD timestamp = 0;
};

struct ConnectionRow {
    std::string proto;
    u_short localPort = 0;
    std::string remoteAddr;
    std::string state;
    DWORD pid = 0;
    std::string procName;
    std::string sentStr = "-";
    std::string recvStr = "-";
    ULONG64 sentBytesVal = 0;
    ULONG64 recvBytesVal = 0;
    ULONG64 totalBytes = 0;
    FirewallStatus fwStatus = FW_STATUS_NONE;
};

struct FirewallRuleRow {
    std::wstring ruleName;
    std::string ruleNameStr;
    u_short port = 0;
    std::string proto;
    bool enabled = false;
    bool allowed = false;
    DWORD pid = 0;
    std::string procName;
    std::string state;
    std::string sentStr = "-";
    std::string recvStr = "-";
    ULONG64 sentBytesVal = 0;
    ULONG64 recvBytesVal = 0;
    int activeConnCount = 0;
};

struct SystemHostMetrics {
    double totalCpuPercent = 0.0;
    ULONG64 usedRamBytes = 0;
    ULONG64 totalRamBytes = 0;
    double ramPercent = 0.0;
    std::string cpuBannerStr;
    std::string ramBannerStr;
};

class ProcessSummaryRow {
public:
    std::string procName;
    DWORD representativePid = 0;
    int portsCount = 0;
    int connsCount = 0;
    ULONG64 sentBytes = 0;
    ULONG64 recvBytes = 0;
    std::string sentStr = "-";
    std::string recvStr = "-";
    
    // CPU & RAM metrics
    double cpuPercent = 0.0;
    ULONG64 ramBytes = 0;
    std::string cpuStr = "-";
    std::string ramStr = "-";

    void addConnection(u_short /*port*/, ULONG64 sent, ULONG64 recv) {
        connsCount++;
        sentBytes += sent;
        recvBytes += recv;
    }

    void finalize(int uniquePortsCount);
};
