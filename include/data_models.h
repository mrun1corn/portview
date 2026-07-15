#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include "utils.h"

struct PreviousBytes {
    ULONG64 sentBytes;
    ULONG64 recvBytes;
    DWORD timestamp;
};

class ProcessSummaryRow {
public:
    std::string procName;
    int portsCount = 0;
    int connsCount = 0;
    ULONG64 sentBytes = 0;
    ULONG64 recvBytes = 0;
    std::string sentStr = "-";
    std::string recvStr = "-";

    void addConnection(u_short port, ULONG64 sent, ULONG64 recv) {
        connsCount++;
        sentBytes += sent;
        recvBytes += recv;
    }

    void finalize(int uniquePortsCount) {
        portsCount = uniquePortsCount;
        sentStr = (sentBytes > 0) ? FormatBytes(sentBytes) : "-";
        recvStr = (recvBytes > 0) ? FormatBytes(recvBytes) : "-";
    }
};

