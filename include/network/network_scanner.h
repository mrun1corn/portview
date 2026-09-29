#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include "core/data_models.h"

class NetworkScanner {
public:
    static NetworkScanner& Instance();

    void Scan(std::vector<ConnectionRow>& connections,
              std::unordered_map<std::string, ULONG64>& processTraffic,
              DWORD& tcpCount, DWORD& udpCount);

    void BuildSummaries(const std::vector<ConnectionRow>& connections,
                        std::vector<ProcessSummaryRow>& summaries);

    std::string ResolveHostname(DWORD ipAddress);
    std::string FormatRemoteEndpoint(DWORD ipAddress, DWORD port);

private:
    NetworkScanner() = default;
    ~NetworkScanner() = default;
    NetworkScanner(const NetworkScanner&) = delete;
    NetworkScanner& operator=(const NetworkScanner&) = delete;

    std::mutex dnsMutex_;
    std::unordered_map<DWORD, std::string> dnsCache_;
    std::unordered_set<DWORD> inFlightDnsQueries_;
    std::unordered_map<std::string, PreviousBytes> prevBytesMap_;
};

// Aliases for backward compatibility
using NetworkTableScanner = NetworkScanner;

inline void LoadData(std::vector<ConnectionRow>& connections,
                     std::unordered_map<std::string, ULONG64>& processTraffic,
                     DWORD& tcpCount, DWORD& udpCount) {
    NetworkScanner::Instance().Scan(connections, processTraffic, tcpCount, udpCount);
}

inline void BuildProcessSummaries(const std::vector<ConnectionRow>& connections,
                                 std::vector<ProcessSummaryRow>& summaries) {
    NetworkScanner::Instance().BuildSummaries(connections, summaries);
}
