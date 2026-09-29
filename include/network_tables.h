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
#include "data_models.h"

class NetworkTableScanner {
public:
    static NetworkTableScanner& Instance();

    void Scan(std::vector<ConnectionRow>& connections,
              std::unordered_map<std::string, ULONG64>& processTraffic,
              DWORD& tcpCount, DWORD& udpCount);

    void BuildSummaries(const std::vector<ConnectionRow>& connections,
                        std::vector<ProcessSummaryRow>& summaries);

    std::string ResolveHostname(DWORD ipAddress);
    std::string FormatRemoteEndpoint(DWORD ipAddress, DWORD port);

private:
    NetworkTableScanner() = default;
    ~NetworkTableScanner() = default;
    NetworkTableScanner(const NetworkTableScanner&) = delete;
    NetworkTableScanner& operator=(const NetworkTableScanner&) = delete;

    std::mutex dnsMutex_;
    std::unordered_map<DWORD, std::string> dnsCache_;
    std::unordered_set<DWORD> inFlightDnsQueries_;

    std::unordered_map<std::string, PreviousBytes> prevBytesMap_;
};

// Convenience procedural interface
inline void LoadData(std::vector<ConnectionRow>& connections,
                     std::unordered_map<std::string, ULONG64>& processTraffic,
                     DWORD& tcpCount, DWORD& udpCount) {
    NetworkTableScanner::Instance().Scan(connections, processTraffic, tcpCount, udpCount);
}

inline void BuildProcessSummaries(const std::vector<ConnectionRow>& connections,
                                 std::vector<ProcessSummaryRow>& summaries) {
    NetworkTableScanner::Instance().BuildSummaries(connections, summaries);
}
