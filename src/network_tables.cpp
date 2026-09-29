#include "network_tables.h"
#include "utils.h"
#include "process_resolver.h"
#include "firewall.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <algorithm>
#include <thread>

NetworkTableScanner& NetworkTableScanner::Instance() {
    static NetworkTableScanner instance;
    return instance;
}

std::string NetworkTableScanner::ResolveHostname(DWORD ipAddress) {
    if (ipAddress == 0) {
        return "*";
    }

    // Localhost optimization
    if (ipAddress == 0x0100007f) {
        return "localhost";
    }

    {
        std::lock_guard<std::mutex> lock(dnsMutex_);
        auto it = dnsCache_.find(ipAddress);
        if (it != dnsCache_.end()) {
            return it->second;
        }

        // Limit concurrent in-flight DNS requests to avoid thread explosion
        constexpr size_t kMaxConcurrentLookups = 8;
        if (inFlightDnsQueries_.size() < kMaxConcurrentLookups &&
            inFlightDnsQueries_.find(ipAddress) == inFlightDnsQueries_.end()) {
            
            inFlightDnsQueries_.insert(ipAddress);
            std::string fallbackIp = IpToString(ipAddress);

            std::thread([this, ipAddress, fallbackIp]() {
                sockaddr_in sa{};
                sa.sin_family = AF_INET;
                sa.sin_addr.s_addr = ipAddress;
                sa.sin_port = 0;

                char host[NI_MAXHOST] = {0};
                int result = getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
                                         host, sizeof(host), NULL, 0, NI_NOFQDN);
                std::string hostname = (result == 0) ? host : fallbackIp;

                {
                    std::lock_guard<std::mutex> innerLock(dnsMutex_);
                    dnsCache_[ipAddress] = std::move(hostname);
                    inFlightDnsQueries_.erase(ipAddress);
                }
            }).detach();
        }
    }

    return IpToString(ipAddress);
}

std::string NetworkTableScanner::FormatRemoteEndpoint(DWORD ipAddress, DWORD port) {
    if (ipAddress == 0 && port == 0) {
        return "0.0.0.0:*";
    }
    u_short rPort = ntohs(static_cast<u_short>(port));
    std::string host = ResolveHostname(ipAddress);
    return host + ":" + std::to_string(rPort);
}

void NetworkTableScanner::Scan(std::vector<ConnectionRow>& connections,
                              std::unordered_map<std::string, ULONG64>& processTraffic,
                              DWORD& tcpCount, DWORD& udpCount) {
    connections.clear();
    processTraffic.clear();
    tcpCount = 0;
    udpCount = 0;

    bool elevated = IsElevated();
    DWORD currentTimestamp = GetTickCount();
    std::unordered_map<std::string, PreviousBytes> newPrevBytes;

    // 1. Fetch TCP table
    ULONG size = 0;
    DWORD dwRetVal = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<char> buffer;
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;

    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(size);
        pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        dwRetVal = GetExtendedTcpTable(pTcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    if (dwRetVal == NO_ERROR && pTcpTable != nullptr) {
        tcpCount = pTcpTable->dwNumEntries;
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
            const auto& row = pTcpTable->table[i];

            ConnectionRow conn;
            conn.proto = "TCP";
            conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            conn.remoteAddr = FormatRemoteEndpoint(row.dwRemoteAddr, row.dwRemotePort);
            conn.state = TcpStateToString(row.dwState);
            conn.pid = row.dwOwningPid;
            conn.procName = ProcessResolver::GetProcessName(conn.pid);

            if (elevated) {
                MIB_TCPROW mibRow;
                mibRow.dwState = row.dwState;
                mibRow.dwLocalAddr = row.dwLocalAddr;
                mibRow.dwLocalPort = row.dwLocalPort;
                mibRow.dwRemoteAddr = row.dwRemoteAddr;
                mibRow.dwRemotePort = row.dwRemotePort;

                TCP_ESTATS_DATA_RW_v0 rw{};
                rw.EnableCollection = TRUE;
                SetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, reinterpret_cast<unsigned char*>(&rw), 0, sizeof(rw), 0);

                TCP_ESTATS_DATA_ROD_v0 dataRod{};
                ULONG rodSize = sizeof(dataRod);
                DWORD res = GetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0,
                                                     reinterpret_cast<unsigned char*>(&dataRod), 0, rodSize);
                if (res == NO_ERROR) {
                    ULONG64 rawSent = dataRod.DataBytesOut;
                    ULONG64 rawRecv = dataRod.DataBytesIn;
                    std::string key = conn.proto + ":" + std::to_string(conn.localPort) + "->" + conn.remoteAddr;

                    double sentSpeed = 0.0;
                    double recvSpeed = 0.0;
                    auto it = prevBytesMap_.find(key);
                    if (it != prevBytesMap_.end()) {
                        DWORD timeDelta = currentTimestamp - it->second.timestamp;
                        if (timeDelta > 0) {
                            if (rawSent >= it->second.sentBytes) {
                                sentSpeed = (rawSent - it->second.sentBytes) / (timeDelta / 1000.0);
                            }
                            if (rawRecv >= it->second.recvBytes) {
                                recvSpeed = (rawRecv - it->second.recvBytes) / (timeDelta / 1000.0);
                            }
                        }
                    }

                    PreviousBytes pb;
                    pb.sentBytes = rawSent;
                    pb.recvBytes = rawRecv;
                    pb.timestamp = currentTimestamp;
                    newPrevBytes[key] = pb;

                    conn.sentBytesVal = static_cast<ULONG64>(sentSpeed);
                    conn.recvBytesVal = static_cast<ULONG64>(recvSpeed);
                    conn.sentStr = FormatSpeed(sentSpeed);
                    conn.recvStr = FormatSpeed(recvSpeed);
                    conn.totalBytes = conn.sentBytesVal + conn.recvBytesVal;
                    processTraffic[conn.procName] += conn.totalBytes;
                }
            }

            conn.fwStatus = FirewallManager::Instance().QueryStatus(conn.localPort, conn.proto);
            connections.push_back(std::move(conn));
        }
    }

    // 2. Fetch UDP table
    ULONG udpSize = 0;
    DWORD dwUdpRetVal = GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<char> udpBuffer;
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;

    if (dwUdpRetVal == ERROR_INSUFFICIENT_BUFFER) {
        udpBuffer.resize(udpSize);
        pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpBuffer.data());
        dwUdpRetVal = GetExtendedUdpTable(pUdpTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    }

    if (dwUdpRetVal == NO_ERROR && pUdpTable != nullptr) {
        udpCount = pUdpTable->dwNumEntries;
        for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
            const auto& row = pUdpTable->table[i];

            ConnectionRow conn;
            conn.proto = "UDP";
            conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            conn.remoteAddr = "*:*";
            conn.state = "-";
            conn.pid = row.dwOwningPid;
            conn.procName = ProcessResolver::GetProcessName(conn.pid);
            conn.fwStatus = FirewallManager::Instance().QueryStatus(conn.localPort, conn.proto);
            connections.push_back(std::move(conn));
        }
    }

    // Sort connections: first by PROTO (TCP before UDP), then by PORT
    std::sort(connections.begin(), connections.end(), [](const ConnectionRow& a, const ConnectionRow& b) {
        bool aIsTcp = (a.proto == "TCP");
        bool bIsTcp = (b.proto == "TCP");
        if (aIsTcp != bIsTcp) {
            return aIsTcp;
        }
        if (a.proto != b.proto) {
            return a.proto < b.proto;
        }
        return a.localPort < b.localPort;
    });

    if (elevated) {
        prevBytesMap_ = std::move(newPrevBytes);
    }
}

void NetworkTableScanner::BuildSummaries(const std::vector<ConnectionRow>& connections,
                                         std::vector<ProcessSummaryRow>& summaries) {
    summaries.clear();
    std::unordered_map<std::string, std::vector<size_t>> groups;
    for (size_t i = 0; i < connections.size(); ++i) {
        std::string name = connections[i].procName;
        if (name.empty() || name == "-") {
            name = "Unknown";
        }
        groups[name].push_back(i);
    }

    // Add idle processes from firewall rules snapshot
    std::vector<FirewallRuleRow> rules = FirewallManager::Instance().GetRulesSnapshot();
    std::unordered_map<std::string, std::vector<FirewallRuleRow>> idleProcRules;
    for (const auto& rule : rules) {
        if (!rule.procName.empty() && rule.procName != "-") {
            std::string name = rule.procName;
            if (groups.find(name) == groups.end()) {
                idleProcRules[name].push_back(rule);
            }
        }
    }

    for (const auto& [name, indices] : groups) {
        ProcessSummaryRow summary;
        summary.procName = name;
        std::unordered_set<u_short> uniquePorts;

        for (size_t idx : indices) {
            const auto& conn = connections[idx];
            uniquePorts.insert(conn.localPort);
            summary.addConnection(conn.localPort, conn.sentBytesVal, conn.recvBytesVal);
        }

        summary.finalize(static_cast<int>(uniquePorts.size()));
        summaries.push_back(std::move(summary));
    }

    for (const auto& [name, idleRules] : idleProcRules) {
        ProcessSummaryRow summary;
        summary.procName = name;
        std::unordered_set<u_short> uniquePorts;
        for (const auto& r : idleRules) {
            uniquePorts.insert(r.port);
        }
        summary.finalize(static_cast<int>(uniquePorts.size()));
        summaries.push_back(std::move(summary));
    }

    std::sort(summaries.begin(), summaries.end(), [](const ProcessSummaryRow& a, const ProcessSummaryRow& b) {
        ULONG64 aTotal = a.sentBytes + a.recvBytes;
        ULONG64 bTotal = b.sentBytes + b.recvBytes;
        if (aTotal != bTotal) {
            return aTotal > bTotal;
        }
        if (a.connsCount != b.connsCount) {
            return a.connsCount > b.connsCount;
        }
        if (a.portsCount != b.portsCount) {
            return a.portsCount > b.portsCount;
        }
        return a.procName < b.procName;
    });
}
