#include <algorithm>
#include "network_tables.h"
#include "utils.h"
#include "process_resolver.h"
#include "firewall.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <mutex>
#include <unordered_set>
#include <thread>

std::mutex g_dnsMutex;
std::unordered_map<DWORD, std::string> g_dnsCache;
std::unordered_set<DWORD> g_resolvingQueue;
std::unordered_map<std::string, PreviousBytes> g_prevConnectionBytes;

std::string ResolveIpToHostname(DWORD ipAddress) {
    if (ipAddress == 0) {
        return "*";
    }

    // Localhost optimization to avoid querying DNS
    if (ipAddress == 0x0100007f) {
        return "localhost";
    }

    {
        std::lock_guard<std::mutex> lock(g_dnsMutex);
        auto it = g_dnsCache.find(ipAddress);
        if (it != g_dnsCache.end()) {
            return it->second;
        }

        // Kick off asynchronous resolution if not already in flight
        if (g_resolvingQueue.find(ipAddress) == g_resolvingQueue.end()) {
            g_resolvingQueue.insert(ipAddress);
            
            std::string fallbackIp = IpToString(ipAddress);
            std::thread([ipAddress, fallbackIp]() {
                sockaddr_in sa;
                sa.sin_family = AF_INET;
                sa.sin_addr.s_addr = ipAddress;
                sa.sin_port = 0;

                char host[NI_MAXHOST];
                int result = getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NOFQDN);
                std::string hostname = (result == 0) ? host : fallbackIp;

                {
                    std::lock_guard<std::mutex> lock(g_dnsMutex);
                    g_dnsCache[ipAddress] = hostname;
                    g_resolvingQueue.erase(ipAddress);
                }
            }).detach();
        }
    }

    return IpToString(ipAddress);
}

std::string GetRemoteAddrString(DWORD ipAddress, DWORD port) {
    if (ipAddress == 0 && port == 0) {
        return "0.0.0.0:*";
    }
    u_short rPort = ntohs((u_short)port);
    std::string host = ResolveIpToHostname(ipAddress);
    return host + ":" + std::to_string(rPort);
}

void LoadData(std::vector<ConnectionRow>& connections, std::unordered_map<std::string, ULONG64>& processTraffic, DWORD& tcpCount, DWORD& udpCount) {
    connections.clear();
    processTraffic.clear();
    tcpCount = 0;
    udpCount = 0;

    bool elevated = IsElevated();
    DWORD currentTimestamp = GetTickCount();
    std::unordered_map<std::string, PreviousBytes> newPrevBytes;
    // 1. Fetch TCP
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
            conn.localPort = ntohs((u_short)row.dwLocalPort);
            
            conn.remoteAddr = GetRemoteAddrString(row.dwRemoteAddr, row.dwRemotePort);
            conn.state = TcpStateToString(row.dwState);
            conn.pid = row.dwOwningPid;
            conn.procName = GetProcessName(conn.pid);
            conn.sentStr = "-";
            conn.recvStr = "-";
            conn.sentBytesVal = 0;
            conn.recvBytesVal = 0;
            conn.totalBytes = 0;

            if (elevated) {
                MIB_TCPROW mibRow;
                mibRow.dwState = row.dwState;
                mibRow.dwLocalAddr = row.dwLocalAddr;
                mibRow.dwLocalPort = row.dwLocalPort;
                mibRow.dwRemoteAddr = row.dwRemoteAddr;
                mibRow.dwRemotePort = row.dwRemotePort;

                TCP_ESTATS_DATA_RW_v0 rw;
                rw.EnableCollection = TRUE;
                SetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, (unsigned char*)&rw, 0, sizeof(rw), 0);

                TCP_ESTATS_DATA_ROD_v0 dataRod;
                ULONG rodSize = sizeof(dataRod);
                DWORD res = GetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0, (unsigned char*)&dataRod, 0, rodSize);
                if (res == NO_ERROR) {
                    ULONG64 rawSent = dataRod.DataBytesOut;
                    ULONG64 rawRecv = dataRod.DataBytesIn;
                    std::string key = conn.proto + ":" + std::to_string(conn.localPort) + "->" + conn.remoteAddr;
                    
                    double sentSpeed = 0;
                    double recvSpeed = 0;
                    auto it = g_prevConnectionBytes.find(key);
                    if (it != g_prevConnectionBytes.end()) {
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
            conn.fwStatus = QueryFirewallCache(conn.localPort, conn.proto);
            connections.push_back(conn);
        }
    }

    // 2. Fetch UDP
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
            conn.localPort = ntohs((u_short)row.dwLocalPort);
            conn.remoteAddr = "*:*";
            conn.state = "-";
            conn.pid = row.dwOwningPid;
            conn.procName = GetProcessName(conn.pid);
            conn.sentStr = "-";
            conn.recvStr = "-";
            conn.sentBytesVal = 0;
            conn.recvBytesVal = 0;
            conn.totalBytes = 0;
            conn.fwStatus = QueryFirewallCache(conn.localPort, conn.proto);
            connections.push_back(conn);
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
        g_prevConnectionBytes = std::move(newPrevBytes);
    }
}

void BuildProcessSummaries(const std::vector<ConnectionRow>& connections, std::vector<ProcessSummaryRow>& summaries) {
    summaries.clear();
    std::unordered_map<std::string, std::vector<size_t>> groups;
    for (size_t i = 0; i < connections.size(); ++i) {
        std::string name = connections[i].procName;
        if (name.empty() || name == "-") {
            name = "Unknown";
        }
        groups[name].push_back(i);
    }

    // Add idle processes from firewall rules
    std::vector<FirewallRuleRow> rules;
    {
        std::lock_guard<std::mutex> lock(g_fwMutex);
        rules = g_fwRulesList;
    }

    // Map process name to its custom rules
    std::unordered_map<std::string, std::vector<FirewallRuleRow>> idleProcRules;
    for (const auto& rule : rules) {
        if (!rule.procName.empty() && rule.procName != "-") {
            std::string name = rule.procName;
            if (groups.find(name) == groups.end()) {
                idleProcRules[name].push_back(rule);
            }
        }
    }

    // First process active groups
    for (const auto& pair : groups) {
        const std::string& name = pair.first;
        ProcessSummaryRow row;
        row.procName = name;

        std::unordered_set<u_short> uniquePorts;
        for (size_t idx : pair.second) {
            const auto& conn = connections[idx];
            uniquePorts.insert(conn.localPort);
            row.addConnection(conn.localPort, conn.sentBytesVal, conn.recvBytesVal);
        }

        row.finalize(static_cast<int>(uniquePorts.size()));
        summaries.push_back(row);
    }

    // Now process idle firewall-only groups
    // Now process idle firewall-only groups
    for (const auto& pair : idleProcRules) {
        const std::string& name = pair.first;
        ProcessSummaryRow row;
        row.procName = name;
        
        std::unordered_set<u_short> uniquePorts;
        for (const auto& rule : pair.second) {
            uniquePorts.insert(rule.port);
        }
        row.finalize(static_cast<int>(uniquePorts.size()));
        if (row.portsCount > 0 || row.connsCount > 0) {
            summaries.push_back(row);
        }
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

