#include "network/network_scanner.h"
#include "core/system_metrics.h"
#include "core/utils.h"
#include "network/process_resolver.h"
#include "security/firewall_manager.h"
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>
// clang-format on
#include <algorithm>
#include <thread>

NetworkScanner &NetworkScanner::Instance() {
  static NetworkScanner instance;
  return instance;
}

std::string NetworkScanner::ResolveHostname(DWORD ipAddress) {
  if (ipAddress == 0) {
    return "*";
  }

  if (ipAddress == 0x0100007f) {
    return "localhost";
  }

  {
    std::lock_guard<std::mutex> lock(dnsMutex_);
    auto it = dnsCache_.find(ipAddress);
    if (it != dnsCache_.end()) {
      return it->second;
    }

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
        int result = getnameinfo(reinterpret_cast<sockaddr *>(&sa), sizeof(sa),
                                 host, sizeof(host), NULL, 0, NI_NOFQDN);
        std::string hostname = (result == 0) ? host : fallbackIp;

        {
          std::lock_guard<std::mutex> innerLock(dnsMutex_);
          if (dnsCache_.size() >= 512) {
            dnsCache_.clear();
          }
          dnsCache_[ipAddress] = std::move(hostname);
          inFlightDnsQueries_.erase(ipAddress);
        }
      }).detach();
    }
  }

  return IpToString(ipAddress);
}

std::string NetworkScanner::FormatRemoteEndpoint(DWORD ipAddress, DWORD port) {
  if (ipAddress == 0 && port == 0) {
    return "0.0.0.0:*";
  }
  u_short rPort = ntohs(static_cast<u_short>(port));
  std::string host = ResolveHostname(ipAddress);
  return host + ":" + std::to_string(rPort);
}

void NetworkScanner::Scan(
    std::vector<ConnectionRow> &connections,
    std::unordered_map<std::string, ULONG64> &processTraffic, DWORD &tcpCount,
    DWORD &udpCount) {
  connections.clear();
  processTraffic.clear();
  tcpCount = 0;
  udpCount = 0;

  DWORD now = GetTickCount();

  std::unordered_set<std::string> activeKeys;

  // 1. TCP Connections
  ULONG tcpSize = 0;
  GetExtendedTcpTable(NULL, &tcpSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                      0);
  std::vector<BYTE> tcpBuffer(tcpSize);
  if (GetExtendedTcpTable(tcpBuffer.data(), &tcpSize, FALSE, AF_INET,
                          TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
    auto *pTcpTable =
        reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tcpBuffer.data());
    tcpCount = pTcpTable->dwNumEntries;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
      MIB_TCPROW_OWNER_PID &row = pTcpTable->table[i];
      ConnectionRow conn;
      conn.proto = "TCP";
      conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
      conn.remoteAddr =
          FormatRemoteEndpoint(row.dwRemoteAddr, row.dwRemotePort);
      conn.state = TcpStateToString(row.dwState);
      conn.pid = row.dwOwningPid;
      conn.procName = ProcessResolver::GetProcessName(row.dwOwningPid);

      if (IsElevated()) {
        MIB_TCPROW tcpRow{};
        tcpRow.dwState = row.dwState;
        tcpRow.dwLocalAddr = row.dwLocalAddr;
        tcpRow.dwLocalPort = row.dwLocalPort;
        tcpRow.dwRemoteAddr = row.dwRemoteAddr;
        tcpRow.dwRemotePort = row.dwRemotePort;

        TCP_ESTATS_DATA_RW_v0 dataRw{};
        dataRw.EnableCollection = TRUE;
        SetPerTcpConnectionEStats(&tcpRow, TcpConnectionEstatsData,
                                  reinterpret_cast<PUCHAR>(&dataRw), 0,
                                  sizeof(dataRw), 0);

        TCP_ESTATS_DATA_ROD_v0 dataRod{};
        ULONG status = GetPerTcpConnectionEStats(
            &tcpRow, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0,
            reinterpret_cast<PUCHAR>(&dataRod), 0, sizeof(dataRod));

        if (status == NO_ERROR) {
          conn.sentBytesVal = dataRod.DataBytesOut;
          conn.recvBytesVal = dataRod.DataBytesIn;
          conn.totalBytes = conn.sentBytesVal + conn.recvBytesVal;

          std::string key = conn.proto + ":" + std::to_string(row.dwLocalAddr) +
                            ":" + std::to_string(row.dwLocalPort) + "-" +
                            std::to_string(row.dwRemoteAddr) + ":" +
                            std::to_string(row.dwRemotePort);
          activeKeys.insert(key);

          auto it = prevBytesMap_.find(key);
          if (it != prevBytesMap_.end()) {
            DWORD timeDiff = now - it->second.timestamp;
            if (timeDiff > 0) {
              ULONG64 sentDiff =
                  (conn.sentBytesVal >= it->second.sentBytes)
                      ? (conn.sentBytesVal - it->second.sentBytes)
                      : 0;
              ULONG64 recvDiff =
                  (conn.recvBytesVal >= it->second.recvBytes)
                      ? (conn.recvBytesVal - it->second.recvBytes)
                      : 0;

              double sentSpeed = (static_cast<double>(sentDiff) * 1000.0) /
                                 static_cast<double>(timeDiff);
              double recvSpeed = (static_cast<double>(recvDiff) * 1000.0) /
                                 static_cast<double>(timeDiff);

              conn.sentStr = FormatSpeed(sentSpeed);
              conn.recvStr = FormatSpeed(recvSpeed);

              processTraffic[conn.procName] += (sentDiff + recvDiff);
            }
          } else {
            conn.sentStr = FormatSpeed(0);
            conn.recvStr = FormatSpeed(0);
          }

          PreviousBytes pb;
          pb.sentBytes = conn.sentBytesVal;
          pb.recvBytes = conn.recvBytesVal;
          pb.timestamp = now;
          prevBytesMap_[key] = pb;
        }
      }

      conn.fwStatus = FirewallManager::Instance().EvaluateStatus(
          conn.localPort, conn.proto, conn.procName);
      connections.push_back(std::move(conn));
    }
  }

  // 2. UDP Listeners
  ULONG udpSize = 0;
  GetExtendedUdpTable(NULL, &udpSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
  std::vector<BYTE> udpBuffer(udpSize);
  if (GetExtendedUdpTable(udpBuffer.data(), &udpSize, FALSE, AF_INET,
                          UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
    auto *pUdpTable =
        reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpBuffer.data());
    udpCount = pUdpTable->dwNumEntries;

    for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
      MIB_UDPROW_OWNER_PID &row = pUdpTable->table[i];
      ConnectionRow conn;
      conn.proto = "UDP";
      conn.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
      conn.remoteAddr = "*:*";
      conn.state = "LISTENING";
      conn.pid = row.dwOwningPid;
      conn.procName = ProcessResolver::GetProcessName(row.dwOwningPid);
      conn.fwStatus = FirewallManager::Instance().EvaluateStatus(
          conn.localPort, conn.proto, conn.procName);
      connections.push_back(std::move(conn));
    }
  }

  // Prune stale connection keys to prevent unbounded memory growth
  for (auto it = prevBytesMap_.begin(); it != prevBytesMap_.end();) {
    if (activeKeys.find(it->first) == activeKeys.end()) {
      it = prevBytesMap_.erase(it);
    } else {
      ++it;
    }
  }
}

void NetworkScanner::BuildSummaries(
    const std::vector<ConnectionRow> &connections,
    std::vector<ProcessSummaryRow> &summaries) {
  summaries.clear();

  std::unordered_set<DWORD> activePids;
  for (const auto &conn : connections) {
    if (conn.pid > 0) {
      activePids.insert(conn.pid);
    }
  }
  SystemMetrics::Instance().PruneDeadPids(activePids);

  std::unordered_map<std::string, std::vector<size_t>> groups;
  for (size_t i = 0; i < connections.size(); ++i) {
    std::string name = connections[i].procName;
    if (name.empty() || name == "-") {
      name = "Unknown";
    }
    groups[name].push_back(i);
  }

  // Add idle processes from firewall rules snapshot
  std::vector<FirewallRuleRow> rules =
      FirewallManager::Instance().GetRulesSnapshot();
  std::unordered_map<std::string, std::vector<FirewallRuleRow>> idleProcRules;
  for (const auto &rule : rules) {
    if (!rule.procName.empty() && rule.procName != "-") {
      std::string name = rule.procName;
      if (groups.find(name) == groups.end()) {
        idleProcRules[name].push_back(rule);
      }
    }
  }

  for (const auto &[name, indices] : groups) {
    ProcessSummaryRow summary;
    summary.procName = name;
    std::unordered_set<u_short> uniquePorts;
    std::unordered_set<DWORD> uniquePids;

    for (size_t idx : indices) {
      const auto &conn = connections[idx];
      uniquePorts.insert(conn.localPort);
      if (conn.pid > 0) {
        uniquePids.insert(conn.pid);
      }
      summary.addConnection(conn.localPort, conn.sentBytesVal,
                            conn.recvBytesVal);
    }

    // Aggregate CPU & RAM across all PIDs of this process
    for (DWORD pid : uniquePids) {
      double procCpu = 0.0;
      ULONG64 procRam = 0;
      SystemMetrics::Instance().QueryProcessMetrics(pid, procCpu, procRam);
      summary.cpuPercent += procCpu;
      summary.ramBytes += procRam;
      if (summary.representativePid == 0) {
        summary.representativePid = pid;
      }
      summary.pids.push_back(pid);
    }

    summary.finalize(static_cast<int>(uniquePorts.size()));
    summaries.push_back(std::move(summary));
  }

  for (const auto &[name, idleRules] : idleProcRules) {
    ProcessSummaryRow summary;
    summary.procName = name;
    std::unordered_set<u_short> uniquePorts;
    for (const auto &r : idleRules) {
      uniquePorts.insert(r.port);
    }
    summary.finalize(static_cast<int>(uniquePorts.size()));
    summaries.push_back(std::move(summary));
  }

  std::sort(summaries.begin(), summaries.end(),
            [](const ProcessSummaryRow &a, const ProcessSummaryRow &b) {
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
