#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>

// Link with iphlpapi.lib and ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Convert TCP connection state to string
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

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

std::string GetProcessName(DWORD pid) {
    static std::unordered_map<DWORD, std::string> cache;
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return it->second;
    }

    if (pid == 0) {
        return "System Idle Process";
    } else if (pid == 4) {
        return "System";
    }

    std::string processName = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            std::wstring wpath(path);
            size_t lastSlash = wpath.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                std::wstring wname = wpath.substr(lastSlash + 1);
                processName = WStringToString(wname);
            } else {
                processName = WStringToString(wpath);
            }
        }
        CloseHandle(hProcess);
    }
    cache[pid] = processName;
    return processName;
}
void PauseIfSpawnedConsole() {
    DWORD processList[2];
    DWORD count = GetConsoleProcessList(processList, 2);
    if (count == 1) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
}

int main(int argc, char* argv[]) {
    // Simple Argument Parsing
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            std::cout << "portview v1.0 — Windows Port & Traffic Reviewer\n\n"
                      << "Usage: portview.exe [options]\n\n"
                      << "Options:\n"
                      << "  -h, --help     Show this help message\n"
                      << "  -v, --version  Show version information\n\n"
                      << "Note: Run as administrator to see per-connection traffic stats.\n";
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "portview v1.0\n";
            return 0;
        }
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        PauseIfSpawnedConsole();
        return 1;
    }

    std::cout << "portview v1.0 — Windows Port & Traffic Reviewer\n\n";
    // Enumerate TCP connections using GetExtendedTcpTable
    ULONG size = 0;
    DWORD dwRetVal = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<char> buffer;
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;

    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(size);
        pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        dwRetVal = GetExtendedTcpTable(pTcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    if (dwRetVal != NO_ERROR) {
        std::cerr << "Failed to retrieve TCP table. Error: " << dwRetVal << "\n";
        WSACleanup();
        PauseIfSpawnedConsole();
        return 1;
    }

    std::cout << "TCP Connections (" << pTcpTable->dwNumEntries << " active)\n";
    std::cout << "PORT    REMOTE               STATE         PID    PROCESS            SENT        RECV\n";

    bool elevated = IsElevated();
    std::unordered_map<std::string, ULONG64> processTraffic;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
        auto row = pTcpTable->table[i];
        
        // Local Port (network byte order, convert to host byte order)
        u_short localPort = ntohs((u_short)row.dwLocalPort);
        
        // Remote Address and Port
        std::string remoteIp = IpToString(row.dwRemoteAddr);
        u_short remotePort = ntohs((u_short)row.dwRemotePort);
        std::string remoteAddr = remoteIp + ":" + std::to_string(remotePort);
        if (row.dwRemoteAddr == 0 && remotePort == 0) {
            remoteAddr = "0.0.0.0:*";
        }

        std::string state = TcpStateToString(row.dwState);
        DWORD pid = row.dwOwningPid;
        std::string procName = GetProcessName(pid);

        std::string sentStr = "—";
        std::string recvStr = "—";

        if (elevated) {
            // Try to enable and read stats.
            // SetPerTcpConnectionEStats enables stats for this TCP connection row.
            // However, SetPerTcpConnectionEStats requires a MIB_TCPROW or MIB_TCPROW_LH.
            // Since pTcpTable has table[i] as MIB_TCPROW_OWNER_PID, we need to map or construct a MIB_TCPROW
            // actually, SetPerTcpConnectionEStats expects TCP_ESTATS_TYPE, and an IP Helper TCP row representation.
            // Under Windows SDK:
            // SetPerTcpConnectionEStats(PMIB_TCPROW row, TCP_ESTATS_TYPE type, PBYTE path, ULONG pathVersion, ULONG pathSize)
            // Let's build a MIB_TCPROW from row.
            MIB_TCPROW mibRow;
            mibRow.dwState = row.dwState;
            mibRow.dwLocalAddr = row.dwLocalAddr;
            mibRow.dwLocalPort = row.dwLocalPort;
            mibRow.dwRemoteAddr = row.dwRemoteAddr;
            mibRow.dwRemotePort = row.dwRemotePort;

            TCP_ESTATS_DATA_RW_v0 rw;
            rw.EnableCollection = TRUE;
            SetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, (unsigned char*)&rw, 0, sizeof(rw), 0);

            // Now query stats.
            TCP_ESTATS_DATA_ROD_v0 dataRod;
            ULONG rodSize = sizeof(dataRod);
            DWORD res = GetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0, (unsigned char*)&dataRod, 0, rodSize);
            if (res == NO_ERROR) {
                sentStr = FormatBytes(dataRod.DataBytesOut);
                recvStr = FormatBytes(dataRod.DataBytesIn);
                processTraffic[procName] += dataRod.DataBytesOut + dataRod.DataBytesIn;
            }
        }

        printf("%-7u %-20s %-13s %-6u %-18s %-11s %-11s\n",
               localPort, remoteAddr.c_str(), state.c_str(), pid, procName.c_str(), sentStr.c_str(), recvStr.c_str());
    }


    // Enumerate UDP listeners using GetExtendedUdpTable
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
        std::cout << "\nUDP Listeners (" << pUdpTable->dwNumEntries << " active)\n";
        std::cout << "PORT    PID    PROCESS\n";
        for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
            const auto& row = pUdpTable->table[i];
            u_short localPort = ntohs((u_short)row.dwLocalPort);
            DWORD pid = row.dwOwningPid;
            std::string procName = GetProcessName(pid);
            printf("%-7u %-6u %-18s\n", localPort, pid, procName.c_str());
        }
    } else {
        std::cerr << "\nFailed to retrieve UDP table. Error: " << dwUdpRetVal << "\n";
    }

    DWORD tcpCount = (dwRetVal == NO_ERROR && pTcpTable != nullptr) ? pTcpTable->dwNumEntries : 0;
    DWORD udpCount = (dwUdpRetVal == NO_ERROR && pUdpTable != nullptr) ? pUdpTable->dwNumEntries : 0;

    std::string topTalker = "";
    ULONG64 maxTraffic = 0;
    for (const auto& pair : processTraffic) {
        if (pair.second > maxTraffic) {
            maxTraffic = pair.second;
            topTalker = pair.first;
        }
    }

    std::cout << "\nSummary: " << tcpCount << " TCP | " << udpCount << " UDP";
    if (maxTraffic > 0 && !topTalker.empty()) {
        std::cout << " | Top talker: " << topTalker << " (" << FormatBytes(maxTraffic) << ")";
    }
    std::cout << "\n";

    PauseIfSpawnedConsole();
    WSACleanup();
    return 0;
}
