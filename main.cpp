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
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        return 1;
    }

    std::cout << "portview v1.0 — Windows Port & Traffic Reviewer\n\n";

    // Enumerate TCP
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
        std::cout << "TCP Connections (" << pTcpTable->dwNumEntries << " active)\n";
        std::cout << "PORT    REMOTE               STATE         PID    PROCESS            SENT        RECV\n";
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
            const auto& row = pTcpTable->table[i];
            u_short localPort = ntohs((u_short)row.dwLocalPort);
            std::string remoteIp = IpToString(row.dwRemoteAddr);
            u_short remotePort = ntohs((u_short)row.dwRemotePort);
            std::string remoteAddr = remoteIp + ":" + std::to_string(remotePort);
            if (row.dwRemoteAddr == 0 && remotePort == 0) {
                remoteAddr = "0.0.0.0:*";
            }
            std::string state = TcpStateToString(row.dwState);
            DWORD pid = row.dwOwningPid;
            std::string procName = GetProcessName(pid);
            printf("%-7u %-20s %-13s %-6u %-18s %-11s %-11s\n",
                   localPort, remoteAddr.c_str(), state.c_str(), pid, procName.c_str(), "—", "—");
        }
    }

    // Enumerate UDP
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
    }

    WSACleanup();
    return 0;
}
