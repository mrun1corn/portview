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
#include <io.h>

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
struct ConnectionRow {
    std::string proto;
    u_short localPort;
    std::string remoteAddr;
    std::string state;
    DWORD pid;
    std::string procName;
    std::string sentStr;
    std::string recvStr;
    ULONG64 totalBytes;
};

bool IsStdoutTerminal() {
    return _isatty(_fileno(stdout)) != 0;
}

void GetConsoleSize(int& width, int& height) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    } else {
        width = 80;
        height = 25;
    }
}

void ShowConsoleCursor(bool showFlag) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hOut, &cursorInfo);
    cursorInfo.bVisible = showFlag;
    SetConsoleCursorInfo(hOut, &cursorInfo);
}

void SetCursorPosition(int x, int y) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        COORD coord = { (SHORT)(csbi.srWindow.Left + x), (SHORT)(csbi.srWindow.Top + y) };
        SetConsoleCursorPosition(hOut, coord);
    }
}

void PauseIfSpawnedConsole() {
    DWORD processList[2];
    DWORD count = GetConsoleProcessList(processList, 2);
    if (count == 1) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
}

void LoadData(std::vector<ConnectionRow>& connections, std::unordered_map<std::string, ULONG64>& processTraffic, DWORD& tcpCount, DWORD& udpCount) {
    connections.clear();
    processTraffic.clear();
    tcpCount = 0;
    udpCount = 0;

    bool elevated = IsElevated();

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
            
            std::string remoteIp = IpToString(row.dwRemoteAddr);
            u_short remotePort = ntohs((u_short)row.dwRemotePort);
            conn.remoteAddr = remoteIp + ":" + std::to_string(remotePort);
            if (row.dwRemoteAddr == 0 && remotePort == 0) {
                conn.remoteAddr = "0.0.0.0:*";
            }
            conn.state = TcpStateToString(row.dwState);
            conn.pid = row.dwOwningPid;
            conn.procName = GetProcessName(conn.pid);
            conn.sentStr = "—";
            conn.recvStr = "—";
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
                    conn.sentStr = FormatBytes(dataRod.DataBytesOut);
                    conn.recvStr = FormatBytes(dataRod.DataBytesIn);
                    conn.totalBytes = dataRod.DataBytesOut + dataRod.DataBytesIn;
                    processTraffic[conn.procName] += conn.totalBytes;
                }
            }
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
            conn.state = "—";
            conn.pid = row.dwOwningPid;
            conn.procName = GetProcessName(conn.pid);
            conn.sentStr = "—";
            conn.recvStr = "—";
            conn.totalBytes = 0;

            connections.push_back(conn);
        }
    }

    // Sort connections: first by PROTO (TCP before UDP), then by PORT
    std::sort(connections.begin(), connections.end(), [](const ConnectionRow& a, const ConnectionRow& b) {
        if (a.proto != b.proto) {
            return a.proto == "TCP";
        }
        return a.localPort < b.localPort;
    });
}

void PrintStaticOutput() {
    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    LoadData(connections, processTraffic, tcpCount, udpCount);

    std::cout << "TCP Connections (" << tcpCount << " active)\n";
    std::cout << "PORT    REMOTE               STATE         PID    PROCESS            SENT        RECV\n";
    for (const auto& conn : connections) {
        if (conn.proto == "TCP") {
            printf("%-7u %-20s %-13s %-6u %-18s %-11s %-11s\n",
                   conn.localPort, conn.remoteAddr.c_str(), conn.state.c_str(),
                   conn.pid, conn.procName.c_str(), conn.sentStr.c_str(), conn.recvStr.c_str());
        }
    }

    std::cout << "\nUDP Listeners (" << udpCount << " active)\n";
    std::cout << "PORT    PID    PROCESS\n";
    for (const auto& conn : connections) {
        if (conn.proto == "UDP") {
            printf("%-7u %-6u %-18s\n", conn.localPort, conn.pid, conn.procName.c_str());
        }
    }

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
}

void RunInteractiveLoop() {
    bool running = true;
    int scrollOffset = 0;
    DWORD lastRefreshTime = 0;
    const DWORD refreshIntervalMs = 1500;

    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    LoadData(connections, processTraffic, tcpCount, udpCount);
    lastRefreshTime = GetTickCount();

    ShowConsoleCursor(false);

    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prevMode;
    GetConsoleMode(hInput, &prevMode);
    SetConsoleMode(hInput, (prevMode & ~ENABLE_MOUSE_INPUT & ~ENABLE_WINDOW_INPUT) | ENABLE_PROCESSED_INPUT);

    while (running) {
        int width, height;
        GetConsoleSize(width, height);

        int headerLines = 2; // Banner + Columns
        int footerLines = 1; // Summary
        int viewportHeight = height - headerLines - footerLines - 1;
        if (viewportHeight < 0) viewportHeight = 0;

        DWORD currentTime = GetTickCount();
        if (currentTime - lastRefreshTime >= refreshIntervalMs) {
            LoadData(connections, processTraffic, tcpCount, udpCount);
            lastRefreshTime = currentTime;
        }

        int totalRows = static_cast<int>(connections.size());
        if (scrollOffset > totalRows - viewportHeight) {
            scrollOffset = totalRows - viewportHeight;
        }
        if (scrollOffset < 0) {
            scrollOffset = 0;
        }

        SetCursorPosition(0, 0);

        char headerBuf[256];
        sprintf(headerBuf, "portview v1.0 | Arrow Keys: Scroll | Page Up/Down | Esc/Q: Quit");
        std::string headerStr(headerBuf);
        if (headerStr.length() < (size_t)width - 1) {
            headerStr.append((width - 1) - headerStr.length(), ' ');
        } else if (headerStr.length() > (size_t)width - 1) {
            headerStr = headerStr.substr(0, width - 1);
        }
        std::cout << headerStr << "\n";

        char colBuf[256];
        sprintf(colBuf, "%-6s %-7s %-20s %-13s %-6s %-18s %-11s %-11s",
                "PROTO", "PORT", "REMOTE", "STATE", "PID", "PROCESS", "SENT", "RECV");
        std::string colStr(colBuf);
        if (colStr.length() < (size_t)width - 1) {
            colStr.append((width - 1) - colStr.length(), ' ');
        } else if (colStr.length() > (size_t)width - 1) {
            colStr = colStr.substr(0, width - 1);
        }
        std::cout << colStr << "\n";

        for (int i = 0; i < viewportHeight; ++i) {
            int idx = scrollOffset + i;
            if (idx < totalRows) {
                const auto& row = connections[idx];
                char rowBuf[512];
                sprintf(rowBuf, "%-6s %-7u %-20s %-13s %-6u %-18s %-11s %-11s",
                        row.proto.c_str(), row.localPort, row.remoteAddr.c_str(),
                        row.state.c_str(), row.pid, row.procName.c_str(),
                        row.sentStr.c_str(), row.recvStr.c_str());
                std::string rowStr(rowBuf);
                if (rowStr.length() < (size_t)width - 1) {
                    rowStr.append((width - 1) - rowStr.length(), ' ');
                } else if (rowStr.length() > (size_t)width - 1) {
                    rowStr = rowStr.substr(0, width - 1);
                }
                std::cout << rowStr << "\n";
            } else {
                std::string emptyStr(width - 1, ' ');
                std::cout << emptyStr << "\n";
            }
        }

        std::string topTalker = "";
        ULONG64 maxTraffic = 0;
        for (const auto& pair : processTraffic) {
            if (pair.second > maxTraffic) {
                maxTraffic = pair.second;
                topTalker = pair.first;
            }
        }

        std::string summaryStr = "Summary: " + std::to_string(tcpCount) + " TCP | " + std::to_string(udpCount) + " UDP";
        if (maxTraffic > 0 && !topTalker.empty()) {
            summaryStr += " | Top talker: " + topTalker + " (" + FormatBytes(maxTraffic) + ")";
        }
        if (summaryStr.length() < (size_t)width - 1) {
            summaryStr.append((width - 1) - summaryStr.length(), ' ');
        } else if (summaryStr.length() > (size_t)width - 1) {
            summaryStr = summaryStr.substr(0, width - 1);
        }
        std::cout << summaryStr;

        DWORD waitResult = WaitForSingleObject(hInput, 100);
        if (waitResult == WAIT_OBJECT_0) {
            INPUT_RECORD inputRecords[128];
            DWORD numRead = 0;
            if (ReadConsoleInputW(hInput, inputRecords, 128, &numRead)) {
                for (DWORD r = 0; r < numRead; ++r) {
                    if (inputRecords[r].EventType == KEY_EVENT && inputRecords[r].Event.KeyEvent.bKeyDown) {
                        WORD keyCode = inputRecords[r].Event.KeyEvent.wVirtualKeyCode;
                        char ascChar = inputRecords[r].Event.KeyEvent.uChar.AsciiChar;

                        if (keyCode == VK_ESCAPE || ascChar == 'q' || ascChar == 'Q') {
                            running = false;
                            break;
                        } else if (keyCode == VK_UP) {
                            if (scrollOffset > 0) scrollOffset--;
                        } else if (keyCode == VK_DOWN) {
                            if (scrollOffset < totalRows - viewportHeight) scrollOffset++;
                        } else if (keyCode == VK_PRIOR) {
                            scrollOffset -= viewportHeight;
                            if (scrollOffset < 0) scrollOffset = 0;
                        } else if (keyCode == VK_NEXT) {
                            scrollOffset += viewportHeight;
                            if (scrollOffset > totalRows - viewportHeight) scrollOffset = totalRows - viewportHeight;
                        } else if (keyCode == VK_HOME) {
                            scrollOffset = 0;
                        } else if (keyCode == VK_END) {
                            scrollOffset = totalRows - viewportHeight;
                        }
                    }
                }
            }
        }
    }

    SetConsoleMode(hInput, prevMode);
    ShowConsoleCursor(true);
}

int main(int argc, char* argv[]) {
    bool staticMode = false;

    // Simple Argument Parsing
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            std::cout << "portview v1.0 — Windows Port & Traffic Reviewer\n\n"
                      << "Usage: portview.exe [options]\n\n"
                      << "Options:\n"
                      << "  -h, --help     Show this help message\n"
                      << "  -v, --version  Show version information\n"
                      << "  -s, --static   Print a single snapshot and exit (non-interactive)\n\n"
                      << "Note: Run as administrator to see per-connection traffic stats.\n";
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "portview v1.0\n";
            return 0;
        } else if (arg == "-s" || arg == "--static") {
            staticMode = true;
        }
    }

    // If output is redirected to a file or pipe, default to static mode
    if (!IsStdoutTerminal()) {
        staticMode = true;
    }

    // Initialize Winsock (required for IpToString and network operations)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        return 1;
    }

    if (staticMode) {
        PrintStaticOutput();
        PauseIfSpawnedConsole();
    } else {
        RunInteractiveLoop();
        PauseIfSpawnedConsole();
    }

    WSACleanup();
    return 0;
}
