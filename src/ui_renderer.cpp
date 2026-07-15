#include <unordered_set>
#include "ui_renderer.h"
#include "data_models.h"
#include "network_tables.h"
#include <iostream>
#include <io.h>
#include <conio.h>
#include <iomanip>
#include <algorithm>

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

bool EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return false;
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return false;
    dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    return SetConsoleMode(hOut, dwMode) != 0;
}

void PrintSummaryRow(const ProcessSummaryRow& row, bool selected, int width) {
    char rowBuf[512];
    if (selected) {
        sprintf(rowBuf, " > %-25s %-7d %-7d %-12s %-12s",
                row.procName.substr(0, 25).c_str(), row.portsCount, row.connsCount, row.sentStr.c_str(), row.recvStr.c_str());
        std::string rowStr(rowBuf);
        if (rowStr.length() < (size_t)width - 1) {
            rowStr.append((width - 1) - rowStr.length(), ' ');
        } else if (rowStr.length() > (size_t)width - 1) {
            rowStr = rowStr.substr(0, width - 1);
        }
        std::cout << "\x1b[30;106m" << rowStr << "\x1b[0m\n";
    } else {
        std::cout << "   ";
        printf("\x1b[36;1m%-25s\x1b[0m ", row.procName.substr(0, 25).c_str());
        printf("%-7d ", row.portsCount);
        printf("%-7d ", row.connsCount);
        
        if (row.sentStr != "-") printf("\x1b[92m%-12s\x1b[0m ", row.sentStr.c_str());
        else printf("\x1b[90m%-12s\x1b[0m ", "-");
        
        if (row.recvStr != "-") printf("\x1b[92m%-12s\x1b[0m", row.recvStr.c_str());
        else printf("\x1b[90m%-12s\x1b[0m", "-");

        int visualLength = 3 + 26 + 8 + 8 + 13 + 12;
        if (visualLength < width - 1) {
            std::cout << std::string((width - 1) - visualLength, ' ');
        }
        std::cout << "\n";
    }
}

void PrintDetailRow(const ConnectionRow& row, bool selected, int width) {
    if (selected) {
        char rowBuf[512];
        std::string fwStr = "DEFAULT";
        if (row.fwStatus == FW_STATUS_ALLOWED) fwStr = "ALLOWED";
        else if (row.fwStatus == FW_STATUS_BLOCKED) fwStr = "BLOCKED";

        sprintf(rowBuf, " > %-6s %-7u %-20s %-13s %-11s %-11s %-10s",
                row.proto.c_str(), row.localPort, row.remoteAddr.substr(0, 20).c_str(), row.state.c_str(), row.sentStr.c_str(), row.recvStr.c_str(), fwStr.c_str());
        std::string rowStr(rowBuf);
        if (rowStr.length() < (size_t)width - 1) {
            rowStr.append((width - 1) - rowStr.length(), ' ');
        } else if (rowStr.length() > (size_t)width - 1) {
            rowStr = rowStr.substr(0, width - 1);
        }
        std::cout << "\x1b[30;106m" << rowStr << "\x1b[0m\n";
    } else {
        std::cout << "   ";
        
        if (row.proto == "TCP") printf("\x1b[36m%-6s\x1b[0m ", "TCP");
        else printf("\x1b[93m%-6s\x1b[0m ", "UDP");

        printf("%-7u ", row.localPort);
        printf("\x1b[93m%-20s\x1b[0m ", row.remoteAddr.substr(0, 20).c_str());

        if (row.state == "ESTABLISHED") printf("\x1b[92m%-13s\x1b[0m ", "ESTABLISHED");
        else if (row.state == "LISTENING") printf("\x1b[36m%-13s\x1b[0m ", "LISTENING");
        else printf("\x1b[90m%-13s\x1b[0m ", row.state.c_str());

        if (row.sentStr != "-") printf("\x1b[92m%-11s\x1b[0m ", row.sentStr.c_str());
        else printf("\x1b[90m%-11s\x1b[0m ", "-");

        if (row.recvStr != "-") printf("\x1b[92m%-11s\x1b[0m ", row.recvStr.c_str());
        else printf("\x1b[90m%-11s\x1b[0m ", "-");

        if (row.fwStatus == FW_STATUS_ALLOWED) printf("\x1b[92m%-10s\x1b[0m", "ALLOWED");
        else if (row.fwStatus == FW_STATUS_BLOCKED) printf("\x1b[91m%-10s\x1b[0m", "BLOCKED");
        else printf("\x1b[90m%-10s\x1b[0m", "DEFAULT");

        int visualLength = 3 + 7 + 8 + 21 + 14 + 12 + 12 + 10;
        if (visualLength < width - 1) {
            std::cout << std::string((width - 1) - visualLength, ' ');
        }
        std::cout << "\n";
    }
}

void PrintStaticOutput() {
    UpdateFirewallCache();

    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    LoadData(connections, processTraffic, tcpCount, udpCount);

    std::vector<ProcessSummaryRow> summaries;
    BuildProcessSummaries(connections, summaries);

    std::cout << "Process Summary (" << summaries.size() << " active processes)\n";
    std::cout << "PROCESS                   PORTS   CONNS   SENT         RECV\n";
    for (const auto& row : summaries) {
        printf("%-25s %-7d %-7d %-12s %-12s\n",
               row.procName.substr(0, 25).c_str(), row.portsCount, row.connsCount,
               row.sentStr.c_str(), row.recvStr.c_str());
    }

    int allowedFwRules = 0;
    {
        std::lock_guard<std::mutex> lock(g_fwMutex);
        for (const auto& pair : g_fwCache) {
            if (pair.second == FW_STATUS_ALLOWED) {
                allowedFwRules++;
            }
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

    std::cout << "\nSummary: " << tcpCount << " TCP | " << udpCount << " UDP | Allowed FW Ports: " << allowedFwRules;
    if (maxTraffic > 0 && !topTalker.empty()) {
        std::cout << " | Top talker: " << topTalker << " (" << FormatSpeed(static_cast<double>(maxTraffic)) << ")";
    }
    std::cout << "\n";
}

void RunInteractiveLoop() {
    enum ViewState { VIEW_SUMMARY, VIEW_DETAIL };
    ViewState currentView = VIEW_SUMMARY;
    DWORD selectedPid = 0;
    std::string selectedProcName = "";
    u_short selectedPort = 0;
    std::string selectedProto = "";
    std::wstring selectedRuleName = L"";
    int selectedIndex = 0;
    int scrollOffset = 0;
    bool enteringRule = false;
    std::string inputBuffer = "";
    std::string statusMessage = "";
    DWORD statusMessageTimer = 0;
    bool running = true;
    DWORD lastRefreshTime = 0;
    const DWORD refreshIntervalMs = 1500;

    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    LoadData(connections, processTraffic, tcpCount, udpCount);
    std::vector<ProcessSummaryRow> summaries;
    BuildProcessSummaries(connections, summaries);
    lastRefreshTime = GetTickCount();
    std::thread(UpdateFirewallCache).detach();

    ShowConsoleCursor(false);

    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prevMode;
    GetConsoleMode(hInput, &prevMode);
    SetConsoleMode(hInput, (prevMode & ~ENABLE_MOUSE_INPUT) | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT);

    int lastWidth = 0;
    int lastHeight = 0;

    while (running) {
        int width, height;
        GetConsoleSize(width, height);
        if (width != lastWidth || height != lastHeight) {
            std::cout << "\x1b[2J\x1b[H" << std::flush;
            COORD coord;
            coord.X = static_cast<SHORT>(width);
            coord.Y = static_cast<SHORT>(height);
            SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), coord);
            lastWidth = width;
            lastHeight = height;
        }

        int headerLines = 2; // Banner + Columns
        int footerLines = 1; // Summary
        int viewportHeight = height - headerLines - footerLines - 1;
        if (viewportHeight < 0) viewportHeight = 0;

        DWORD currentTime = GetTickCount();
        if (currentTime - lastRefreshTime >= refreshIntervalMs) {
            LoadData(connections, processTraffic, tcpCount, udpCount);
            BuildProcessSummaries(connections, summaries);
            lastRefreshTime = currentTime;
        }

        static DWORD lastFwRefresh = 0;
        if (currentTime - lastFwRefresh >= 10000) {
            std::thread(UpdateFirewallCache).detach();
            lastFwRefresh = currentTime;
        }

        // Build filtered view-specific records
        std::vector<ConnectionRow> detailRows;
        if (currentView == VIEW_DETAIL) {
            std::unordered_set<std::string> portProtoSeen;
            for (const auto& conn : connections) {
                if (conn.procName == selectedProcName) {
                    detailRows.push_back(conn);
                    portProtoSeen.insert(std::to_string(conn.localPort) + ":" + conn.proto);
                }
            }

            // Include idle firewall rules that apply to this process
            std::string procBase = selectedProcName;
            size_t dot = procBase.find_last_of('.');
            if (dot != std::string::npos) {
                procBase = procBase.substr(0, dot);
            }
            std::transform(procBase.begin(), procBase.end(), procBase.begin(), ::tolower);

            std::vector<FirewallRuleRow> matchedRules;
            {
                std::lock_guard<std::mutex> lock(g_fwMutex);
                for (const auto& rule : g_fwRulesList) {
                    std::string ruleNameLower = rule.ruleNameStr;
                    std::transform(ruleNameLower.begin(), ruleNameLower.end(), ruleNameLower.begin(), ::tolower);
                    if (ruleNameLower.find(procBase) != std::string::npos) {
                        matchedRules.push_back(rule);
                    }
                }
            }

            for (const auto& rule : matchedRules) {
                std::string key = std::to_string(rule.port) + ":" + rule.proto;
                if (portProtoSeen.find(key) == portProtoSeen.end()) {
                    ConnectionRow conn;
                    conn.proto = rule.proto;
                    conn.localPort = rule.port;
                    conn.remoteAddr = "*:*";
                    conn.state = "IDLE";
                    conn.pid = 0;
                    conn.procName = selectedProcName;
                    conn.sentStr = "-";
                    conn.recvStr = "-";
                    conn.sentBytesVal = 0;
                    conn.recvBytesVal = 0;
                    conn.totalBytes = 0;
                    conn.fwStatus = rule.enabled ? (rule.allowed ? FW_STATUS_ALLOWED : FW_STATUS_BLOCKED) : FW_STATUS_NONE;

                    detailRows.push_back(conn);
                    portProtoSeen.insert(key);
                }
            }

            std::sort(detailRows.begin(), detailRows.end(), [](const ConnectionRow& a, const ConnectionRow& b) {
                bool aIsIdle = (a.state == "IDLE");
                bool bIsIdle = (b.state == "IDLE");
                if (aIsIdle != bIsIdle) {
                    return !aIsIdle;
                }
                if (a.state != b.state) {
                    return a.state < b.state;
                }
                return a.localPort < b.localPort;
            });
        }

        int totalRows = (currentView == VIEW_SUMMARY) ? static_cast<int>(summaries.size()) : static_cast<int>(detailRows.size());

        // Clamp selectedIndex
        if (selectedIndex < 0) selectedIndex = 0;
        if (selectedIndex >= totalRows) selectedIndex = totalRows - 1;
        if (totalRows == 0) selectedIndex = 0;

        // Auto-scroll logic based on selectedIndex
        if (selectedIndex < scrollOffset) {
            scrollOffset = selectedIndex;
        }
        if (selectedIndex >= scrollOffset + viewportHeight) {
            scrollOffset = selectedIndex - viewportHeight + 1;
        }
        if (scrollOffset > totalRows - viewportHeight) {
            scrollOffset = totalRows - viewportHeight;
        }
        if (scrollOffset < 0) {
            scrollOffset = 0;
        }

        SetCursorPosition(0, 0);

        // Render Banner
        char headerBuf[256];
        if (currentView == VIEW_SUMMARY) {
            if (IsElevated()) {
                sprintf(headerBuf, "portview v1.4 [ELEVATED] | Arrows: Nav | Enter: View | A: Add Rule | Esc: Quit");
            } else {
                sprintf(headerBuf, "portview v1.4 [NON-ELEVATED] (Run as Admin for Traffic) | Arrows: Nav | Enter: View | A: Add Rule | Esc: Quit");
            }
        } else {
            std::string pidStr = (selectedPid == 0) ? "IDLE" : "PID " + std::to_string(selectedPid);
            if (IsElevated()) {
                sprintf(headerBuf, "Process: %s (%s) [ELEVATED] | A: Add Rule | S: Toggle FW | D: Del FW | Esc: Back", selectedProcName.c_str(), pidStr.c_str());
            } else {
                sprintf(headerBuf, "Process: %s (%s) [NON-ELEVATED] | A: Add Rule | S: Toggle FW | D: Del FW | Esc: Back", selectedProcName.c_str(), pidStr.c_str());
            }
        }
        std::string headerStr(headerBuf);
        if (headerStr.length() < (size_t)width - 1) {
            headerStr.append((width - 1) - headerStr.length(), ' ');
        } else if (headerStr.length() > (size_t)width - 1) {
            headerStr = headerStr.substr(0, width - 1);
        }
        std::cout << "\x1b[30;106m" << headerStr << "\x1b[0m\n";

        // Render Column Headers
        char colBuf[256];
        if (currentView == VIEW_SUMMARY) {
            sprintf(colBuf, "   %-25s %-7s %-7s %-12s %-12s",
                    "PROCESS", "PORTS", "CONNS", "SENT", "RECV");
        } else {
            sprintf(colBuf, "   %-6s %-7s %-20s %-13s %-11s %-11s %-10s",
                    "PROTO", "PORT", "REMOTE", "STATE", "SENT", "RECV", "FIREWALL");
        }
        std::string colStr(colBuf);
        if (colStr.length() < (size_t)width - 1) {
            colStr.append((width - 1) - colStr.length(), ' ');
        } else if (colStr.length() > (size_t)width - 1) {
            colStr = colStr.substr(0, width - 1);
        }
        std::cout << "\x1b[36;1m" << colStr << "\x1b[0m\n";

        // Render Viewport rows
        for (int i = 0; i < viewportHeight; ++i) {
            int idx = scrollOffset + i;
            if (idx < totalRows) {
                bool isSelected = (idx == selectedIndex);
                if (currentView == VIEW_SUMMARY) {
                    PrintSummaryRow(summaries[idx], isSelected, width);
                } else {
                    PrintDetailRow(detailRows[idx], isSelected, width);
                }
            } else {
                std::string emptyStr(width - 1, ' ');
                std::cout << emptyStr << "\n";
            }
        }

        std::string summaryStr = "";
        if (enteringRule) {
            summaryStr = "Add Inbound Allow Rule -> Enter Port (e.g., 80/tcp or 53/udp): " + inputBuffer + "_ [Backspace: Delete, Enter: Submit, Esc: Cancel]";
        } else {
            if (!statusMessage.empty() && currentTime - statusMessageTimer < 4000) {
                summaryStr = statusMessage;
            } else {
                statusMessage.clear();
                std::string topTalker = "";
                ULONG64 maxTraffic = 0;
                for (const auto& pair : processTraffic) {
                    if (pair.second > maxTraffic) {
                        maxTraffic = pair.second;
                        topTalker = pair.first;
                    }
                }

                int allowedFwRules = 0;
                {
                    std::lock_guard<std::mutex> lock(g_fwMutex);
                    for (const auto& pair : g_fwCache) {
                        if (pair.second == FW_STATUS_ALLOWED) {
                            allowedFwRules++;
                        }
                    }
                }

                summaryStr = "Summary: " + std::to_string(tcpCount) + " TCP | " + std::to_string(udpCount) + " UDP | Allowed FW Ports: " + std::to_string(allowedFwRules);
                if (maxTraffic > 0 && !topTalker.empty()) {
                    summaryStr += " | Top talker: " + topTalker + " (" + FormatSpeed(static_cast<double>(maxTraffic)) + ")";
                }
            }
        }
        if (summaryStr.length() < (size_t)width - 1) {
            summaryStr.append((width - 1) - summaryStr.length(), ' ');
        } else if (summaryStr.length() > (size_t)width - 1) {
            summaryStr = summaryStr.substr(0, width - 1);
        }
        std::cout << "\x1b[30;106m" << summaryStr << "\x1b[0m";

        // Process Key Events
        DWORD waitResult = WaitForSingleObject(hInput, 100);
        if (waitResult == WAIT_OBJECT_0) {
            INPUT_RECORD inputRecords[128];
            DWORD numRead = 0;
            if (ReadConsoleInputW(hInput, inputRecords, 128, &numRead)) {
                for (DWORD r = 0; r < numRead; ++r) {
                    if (inputRecords[r].EventType == KEY_EVENT && inputRecords[r].Event.KeyEvent.bKeyDown) {
                        WORD keyCode = inputRecords[r].Event.KeyEvent.wVirtualKeyCode;
                        char ascChar = inputRecords[r].Event.KeyEvent.uChar.AsciiChar;

                        if (enteringRule) {
                            if (keyCode == VK_ESCAPE) {
                                enteringRule = false;
                                inputBuffer.clear();
                            } else if (keyCode == VK_BACK) {
                                if (!inputBuffer.empty()) inputBuffer.pop_back();
                            } else if (keyCode == VK_RETURN) {
                                bool parsed = false;
                                size_t slash = inputBuffer.find('/');
                                if (slash != std::string::npos) {
                                    std::string portStr = inputBuffer.substr(0, slash);
                                    std::string protoStr = inputBuffer.substr(slash + 1);
                                    std::transform(protoStr.begin(), protoStr.end(), protoStr.begin(), ::tolower);
                                    try {
                                        int portVal = std::stoi(portStr);
                                        if (portVal > 0 && portVal <= 65535 && (protoStr == "tcp" || protoStr == "udp")) {
                                            bool isTcp = (protoStr == "tcp");
                                            std::wstring procNameW(selectedProcName.begin(), selectedProcName.end());
                                            std::wstring appPath = GetProcessImagePath(selectedPid);
                                            bool success = AddFirewallRule(static_cast<u_short>(portVal), isTcp, procNameW, appPath);
                                            statusMessageTimer = GetTickCount();
                                            if (success) {
                                                statusMessage = "Firewall rule created successfully! Resolving cache...";
                                                std::thread(UpdateFirewallCache).detach();
                                            } else {
                                                statusMessage = "Error: Failed to create firewall rule. Ensure running elevated.";
                                            }
                                            parsed = true;
                                        }
                                    } catch (...) {}
                                }
                                if (!parsed) {
                                    statusMessageTimer = GetTickCount();
                                    statusMessage = "Invalid rule format! Use <port>/<tcp|udp> (e.g. 8080/tcp).";
                                }
                                enteringRule = false;
                                inputBuffer.clear();
                            } else if (std::isalnum(static_cast<unsigned char>(ascChar)) || ascChar == '/') {
                                if (inputBuffer.length() < 30) {
                                    inputBuffer += ascChar;
                                }
                            }
                        } else {
                            if (ascChar == 'a' || ascChar == 'A') {
                                if (currentView == VIEW_SUMMARY && totalRows > 0) {
                                    selectedProcName = summaries[selectedIndex].procName;
                                    selectedPid = 0;
                                    for (const auto& conn : connections) {
                                        if (conn.procName == selectedProcName && conn.pid > 0) {
                                            selectedPid = conn.pid;
                                            break;
                                        }
                                    }
                                }
                                enteringRule = true;
                                inputBuffer.clear();
                                statusMessage.clear();
                            } else if (keyCode == VK_ESCAPE || ascChar == 'q' || ascChar == 'Q') {
                                if (currentView == VIEW_SUMMARY) {
                                    running = false;
                                } else {
                                    currentView = VIEW_SUMMARY;
                                    selectedIndex = 0;
                                    for (size_t k = 0; k < summaries.size(); ++k) {
                                        if (summaries[k].procName == selectedProcName) {
                                            selectedIndex = static_cast<int>(k);
                                            break;
                                        }
                                    }
                                    scrollOffset = 0;
                                }
                                break;
                            } else if (keyCode == VK_BACK) {
                                if (currentView == VIEW_DETAIL) {
                                    currentView = VIEW_SUMMARY;
                                    selectedIndex = 0;
                                    for (size_t k = 0; k < summaries.size(); ++k) {
                                        if (summaries[k].procName == selectedProcName) {
                                            selectedIndex = static_cast<int>(k);
                                            break;
                                        }
                                    }
                                    scrollOffset = 0;
                                }
                            } else if (keyCode == VK_RETURN) {
                                if (currentView == VIEW_SUMMARY && totalRows > 0) {
                                    selectedProcName = summaries[selectedIndex].procName;
                                    selectedPid = 0;
                                    for (const auto& conn : connections) {
                                        if (conn.procName == selectedProcName && conn.pid > 0) {
                                            selectedPid = conn.pid;
                                            break;
                                        }
                                    }
                                    currentView = VIEW_DETAIL;
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                }
                            }
                            else if (ascChar == 's' || ascChar == 'S') {
                                if (currentView == VIEW_DETAIL && totalRows > 0) {
                                    const auto& detailRow = detailRows[selectedIndex];
                                    std::wstring ruleName = L"";
                                    bool isEnabled = false;
                                    {
                                        std::lock_guard<std::mutex> lock(g_fwMutex);
                                        for (const auto& r : g_fwRulesList) {
                                            if (r.port == detailRow.localPort && r.proto == detailRow.proto) {
                                                bool procMatch = (r.procName == selectedProcName);
                                                if (!procMatch && (r.procName == "-" || r.procName.empty())) {
                                                    std::string suffix = " for " + selectedProcName;
                                                    if (r.ruleNameStr.length() >= suffix.length() &&
                                                        r.ruleNameStr.compare(r.ruleNameStr.length() - suffix.length(), suffix.length(), suffix) == 0) {
                                                        procMatch = true;
                                                    }
                                                }
                                                if (procMatch) {
                                                    ruleName = r.ruleName;
                                                    isEnabled = r.enabled;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    statusMessageTimer = GetTickCount();
                                    if (!ruleName.empty()) {
                                        bool success = ToggleFirewallRule(ruleName, !isEnabled);
                                        if (success) {
                                            statusMessage = "Firewall rule status toggled successfully!";
                                            std::thread(UpdateFirewallCache).detach();
                                        } else {
                                            statusMessage = "Error: Failed to toggle firewall rule. Ensure running elevated.";
                                        }
                                    } else {
                                        statusMessage = "No custom firewall rule found for this port.";
                                    }
                                }
                            } else if (ascChar == 'd' || ascChar == 'D' || keyCode == VK_DELETE) {
                                if (currentView == VIEW_DETAIL && totalRows > 0) {
                                    const auto& detailRow = detailRows[selectedIndex];
                                    std::wstring ruleName = L"";
                                    {
                                        std::lock_guard<std::mutex> lock(g_fwMutex);
                                        for (const auto& r : g_fwRulesList) {
                                            if (r.port == detailRow.localPort && r.proto == detailRow.proto) {
                                                bool procMatch = (r.procName == selectedProcName);
                                                if (!procMatch && (r.procName == "-" || r.procName.empty())) {
                                                    std::string suffix = " for " + selectedProcName;
                                                    if (r.ruleNameStr.length() >= suffix.length() &&
                                                        r.ruleNameStr.compare(r.ruleNameStr.length() - suffix.length(), suffix.length(), suffix) == 0) {
                                                        procMatch = true;
                                                    }
                                                }
                                                if (procMatch) {
                                                    ruleName = r.ruleName;
                                                    break;
                                                }
                                            }
                                        }

                                    }
                                    statusMessageTimer = GetTickCount();
                                    if (!ruleName.empty()) {
                                        bool success = DeleteFirewallRule(ruleName);
                                        if (success) {
                                            statusMessage = "Firewall rule deleted successfully!";
                                            std::thread(UpdateFirewallCache).detach();
                                        } else {
                                            statusMessage = "Error: Failed to delete firewall rule. Ensure running elevated.";
                                        }
                                    } else {
                                        statusMessage = "No custom firewall rule found for this port.";
                                    }
                                }
                            } else if (keyCode == VK_UP) {
                                if (selectedIndex > 0) selectedIndex--;
                            } else if (keyCode == VK_DOWN) {
                                if (selectedIndex < totalRows - 1) selectedIndex++;
                            } else if (keyCode == VK_PRIOR) {
                                selectedIndex -= viewportHeight;
                                if (selectedIndex < 0) selectedIndex = 0;
                            } else if (keyCode == VK_NEXT) {
                                selectedIndex += viewportHeight;
                                if (selectedIndex >= totalRows) selectedIndex = totalRows - 1;
                            } else if (keyCode == VK_HOME) {
                                selectedIndex = 0;
                            } else if (keyCode == VK_END) {
                                selectedIndex = totalRows - 1;
                            }
                        }

                    }
                }
            }
        }
    }

    SetConsoleMode(hInput, prevMode);
    ShowConsoleCursor(true);
}

