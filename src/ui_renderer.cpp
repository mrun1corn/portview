#include "ui_renderer.h"
#include "data_models.h"
#include "network_tables.h"
#include "firewall.h"
#include "process_resolver.h"
#include "utils.h"

#include <iostream>
#include <io.h>
#include <conio.h>
#include <iomanip>
#include <algorithm>
#include <unordered_set>
#include <thread>
#include <cstdio>
#include <cctype>

namespace Terminal {

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
    cursorInfo.bVisible = showFlag ? TRUE : FALSE;
    SetConsoleCursorInfo(hOut, &cursorInfo);
}

void SetCursorPosition(int x, int y) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        COORD coord = { static_cast<SHORT>(csbi.srWindow.Left + x), static_cast<SHORT>(csbi.srWindow.Top + y) };
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

} // namespace Terminal

namespace {

std::string PadOrTrim(std::string str, int targetWidth) {
    if (targetWidth <= 0) return "";
    size_t width = static_cast<size_t>(targetWidth);
    if (str.length() < width) {
        str.append(width - str.length(), ' ');
    } else if (str.length() > width) {
        str = str.substr(0, width);
    }
    return str;
}

void RenderAddRuleModal(int consoleWidth, int consoleHeight,
                        const std::string& procName, DWORD pid,
                        bool isTcp, bool isAllow, const std::string& portsInput,
                        bool isElevated) {
    constexpr int boxWidth = 64;
    constexpr int boxHeight = 10;
    int startX = (consoleWidth - boxWidth) / 2;
    int startY = (consoleHeight - boxHeight) / 2;
    if (startX < 0) startX = 0;
    if (startY < 2) startY = 2;

    auto printBoxLine = [&](int y, const std::string& text, const char* color = "\x1b[97;44m") {
        Terminal::SetCursorPosition(startX, y);
        std::string line = PadOrTrim(text, boxWidth);
        std::cout << color << line << "\x1b[0m";
    };

    std::string pidStr = (pid == 0) ? "N/A" : std::to_string(pid);
    std::string procStr = procName.empty() ? "Global (All Processes)" : procName + " (PID " + pidStr + ")";
    std::string protoStr = isTcp ? "[ TCP ] (Press Tab for UDP)" : "[ UDP ] (Press Tab for TCP)";
    std::string actionStr = isAllow ? "[ ALLOW ] (F2: Toggle Block)" : "[ BLOCK ] (F2: Toggle Allow)";
    std::string inputDisplay = portsInput + "_";

    printBoxLine(startY + 0, " +----------------- ADD INBOUND FIREWALL RULE ----------------+ ", "\x1b[97;44;1m");
    printBoxLine(startY + 1, " | Target   : " + procStr);
    printBoxLine(startY + 2, " | Protocol : " + protoStr);
    printBoxLine(startY + 3, " | Action   : " + actionStr);
    printBoxLine(startY + 4, " | Port(s)  : " + inputDisplay, "\x1b[93;44;1m");
    printBoxLine(startY + 5, " | Formats  : 8080 | 8000-8080 | 80,443 | 8080/udp          ");
    if (!isElevated) {
        printBoxLine(startY + 6, " | WARNING  : NOT ELEVATED (Requires Admin to save rule)       ", "\x1b[93;41;1m");
    } else {
        printBoxLine(startY + 6, " | Status   : Elevated (Administrator Privileges Verified)     ", "\x1b[92;44m");
    }
    printBoxLine(startY + 7, " +-------------------------------------------------------------+ ", "\x1b[97;44;1m");
    printBoxLine(startY + 8, "   [Enter] Save Rule    [Tab] Protocol    [Esc] Cancel           ", "\x1b[30;107m");
}

} // anonymous namespace

void PrintSummaryRow(const ProcessSummaryRow& row, bool selected, int width) {
    char rowBuf[512];
    if (selected) {
        std::snprintf(rowBuf, sizeof(rowBuf), " > %-25s %-7d %-7d %-12s %-12s",
                      row.procName.substr(0, 25).c_str(), row.portsCount, row.connsCount,
                      row.sentStr.c_str(), row.recvStr.c_str());
        std::string rowStr = PadOrTrim(rowBuf, width - 1);
        std::cout << "\x1b[30;106m" << rowStr << "\x1b[0m\n";
    } else {
        std::cout << "   ";
        std::printf("\x1b[36;1m%-25s\x1b[0m ", row.procName.substr(0, 25).c_str());
        std::printf("%-7d ", row.portsCount);
        std::printf("%-7d ", row.connsCount);

        if (row.sentStr != "-") std::printf("\x1b[92m%-12s\x1b[0m ", row.sentStr.c_str());
        else std::printf("\x1b[90m%-12s\x1b[0m ", "-");

        if (row.recvStr != "-") std::printf("\x1b[92m%-12s\x1b[0m", row.recvStr.c_str());
        else std::printf("\x1b[90m%-12s\x1b[0m", "-");

        int visualLength = 3 + 26 + 8 + 8 + 13 + 12;
        if (visualLength < width - 1) {
            std::cout << std::string((width - 1) - visualLength, ' ');
        }
        std::cout << "\n";
    }
}

void PrintDetailRow(const ConnectionRow& row, bool selected, int width) {
    std::string fwStr = "DEFAULT";
    if (row.fwStatus == FW_STATUS_ALLOWED) fwStr = "ALLOWED";
    else if (row.fwStatus == FW_STATUS_BLOCKED) fwStr = "BLOCKED";

    char rowBuf[512];
    if (selected) {
        std::snprintf(rowBuf, sizeof(rowBuf), " > %-6s %-7u %-20s %-13s %-11s %-11s %-10s",
                      row.proto.c_str(), row.localPort, row.remoteAddr.substr(0, 20).c_str(),
                      row.state.c_str(), row.sentStr.c_str(), row.recvStr.c_str(), fwStr.c_str());
        std::string rowStr = PadOrTrim(rowBuf, width - 1);
        std::cout << "\x1b[30;106m" << rowStr << "\x1b[0m\n";
    } else {
        std::cout << "   ";

        if (row.proto == "TCP") std::printf("\x1b[36m%-6s\x1b[0m ", "TCP");
        else std::printf("\x1b[93m%-6s\x1b[0m ", "UDP");

        std::printf("%-7u ", row.localPort);
        std::printf("\x1b[93m%-20s\x1b[0m ", row.remoteAddr.substr(0, 20).c_str());

        if (row.state == "ESTABLISHED") std::printf("\x1b[92m%-13s\x1b[0m ", "ESTABLISHED");
        else if (row.state == "LISTENING") std::printf("\x1b[36m%-13s\x1b[0m ", "LISTENING");
        else std::printf("\x1b[90m%-13s\x1b[0m ", row.state.c_str());

        if (row.sentStr != "-") std::printf("\x1b[92m%-11s\x1b[0m ", row.sentStr.c_str());
        else std::printf("\x1b[90m%-11s\x1b[0m ", "-");

        if (row.recvStr != "-") std::printf("\x1b[92m%-11s\x1b[0m ", row.recvStr.c_str());
        else std::printf("\x1b[90m%-11s\x1b[0m ", "-");

        if (row.fwStatus == FW_STATUS_ALLOWED) std::printf("\x1b[92m%-10s\x1b[0m", "ALLOWED");
        else if (row.fwStatus == FW_STATUS_BLOCKED) std::printf("\x1b[91m%-10s\x1b[0m", "BLOCKED");
        else std::printf("\x1b[90m%-10s\x1b[0m", "DEFAULT");

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
        std::printf("%-25s %-7d %-7d %-12s %-12s\n",
                    row.procName.substr(0, 25).c_str(), row.portsCount, row.connsCount,
                    row.sentStr.c_str(), row.recvStr.c_str());
    }

    int allowedFwRules = FirewallManager::Instance().CountAllowedRules();

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
    int selectedIndex = 0;
    int scrollOffset = 0;

    // Rule creation modal state
    bool enteringRule = false;
    std::string ruleTargetProc = "";
    DWORD ruleTargetPid = 0;
    bool ruleIsTcp = true;
    bool ruleIsAllow = true;
    std::string rulePortsInput = "";

    std::string statusMessage = "";
    DWORD statusMessageTimer = 0;
    bool running = true;
    DWORD lastRefreshTime = 0;
    constexpr DWORD kRefreshIntervalMs = 1500;

    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    LoadData(connections, processTraffic, tcpCount, udpCount);
    std::vector<ProcessSummaryRow> summaries;
    BuildProcessSummaries(connections, summaries);
    lastRefreshTime = GetTickCount();

    // Trigger initial background firewall refresh
    std::thread(UpdateFirewallCache).detach();

    Terminal::ShowConsoleCursor(false);

    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prevMode = 0;
    GetConsoleMode(hInput, &prevMode);
    SetConsoleMode(hInput, (prevMode & ~ENABLE_MOUSE_INPUT) | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT);

    int lastWidth = 0;
    int lastHeight = 0;

    while (running) {
        int width = 0, height = 0;
        Terminal::GetConsoleSize(width, height);
        if (width != lastWidth || height != lastHeight) {
            std::cout << "\x1b[2J\x1b[H" << std::flush;
            COORD coord;
            coord.X = static_cast<SHORT>(width);
            coord.Y = static_cast<SHORT>(height);
            SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), coord);
            lastWidth = width;
            lastHeight = height;
        }

        constexpr int headerLines = 2; // Banner + Columns
        constexpr int footerLines = 1; // Summary
        int viewportHeight = height - headerLines - footerLines - 1;
        if (viewportHeight < 0) viewportHeight = 0;

        DWORD currentTime = GetTickCount();
        if (currentTime - lastRefreshTime >= kRefreshIntervalMs) {
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

            std::vector<FirewallRuleRow> matchedRules = FirewallManager::Instance().FindMatchingRules(procBase);
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

        Terminal::SetCursorPosition(0, 0);

        // Render Banner
        char headerBuf[256];
        if (currentView == VIEW_SUMMARY) {
            if (IsElevated()) {
                std::snprintf(headerBuf, sizeof(headerBuf), "portview v1.4 [ELEVATED] | Arrows: Nav | Enter: View Details | A: Add Rule | Esc: Quit");
            } else {
                std::snprintf(headerBuf, sizeof(headerBuf), "portview v1.4 [NON-ELEVATED] | Arrows: Nav | Enter: View Details | A: Add Rule | Esc: Quit");
            }
        } else {
            std::string pidStr = (selectedPid == 0) ? "IDLE" : "PID " + std::to_string(selectedPid);
            if (IsElevated()) {
                std::snprintf(headerBuf, sizeof(headerBuf), "Process: %s (%s) [ELEVATED] | A: Add Rule | S: Toggle FW | D: Del FW | Esc: Back", selectedProcName.c_str(), pidStr.c_str());
            } else {
                std::snprintf(headerBuf, sizeof(headerBuf), "Process: %s (%s) [NON-ELEVATED] | A: Add Rule | S: Toggle FW | D: Del FW | Esc: Back", selectedProcName.c_str(), pidStr.c_str());
            }
        }
        std::cout << "\x1b[30;106m" << PadOrTrim(headerBuf, width - 1) << "\x1b[0m\n";

        // Render Column Headers
        char colBuf[256];
        if (currentView == VIEW_SUMMARY) {
            std::snprintf(colBuf, sizeof(colBuf), "   %-25s %-7s %-7s %-12s %-12s",
                          "PROCESS", "PORTS", "CONNS", "SENT", "RECV");
        } else {
            std::snprintf(colBuf, sizeof(colBuf), "   %-6s %-7s %-20s %-13s %-11s %-11s %-10s",
                          "PROTO", "PORT", "REMOTE", "STATE", "SENT", "RECV", "FIREWALL");
        }
        std::cout << "\x1b[36;1m" << PadOrTrim(colBuf, width - 1) << "\x1b[0m\n";

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
                std::cout << std::string(width > 1 ? width - 1 : 0, ' ') << "\n";
            }
        }

        // Render Status Bar
        std::string summaryStr = "";
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

            int allowedFwRules = FirewallManager::Instance().CountAllowedRules();
            summaryStr = "Summary: " + std::to_string(tcpCount) + " TCP | " + std::to_string(udpCount) + " UDP | Allowed FW Ports: " + std::to_string(allowedFwRules);
            if (maxTraffic > 0 && !topTalker.empty()) {
                summaryStr += " | Top talker: " + topTalker + " (" + FormatSpeed(static_cast<double>(maxTraffic)) + ")";
            }
        }
        std::cout << "\x1b[30;106m" << PadOrTrim(summaryStr, width - 1) << "\x1b[0m";

        // If rule adding modal is active, overlay it centered on screen
        if (enteringRule) {
            RenderAddRuleModal(width, height, ruleTargetProc, ruleTargetPid, ruleIsTcp, ruleIsAllow, rulePortsInput, IsElevated());
        }

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
                                rulePortsInput.clear();
                            } else if (keyCode == VK_TAB) {
                                ruleIsTcp = !ruleIsTcp;
                            } else if (keyCode == VK_F2) {
                                ruleIsAllow = !ruleIsAllow;
                            } else if (keyCode == VK_BACK) {
                                if (!rulePortsInput.empty()) {
                                    rulePortsInput.pop_back();
                                }
                            } else if (keyCode == VK_RETURN) {
                                if (!IsElevated()) {
                                    statusMessage = "Error: Creating firewall rules requires Administrator privileges.";
                                    statusMessageTimer = GetTickCount();
                                    enteringRule = false;
                                    rulePortsInput.clear();
                                } else {
                                    std::string rawInput = rulePortsInput;
                                    while (!rawInput.empty() && std::isspace(static_cast<unsigned char>(rawInput.front()))) rawInput.erase(rawInput.begin());
                                    while (!rawInput.empty() && std::isspace(static_cast<unsigned char>(rawInput.back()))) rawInput.pop_back();

                                    if (rawInput.empty()) {
                                        statusMessage = "Error: Port specification cannot be empty.";
                                        statusMessageTimer = GetTickCount();
                                    } else {
                                        bool effectiveIsTcp = ruleIsTcp;
                                        bool effectiveIsAllow = ruleIsAllow;

                                        // Optional inline parsing: 8080/udp or 8080/block
                                        size_t slash = rawInput.find('/');
                                        if (slash != std::string::npos) {
                                            std::string suffix = rawInput.substr(slash + 1);
                                            rawInput = rawInput.substr(0, slash);
                                            std::transform(suffix.begin(), suffix.end(), suffix.begin(), ::tolower);
                                            if (suffix.find("udp") != std::string::npos) effectiveIsTcp = false;
                                            if (suffix.find("tcp") != std::string::npos) effectiveIsTcp = true;
                                            if (suffix.find("block") != std::string::npos) effectiveIsAllow = false;
                                            if (suffix.find("allow") != std::string::npos) effectiveIsAllow = true;
                                        }

                                        bool validChars = true;
                                        for (char c : rawInput) {
                                            if (!std::isdigit(static_cast<unsigned char>(c)) && c != ',' && c != '-') {
                                                validChars = false;
                                                break;
                                            }
                                        }

                                        if (!validChars || rawInput.empty()) {
                                            statusMessage = "Error: Invalid port format. Examples: 8080, 8000-8080, or 80,443";
                                            statusMessageTimer = GetTickCount();
                                        } else {
                                            std::wstring procNameW(ruleTargetProc.begin(), ruleTargetProc.end());
                                            std::wstring appPath = ProcessResolver::GetProcessImagePath(ruleTargetPid);
                                            bool success = FirewallManager::Instance().AddRule(rawInput, effectiveIsTcp, procNameW, appPath, effectiveIsAllow);
                                            statusMessageTimer = GetTickCount();
                                            if (success) {
                                                statusMessage = "Firewall rule created successfully! Cache refreshing...";
                                                std::thread(UpdateFirewallCache).detach();
                                            } else {
                                                statusMessage = "Error: Failed to create firewall rule via Windows COM API.";
                                            }
                                        }
                                    }
                                    enteringRule = false;
                                    rulePortsInput.clear();
                                }
                            } else if (std::isdigit(static_cast<unsigned char>(ascChar)) || ascChar == ',' || ascChar == '-' || ascChar == '/') {
                                if (rulePortsInput.length() < 32) {
                                    rulePortsInput += ascChar;
                                }
                            }
                        } else {
                            if (ascChar == 'a' || ascChar == 'A') {
                                if (currentView == VIEW_SUMMARY && totalRows > 0) {
                                    ruleTargetProc = summaries[selectedIndex].procName;
                                    ruleTargetPid = 0;
                                    for (const auto& conn : connections) {
                                        if (conn.procName == ruleTargetProc && conn.pid > 0) {
                                            ruleTargetPid = conn.pid;
                                            break;
                                        }
                                    }
                                    ruleIsTcp = true;
                                    ruleIsAllow = true;
                                    rulePortsInput.clear();
                                } else if (currentView == VIEW_DETAIL && totalRows > 0) {
                                    const auto& detailRow = detailRows[selectedIndex];
                                    ruleTargetProc = selectedProcName;
                                    ruleTargetPid = (detailRow.pid > 0) ? detailRow.pid : selectedPid;
                                    ruleIsTcp = (detailRow.proto == "TCP");
                                    ruleIsAllow = true;
                                    rulePortsInput = std::to_string(detailRow.localPort);
                                }
                                enteringRule = true;
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
                            } else if (ascChar == 's' || ascChar == 'S') {
                                if (currentView == VIEW_DETAIL && totalRows > 0) {
                                    const auto& detailRow = detailRows[selectedIndex];
                                    std::wstring ruleName = L"";
                                    bool isEnabled = false;
                                    bool found = FirewallManager::Instance().FindRule(detailRow.localPort, detailRow.proto, selectedProcName, ruleName, isEnabled);

                                    statusMessageTimer = GetTickCount();
                                    if (found && !ruleName.empty()) {
                                        bool success = FirewallManager::Instance().ToggleRule(ruleName, !isEnabled);
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
                                    bool isEnabled = false;
                                    bool found = FirewallManager::Instance().FindRule(detailRow.localPort, detailRow.proto, selectedProcName, ruleName, isEnabled);

                                    statusMessageTimer = GetTickCount();
                                    if (found && !ruleName.empty()) {
                                        bool success = FirewallManager::Instance().DeleteRule(ruleName);
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
    Terminal::ShowConsoleCursor(true);
}
