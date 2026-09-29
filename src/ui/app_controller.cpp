#include "ui/app_controller.h"
#include "ui/terminal_screen.h"
#include "ui/search_filter.h"
#include "ui/components.h"
#include "core/utils.h"
#include "core/system_metrics.h"
#include "network/network_scanner.h"
#include "network/process_resolver.h"
#include "security/firewall_manager.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <thread>
#include <cctype>

namespace {

class ConsoleModeGuard {
public:
    ConsoleModeGuard() {
        hInput_ = GetStdHandle(STD_INPUT_HANDLE);
        if (hInput_ != INVALID_HANDLE_VALUE && GetConsoleMode(hInput_, &origMode_)) {
            hasOrigMode_ = true;
            s_instance = this;
            SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
        }
    }

    ~ConsoleModeGuard() {
        Restore();
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        if (s_instance == this) {
            s_instance = nullptr;
        }
    }

    void Restore() {
        if (hasOrigMode_) {
            SetConsoleMode(hInput_, origMode_);
            Terminal::ShowConsoleCursor(true);
            hasOrigMode_ = false;
        }
    }

    static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
        (void)ctrlType;
        if (s_instance) {
            s_instance->Restore();
        }
        FirewallManager::Instance().WaitForPendingUpdate();
        return FALSE;
    }

private:
    HANDLE hInput_ = INVALID_HANDLE_VALUE;
    DWORD origMode_ = 0;
    bool hasOrigMode_ = false;
    static inline ConsoleModeGuard* s_instance = nullptr;
};

} // anonymous namespace

AppController& AppController::Instance() {
    static AppController instance;
    return instance;
}

void AppController::PrintStatic() {
    FirewallManager::Instance().UpdateCache();

    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    NetworkScanner::Instance().Scan(connections, processTraffic, tcpCount, udpCount);

    std::vector<ProcessSummaryRow> summaries;
    NetworkScanner::Instance().BuildSummaries(connections, summaries);

    SystemHostMetrics hostMetrics = SystemMetrics::Instance().QueryHostMetrics();

    std::cout << "========================================================================================\n";
    std::cout << "portview v1.6 | " << hostMetrics.cpuBannerStr << " | " << hostMetrics.ramBannerStr << "\n";
    std::cout << "========================================================================================\n";
    std::cout << "Process Summary (" << summaries.size() << " active processes)\n";
    std::cout << "PROCESS                   CPU%    RAM        PORTS   CONNS   SENT         RECV\n";
    for (const auto& row : summaries) {
        std::printf("%-24s  %-6s  %-10s %-7d %-7d %-12s %-12s\n",
                    row.procName.substr(0, 24).c_str(),
                    row.cpuStr.c_str(),
                    row.ramStr.c_str(),
                    row.portsCount, row.connsCount,
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

void AppController::RunInteractive() {
    enum ViewState { VIEW_SUMMARY, VIEW_DETAIL };
    ViewState currentView = VIEW_SUMMARY;
    DWORD selectedPid = 0;
    std::string selectedProcName = "";
    int selectedIndex = 0;
    int scrollOffset = 0;

    SummarySortMode sortMode = SORT_TRAFFIC;
    bool sortAscending = false;
    std::string pinnedProcName = "";

    SearchFilter searchFilter;

    // Rule creation modal state
    bool enteringRule = false;
    std::string ruleTargetProc = "";
    DWORD ruleTargetPid = 0;
    bool ruleIsTcp = true;
    bool ruleIsAllow = true;
    std::string rulePortsInput = "";

    // Kill confirmation modal state
    bool confirmingKill = false;
    DWORD killTargetPid = 0;
    std::string killTargetName = "";

    std::string statusMessage = "";
    DWORD statusMessageTimer = 0;
    bool running = true;
    DWORD lastRefreshTime = 0;
    constexpr DWORD kRefreshIntervalMs = 1500;

    std::vector<ConnectionRow> connections;
    std::unordered_map<std::string, ULONG64> processTraffic;
    DWORD tcpCount = 0;
    DWORD udpCount = 0;

    NetworkScanner::Instance().Scan(connections, processTraffic, tcpCount, udpCount);
    std::vector<ProcessSummaryRow> summaries;
    NetworkScanner::Instance().BuildSummaries(connections, summaries);
    lastRefreshTime = GetTickCount();

    FirewallManager::Instance().TriggerAsyncUpdate();
    ConsoleModeGuard consoleGuard;
    Terminal::ShowConsoleCursor(false);

    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD prevMode = 0;
    GetConsoleMode(hInput, &prevMode);
    DWORD mouseMode = ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT;
    mouseMode &= ~ENABLE_QUICK_EDIT_MODE;
    SetConsoleMode(hInput, mouseMode);

    int lastWidth = 0;
    int lastHeight = 0;
    bool needsRedraw = true;

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
            needsRedraw = true;
        }

        constexpr int headerLines = 3; // Banner + Search Bar + Columns
        constexpr int footerLines = 1; // Status bar
        int viewportHeight = height - headerLines - footerLines - 1;
        if (viewportHeight < 0) viewportHeight = 0;

        DWORD currentTime = GetTickCount();
        static SystemHostMetrics cachedHostMetrics;
        if (currentTime - lastRefreshTime >= kRefreshIntervalMs || cachedHostMetrics.cpuBannerStr.empty()) {
            NetworkScanner::Instance().Scan(connections, processTraffic, tcpCount, udpCount);
            NetworkScanner::Instance().BuildSummaries(connections, summaries);
            cachedHostMetrics = SystemMetrics::Instance().QueryHostMetrics();
            lastRefreshTime = currentTime;
            needsRedraw = true;
        }

        static DWORD lastFwRefresh = 0;
        if (currentTime - lastFwRefresh >= 10000) {
            FirewallManager::Instance().TriggerAsyncUpdate();
            lastFwRefresh = currentTime;
        }

        if (!statusMessage.empty() && currentTime - statusMessageTimer >= 4000) {
            statusMessage.clear();
            needsRedraw = true;
        }

        // 1. Build detail rows if in VIEW_DETAIL
        std::vector<ConnectionRow> detailRows;
        if (currentView == VIEW_DETAIL) {
            std::unordered_set<std::string> portProtoSeen;
            for (const auto& conn : connections) {
                if (conn.procName == selectedProcName) {
                    detailRows.push_back(conn);
                    portProtoSeen.insert(std::to_string(conn.localPort) + ":" + conn.proto);
                }
            }

            std::string procBase = selectedProcName;
            size_t dot = procBase.find_last_of('.');
            if (dot != std::string::npos) {
                procBase = procBase.substr(0, dot);
            }
            std::transform(procBase.begin(), procBase.end(), procBase.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

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
                if (aIsIdle != bIsIdle) return !aIsIdle;
                if (a.state != b.state) return a.state < b.state;
                return a.localPort < b.localPort;
            });
        }

        // 2. Filter rows live based on search query
        std::vector<ProcessSummaryRow> filteredSummaries;
        std::vector<ConnectionRow> filteredDetailRows;

        if (currentView == VIEW_SUMMARY) {
            for (const auto& row : summaries) {
                if (searchFilter.Matches(row.procName) || searchFilter.Matches(row.representativePid)) {
                    filteredSummaries.push_back(row);
                }
            }

            std::sort(filteredSummaries.begin(), filteredSummaries.end(), [sortMode, sortAscending](const ProcessSummaryRow& a, const ProcessSummaryRow& b) {
                if (sortMode == SORT_NAME) {
                    if (a.procName != b.procName) {
                        return sortAscending ? (a.procName < b.procName) : (a.procName > b.procName);
                    }
                } else if (sortMode == SORT_CPU) {
                    if (std::abs(a.cpuPercent - b.cpuPercent) >= 0.05) {
                        return sortAscending ? (a.cpuPercent < b.cpuPercent) : (a.cpuPercent > b.cpuPercent);
                    }
                } else if (sortMode == SORT_RAM) {
                    if (a.ramBytes / 65536 != b.ramBytes / 65536) {
                        return sortAscending ? (a.ramBytes < b.ramBytes) : (a.ramBytes > b.ramBytes);
                    }
                } else if (sortMode == SORT_PORTS) {
                    if (a.portsCount != b.portsCount) {
                        return sortAscending ? (a.portsCount < b.portsCount) : (a.portsCount > b.portsCount);
                    }
                } else if (sortMode == SORT_CONNS) {
                    if (a.connsCount != b.connsCount) {
                        return sortAscending ? (a.connsCount < b.connsCount) : (a.connsCount > b.connsCount);
                    }
                } else { // SORT_TRAFFIC
                    ULONG64 aTotal = a.sentBytes + a.recvBytes;
                    ULONG64 bTotal = b.sentBytes + b.recvBytes;
                    if (aTotal != bTotal) {
                        return sortAscending ? (aTotal < bTotal) : (aTotal > bTotal);
                    }
                }
                return a.procName < b.procName;
            });
        } else {
            for (const auto& row : detailRows) {
                if (searchFilter.Matches(row.proto) || searchFilter.Matches(row.localPort) ||
                    searchFilter.Matches(row.remoteAddr) || searchFilter.Matches(row.state)) {
                    filteredDetailRows.push_back(row);
                }
            }
        }

        int totalRows = (currentView == VIEW_SUMMARY) ? static_cast<int>(filteredSummaries.size()) : static_cast<int>(filteredDetailRows.size());
        int rawTotalRows = (currentView == VIEW_SUMMARY) ? static_cast<int>(summaries.size()) : static_cast<int>(detailRows.size());

        // Pin selection to the process name so the cursor follows the process when rows re-sort
        if (currentView == VIEW_SUMMARY && !pinnedProcName.empty()) {
            for (int i = 0; i < static_cast<int>(filteredSummaries.size()); ++i) {
                if (filteredSummaries[i].procName == pinnedProcName) {
                    selectedIndex = i;
                    break;
                }
            }
        } else if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
            if (selectedIndex >= 0 && selectedIndex < static_cast<int>(filteredSummaries.size())) {
                pinnedProcName = filteredSummaries[selectedIndex].procName;
            }
        }

        if (selectedIndex < 0) selectedIndex = 0;
        if (selectedIndex >= totalRows) selectedIndex = totalRows - 1;
        if (totalRows == 0) selectedIndex = 0;

        if (selectedIndex < scrollOffset) scrollOffset = selectedIndex;
        if (selectedIndex >= scrollOffset + viewportHeight) scrollOffset = selectedIndex - viewportHeight + 1;
        if (scrollOffset > totalRows - viewportHeight) scrollOffset = totalRows - viewportHeight;
        if (scrollOffset < 0) scrollOffset = 0;

        // 3. Render Frame atomically if dirty
        if (needsRedraw) {
            needsRedraw = false;
            std::string frame;
            frame.reserve(16384);
            frame += "\x1b[?25l\x1b[H";

            // Banner
            frame += UiComponents::FormatBanner(width, (currentView == VIEW_SUMMARY), selectedProcName, selectedPid, cachedHostMetrics, IsElevated());

            // Search Bar
            frame += searchFilter.FormatBar(width, totalRows, rawTotalRows);

            // Columns
            if (currentView == VIEW_SUMMARY) {
                frame += UiComponents::FormatSummaryColumns(width, sortMode, sortAscending);
            } else {
                frame += UiComponents::FormatDetailColumns(width);
            }

            // Rows
            for (int i = 0; i < viewportHeight; ++i) {
                int idx = scrollOffset + i;
                if (idx < totalRows) {
                    bool isSelected = (idx == selectedIndex);
                    if (currentView == VIEW_SUMMARY) {
                        frame += UiComponents::FormatSummaryRow(filteredSummaries[idx], isSelected, width);
                    } else {
                        frame += UiComponents::FormatDetailRow(filteredDetailRows[idx], isSelected, width);
                    }
                } else {
                    frame += std::string(width > 1 ? width - 1 : 0, ' ');
                }
                frame += "\n";
            }

            // Status Bar
            std::string topTalker = "";
            ULONG64 maxTraffic = 0;
            for (const auto& pair : processTraffic) {
                if (pair.second > maxTraffic) {
                    maxTraffic = pair.second;
                    topTalker = pair.first;
                }
            }
            int allowedFwRules = FirewallManager::Instance().CountAllowedRules();
            frame += UiComponents::FormatStatusBar(width, statusMessage, tcpCount, udpCount, allowedFwRules, topTalker, maxTraffic);

            // Modals Overlay
            if (enteringRule) {
                UiComponents::AppendAddRuleModal(frame, width, height, ruleTargetProc, ruleTargetPid, ruleIsTcp, ruleIsAllow, rulePortsInput, IsElevated());
            } else if (confirmingKill) {
                int startX = (width - 56) / 2;
                int startY = (height - 5) / 2;
                if (startX < 0) startX = 0;
                if (startY < 2) startY = 2;
                auto appendModalLine = [&](int y, const std::string& text, const char* color = "\x1b[97;41;1m") {
                    frame += "\x1b[" + std::to_string(y + 1) + ";" + std::to_string(startX + 1) + "H" + color + PadOrTrim(text, 56) + "\x1b[0m";
                };
                appendModalLine(startY + 0, " +---------------- TERMINATE PROCESS ----------------+ ");
                appendModalLine(startY + 1, " | Are you sure you want to kill this process?        | ");
                std::string targetInfo = " | Target: " + killTargetName + " (PID " + std::to_string(killTargetPid) + ")";
                appendModalLine(startY + 2, PadOrTrim(targetInfo, 54) + " | ");
                appendModalLine(startY + 3, " +----------------------------------------------------+ ");
                appendModalLine(startY + 4, "     [Y] Confirm Termination      [N / Esc] Cancel     ", "\x1b[30;107m");
            }

            Terminal::FlushFrame(frame);
        }

        // 4. Input processing
        DWORD waitResult = WaitForSingleObject(hInput, 50);
        if (waitResult == WAIT_OBJECT_0) {
            INPUT_RECORD inputRecords[128];
            DWORD numRead = 0;
            if (ReadConsoleInputW(hInput, inputRecords, 128, &numRead)) {
                auto executeSaveRule = [&]() {
                    if (!IsElevated()) {
                        statusMessage = "Error: Creating firewall rules requires Administrator privileges.";
                        statusMessageTimer = GetTickCount();
                    } else {
                        std::string rawInput = rulePortsInput;
                        while (!rawInput.empty() && std::isspace(static_cast<unsigned char>(rawInput.front()))) rawInput.erase(rawInput.begin());
                        while (!rawInput.empty() && std::isspace(static_cast<unsigned char>(rawInput.back()))) rawInput.pop_back();

                        if (rawInput.empty()) {
                            statusMessage = "Error: Port specification cannot be empty.";
                            statusMessageTimer = GetTickCount();
                        } else if (!FirewallManager::ValidatePortRange(rawInput)) {
                            statusMessage = "Error: Invalid port(s). Must be 1-65535, comma-separated or ranges <= 1024 ports.";
                            statusMessageTimer = GetTickCount();
                        } else {
                            std::wstring procNameW = StringToWString(ruleTargetProc);
                            std::wstring appPath = ProcessResolver::GetProcessImagePath(ruleTargetPid);
                            bool success = FirewallManager::Instance().AddRule(rawInput, ruleIsTcp, procNameW, appPath, ruleIsAllow);
                            statusMessageTimer = GetTickCount();
                            if (success) {
                                statusMessage = "Firewall rule created successfully! Cache refreshing...";
                                FirewallManager::Instance().TriggerAsyncUpdate();
                            } else {
                                statusMessage = "Error: Failed to create firewall rule via Windows COM API.";
                            }
                        }
                    }
                    enteringRule = false;
                    rulePortsInput.clear();
                };

                for (DWORD r = 0; r < numRead; ++r) {
                    if (inputRecords[r].EventType == MOUSE_EVENT) {
                        const auto& mouseEvent = inputRecords[r].Event.MouseEvent;

                        // Ignore pure mouse movement / hover events to avoid unnecessary redraws
                        if (mouseEvent.dwEventFlags == MOUSE_MOVED && mouseEvent.dwButtonState == 0) {
                            continue;
                        }

                        // 1. Mouse wheel scrolling
                        if (mouseEvent.dwEventFlags & MOUSE_WHEELED) {
                            needsRedraw = true;
                            short wheelDelta = static_cast<short>(HIWORD(mouseEvent.dwButtonState));
                            if (wheelDelta > 0) {
                                selectedIndex = (selectedIndex >= 3) ? (selectedIndex - 3) : 0;
                            } else if (wheelDelta < 0) {
                                if (selectedIndex + 3 < totalRows) selectedIndex += 3;
                                else selectedIndex = (totalRows > 0) ? (totalRows - 1) : 0;
                            }
                            if (currentView == VIEW_SUMMARY && selectedIndex >= 0 && selectedIndex < static_cast<int>(filteredSummaries.size())) {
                                pinnedProcName = filteredSummaries[selectedIndex].procName;
                            }
                        }
                        // 2. Left-click & double-click
                        else if (mouseEvent.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) {
                            needsRedraw = true;
                            int clickX = mouseEvent.dwMousePosition.X;
                            int clickY = mouseEvent.dwMousePosition.Y;

                            if (enteringRule) {
                                constexpr int boxWidth = 64;
                                constexpr int boxHeight = 10;
                                int startX = (width - boxWidth) / 2;
                                int startY = (height - boxHeight) / 2;
                                if (startX < 0) startX = 0;
                                if (startY < 2) startY = 2;

                                if (clickY == startY + 2 && clickX >= startX && clickX < startX + boxWidth) {
                                    ruleIsTcp = !ruleIsTcp;
                                } else if (clickY == startY + 3 && clickX >= startX && clickX < startX + boxWidth) {
                                    ruleIsAllow = !ruleIsAllow;
                                } else if (clickY == startY + 8 && clickX >= startX && clickX < startX + boxWidth) {
                                    if (clickX >= startX + 35) {
                                        enteringRule = false;
                                        rulePortsInput.clear();
                                    } else {
                                        executeSaveRule();
                                    }
                                }
                            } else if (confirmingKill) {
                                int startX = (width - 56) / 2;
                                int startY = (height - 5) / 2;
                                if (startX < 0) startX = 0;
                                if (startY < 2) startY = 2;
                                if (clickY == startY + 4 && clickX >= startX && clickX < startX + 56) {
                                    if (clickX < startX + 28) {
                                        bool killed = SystemMetrics::KillProcess(killTargetPid);
                                        statusMessageTimer = GetTickCount();
                                        statusMessage = killed ? ("Process " + killTargetName + " (PID " + std::to_string(killTargetPid) + ") terminated successfully.") : "Error: Failed to terminate process.";
                                        confirmingKill = false;
                                    } else {
                                        confirmingKill = false;
                                    }
                                }
                            } else {
                                if (clickY == 1 && clickX >= 35 && !searchFilter.IsEmpty()) {
                                    searchFilter.Clear();
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                } else if (clickY == 0 && currentView == VIEW_DETAIL && clickX >= width - 20) {
                                    currentView = VIEW_SUMMARY;
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                } else if (clickY == 2 && currentView == VIEW_SUMMARY) {
                                    SummarySortMode clickedSort = sortMode;
                                    if (clickX < 28) {
                                        clickedSort = SORT_NAME;
                                    } else if (clickX < 36) {
                                        clickedSort = SORT_CPU;
                                    } else if (clickX < 47) {
                                        clickedSort = SORT_RAM;
                                    } else if (clickX < 55) {
                                        clickedSort = SORT_PORTS;
                                    } else if (clickX < 63) {
                                        clickedSort = SORT_CONNS;
                                    } else {
                                        clickedSort = SORT_TRAFFIC;
                                    }

                                    if (clickedSort == sortMode) {
                                        sortAscending = !sortAscending;
                                    } else {
                                        sortMode = clickedSort;
                                        sortAscending = (sortMode == SORT_NAME);
                                    }
                                } else if (clickY >= headerLines && clickY < headerLines + viewportHeight) {
                                    int rowIdx = scrollOffset + (clickY - headerLines);
                                    if (rowIdx < totalRows) {
                                        if (mouseEvent.dwEventFlags & DOUBLE_CLICK) {
                                            if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                                selectedProcName = filteredSummaries[rowIdx].procName;
                                                selectedPid = filteredSummaries[rowIdx].representativePid;
                                                currentView = VIEW_DETAIL;
                                                selectedIndex = 0;
                                                scrollOffset = 0;
                                                searchFilter.Clear();
                                            } else if (currentView == VIEW_DETAIL && !filteredDetailRows.empty()) {
                                                const auto& detailRow = filteredDetailRows[rowIdx];
                                                std::wstring ruleName = L"";
                                                bool isEnabled = false;
                                                bool found = FirewallManager::Instance().FindRule(detailRow.localPort, detailRow.proto, selectedProcName, ruleName, isEnabled);
                                                statusMessageTimer = GetTickCount();
                                                if (found && !ruleName.empty()) {
                                                    bool success = FirewallManager::Instance().ToggleRule(ruleName, !isEnabled);
                                                    statusMessage = success ? "Firewall rule status toggled successfully!" : "Error: Failed to toggle firewall rule.";
                                                    if (success) FirewallManager::Instance().TriggerAsyncUpdate();
                                                }
                                            }
                                        } else {
                                            selectedIndex = rowIdx;
                                            if (currentView == VIEW_SUMMARY && rowIdx < static_cast<int>(filteredSummaries.size())) {
                                                pinnedProcName = filteredSummaries[rowIdx].procName;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // 3. Right-click context action (open Add Rule modal)
                        else if (mouseEvent.dwButtonState & RIGHTMOST_BUTTON_PRESSED) {
                            needsRedraw = true;
                            int clickY = mouseEvent.dwMousePosition.Y;
                            if (!enteringRule && !confirmingKill && clickY >= headerLines && clickY < headerLines + viewportHeight) {
                                int rowIdx = scrollOffset + (clickY - headerLines);
                                if (rowIdx < totalRows) {
                                    selectedIndex = rowIdx;
                                    if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                        ruleTargetProc = filteredSummaries[selectedIndex].procName;
                                        ruleTargetPid = filteredSummaries[selectedIndex].representativePid;
                                        ruleIsTcp = true;
                                        ruleIsAllow = true;
                                        rulePortsInput.clear();
                                        enteringRule = true;
                                    } else if (currentView == VIEW_DETAIL && !filteredDetailRows.empty()) {
                                        const auto& detailRow = filteredDetailRows[selectedIndex];
                                        ruleTargetProc = selectedProcName;
                                        ruleTargetPid = (detailRow.pid > 0) ? detailRow.pid : selectedPid;
                                        ruleIsTcp = (detailRow.proto == "TCP");
                                        ruleIsAllow = true;
                                        rulePortsInput = std::to_string(detailRow.localPort);
                                        enteringRule = true;
                                    }
                                }
                            }
                        }
                    } else if (inputRecords[r].EventType == KEY_EVENT && inputRecords[r].Event.KeyEvent.bKeyDown) {
                        needsRedraw = true;
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
                                if (!rulePortsInput.empty()) rulePortsInput.pop_back();
                            } else if (keyCode == VK_RETURN) {
                                executeSaveRule();
                            } else if (std::isdigit(static_cast<unsigned char>(ascChar)) || ascChar == ',' || ascChar == '-' || ascChar == '*') {
                                if (rulePortsInput.length() < 32) rulePortsInput += ascChar;
                            }
                        } else if (confirmingKill) {
                            if (ascChar == 'y' || ascChar == 'Y') {
                                bool killed = SystemMetrics::KillProcess(killTargetPid);
                                statusMessageTimer = GetTickCount();
                                if (killed) {
                                    statusMessage = "Process " + killTargetName + " (PID " + std::to_string(killTargetPid) + ") terminated successfully.";
                                } else {
                                    statusMessage = "Error: Failed to terminate process. (Access Denied or elevated process).";
                                }
                                confirmingKill = false;
                            } else if (ascChar == 'n' || ascChar == 'N' || keyCode == VK_ESCAPE) {
                                confirmingKill = false;
                            }
                        } else {
                            // Standard Navigation & Actions
                            if (keyCode == VK_ESCAPE) {
                                if (!searchFilter.IsEmpty()) {
                                    searchFilter.Clear();
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                } else if (currentView == VIEW_DETAIL) {
                                    currentView = VIEW_SUMMARY;
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                } else {
                                    running = false;
                                }
                            } else if (keyCode == VK_BACK) {
                                if (!searchFilter.IsEmpty()) {
                                    searchFilter.Pop();
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                } else if (currentView == VIEW_DETAIL) {
                                    currentView = VIEW_SUMMARY;
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                }
                            } else if (keyCode == VK_RETURN) {
                                if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                    selectedProcName = filteredSummaries[selectedIndex].procName;
                                    selectedPid = filteredSummaries[selectedIndex].representativePid;
                                    currentView = VIEW_DETAIL;
                                    selectedIndex = 0;
                                    scrollOffset = 0;
                                    searchFilter.Clear();
                                }
                            } else if (keyCode == VK_UP) {
                                if (selectedIndex > 0) selectedIndex--;
                                if (currentView == VIEW_SUMMARY && selectedIndex >= 0 && selectedIndex < static_cast<int>(filteredSummaries.size())) {
                                    pinnedProcName = filteredSummaries[selectedIndex].procName;
                                }
                            } else if (keyCode == VK_DOWN) {
                                if (selectedIndex < totalRows - 1) selectedIndex++;
                                if (currentView == VIEW_SUMMARY && selectedIndex >= 0 && selectedIndex < static_cast<int>(filteredSummaries.size())) {
                                    pinnedProcName = filteredSummaries[selectedIndex].procName;
                                }
                            } else if (keyCode == VK_PRIOR) {
                                selectedIndex -= viewportHeight;
                                if (selectedIndex < 0) selectedIndex = 0;
                                if (currentView == VIEW_SUMMARY && selectedIndex >= 0 && selectedIndex < static_cast<int>(filteredSummaries.size())) {
                                    pinnedProcName = filteredSummaries[selectedIndex].procName;
                                }
                            } else if (keyCode == VK_NEXT) {
                                selectedIndex += viewportHeight;
                                if (selectedIndex >= totalRows) selectedIndex = totalRows - 1;
                                if (currentView == VIEW_SUMMARY && selectedIndex >= 0 && selectedIndex < static_cast<int>(filteredSummaries.size())) {
                                    pinnedProcName = filteredSummaries[selectedIndex].procName;
                                }
                            } else if (keyCode == VK_HOME) {
                                selectedIndex = 0;
                                if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                    pinnedProcName = filteredSummaries[0].procName;
                                }
                            } else if (keyCode == VK_END) {
                                selectedIndex = (totalRows > 0) ? (totalRows - 1) : 0;
                                if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                    pinnedProcName = filteredSummaries.back().procName;
                                }
                            } else if (keyCode == VK_F3) {
                                if (currentView == VIEW_SUMMARY) {
                                    sortMode = static_cast<SummarySortMode>((static_cast<int>(sortMode) + 1) % 6);
                                }
                            } else if (keyCode == VK_F5) {
                                if (currentView == VIEW_SUMMARY) {
                                    sortAscending = !sortAscending;
                                }
                            } else if (keyCode == VK_F2 || (keyCode == VK_TAB && currentView == VIEW_DETAIL && searchFilter.IsEmpty())) {
                                if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                    ruleTargetProc = filteredSummaries[selectedIndex].procName;
                                    ruleTargetPid = filteredSummaries[selectedIndex].representativePid;
                                    ruleIsTcp = true;
                                    ruleIsAllow = true;
                                    rulePortsInput.clear();
                                    enteringRule = true;
                                } else if (currentView == VIEW_DETAIL && !filteredDetailRows.empty()) {
                                    const auto& detailRow = filteredDetailRows[selectedIndex];
                                    ruleTargetProc = selectedProcName;
                                    ruleTargetPid = (detailRow.pid > 0) ? detailRow.pid : selectedPid;
                                    ruleIsTcp = (detailRow.proto == "TCP");
                                    ruleIsAllow = true;
                                    rulePortsInput = std::to_string(detailRow.localPort);
                                    enteringRule = true;
                                }
                            } else if (keyCode == VK_F4) {
                                if (currentView == VIEW_DETAIL && !filteredDetailRows.empty()) {
                                    const auto& detailRow = filteredDetailRows[selectedIndex];
                                    std::wstring ruleName = L"";
                                    bool isEnabled = false;
                                    bool found = FirewallManager::Instance().FindRule(detailRow.localPort, detailRow.proto, selectedProcName, ruleName, isEnabled);
                                    statusMessageTimer = GetTickCount();
                                    if (found && !ruleName.empty()) {
                                        bool success = FirewallManager::Instance().ToggleRule(ruleName, !isEnabled);
                                        if (success) {
                                            statusMessage = "Firewall rule status toggled successfully!";
                                            FirewallManager::Instance().TriggerAsyncUpdate();
                                        } else {
                                            statusMessage = "Error: Failed to toggle firewall rule. Ensure running elevated.";
                                        }
                                    } else {
                                        statusMessage = "No custom firewall rule found for this port.";
                                    }
                                }
                            } else if (keyCode == VK_DELETE || keyCode == VK_F8) {
                                if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                    killTargetPid = filteredSummaries[selectedIndex].representativePid;
                                    killTargetName = filteredSummaries[selectedIndex].procName;
                                    if (killTargetPid > 4) {
                                        confirmingKill = true;
                                    } else {
                                        statusMessage = "Cannot terminate critical system process.";
                                        statusMessageTimer = GetTickCount();
                                    }
                                } else if (currentView == VIEW_DETAIL && !filteredDetailRows.empty()) {
                                    killTargetPid = filteredDetailRows[selectedIndex].pid;
                                    killTargetName = selectedProcName;
                                    if (killTargetPid > 4) {
                                        confirmingKill = true;
                                    } else {
                                        statusMessage = "Cannot terminate process with PID <= 4.";
                                        statusMessageTimer = GetTickCount();
                                    }
                                }
                            } else if (ascChar == 3) { // Ctrl+C
                                if (currentView == VIEW_SUMMARY && !filteredSummaries.empty()) {
                                    const auto& row = filteredSummaries[selectedIndex];
                                    std::string clip = row.procName + " (PID " + std::to_string(row.representativePid) + ")";
                                    if (CopyToClipboard(clip)) {
                                        statusMessage = "Copied to clipboard: " + clip;
                                    } else {
                                        statusMessage = "Failed to copy to clipboard.";
                                    }
                                    statusMessageTimer = GetTickCount();
                                } else if (currentView == VIEW_DETAIL && !filteredDetailRows.empty()) {
                                    const auto& row = filteredDetailRows[selectedIndex];
                                    std::string clip = row.proto + " " + std::to_string(row.localPort) + " -> " + row.remoteAddr;
                                    if (CopyToClipboard(clip)) {
                                        statusMessage = "Copied to clipboard: " + clip;
                                    } else {
                                        statusMessage = "Failed to copy to clipboard.";
                                    }
                                    statusMessageTimer = GetTickCount();
                                }
                            } else if (std::isprint(static_cast<unsigned char>(ascChar))) {
                                searchFilter.Append(ascChar);
                                selectedIndex = 0;
                                scrollOffset = 0;
                            }
                        }
                    }
                }
            }
        }
    }

    consoleGuard.Restore();
    FirewallManager::Instance().WaitForPendingUpdate();
}
