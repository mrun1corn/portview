#include "ui/components.h"
#include "core/utils.h"
#include <cstdio>
#include <algorithm>

namespace UiComponents {

std::string FormatBanner(int width, bool isSummary, const std::string& procName, DWORD pid,
                         const SystemHostMetrics& hostMetrics, bool isElevated) {
    char headerBuf[256];
    std::string elevStr = isElevated ? "[ELEVATED]" : "[NON-ELEVATED]";

    if (isSummary) {
        std::snprintf(headerBuf, sizeof(headerBuf), "portview v1.4 %s | %s | %s | F3: Sort | F2: Add Rule | Del: Kill | Esc: Quit",
                      elevStr.c_str(), hostMetrics.cpuBannerStr.c_str(), hostMetrics.ramBannerStr.c_str());
    } else {
        std::string pidStr = (pid == 0) ? "IDLE" : "PID " + std::to_string(pid);
        std::snprintf(headerBuf, sizeof(headerBuf), "Process: %s (%s) %s | F2: Add Rule | F4: Toggle FW | Del: Del FW | Esc: Back",
                      procName.c_str(), pidStr.c_str(), elevStr.c_str());
    }

    return "\x1b[30;106m" + PadOrTrim(headerBuf, width - 1) + "\x1b[0m\n";
}

std::string FormatSummaryColumns(int width, SummarySortMode sortMode, bool ascending) {
    char arrow = ascending ? '^' : 'v';
    std::string pName = (sortMode == SORT_NAME) ? ("PROCESS " + std::string(1, arrow)) : "PROCESS";
    std::string cpu = (sortMode == SORT_CPU) ? ("CPU% " + std::string(1, arrow)) : "CPU%";
    std::string ram = (sortMode == SORT_RAM) ? ("RAM " + std::string(1, arrow)) : "RAM";
    std::string ports = (sortMode == SORT_PORTS) ? ("PORTS " + std::string(1, arrow)) : "PORTS";
    std::string conns = (sortMode == SORT_CONNS) ? ("CONNS " + std::string(1, arrow)) : "CONNS";
    std::string sent = (sortMode == SORT_TRAFFIC) ? ("SENT " + std::string(1, arrow)) : "SENT";
    std::string recv = "RECV";

    char colBuf[256];
    std::snprintf(colBuf, sizeof(colBuf), "   %-24s %-7s %-10s %-7s %-7s %-12s %-12s",
                  pName.c_str(), cpu.c_str(), ram.c_str(), ports.c_str(), conns.c_str(), sent.c_str(), recv.c_str());
    return "\x1b[36;1m" + PadOrTrim(colBuf, width - 1) + "\x1b[0m\n";
}

std::string FormatDetailColumns(int width) {
    char colBuf[256];
    std::snprintf(colBuf, sizeof(colBuf), "   %-6s %-7s %-20s %-15s %-11s %-11s %-11s",
                  "PROTO", "PORT", "REMOTE", "STATE", "SENT", "RECV", "FIREWALL");
    return "\x1b[36;1m" + PadOrTrim(colBuf, width - 1) + "\x1b[0m\n";
}

std::string FormatSummaryRow(const ProcessSummaryRow& row, bool selected, int width) {
    if (selected) {
        char rowBuf[512];
        std::snprintf(rowBuf, sizeof(rowBuf), " > %-24s %-7s %-10s %-7d %-7d %-12s %-12s",
                      row.procName.substr(0, 24).c_str(), row.cpuStr.c_str(), row.ramStr.c_str(),
                      row.portsCount, row.connsCount, row.sentStr.c_str(), row.recvStr.c_str());
        return "\x1b[30;106m" + PadOrTrim(rowBuf, width - 1) + "\x1b[0m";
    } else {
        char procBuf[32];
        std::snprintf(procBuf, sizeof(procBuf), "%-24s", row.procName.substr(0, 24).c_str());
        char cpuBuf[16];
        std::snprintf(cpuBuf, sizeof(cpuBuf), "%-7s", row.cpuStr.c_str());
        char ramBuf[16];
        std::snprintf(ramBuf, sizeof(ramBuf), "%-10s", row.ramStr.c_str());
        char countsBuf[32];
        std::snprintf(countsBuf, sizeof(countsBuf), "%-7d %-7d ", row.portsCount, row.connsCount);
        char sentBuf[32];
        std::snprintf(sentBuf, sizeof(sentBuf), "%-12s", row.sentStr.c_str());
        char recvBuf[32];
        std::snprintf(recvBuf, sizeof(recvBuf), "%-12s", row.recvStr.c_str());

        std::string line = "   ";
        line += "\x1b[36;1m" + std::string(procBuf) + "\x1b[0m ";
        if (row.cpuPercent > 0.0) line += "\x1b[93m" + std::string(cpuBuf) + "\x1b[0m ";
        else line += "\x1b[90m" + std::string(cpuBuf) + "\x1b[0m ";

        if (row.ramBytes > 0) line += "\x1b[92m" + std::string(ramBuf) + "\x1b[0m ";
        else line += "\x1b[90m" + std::string(ramBuf) + "\x1b[0m ";

        line += countsBuf;
        if (row.sentStr != "-") line += "\x1b[92m" + std::string(sentBuf) + "\x1b[0m ";
        else line += "\x1b[90m" + std::string(sentBuf) + "\x1b[0m ";

        if (row.recvStr != "-") line += "\x1b[92m" + std::string(recvBuf) + "\x1b[0m";
        else line += "\x1b[90m" + std::string(recvBuf) + "\x1b[0m";

        int visualLength = 3 + 25 + 8 + 11 + 8 + 8 + 13 + 12;
        if (visualLength < width - 1) {
            line.append((width - 1) - visualLength, ' ');
        }
        return line;
    }
}

std::string FormatDetailRow(const ConnectionRow& row, bool selected, int width) {
    std::string fwStr = "DEFAULT";
    if (row.fwStatus == FW_STATUS_ALLOWED) fwStr = "ALLOWED";
    else if (row.fwStatus == FW_STATUS_BLOCKED) fwStr = "BLOCKED";

    if (selected) {
        char rowBuf[512];
        std::snprintf(rowBuf, sizeof(rowBuf), " > %-6s %-7u %-20s %-15s %-11s %-11s %-11s",
                      row.proto.c_str(), row.localPort, row.remoteAddr.substr(0, 20).c_str(),
                      row.state.c_str(), row.sentStr.c_str(), row.recvStr.c_str(), fwStr.c_str());
        return "\x1b[30;106m" + PadOrTrim(rowBuf, width - 1) + "\x1b[0m";
    } else {
        char portBuf[16];
        std::snprintf(portBuf, sizeof(portBuf), "%-7u ", row.localPort);
        char remoteBuf[32];
        std::snprintf(remoteBuf, sizeof(remoteBuf), "%-20s", row.remoteAddr.substr(0, 20).c_str());
        char sentBuf[16];
        std::snprintf(sentBuf, sizeof(sentBuf), "%-11s", row.sentStr.c_str());
        char recvBuf[16];
        std::snprintf(recvBuf, sizeof(recvBuf), "%-11s", row.recvStr.c_str());

        std::string line = "   ";
        if (row.proto == "TCP") line += "\x1b[36mTCP   \x1b[0m ";
        else line += "\x1b[93mUDP   \x1b[0m ";

        line += portBuf;
        line += "\x1b[93m" + std::string(remoteBuf) + "\x1b[0m ";

        char stateBuf[32];
        std::snprintf(stateBuf, sizeof(stateBuf), "%-15s", row.state.c_str());

        if (row.state == "ESTABLISHED") line += "\x1b[92m" + std::string(stateBuf) + "\x1b[0m ";
        else if (row.state == "LISTENING") line += "\x1b[36m" + std::string(stateBuf) + "\x1b[0m ";
        else if (row.state.find("WAIT") != std::string::npos) line += "\x1b[93m" + std::string(stateBuf) + "\x1b[0m ";
        else line += "\x1b[90m" + std::string(stateBuf) + "\x1b[0m ";

        if (row.sentStr != "-") line += "\x1b[92m" + std::string(sentBuf) + "\x1b[0m ";
        else line += "\x1b[90m" + std::string(sentBuf) + "\x1b[0m ";

        if (row.recvStr != "-") line += "\x1b[92m" + std::string(recvBuf) + "\x1b[0m ";
        else line += "\x1b[90m" + std::string(recvBuf) + "\x1b[0m ";

        if (row.fwStatus == FW_STATUS_ALLOWED) line += "\x1b[92m[ ALLOW ]  \x1b[0m";
        else if (row.fwStatus == FW_STATUS_BLOCKED) line += "\x1b[91m[ BLOCK ]  \x1b[0m";
        else line += "\x1b[90m[ DEFAULT ]\x1b[0m";

        int visualLength = 3 + 7 + 8 + 21 + 16 + 12 + 12 + 11;
        if (visualLength < width - 1) {
            line.append((width - 1) - visualLength, ' ');
        }
        return line;
    }
}

std::string FormatStatusBar(int width, const std::string& statusMessage,
                            DWORD tcpCount, DWORD udpCount, int allowedFwRules,
                            const std::string& topTalker, ULONG64 maxTraffic) {
    std::string summaryStr;
    if (!statusMessage.empty()) {
        summaryStr = statusMessage;
    } else {
        summaryStr = "Summary: " + std::to_string(tcpCount) + " TCP | " + std::to_string(udpCount) + " UDP | Allowed FW Ports: " + std::to_string(allowedFwRules);
        if (maxTraffic > 0 && !topTalker.empty()) {
            summaryStr += " | Top talker: " + topTalker + " (" + FormatSpeed(static_cast<double>(maxTraffic)) + ")";
        }
    }
    return "\x1b[30;106m" + PadOrTrim(summaryStr, width - 1) + "\x1b[0m";
}

void AppendAddRuleModal(std::string& frame, int consoleWidth, int consoleHeight,
                        const std::string& procName, DWORD pid,
                        bool isTcp, bool isAllow, const std::string& portsInput,
                        bool isElevated) {
    constexpr int boxWidth = 64;
    constexpr int boxHeight = 10;
    int startX = (consoleWidth - boxWidth) / 2;
    int startY = (consoleHeight - boxHeight) / 2;
    if (startX < 0) startX = 0;
    if (startY < 2) startY = 2;

    auto appendBoxLine = [&](int y, const std::string& text, const char* color = "\x1b[97;44m") {
        frame += "\x1b[" + std::to_string(y + 1) + ";" + std::to_string(startX + 1) + "H";
        frame += color;
        frame += PadOrTrim(text, boxWidth);
        frame += "\x1b[0m";
    };

    std::string pidStr = (pid == 0) ? "N/A" : std::to_string(pid);
    std::string procStr = procName.empty() ? "Global (All Processes)" : procName + " (PID " + pidStr + ")";
    std::string protoStr = isTcp ? "[ TCP ] (Press Tab for UDP)" : "[ UDP ] (Press Tab for TCP)";
    std::string actionStr = isAllow ? "[ ALLOW ] (F2: Toggle Block)" : "[ BLOCK ] (F2: Toggle Allow)";
    std::string inputDisplay = portsInput + "_";

    appendBoxLine(startY + 0, " +----------------- ADD INBOUND FIREWALL RULE ----------------+ ", "\x1b[97;44;1m");
    appendBoxLine(startY + 1, " | Target   : " + procStr);
    appendBoxLine(startY + 2, " | Protocol : " + protoStr);
    appendBoxLine(startY + 3, " | Action   : " + actionStr);
    appendBoxLine(startY + 4, " | Port(s)  : " + inputDisplay, "\x1b[93;44;1m");
    appendBoxLine(startY + 5, " | Formats  : 8080 | 8000-8080 | 80,443 | 8080/udp          ");
    if (!isElevated) {
        appendBoxLine(startY + 6, " | WARNING  : NOT ELEVATED (Requires Admin to save rule)       ", "\x1b[93;41;1m");
    } else {
        appendBoxLine(startY + 6, " | Status   : Elevated (Administrator Privileges Verified)     ", "\x1b[92;44m");
    }
    appendBoxLine(startY + 7, " +-------------------------------------------------------------+ ", "\x1b[97;44;1m");
    appendBoxLine(startY + 8, "   [Enter] Save Rule    [Tab] Protocol    [Esc] Cancel           ", "\x1b[30;107m");
}

} // namespace UiComponents
