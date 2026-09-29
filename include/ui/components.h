#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <string>
#include "core/data_models.h"

enum SummarySortMode {
    SORT_TRAFFIC = 0,
    SORT_CPU,
    SORT_RAM,
    SORT_CONNS,
    SORT_PORTS,
    SORT_NAME
};

namespace UiComponents {

std::string FormatBanner(int width, bool isSummary, const std::string& procName, DWORD pid,
                         const SystemHostMetrics& hostMetrics, bool isElevated);

std::string FormatSummaryColumns(int width, SummarySortMode sortMode = SORT_TRAFFIC, bool ascending = false);
std::string FormatDetailColumns(int width);

std::string FormatSummaryRow(const ProcessSummaryRow& row, bool selected, int width);
std::string FormatDetailRow(const ConnectionRow& row, bool selected, int width);

std::string FormatStatusBar(int width, const std::string& statusMessage,
                            DWORD tcpCount, DWORD udpCount, int allowedFwRules,
                            const std::string& topTalker, ULONG64 maxTraffic);

void AppendAddRuleModal(std::string& frame, int consoleWidth, int consoleHeight,
                        const std::string& procName, DWORD pid,
                        bool isTcp, bool isAllow, const std::string& portsInput,
                        bool isElevated);

} // namespace UiComponents
