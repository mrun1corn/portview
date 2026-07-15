#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "data_models.h"

std::string ResolveIpToHostname(DWORD ipAddress);
std::string GetRemoteAddrString(DWORD ipAddress, DWORD port);
void LoadData(std::vector<ConnectionRow>& connections, std::unordered_map<std::string, ULONG64>& processTraffic, DWORD& tcpCount, DWORD& udpCount);
void BuildProcessSummaries(const std::vector<ConnectionRow>& connections, std::vector<ProcessSummaryRow>& summaries);
