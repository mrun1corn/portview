#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <netfw.h>

struct ConnectionRow; // Forward declaration

enum FirewallStatus {
    FW_STATUS_NONE,      // No rule (default blocked)
    FW_STATUS_ALLOWED,   // Explicitly allowed
    FW_STATUS_BLOCKED    // Explicitly blocked
};

struct FirewallRuleRow {
    std::wstring ruleName;
    std::string ruleNameStr;
    u_short port;
    std::string proto;
    bool enabled;
    bool allowed;
    DWORD pid;
    std::string procName;
    std::string state;
    std::string sentStr;
    std::string recvStr;
    ULONG64 sentBytesVal;
    ULONG64 recvBytesVal;
    int activeConnCount;
};

extern std::mutex g_fwMutex;
extern std::unordered_map<std::string, FirewallStatus> g_fwCache;
extern std::vector<FirewallRuleRow> g_fwRulesList;

void ParseAndAddRules(const std::string& portsStr, const std::wstring& wname, const std::string& nameStr, const std::string& protoStr, bool enabled, bool allowed, const std::string& ruleProcName, std::vector<FirewallRuleRow>& tempRulesList, std::unordered_map<std::string, FirewallStatus>& tempCache);
void UpdateFirewallCache();
FirewallStatus QueryFirewallCache(u_short port, const std::string& proto);
bool AddFirewallRule(u_short port, bool isTcp, const std::wstring& procName, const std::wstring& appPath);
bool ToggleFirewallRule(const std::wstring& ruleName, bool enable);
bool DeleteFirewallRule(const std::wstring& ruleName);
void BuildFirewallRuleRows(const std::vector<ConnectionRow>& connections, std::vector<FirewallRuleRow>& rules);
