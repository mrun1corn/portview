#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <netfw.h>
#include "data_models.h"

class FirewallManager {
public:
    static FirewallManager& Instance();

    void UpdateCache();
    FirewallStatus QueryStatus(u_short port, const std::string& proto) const;
    std::vector<FirewallRuleRow> GetRulesSnapshot() const;
    int CountAllowedRules() const;
    std::vector<FirewallRuleRow> FindMatchingRules(const std::string& procBase) const;
    bool FindRule(u_short port, const std::string& proto, const std::string& procName, std::wstring& outRuleName, bool& outIsEnabled) const;

    bool AddRule(const std::string& portsStr, bool isTcp, const std::wstring& procName,
                 const std::wstring& appPath, bool isAllow = true, const std::string& customName = "");
    bool AddRule(u_short port, bool isTcp, const std::wstring& procName,
                 const std::wstring& appPath, bool isAllow = true) {
        return AddRule(std::to_string(port), isTcp, procName, appPath, isAllow);
    }
    bool ToggleRule(const std::wstring& ruleName, bool enable);
    bool DeleteRule(const std::wstring& ruleName);

private:
    FirewallManager() = default;
    ~FirewallManager() = default;
    FirewallManager(const FirewallManager&) = delete;
    FirewallManager& operator=(const FirewallManager&) = delete;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, FirewallStatus> cache_;
    std::vector<FirewallRuleRow> rulesList_;
};

// Convenience entry point
inline void UpdateFirewallCache() {
    FirewallManager::Instance().UpdateCache();
}
