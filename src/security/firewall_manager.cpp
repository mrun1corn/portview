#include "security/firewall_manager.h"
#include "core/utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <algorithm>

namespace {

struct FirewallComScope {
    INetFwPolicy2* policy = nullptr;
    INetFwRules* rules = nullptr;

    FirewallComScope() {
        HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
                                      __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&policy));
        if (SUCCEEDED(hr) && policy != nullptr) {
            hr = policy->get_Rules(&rules);
            if (FAILED(hr) || rules == nullptr) {
                policy->Release();
                policy = nullptr;
                rules = nullptr;
            }
        }
    }

    ~FirewallComScope() {
        if (rules) { rules->Release(); rules = nullptr; }
        if (policy) { policy->Release(); policy = nullptr; }
    }

    bool IsValid() const { return policy != nullptr && rules != nullptr; }
};

void ParseAndAddRules(const std::string& portsStr, const std::wstring& wname, const std::string& nameStr,
                       const std::string& protoStr, bool enabled, bool allowed, const std::string& ruleProcName,
                       std::vector<FirewallRuleRow>& tempRulesList, std::unordered_map<std::string, FirewallStatus>& tempCache) {
    FirewallStatus status = allowed ? FW_STATUS_ALLOWED : FW_STATUS_BLOCKED;
    std::string resolvedProc = ruleProcName;
    if (resolvedProc == "-" || resolvedProc.empty()) {
        size_t forIdx = nameStr.rfind(" for ");
        if (forIdx != std::string::npos) {
            resolvedProc = nameStr.substr(forIdx + 5);
        }
    }

    auto makeRule = [&](u_short p) {
        FirewallRuleRow r;
        r.ruleName = wname;
        r.ruleNameStr = nameStr;
        r.port = p;
        r.proto = protoStr;
        r.enabled = enabled;
        r.allowed = allowed;
        r.procName = resolvedProc;
        return r;
    };

    size_t start = 0;
    size_t end = portsStr.find(',');
    auto addRow = [&](const std::string& token) {
        if (token.empty()) return;
        if (token == "*") {
            if (enabled) {
                tempCache["*:TCP"] = status;
                tempCache["*:UDP"] = status;
            }
            tempRulesList.push_back(makeRule(0));
        } else {
            size_t hyphen = token.find('-');
            if (hyphen != std::string::npos) {
                try {
                    int s = std::stoi(token.substr(0, hyphen));
                    int e = std::stoi(token.substr(hyphen + 1));
                    if (s >= 1 && s <= 65535 && e >= 1 && e <= 65535 && s <= e && (e - s) <= 1024) {
                        for (int p = s; p <= e; ++p) {
                            if (enabled) {
                                tempCache[std::to_string(p) + ":" + protoStr] = status;
                            }
                            tempRulesList.push_back(makeRule(static_cast<u_short>(p)));
                        }
                    }
                } catch (...) {}
            } else {
                try {
                    int p = std::stoi(token);
                    if (p >= 1 && p <= 65535) {
                        if (enabled) {
                            tempCache[token + ":" + protoStr] = status;
                        }
                        tempRulesList.push_back(makeRule(static_cast<u_short>(p)));
                    }
                } catch (...) {}
            }
        }
    };

    while (end != std::string::npos) {
        addRow(portsStr.substr(start, end - start));
        start = end + 1;
        end = portsStr.find(',', start);
    }
    addRow(portsStr.substr(start));
}

} // anonymous namespace

FirewallManager::FirewallManager() = default;

FirewallManager::~FirewallManager() {
    WaitForPendingUpdate();
}

FirewallManager& FirewallManager::Instance() {
    static FirewallManager instance;
    return instance;
}

void FirewallManager::TriggerAsyncUpdate() {
    std::lock_guard<std::mutex> lock(updateThreadMutex_);
    if (isUpdating_.load()) {
        return;
    }
    if (updateThread_.joinable()) {
        updateThread_.join();
    }
    isUpdating_.store(true);
    updateThread_ = std::thread([this]() {
        UpdateCache();
        isUpdating_.store(false);
    });
}

void FirewallManager::WaitForPendingUpdate() {
    std::lock_guard<std::mutex> lock(updateThreadMutex_);
    if (updateThread_.joinable()) {
        updateThread_.join();
    }
}

bool FirewallManager::ValidatePortRange(const std::string& portsStr) {
    if (portsStr.empty()) return false;
    if (portsStr == "*") return true;

    for (char c : portsStr) {
        if (!isdigit(static_cast<unsigned char>(c)) && c != ',' && c != '-') {
            return false;
        }
    }

    size_t start = 0;
    size_t end = portsStr.find(',');
    int totalPorts = 0;

    auto checkToken = [&](const std::string& token) -> bool {
        if (token.empty()) return false;
        size_t hyphen = token.find('-');
        if (hyphen != std::string::npos) {
            if (hyphen == 0 || hyphen == token.length() - 1 || token.find('-', hyphen + 1) != std::string::npos) {
                return false;
            }
            try {
                int s = std::stoi(token.substr(0, hyphen));
                int e = std::stoi(token.substr(hyphen + 1));
                if (s < 1 || s > 65535 || e < 1 || e > 65535 || s > e) {
                    return false;
                }
                int count = (e - s) + 1;
                if (count > 1024) return false;
                totalPorts += count;
            } catch (...) {
                return false;
            }
        } else {
            try {
                int p = std::stoi(token);
                if (p < 1 || p > 65535) return false;
                totalPorts += 1;
            } catch (...) {
                return false;
            }
        }
        return totalPorts <= 4096;
    };

    while (end != std::string::npos) {
        if (!checkToken(portsStr.substr(start, end - start))) {
            return false;
        }
        start = end + 1;
        end = portsStr.find(',', start);
    }
    return checkToken(portsStr.substr(start));
}

void FirewallManager::UpdateCache() {
    ScopedCom comGuard(COINIT_APARTMENTTHREADED);
    FirewallComScope fwScope;
    if (!fwScope.IsValid()) return;

    IUnknown* pEnumerator = nullptr;
    HRESULT hr = fwScope.rules->get__NewEnum(&pEnumerator);
    if (FAILED(hr)) return;

    IEnumVARIANT* pVariant = nullptr;
    hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(&pVariant));
    pEnumerator->Release();
    if (FAILED(hr)) return;

    std::unordered_map<std::string, FirewallStatus> tempCache;
    std::vector<FirewallRuleRow> tempRulesList;

    VARIANT var;
    VariantInit(&var);
    ULONG cFetched = 0;
    while (pVariant->Next(1, &var, &cFetched) == S_OK) {
        if (var.vt == VT_DISPATCH && var.pdispVal != nullptr) {
            INetFwRule* pFwRule = nullptr;
            hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
            if (SUCCEEDED(hr) && pFwRule != nullptr) {
                VARIANT_BOOL enabled = VARIANT_FALSE;
                NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;

                pFwRule->get_Enabled(&enabled);
                pFwRule->get_Direction(&dir);

                if (dir == NET_FW_RULE_DIR_IN) {
                    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
                    pFwRule->get_Action(&action);

                    LONG protocol = 0;
                    pFwRule->get_Protocol(&protocol);

                    std::string protoStr = "";
                    if (protocol == NET_FW_IP_PROTOCOL_TCP) protoStr = "TCP";
                    else if (protocol == NET_FW_IP_PROTOCOL_UDP) protoStr = "UDP";

                    if (!protoStr.empty()) {
                        BSTR bstrName = nullptr;
                        pFwRule->get_Name(&bstrName);
                        std::wstring wname = bstrName ? bstrName : L"";
                        std::string nameStr = WStringToString(wname);
                        if (bstrName) SysFreeString(bstrName);

                        std::string ruleProcName = "-";
                        BSTR bstrApp = nullptr;
                        if (SUCCEEDED(pFwRule->get_ApplicationName(&bstrApp)) && bstrApp != nullptr) {
                            std::wstring wapp(bstrApp);
                            SysFreeString(bstrApp);
                            size_t lastSlash = wapp.find_last_of(L"\\/");
                            if (lastSlash != std::wstring::npos) {
                                ruleProcName = WStringToString(wapp.substr(lastSlash + 1));
                            } else {
                                ruleProcName = WStringToString(wapp);
                            }
                        }

                        BSTR bstrPorts = nullptr;
                        if (SUCCEEDED(pFwRule->get_LocalPorts(&bstrPorts)) && bstrPorts != nullptr) {
                            std::wstring wports(bstrPorts, SysStringLen(bstrPorts));
                            SysFreeString(bstrPorts);

                            std::string ports = WStringToString(wports);
                            if (!ports.empty()) {
                                ParseAndAddRules(ports, wname, nameStr, protoStr, (enabled == VARIANT_TRUE), (action == NET_FW_ACTION_ALLOW), ruleProcName, tempRulesList, tempCache);
                            }
                        }
                    }
                }
                pFwRule->Release();
            }
        }
        VariantClear(&var);
    }

    pVariant->Release();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_ = std::move(tempCache);
        rulesList_ = std::move(tempRulesList);
    }
}

FirewallStatus FirewallManager::QueryStatus(u_short port, const std::string& proto) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = std::to_string(port) + ":" + proto;
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        return it->second;
    }
    auto itWildcard = cache_.find("*:" + proto);
    if (itWildcard != cache_.end()) {
        return itWildcard->second;
    }
    return FW_STATUS_NONE;
}

std::vector<FirewallRuleRow> FirewallManager::GetRulesSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rulesList_;
}

int FirewallManager::CountAllowedRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    int count = 0;
    for (const auto& pair : cache_) {
        if (pair.second == FW_STATUS_ALLOWED) {
            count++;
        }
    }
    return count;
}

std::vector<FirewallRuleRow> FirewallManager::FindMatchingRules(const std::string& procBase) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FirewallRuleRow> matched;
    for (const auto& rule : rulesList_) {
        std::string ruleNameLower = rule.ruleNameStr;
        std::transform(ruleNameLower.begin(), ruleNameLower.end(), ruleNameLower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (ruleNameLower.find(procBase) != std::string::npos) {
            matched.push_back(rule);
        }
    }
    return matched;
}

bool FirewallManager::FindRule(u_short port, const std::string& proto, const std::string& procName, std::wstring& outRuleName, bool& outIsEnabled) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& r : rulesList_) {
        if (r.port == port && r.proto == proto) {
            bool procMatch = (r.procName == procName);
            if (!procMatch && (r.procName == "-" || r.procName.empty())) {
                std::string suffix = " for " + procName;
                if (r.ruleNameStr.length() >= suffix.length() &&
                    r.ruleNameStr.compare(r.ruleNameStr.length() - suffix.length(), suffix.length(), suffix) == 0) {
                    procMatch = true;
                }
            }
            if (procMatch) {
                outRuleName = r.ruleName;
                outIsEnabled = r.enabled;
                return true;
            }
        }
    }
    return false;
}

bool FirewallManager::AddRule(const std::string& portsStr, bool isTcp, const std::wstring& procName,
                             const std::wstring& appPath, bool isAllow, const std::string& customName) {
    if (!ValidatePortRange(portsStr)) return false;

    ScopedCom comGuard(COINIT_APARTMENTTHREADED);
    FirewallComScope fwScope;
    if (!fwScope.IsValid()) return false;

    INetFwRule* pFwRule = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
    if (FAILED(hr)) return false;

    std::wstring protoWStr = isTcp ? L"TCP" : L"UDP";
    std::wstring actionWStr = isAllow ? L"Allowed" : L"Blocked";
    std::wstring ruleName;
    if (!customName.empty()) {
        ruleName = StringToWString(customName);
    } else {
        std::wstring pStr = StringToWString(portsStr);
        ruleName = L"PortView " + actionWStr + L" Port " + pStr + L" (" + protoWStr + L") for " + (procName.empty() ? L"Global" : procName);
    }

    BSTR bName = SysAllocString(ruleName.c_str());
    std::wstring desc = L"Inbound " + (isAllow ? std::wstring(L"allow") : std::wstring(L"block")) + L" rule created by PortView";
    BSTR bDesc = SysAllocString(desc.c_str());
    std::wstring wPortsStr = StringToWString(portsStr);
    BSTR bPorts = SysAllocString(wPortsStr.c_str());

    pFwRule->put_Name(bName);
    pFwRule->put_Description(bDesc);
    pFwRule->put_Protocol(isTcp ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP);
    pFwRule->put_LocalPorts(bPorts);
    pFwRule->put_Direction(NET_FW_RULE_DIR_IN);
    pFwRule->put_Action(isAllow ? NET_FW_ACTION_ALLOW : NET_FW_ACTION_BLOCK);
    pFwRule->put_Enabled(VARIANT_TRUE);

    if (!appPath.empty()) {
        BSTR bApp = SysAllocString(appPath.c_str());
        pFwRule->put_ApplicationName(bApp);
        SysFreeString(bApp);
    }

    hr = fwScope.rules->Add(pFwRule);

    SysFreeString(bName);
    SysFreeString(bDesc);
    SysFreeString(bPorts);
    pFwRule->Release();

    return SUCCEEDED(hr);
}

bool FirewallManager::ToggleRule(const std::wstring& ruleName, bool enable) {
    ScopedCom comGuard(COINIT_APARTMENTTHREADED);
    FirewallComScope fwScope;
    if (!fwScope.IsValid()) return false;

    INetFwRule* pFwRule = nullptr;
    BSTR bName = SysAllocString(ruleName.c_str());
    HRESULT hr = fwScope.rules->Item(bName, &pFwRule);
    SysFreeString(bName);

    if (SUCCEEDED(hr) && pFwRule != nullptr) {
        pFwRule->put_Enabled(enable ? VARIANT_TRUE : VARIANT_FALSE);
        pFwRule->Release();
    }

    return SUCCEEDED(hr);
}

bool FirewallManager::DeleteRule(const std::wstring& ruleName) {
    ScopedCom comGuard(COINIT_APARTMENTTHREADED);
    FirewallComScope fwScope;
    if (!fwScope.IsValid()) return false;

    BSTR bName = SysAllocString(ruleName.c_str());
    HRESULT hr = fwScope.rules->Remove(bName);
    SysFreeString(bName);

    return SUCCEEDED(hr);
}
