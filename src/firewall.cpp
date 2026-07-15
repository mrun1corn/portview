#include "firewall.h"
#include "utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <algorithm>

std::mutex g_fwMutex;
std::unordered_map<std::string, FirewallStatus> g_fwCache;
std::vector<FirewallRuleRow> g_fwRulesList;

void ParseAndAddRules(const std::string& portsStr, const std::wstring& wname, const std::string& nameStr, const std::string& protoStr, bool enabled, bool allowed, const std::string& ruleProcName, std::vector<FirewallRuleRow>& tempRulesList, std::unordered_map<std::string, FirewallStatus>& tempCache) {
    FirewallStatus status = allowed ? FW_STATUS_ALLOWED : FW_STATUS_BLOCKED;
    std::string resolvedProc = ruleProcName;
    if (resolvedProc == "-" || resolvedProc.empty()) {
        size_t forIdx = nameStr.rfind(" for ");
        if (forIdx != std::string::npos) {
            resolvedProc = nameStr.substr(forIdx + 5);
        }
    }
    size_t start = 0;
    size_t end = portsStr.find(',');
    auto addRow = [&](const std::string& token) {
        if (token.empty()) return;
        if (token == "*") {
            if (enabled) {
                tempCache["*:TCP"] = status;
                tempCache["*:UDP"] = status;
            }
            FirewallRuleRow r;
            r.ruleName = wname;
            r.ruleNameStr = nameStr;
            r.port = 0;
            r.proto = protoStr;
            r.enabled = enabled;
            r.allowed = allowed;
            r.procName = resolvedProc;
            tempRulesList.push_back(r);
        } else {
            size_t hyphen = token.find('-');
            if (hyphen != std::string::npos) {
                try {
                    int s = std::stoi(token.substr(0, hyphen));
                    int e = std::stoi(token.substr(hyphen + 1));
                    for (int p = s; p <= e; ++p) {
                        if (enabled) {
                            tempCache[std::to_string(p) + ":" + protoStr] = status;
                        }
                        FirewallRuleRow r;
                        r.ruleName = wname;
                        r.ruleNameStr = nameStr;
                        r.port = static_cast<u_short>(p);
                        r.proto = protoStr;
                        r.enabled = enabled;
                        r.allowed = allowed;
                        r.procName = resolvedProc;
                        tempRulesList.push_back(r);
                    }
                } catch (...) {}
            } else {
                try {
                    int p = std::stoi(token);
                    if (enabled) {
                        tempCache[token + ":" + protoStr] = status;
                    }
                    FirewallRuleRow r;
                    r.ruleName = wname;
                    r.ruleNameStr = nameStr;
                    r.port = static_cast<u_short>(p);
                    r.proto = protoStr;
                    r.enabled = enabled;
                    r.allowed = allowed;
                    r.procName = resolvedProc;
                    tempRulesList.push_back(r);
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

void UpdateFirewallCache() {
    HRESULT hrCom = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) {
        if (SUCCEEDED(hrCom)) CoUninitialize();
        return;
    }

    INetFwRules* pFwRules = nullptr;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pNetFwPolicy2->Release();
        if (SUCCEEDED(hrCom)) CoUninitialize();
        return;
    }

    IUnknown* pEnumerator = nullptr;
    hr = pFwRules->get__NewEnum(&pEnumerator);
    if (FAILED(hr)) {
        pFwRules->Release();
        pNetFwPolicy2->Release();
        if (SUCCEEDED(hrCom)) CoUninitialize();
        return;
    }

    IEnumVARIANT* pVariant = nullptr;
    hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariant);
    pEnumerator->Release();
    if (FAILED(hr)) {
        pFwRules->Release();
        pNetFwPolicy2->Release();
        if (SUCCEEDED(hrCom)) CoUninitialize();
        return;
    }

    std::unordered_map<std::string, FirewallStatus> tempCache;
    std::vector<FirewallRuleRow> tempRulesList;

    VARIANT var;
    VariantInit(&var);
    ULONG cFetched = 0;
    while (pVariant->Next(1, &var, &cFetched) == S_OK) {
        if (var.vt == VT_DISPATCH && var.pdispVal != nullptr) {
            INetFwRule* pFwRule = nullptr;
            hr = var.pdispVal->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);
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

                        BSTR bstrApp = nullptr;
                        std::string ruleProcName = "-";
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
    pFwRules->Release();
    pNetFwPolicy2->Release();

    {
        std::lock_guard<std::mutex> lock(g_fwMutex);
        g_fwCache = std::move(tempCache);
        g_fwRulesList = std::move(tempRulesList);
    }

    if (SUCCEEDED(hrCom)) {
        CoUninitialize();
    }
}

FirewallStatus QueryFirewallCache(u_short port, const std::string& proto) {
    std::lock_guard<std::mutex> lock(g_fwMutex);
    std::string key = std::to_string(port) + ":" + proto;
    auto it = g_fwCache.find(key);
    if (it != g_fwCache.end()) {
        return it->second;
    }
    auto itWildcard = g_fwCache.find("*:" + proto);
    if (itWildcard != g_fwCache.end()) {
        return itWildcard->second;
    }
    return FW_STATUS_NONE;
}

bool AddFirewallRule(u_short port, bool isTcp, const std::wstring& procName, const std::wstring& appPath) {
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) return false;

    INetFwRules* pFwRules = nullptr;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pNetFwPolicy2->Release();
        return false;
    }

    INetFwRule* pFwRule = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
    if (FAILED(hr)) {
        pFwRules->Release();
        pNetFwPolicy2->Release();
        return false;
    }

    std::wstring ruleName = L"PortView Allowed Port " + std::to_wstring(port) + (isTcp ? L" (TCP)" : L" (UDP)") + L" for " + procName;
    BSTR bName = SysAllocString(ruleName.c_str());
    BSTR bDesc = SysAllocString(L"Inbound allow rule created by PortView");
    BSTR bPorts = SysAllocString(std::to_wstring(port).c_str());

    pFwRule->put_Name(bName);
    pFwRule->put_Description(bDesc);
    pFwRule->put_Protocol(isTcp ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP);
    pFwRule->put_LocalPorts(bPorts);
    pFwRule->put_Direction(NET_FW_RULE_DIR_IN);
    pFwRule->put_Action(NET_FW_ACTION_ALLOW);
    pFwRule->put_Enabled(VARIANT_TRUE);

    if (!appPath.empty()) {
        BSTR bApp = SysAllocString(appPath.c_str());
        pFwRule->put_ApplicationName(bApp);
        SysFreeString(bApp);
    }

    hr = pFwRules->Add(pFwRule);

    SysFreeString(bName);
    SysFreeString(bDesc);
    SysFreeString(bPorts);

    pFwRule->Release();
    pFwRules->Release();
    pNetFwPolicy2->Release();

    return SUCCEEDED(hr);
}

bool ToggleFirewallRule(const std::wstring& ruleName, bool enable) {
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) return false;

    INetFwRules* pFwRules = nullptr;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pNetFwPolicy2->Release();
        return false;
    }

    INetFwRule* pFwRule = nullptr;
    BSTR bName = SysAllocString(ruleName.c_str());
    hr = pFwRules->Item(bName, &pFwRule);
    SysFreeString(bName);

    if (SUCCEEDED(hr) && pFwRule != nullptr) {
        pFwRule->put_Enabled(enable ? VARIANT_TRUE : VARIANT_FALSE);
        pFwRule->Release();
    }

    pFwRules->Release();
    pNetFwPolicy2->Release();
    return SUCCEEDED(hr);
}

bool DeleteFirewallRule(const std::wstring& ruleName) {
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (FAILED(hr)) return false;

    INetFwRules* pFwRules = nullptr;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        pNetFwPolicy2->Release();
        return false;
    }

    BSTR bName = SysAllocString(ruleName.c_str());
    hr = pFwRules->Remove(bName);
    SysFreeString(bName);

    pFwRules->Release();
    pNetFwPolicy2->Release();
    return SUCCEEDED(hr);
}

void BuildFirewallRuleRows(const std::vector<ConnectionRow>& connections, std::vector<FirewallRuleRow>& rules) {
    {
        std::lock_guard<std::mutex> lock(g_fwMutex);
        rules = g_fwRulesList;
    }

    for (auto& rule : rules) {
        rule.activeConnCount = 0;
        rule.sentBytesVal = 0;
        rule.recvBytesVal = 0;
        rule.pid = 0;
        if (rule.procName.empty()) {
            rule.procName = "-";
        }
        rule.state = "IDLE";
        rule.sentStr = "-";
        rule.recvStr = "-";

        for (const auto& conn : connections) {
            if ((rule.port == 0 || conn.localPort == rule.port) && conn.proto == rule.proto) {
                rule.activeConnCount++;
                if (rule.pid == 0 || conn.state == "LISTENING") {
                    rule.pid = conn.pid;
                    rule.procName = conn.procName;
                    rule.state = conn.state;
                }
                rule.sentBytesVal += conn.sentBytesVal;
                rule.recvBytesVal += conn.recvBytesVal;
            }
        }

        if (rule.activeConnCount > 0) {
            rule.sentStr = (rule.sentBytesVal > 0) ? FormatBytes(rule.sentBytesVal) : "-";
            rule.recvStr = (rule.recvBytesVal > 0) ? FormatBytes(rule.recvBytesVal) : "-";
        }
    }

    std::sort(rules.begin(), rules.end(), [](const FirewallRuleRow& a, const FirewallRuleRow& b) {
        if (a.activeConnCount != b.activeConnCount) {
            return a.activeConnCount > b.activeConnCount;
        }
        if (a.enabled != b.enabled) {
            return a.enabled > b.enabled;
        }
        return a.port < b.port;
    });
}
