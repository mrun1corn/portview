#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <netfw.h>
#include <objbase.h>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <io.h>

// Link with iphlpapi.lib and ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Convert TCP connection state to string
std::string TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
}

std::string IpToString(DWORD ipAddress) {
    IN_ADDR inAddr;
    inAddr.S_un.S_addr = ipAddress;
    char ipStr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &inAddr, ipStr, sizeof(ipStr))) {
        return ipStr;
    }
    return "0.0.0.0";
}

std::mutex g_dnsMutex;
std::unordered_map<DWORD, std::string> g_dnsCache;
std::unordered_set<DWORD> g_resolvingQueue;

std::string ResolveIpToHostname(DWORD ipAddress) {
    if (ipAddress == 0) {
        return "*";
    }

    // Localhost optimization to avoid querying DNS
    if (ipAddress == 0x0100007f) {
        return "localhost";
    }

    {
        std::lock_guard<std::mutex> lock(g_dnsMutex);
        auto it = g_dnsCache.find(ipAddress);
        if (it != g_dnsCache.end()) {
            return it->second;
        }

        // Kick off asynchronous resolution if not already in flight
        if (g_resolvingQueue.find(ipAddress) == g_resolvingQueue.end()) {
            g_resolvingQueue.insert(ipAddress);
            
            std::string fallbackIp = IpToString(ipAddress);
            std::thread([ipAddress, fallbackIp]() {
                sockaddr_in sa;
                sa.sin_family = AF_INET;
                sa.sin_addr.s_addr = ipAddress;
                sa.sin_port = 0;

                char host[NI_MAXHOST];
                int result = getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NOFQDN);
                std::string hostname = (result == 0) ? host : fallbackIp;

                {
                    std::lock_guard<std::mutex> lock(g_dnsMutex);
                    g_dnsCache[ipAddress] = hostname;
                    g_resolvingQueue.erase(ipAddress);
                }
            }).detach();
        }
    }

    return IpToString(ipAddress);
}

std::string GetRemoteAddrString(DWORD ipAddress, DWORD port) {
    if (ipAddress == 0 && port == 0) {
        return "0.0.0.0:*";
    }
    u_short rPort = ntohs((u_short)port);
    std::string host = ResolveIpToHostname(ipAddress);
    return host + ":" + std::to_string(rPort);
}

bool IsElevated() {
    bool elevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    return elevated;
}

std::string FormatBytes(ULONG64 bytes) {
    double num = static_cast<double>(bytes);
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    while (num >= 1024.0 && unitIndex < 4) {
        num /= 1024.0;
        unitIndex++;
    }
    char buf[64];
    if (unitIndex == 0) {
        sprintf(buf, "%d B", static_cast<int>(bytes));
    } else {
        sprintf(buf, "%.1f %s", num, units[unitIndex]);
    }
    return buf;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

std::string GetProcessName(DWORD pid) {
    static std::unordered_map<DWORD, std::string> cache;
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return it->second;
    }

    if (pid == 0) {
        return "System Idle Process";
    } else if (pid == 4) {
        return "System";
    }

    std::string processName = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            std::wstring wpath(path);
            size_t lastSlash = wpath.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                std::wstring wname = wpath.substr(lastSlash + 1);
                processName = WStringToString(wname);
            } else {
                processName = WStringToString(wpath);
            }
        }
        CloseHandle(hProcess);
    }
    cache[pid] = processName;
    return processName;
}
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

std::wstring GetProcessImagePath(DWORD pid) {
    if (pid == 0 || pid == 4) return L"";
    std::wstring pathStr = L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            pathStr = path;
        }
        CloseHandle(hProcess);
    }
    return pathStr;
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


struct ConnectionRow {
    std::string proto;
    u_short localPort;
    std::string remoteAddr;
    std::string state;
    DWORD pid;
    std::string procName;
    std::string sentStr;
    std::string recvStr;
    ULONG64 sentBytesVal;
    ULONG64 recvBytesVal;
    ULONG64 totalBytes;
    FirewallStatus fwStatus;
};


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

void LoadData(std::vector<ConnectionRow>& connections, std::unordered_map<std::string, ULONG64>& processTraffic, DWORD& tcpCount, DWORD& udpCount) {
    connections.clear();
    processTraffic.clear();
    tcpCount = 0;
    udpCount = 0;

    bool elevated = IsElevated();

    // 1. Fetch TCP
    ULONG size = 0;
    DWORD dwRetVal = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<char> buffer;
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;

    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(size);
        pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        dwRetVal = GetExtendedTcpTable(pTcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    if (dwRetVal == NO_ERROR && pTcpTable != nullptr) {
        tcpCount = pTcpTable->dwNumEntries;
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
            const auto& row = pTcpTable->table[i];
            
            ConnectionRow conn;
            conn.proto = "TCP";
            conn.localPort = ntohs((u_short)row.dwLocalPort);
            
            conn.remoteAddr = GetRemoteAddrString(row.dwRemoteAddr, row.dwRemotePort);
            conn.state = TcpStateToString(row.dwState);
            conn.pid = row.dwOwningPid;
            conn.procName = GetProcessName(conn.pid);
            conn.sentStr = "-";
            conn.recvStr = "-";
            conn.sentBytesVal = 0;
            conn.recvBytesVal = 0;
            conn.totalBytes = 0;

            if (elevated) {
                MIB_TCPROW mibRow;
                mibRow.dwState = row.dwState;
                mibRow.dwLocalAddr = row.dwLocalAddr;
                mibRow.dwLocalPort = row.dwLocalPort;
                mibRow.dwRemoteAddr = row.dwRemoteAddr;
                mibRow.dwRemotePort = row.dwRemotePort;

                TCP_ESTATS_DATA_RW_v0 rw;
                rw.EnableCollection = TRUE;
                SetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, (unsigned char*)&rw, 0, sizeof(rw), 0);

                TCP_ESTATS_DATA_ROD_v0 dataRod;
                ULONG rodSize = sizeof(dataRod);
                DWORD res = GetPerTcpConnectionEStats(&mibRow, TcpConnectionEstatsData, NULL, 0, 0, NULL, 0, 0, (unsigned char*)&dataRod, 0, rodSize);
                if (res == NO_ERROR) {
                    conn.sentStr = FormatBytes(dataRod.DataBytesOut);
                    conn.recvStr = FormatBytes(dataRod.DataBytesIn);
                    conn.sentBytesVal = dataRod.DataBytesOut;
                    conn.recvBytesVal = dataRod.DataBytesIn;
                    conn.totalBytes = dataRod.DataBytesOut + dataRod.DataBytesIn;
                    processTraffic[conn.procName] += conn.totalBytes;
                }
            }
            conn.fwStatus = QueryFirewallCache(conn.localPort, conn.proto);
            connections.push_back(conn);
        }
    }

    // 2. Fetch UDP
    ULONG udpSize = 0;
    DWORD dwUdpRetVal = GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<char> udpBuffer;
    PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;

    if (dwUdpRetVal == ERROR_INSUFFICIENT_BUFFER) {
        udpBuffer.resize(udpSize);
        pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udpBuffer.data());
        dwUdpRetVal = GetExtendedUdpTable(pUdpTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    }

    if (dwUdpRetVal == NO_ERROR && pUdpTable != nullptr) {
        udpCount = pUdpTable->dwNumEntries;
        for (DWORD i = 0; i < pUdpTable->dwNumEntries; ++i) {
            const auto& row = pUdpTable->table[i];
            
            ConnectionRow conn;
            conn.proto = "UDP";
            conn.localPort = ntohs((u_short)row.dwLocalPort);
            conn.remoteAddr = "*:*";
            conn.state = "-";
            conn.pid = row.dwOwningPid;
            conn.procName = GetProcessName(conn.pid);
            conn.sentStr = "-";
            conn.recvStr = "-";
            conn.sentBytesVal = 0;
            conn.recvBytesVal = 0;
            conn.totalBytes = 0;
            conn.fwStatus = QueryFirewallCache(conn.localPort, conn.proto);
            connections.push_back(conn);
        }
    }

    // Sort connections: first by PROTO (TCP before UDP), then by PORT
    std::sort(connections.begin(), connections.end(), [](const ConnectionRow& a, const ConnectionRow& b) {
        if (a.proto != b.proto) {
            return a.proto == "TCP";
        }
        return a.localPort < b.localPort;
    });
}


struct ProcessSummaryRow {
    std::string procName;
    int portsCount;
    int connsCount;
    ULONG64 sentBytes;
    ULONG64 recvBytes;
    std::string sentStr;
    std::string recvStr;
};

void BuildProcessSummaries(const std::vector<ConnectionRow>& connections, std::vector<ProcessSummaryRow>& summaries) {
    summaries.clear();
    std::unordered_map<std::string, std::vector<size_t>> groups;
    for (size_t i = 0; i < connections.size(); ++i) {
        std::string name = connections[i].procName;
        if (name.empty() || name == "-") {
            name = "Unknown";
        }
        groups[name].push_back(i);
    }

    // Add idle processes from firewall rules
    std::vector<FirewallRuleRow> rules;
    {
        std::lock_guard<std::mutex> lock(g_fwMutex);
        rules = g_fwRulesList;
    }

    // Map process name to its custom rules
    std::unordered_map<std::string, std::vector<FirewallRuleRow>> idleProcRules;
    for (const auto& rule : rules) {
        if (!rule.procName.empty() && rule.procName != "-") {
            std::string name = rule.procName;
            if (groups.find(name) == groups.end()) {
                idleProcRules[name].push_back(rule);
            }
        }
    }

    // First process active groups
    for (const auto& pair : groups) {
        const std::string& name = pair.first;
        ProcessSummaryRow row;
        row.procName = name;
        row.sentBytes = 0;
        row.recvBytes = 0;
        row.connsCount = 0;

        std::unordered_set<u_short> uniquePorts;
        for (size_t idx : pair.second) {
            const auto& conn = connections[idx];
            uniquePorts.insert(conn.localPort);
            row.connsCount++;
            row.sentBytes += conn.sentBytesVal;
            row.recvBytes += conn.recvBytesVal;
        }

        row.portsCount = static_cast<int>(uniquePorts.size());
        row.sentStr = (row.sentBytes > 0) ? FormatBytes(row.sentBytes) : "-";
        row.recvStr = (row.recvBytes > 0) ? FormatBytes(row.recvBytes) : "-";
        summaries.push_back(row);
    }

    // Now process idle firewall-only groups
    for (const auto& pair : idleProcRules) {
        const std::string& name = pair.first;
        ProcessSummaryRow row;
        row.procName = name;
        row.sentBytes = 0;
        row.recvBytes = 0;
        row.connsCount = 0;

        std::unordered_set<u_short> uniquePorts;
        for (const auto& r : pair.second) {
            if (r.port > 0) {
                uniquePorts.insert(r.port);
            }
        }

        row.portsCount = static_cast<int>(uniquePorts.size());
        row.sentStr = "-";
        row.recvStr = "-";
        if (row.portsCount > 0 || row.connsCount > 0) {
            summaries.push_back(row);
        }
    }

    std::sort(summaries.begin(), summaries.end(), [](const ProcessSummaryRow& a, const ProcessSummaryRow& b) {
        ULONG64 aTotal = a.sentBytes + a.recvBytes;
        ULONG64 bTotal = b.sentBytes + b.recvBytes;
        if (aTotal != bTotal) {
            return aTotal > bTotal;
        }
        if (a.connsCount != b.connsCount) {
            return a.connsCount > b.connsCount;
        }
        if (a.portsCount != b.portsCount) {
            return a.portsCount > b.portsCount;
        }
        return a.procName < b.procName;
    });
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
        std::cout << " | Top talker: " << topTalker << " (" << FormatBytes(maxTraffic) << ")";
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
                if (a.state != b.state) {
                    return a.state != "IDLE";
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
                sprintf(headerBuf, "portview v1.1 [ELEVATED] | Arrows: Nav | Enter: View | A: Add Rule | Esc: Quit");
            } else {
                sprintf(headerBuf, "portview v1.1 [NON-ELEVATED] (Run as Admin for Traffic) | Arrows: Nav | Enter: View | A: Add Rule | Esc: Quit");
            }
        } else {
            std::string pidStr = (selectedPid == 0) ? "IDLE" : "PID " + std::to_string(selectedPid);
            if (IsElevated()) {
                sprintf(headerBuf, "Process: %s (%s) [ELEVATED] | A: Add Rule | Esc: Back", selectedProcName.c_str(), pidStr.c_str());
            } else {
                sprintf(headerBuf, "Process: %s (%s) [NON-ELEVATED] | A: Add Rule | Esc: Back", selectedProcName.c_str(), pidStr.c_str());
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
                    summaryStr += " | Top talker: " + topTalker + " (" + FormatBytes(maxTraffic) + ")";
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


int main(int argc, char* argv[]) {
    bool staticMode = false;

    // Simple Argument Parsing
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            std::cout << "portview v1.1 — Windows Port & Traffic Reviewer\n\n"
                      << "Usage: portview.exe [options]\n\n"
                      << "Options:\n"
                      << "  -h, --help     Show this help message\n"
                      << "  -v, --version  Show version information\n"
                      << "  -s, --static   Print a single snapshot and exit (non-interactive)\n\n"
                      << "Note: Run as administrator to see per-connection traffic stats.\n";
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "portview v1.1\n";
            return 0;
        } else if (arg == "-s" || arg == "--static") {
            staticMode = true;
        }
    }

    // If output is redirected to a file or pipe, default to static mode
    if (!IsStdoutTerminal()) {
        staticMode = true;
    }

    HRESULT hrCom = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    // Initialize Winsock (required for IpToString and network operations)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock.\n";
        return 1;
    }

    if (!staticMode) {
        EnableVirtualTerminalProcessing();
    }

    if (staticMode) {
        PrintStaticOutput();
        PauseIfSpawnedConsole();
    } else {
        RunInteractiveLoop();
        PauseIfSpawnedConsole();
    }

    if (SUCCEEDED(hrCom)) {
        CoUninitialize();
    }

    WSACleanup();
    return 0;
}
