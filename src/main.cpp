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
#include "utils.h"
#include "process_resolver.h"
#include "data_models.h"
#include "network_tables.h"
#include "ui_renderer.h"
#include "firewall.h"

// Link with iphlpapi.lib and ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Convert TCP connection state to string








































int main(int argc, char* argv[]) {
    bool staticMode = false;

    // Simple Argument Parsing
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-h" || arg == "--help") {
            std::cout << "portview v1.4 — Windows Port & Traffic Reviewer\n\n"
                      << "Usage: portview.exe [options]\n\n"
                      << "Options:\n"
                      << "  -h, --help     Show this help message\n"
                      << "  -v, --version  Show version information\n"
                      << "  -s, --static   Print a single snapshot and exit (non-interactive)\n\n"
                      << "Note: Run as administrator to see per-connection traffic stats.\n";
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "portview v1.4\n";
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
