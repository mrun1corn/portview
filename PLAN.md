# portview — Project Plan

## Overview

`portview` is a Windows CLI tool that lists all open TCP/UDP ports, maps them to their owning process, and displays per-connection traffic statistics (bytes sent/received). Single binary, zero external dependencies — built entirely on the Windows SDK.

## Goals

- Show all active TCP connections and UDP listeners
- Map each port to its owning process (PID + name)
- Display per-connection traffic stats (bytes in/out) when running elevated
- Clean, human-readable tabular output (interactive TUI)
- Modular architecture, zero third-party dependencies (Windows API only)
- Real-time continuous monitoring (speed and traffic)
- Firewall rule management integration

## Architecture

```
portview.exe
├── network_tables.cpp  → GetExtendedTcpTable(), GetExtendedUdpTable()
├── traffic_stats.cpp   → SetPerTcpConnectionEStats(), GetPerTcpConnectionEStats()
├── process_resolver.cpp→ OpenProcess(), QueryFullProcessImageNameW()
├── firewall_manager.cpp→ INetFwPolicy2 / COM APIs
├── ui_renderer.cpp     → Windows Console ANSI escape sequences
└── main.cpp            → Application entry point & coordination
```

## Windows APIs

| Purpose | API | Header |
|---|---|---|
| TCP connections + PID | `GetExtendedTcpTable` | `iphlpapi.h` |
| UDP listeners + PID | `GetExtendedUdpTable` | `iphlpapi.h` |
| Enable traffic collection | `SetPerTcpConnectionEStats` | `iphlpapi.h` |
| Read traffic stats | `GetPerTcpConnectionEStats` | `iphlpapi.h` |
| Process name from PID | `OpenProcess` + `QueryFullProcessImageNameW` | `windows.h` |

### Important: Traffic Stats Collection

`GetPerTcpConnectionEStats` returns **zeroed values** by default. Stats collection must be explicitly enabled per-connection by calling `SetPerTcpConnectionEStats` with `TcpBoolOptEnabled` first. The tool will:

1. Enumerate all TCP connections
2. Call `SetPerTcpConnectionEStats` to enable collection on each connection
3. Wait briefly (or on re-run) to accumulate data
4. Call `GetPerTcpConnectionEStats` to read bytes sent/received

This requires **administrator privileges**.

## Output Format

```
portview v1.0 — Windows Port & Traffic Reviewer

TCP Connections (14 active)
PORT    REMOTE               STATE         PID    PROCESS            SENT        RECV
 443    142.250.80.46:443    ESTABLISHED   8124   chrome.exe         12.4 KB     156.2 KB
 5432   127.0.0.1:5432       ESTABLISHED   3200   postgres.exe       1.1 MB      3.4 MB
 8080   0.0.0.0:*            LISTENING     9012   node.exe           —           —
 ...

UDP Listeners (6 active)
PORT    PID    PROCESS
 53     1124   svchost.exe
 5353   8124   chrome.exe
 ...

Summary: 14 TCP | 6 UDP | Top talker: chrome.exe (168.6 KB)
```

## Build System

- Standard: C++17

## Project Structure

```
portview/
├── CMakeLists.txt
├── README.md
├── PLAN.md
├── TODO.md
├── LICENSE
├── portview.ico
├── resource.rc
├── include/
│   ├── data_models.h
│   ├── firewall.h
│   ├── network_tables.h
│   ├── process_resolver.h
│   ├── ui_renderer.h
│   └── utils.h
└── src/
    ├── firewall.cpp
    ├── main.cpp
    ├── network_tables.cpp
    ├── process_resolver.cpp
    ├── ui_renderer.cpp
    └── utils.cpp
```

## Scope

### In Scope

- List all TCP connections with state (LISTENING, ESTABLISHED, TIME_WAIT, etc.)
- List all UDP listeners
- Per-TCP-connection bytes sent/received and speed (elevated only)
- Process name + PID resolution
- Interactive Text UI (TUI) with real-time updates and arrow-key navigation
- Firewall rule management (view and toggle rules for selected ports/processes)
- Human-readable byte formatting (B, KB, MB, GB)
- Summary line with top talker
- Graceful degradation without elevation (ports + process, no traffic stats)

### Out of Scope

- Packet capture / deep packet inspection
- Cross-platform support
- Service / daemon mode

## Constraints

- `SetPerTcpConnectionEStats` / `GetPerTcpConnectionEStats` require **administrator/elevated** privileges
- Firewall COM APIs also require elevation.
- Without elevation: tool shows ports, state, PID, process name — just no byte counters or firewall toggles.

## Milestones

1. **Skeleton** — CMake project, compiles and prints version
2. **TCP table** — enumerate and display TCP connections with state
3. **UDP table** — enumerate and display UDP listeners
4. **Process resolution** — map PID to process name
5. **Traffic stats** — enable collection + read bytes via EStats API
6. **Polish** — formatting, summary, error handling, README
