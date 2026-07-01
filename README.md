# portview

A Windows CLI tool that lists all open TCP/UDP ports, maps them to their owning process, and shows per-connection traffic stats.

![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/Language-C++17-00599C?style=flat-square&logo=cplusplus)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)

## Features

- 📋 Lists all active **TCP connections** with state (LISTENING, ESTABLISHED, TIME_WAIT, etc.)
- 📋 Lists all **UDP listeners**
- 🔍 Maps each port to its **owning process** (PID + executable name)
- 📊 Shows **per-connection traffic stats** — bytes sent and received (requires elevation)
- 📈 **Summary** with connection counts and top talker
- ⚡ Single binary, **zero external dependencies** — built on Windows SDK only

## Example Output

```
portview v1.0 — Windows Port & Traffic Reviewer

TCP Connections (14 active)
PORT    REMOTE               STATE         PID    PROCESS            SENT        RECV
 443    142.250.80.46:443    ESTABLISHED   8124   chrome.exe         12.4 KB     156.2 KB
 5432   127.0.0.1:5432       ESTABLISHED   3200   postgres.exe       1.1 MB      3.4 MB
 8080   0.0.0.0:*            LISTENING     9012   node.exe           —           —

UDP Listeners (6 active)
PORT    PID    PROCESS
 53     1124   svchost.exe
 5353   8124   chrome.exe

Summary: 14 TCP | 6 UDP | Top talker: chrome.exe (168.6 KB)
```

## Build

### Requirements

- Windows 10/11
- CMake 3.15+
- MSVC (Visual Studio 2019+) or MinGW-w64

### Steps

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

The output binary is `build/Release/portview.exe`.

## Usage

```bash
# Basic — launches interactive UI with real-time refresh and scroll
portview.exe

# Static snapshot — outputs a single table capture (non-interactive)
portview.exe --static

# With traffic stats — run as administrator
# Right-click terminal → "Run as administrator"
portview.exe
```

### Interactive Controls

- **Arrow Up/Down**: Scroll the list line-by-line
- **Page Up/Down**: Scroll the list page-by-page
- **Home/End**: Jump to the top/bottom of the list
- **Esc/Q**: Exit the application

> **Note:** Traffic statistics (bytes sent/received) require administrator privileges. Without elevation, the tool still shows all ports, states, and process names but with byte counters empty (`—`).
## How It Works

1. Calls `GetExtendedTcpTable` / `GetExtendedUdpTable` to enumerate all connections
2. Resolves each PID to a process name via `QueryFullProcessImageNameW`
3. If elevated, enables per-connection stats collection with `SetPerTcpConnectionEStats`
4. Reads traffic data via `GetPerTcpConnectionEStats`
5. Formats and prints the table

All APIs are from the Windows SDK (`iphlpapi.h`, `ws2_32.h`) — no third-party libraries.

## Project Structure

```
portview/
├── CMakeLists.txt     # Build configuration
├── main.cpp           # All source code
├── README.md          # This file
├── PLAN.md            # Project plan and architecture
├── TODO.md            # Development checklist
└── LICENSE            # MIT License
```

## License

MIT
