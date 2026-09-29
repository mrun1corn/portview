# portview

> **A modern, interactive TUI network inspector and lightweight `netstat` / `TCPView` alternative for Windows.**  
> Monitor open TCP/UDP ports, aggregate connections by process, track real-time CPU/RAM resource usage, measure live per-socket bandwidth, and manage Windows Firewall rules directly from your terminal with zero external dependencies.

[![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)](https://github.com/mrun1corn/portview)
[![Language](https://img.shields.io/badge/Language-C++17-00599C?style=flat-square&logo=cplusplus)](https://github.com/mrun1corn/portview)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)](https://github.com/mrun1corn/portview)
[![Latest Release](https://img.shields.io/github/v/release/mrun1corn/portview?style=flat-square&logo=github)](https://github.com/mrun1corn/portview/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/mrun1corn/portview/total?style=flat-square&logo=github)](https://github.com/mrun1corn/portview/releases)
[![Build & Release](https://img.shields.io/github/actions/workflow/status/mrun1corn/portview/release.yml?style=flat-square&logo=githubactions&label=release)](https://github.com/mrun1corn/portview/actions/workflows/release.yml)
[![CI Tests](https://img.shields.io/github/actions/workflow/status/mrun1corn/portview/ci.yml?style=flat-square&logo=githubactions&label=tests)](https://github.com/mrun1corn/portview/actions/workflows/ci.yml)

---

## Quick Install

Download and run the latest standalone executable with a single PowerShell command:

```powershell
Invoke-WebRequest -Uri "https://github.com/mrun1corn/portview/releases/latest/download/portview.exe" -OutFile "portview.exe"; .\portview.exe
```

> **ProTip:** Run your terminal as **Administrator** to enable per-connection bandwidth telemetry (`SENT` / `RECV`) and Windows Firewall rule creation. Without administrator rights, PortView functions gracefully for all port enumeration, live searching, and process inspection.

---

## Why PortView? (Comparison Matrix)

| Feature | `portview` | `netstat -ano` | Sysinternals `TCPView` | Resource Monitor (`resmon`) |
| :--- | :---: | :---: | :---: | :---: |
| **Interface** | **Interactive TUI** | Static Plaintext Dump | Legacy GUI Window | Heavy GUI Dashboard |
| **Live Type-to-Filter** | ✅ Instant | ❌ Pipes / Grep only | ⚠️ Basic text box | ⚠️ Checkboxes |
| **Dynamic Column Sorting** | ✅ Click & F3/F5 | ❌ None | ✅ Clickable headers | ⚠️ Limited |
| **Native Mouse Support** | ✅ Clicks & Wheel | ❌ None | ✅ Yes | ✅ Yes |
| **External Dependencies** | ✅ **Zero** | ✅ Zero | ⚠️ Requires Sysinternals | ✅ Built-in |
| **Process CPU% & RAM** | ✅ Live with EMA | ❌ No | ❌ No | ✅ Yes |
| **Firewall Rule Creator** | ✅ Built-in Modal | ❌ No | ❌ No | ❌ No |
| **Firewall Rule Toggler** | ✅ One-key (<kbd>F4</kbd>) | ❌ No | ❌ No | ❌ No |
| **Kill Process on Port** | ✅ Built-in (<kbd>Del</kbd>) | ❌ Requires `taskkill` | ✅ Process menu | ✅ Context menu |
| **Zero-Flicker Double Buffer** | ✅ 60fps-like | ❌ Screen clearing | ⚠️ Periodic blink | N/A |
| **Scriptable Snapshot Mode** | ✅ `--static` | ✅ Output dump | ❌ GUI only | ❌ GUI only |

---

## Features

- 🔍 **Default Live Search & Filter**: Starts in type-to-filter mode instantly. Type any substring to filter by process name, PID, port, or connection state in real time.
- 📊 **Dynamic Column Sorting**: Click column headers or press <kbd>F3</kbd>/<kbd>F5</kbd> to sort ascending/descending by Process Name, CPU%, RAM, Ports, Conns, or Bandwidth.
- 🖱️ **Full Native Mouse Support**: Mouse wheel scrolling, row clicking, double-click drill-down/toggle, and right-click context menu.
- 📈 **Live CPU & RAM Monitoring**: Per-process working set RAM and CPU% delta tracking, stabilized with Exponential Moving Average (EMA) to prevent number jitter.
- 🛡️ **Built-in Windows Firewall Manager**: Real-time rule lookup via COM `NetFwPolicy2`, interactive rule creation modal with port validation (1–65535, bounded ranges, DOS allocation guards), and one-key rule toggling (<kbd>F4</kbd>).
- 🔒 **Hardened & Memory-Safe Architecture**: Bounded caches, active connection/PID pruning (zero slow memory leak), thread-safe asynchronous updates with clean shutdown joins, and RAII console mode & cursor restoration.
- 📋 **Process Overview & Deep Drill-Down**: Toggle between high-level aggregated process view and individual socket endpoint inspections.
- 📊 **Per-Connection Bandwidth Stats**: Live tracking of sent/received byte rates and top talkers via Windows Extended TCP/UDP stats.
- 🔪 **Process Management & Clipboard**: Terminate rogue processes (<kbd>Del</kbd> / <kbd>F8</kbd>) and copy process details to clipboard (<kbd>Ctrl+C</kbd>).
- 🚀 **Zero-Flicker Double Buffering**: Off-screen frame rendering guarantees smooth 60fps-like terminal refreshes without console flicker.
- ⚡ **Zero External Dependencies**: Built 100% on standard Windows SDK APIs (`iphlpapi`, `ws2_32`, `ole32`, `psapi`) with static CRT runtime (`/MT`).

---

## Example Output

```text
========================================================================================
portview v1.5 [ELEVATED] | CPU: 2.1% | RAM: 6.8 GB / 7.7 GB (87%) | F3: Sort | Esc: Quit
========================================================================================
[/] Filter: chrome                                                        (1/39 processes)
   PROCESS                  CPU%    RAM        PORTS   CONNS   SENT v       RECV        
 > chrome.exe               1.2%    232.6 MB   7       14      12.4 KB/s    156.2 KB/s  
   python.exe               0.0%    18.5 MB    6       6       -            -           
   Code.exe                 0.4%    435.1 MB   5       5       -            -           
----------------------------------------------------------------------------------------
Summary: 30 TCP | 8 UDP | Allowed FW Ports: 12 | Top talker: chrome.exe (168.6 KB/s)
```

---

## Controls

### Mouse Controls
| Action | Gesture | Description |
| :--- | :--- | :--- |
| **Select Row** | Left Click | Highlights and selects the clicked process or connection row |
| **Drill-down / Toggle** | Double Click | Opens process detail view (Summary) or toggles Firewall rule (Detail) |
| **Sort Column** | Left Click on Header (Row 2) | Sorts by clicked column; second click toggles ascending/descending |
| **Add Rule Modal** | Right Click on Row | Opens interactive firewall rule creation modal populated with target info |
| **Scroll View** | Mouse Wheel | Smooth 3-row scrolling through the viewport |
| **Clear Filter** | Left Click on `[Clear]` | Clears active filter query |

### Keyboard Controls
| Key | Function |
| :--- | :--- |
| **Typing** | Live search / filter (alphanumeric, dots, dashes) |
| <kbd>Backspace</kbd> | Deletes last filter character; if empty, navigates back to Summary view |
| <kbd>Esc</kbd> | Clears filter / exits modal / quits application |
| <kbd>Enter</kbd> | Drill down into selected process socket details |
| <kbd>F3</kbd> | Cycle sort column (`SENT/RECV` $\rightarrow$ `CPU%` $\rightarrow$ `RAM` $\rightarrow$ `PORTS` $\rightarrow$ `CONNS` $\rightarrow$ `PROCESS`) |
| <kbd>F5</kbd> | Toggle sort direction (Ascending `^` / Descending `v`) |
| <kbd>F2</kbd> / <kbd>Tab</kbd> | Open Add Firewall Rule modal / toggle protocol |
| <kbd>F4</kbd> | Toggle active firewall rule between Allowed and Blocked |
| <kbd>Del</kbd> / <kbd>F8</kbd> | Terminate selected process (with safety confirmation) |
| <kbd>Ctrl+C</kbd> | Copy selected process name and PID to system clipboard |
| <kbd>↑</kbd> / <kbd>↓</kbd> | Move selection up / down |
| <kbd>PgUp</kbd> / <kbd>PgDn</kbd> | Move selection up / down one page |
| <kbd>Home</kbd> / <kbd>End</kbd> | Jump to top / bottom of list |

---

## Frequently Asked Questions (FAQ)

<details>
<summary><b>How do I find which process is listening on port 8080 or 3000?</b></summary>

Launch `portview.exe`, type `8080` (or `3000`), and PortView will immediately filter down to the exact process, PID, and connection state. Press <kbd>Enter</kbd> or double-click to inspect socket details.
</details>

<details>
<summary><b>How do I kill a process locking a port without opening Task Manager?</b></summary>

Highlight the process row in PortView and press <kbd>Del</kbd> or <kbd>F8</kbd>. A safety confirmation dialog will appear. Press <kbd>Y</kbd> or click **Confirm** to terminate the process instantly.
</details>

<details>
<summary><b>How do I open or block a port in Windows Firewall?</b></summary>

Right-click on any process row or press <kbd>F2</kbd>. PortView opens an in-terminal modal prefilled with the process name and application path. Specify the ports (e.g., `8080`, `3000-3010`, or `80,443`), toggle Allow/Block, and press <kbd>Enter</kbd> to commit directly to Windows Firewall via COM.
</details>

<details>
<summary><b>Why does bandwidth telemetry require Administrator elevation?</b></summary>

Windows requires elevated privileges to query the Extended TCP/UDP statistics (`SetPerTcpConnectionEStats` / `GetPerTcpConnectionEStats`) and to modify Windows Firewall policies. Without elevation, PortView still provides complete port mapping, process resolution, and live search.
</details>

---

## Build from Source

### Requirements
- Windows 10 or 11
- CMake 3.15+
- MSVC (Visual Studio 2019+ or C++ Build Tools)

### Compilation Steps

```powershell
git clone https://github.com/mrun1corn/portview.git
cd portview
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The resulting standalone executable is generated at `build/Release/portview.exe` with static MSVC runtime (`/MT`), requiring no external DLLs or VC Redistributables.

### Running Automated Tests

Run the built-in test suite via CTest:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

---

## Modular Monolith Architecture

The codebase is organized as a clean **Modular Monolith** with decoupled domain subsystems:

```text
portview/
├── CMakeLists.txt                # Root CMake configuration (/W4 /WX /sdl /MT)
├── include/                      # Public domain headers
│   ├── core/                     # Core data models, metrics & utility routines
│   │   ├── data_models.h         # ConnectionRow, ProcessSummaryRow, FirewallRuleRow
│   │   ├── system_metrics.h      # Host & process CPU/RAM engine with EMA smoothing & dead PID pruning
│   │   └── utils.h               # String formatting, UTF-8/UTF-16 conversion, elevation checks
│   ├── network/                  # Network capture & protocol domain
│   │   ├── network_scanner.h     # TCP/UDP enumeration, traffic aggregation & bounded DNS cache
│   │   └── process_resolver.h    # PID-to-process name and image path resolution
│   ├── security/                 # Firewall & COM security domain
│   │   └── firewall_manager.h    # Windows NetFwPolicy2 COM manager, port validator & async thread pool
│   └── ui/                       # Terminal rendering & controller subsystem
│       ├── terminal_screen.h     # Double-buffered VT console engine & mouse mode
│       ├── search_filter.h       # Live type-to-filter engine
│       ├── components.h          # Banner, column headers, modals & status bar
│       └── app_controller.h      # Interactive event loop, RAII console guard & static runner
├── src/                          # Modular implementations
│   ├── core/
│   │   ├── system_metrics.cpp
│   │   └── utils.cpp
│   ├── network/
│   │   ├── network_scanner.cpp
│   │   └── process_resolver.cpp
│   ├── security/
│   │   └── firewall_manager.cpp
│   ├── ui/
│   │   ├── app_controller.cpp
│   │   ├── components.cpp
│   │   ├── search_filter.cpp
│   │   └── terminal_screen.cpp
│   └── main.cpp                  # CLI entrypoint & RAII guard initialization
├── tests/
│   └── test_main.cpp             # Automated unit tests for port validation and string utils
└── .github/
    ├── workflows/
    │   ├── ci.yml                # Automated MSVC /W4 /WX build, CTest & CLI smoke tests
    │   └── release.yml           # Automated multi-release packaging & changelogs (pinned SHAs)
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.yml        # Structured bug report form
    │   ├── feature_request.yml   # Feature proposal form
    │   └── config.yml            # Community discussion links
    └── pull_request_template.md  # Standardized PR checklist
```

---

## Contributing

Contributions, bug reports, and suggestions are welcome! Please check out [CONTRIBUTING.md](CONTRIBUTING.md) to get started and read our [SECURITY.md](SECURITY.md) policy.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
