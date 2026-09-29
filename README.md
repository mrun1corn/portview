# portview

A modern, zero-dependency Windows terminal dashboard and port inspector that lists open TCP/UDP ports, aggregates connections by process, monitors real-time CPU/RAM resource usage, tracks live per-connection traffic, and provides native Windows Firewall controls.

[![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows)](https://github.com/mrun1corn/portview)
[![Language](https://img.shields.io/badge/Language-C++17-00599C?style=flat-square&logo=cplusplus)](https://github.com/mrun1corn/portview)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)](https://github.com/mrun1corn/portview)
[![Latest Release](https://img.shields.io/github/v/release/mrun1corn/portview?style=flat-square&logo=github)](https://github.com/mrun1corn/portview/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/mrun1corn/portview/total?style=flat-square&logo=github)](https://github.com/mrun1corn/portview/releases)
[![Build & Release](https://img.shields.io/github/actions/workflow/status/mrun1corn/portview/release.yml?style=flat-square&logo=githubactions&label=build)](https://github.com/mrun1corn/portview/actions/workflows/release.yml)

---

## Features

- 🔍 **Default Live Search & Filter**: Starts in type-to-filter mode instantly. Type any substring to filter by process name, PID, port, or connection state in real time.
- 📊 **Dynamic Column Sorting**: Click column headers or press <kbd>F3</kbd>/<kbd>F5</kbd> to sort ascending/descending by Process Name, CPU%, RAM, Ports, Conns, or Bandwidth.
- 🖱️ **Full Native Mouse Support**: Mouse wheel scrolling, row clicking, double-click drill-down/toggle, and right-click context menu.
- 📈 **Live CPU & RAM Monitoring**: Per-process working set RAM and CPU% delta tracking, stabilized with Exponential Moving Average (EMA) to prevent number jitter.
- 🛡️ **Built-in Windows Firewall Manager**: Real-time rule lookup via COM `NetFwPolicy2`, interactive rule creation modal (ports, ranges like `8000-8080`, comma lists), and one-key rule toggling (<kbd>F4</kbd>).
- 📋 **Process Overview & Deep Drill-Down**: Toggle between high-level aggregated process view and individual socket endpoint inspections.
- 📊 **Per-Connection Bandwidth Stats**: Live tracking of sent/received byte rates and top talkers via Windows Extended TCP/UDP stats.
- 🔪 **Process Management & Clipboard**: Terminate rogue processes (<kbd>Del</kbd> / <kbd>F8</kbd>) and copy process details to clipboard (<kbd>Ctrl+C</kbd>).
- 🚀 **Zero-Flicker Double Buffering**: Off-screen frame rendering guarantees smooth 60fps-like terminal refreshes without console flicker.
- ⚡ **Zero External Dependencies**: Built 100% on standard Windows SDK APIs (`iphlpapi`, `ws2_32`, `ole32`, `psapi`).

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

## Build

### Requirements
- Windows 10 or 11
- CMake 3.15+
- MSVC (Visual Studio 2019+ or Build Tools)

### Compilation Steps

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

The resulting standalone executable is generated at `build/Release/portview.exe`.

---

## Usage

```powershell
# Interactive dashboard (Run terminal as Administrator for full traffic stats & firewall management)
.\portview.exe

# Static snapshot capture (scriptable / pipe-friendly)
.\portview.exe --static

# Display version
.\portview.exe --version

# Show help
.\portview.exe --help
```

---

## Modular Monolith Architecture

The codebase is organized as a clean **Modular Monolith** with decoupled domain subsystems:

```text
portview/
├── CMakeLists.txt                # Root CMake configuration
├── include/                      # Public domain headers
│   ├── core/                     # Core data models, metrics & utility routines
│   │   ├── data_models.h         # ConnectionRow, ProcessSummaryRow, FirewallRuleRow
│   │   ├── system_metrics.h      # Host & process CPU/RAM engine with EMA smoothing
│   │   └── utils.h               # String formatting, elevation checks, clipboard helper
│   ├── network/                  # Network capture & protocol domain
│   │   ├── network_scanner.h     # TCP/UDP enumeration, traffic aggregation & DNS
│   │   └── process_resolver.h    # PID-to-process name and image path resolution
│   ├── security/                 # Firewall & COM security domain
│   │   └── firewall_manager.h    # Windows NetFwPolicy2 COM manager & port range parser
│   └── ui/                       # Terminal rendering & controller subsystem
│       ├── terminal_screen.h     # Double-buffered VT console engine & mouse mode
│       ├── search_filter.h       # Live type-to-filter engine
│       ├── components.h          # Banner, column headers, modals & status bar
│       └── app_controller.h      # Interactive event loop & static runner
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
└── .github/workflows/
    ├── release.yml               # Automated multi-release packaging & changelogs
    └── telemetry.yml             # Download telemetry tracking & asset verification CI
```

---

## Telemetry & CI

- **Release CI** (`release.yml`): Automatically compiles Release binaries on `v*` tags, generates change logs from git commits, and publishes binaries to GitHub Releases.
- **Download Telemetry CI** (`telemetry.yml`): Runs daily and on manual triggers to query the GitHub API, track release asset download counters, generate rich GitHub Step Summary reports, verify asset download availability, and preserve historical JSON telemetry data.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
