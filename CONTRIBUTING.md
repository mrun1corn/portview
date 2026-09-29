# Contributing to PortView

Thank you for your interest in contributing to **PortView**! We welcome community contributions, bug reports, and feature proposals.

---

## Code of Conduct

Please maintain a friendly, professional, and respectful environment for everyone.

---

## Development Setup

### Prerequisites
- Windows 10 or 11
- CMake 3.15 or newer
- Visual Studio 2019/2022 (MSVC with C++17 support)
- Git for Windows

### Building from Source

```powershell
# Clone the repository
git clone https://github.com/mrun1corn/portview.git
cd portview

# Configure and compile
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Test binary
.\build\Release\portview.exe --version
.\build\Release\portview.exe --static
```

---

## Design Principles

1. **Zero External Dependencies**: All network, process, security, and UI code must rely strictly on standard Windows SDK APIs (`iphlpapi`, `ws2_32`, `ole32`, `psapi`). Do not introduce third-party libraries.
2. **Modular Monolith**: Code is cleanly separated into decoupled domains:
   - `core/`: Data models, system metrics, and utility helpers.
   - `network/`: TCP/UDP socket enumeration, traffic measurement, and DNS resolution.
   - `security/`: COM-based Windows Firewall (`NetFwPolicy2`) management.
   - `ui/`: Terminal screen rendering, interactive controls, and modal components.
3. **Context & Resource Hygiene**: Avoid high-frequency polling; cache and smooth volatile metrics like CPU/RAM.

---

## Submitting Pull Requests

1. Fork the repository and create your feature branch: `git checkout -b feat/my-new-feature`.
2. Follow conventional commit messages: `feat(...)`, `fix(...)`, `refactor(...)`, `docs(...)`.
3. Verify that the Release build compiles with **0 warnings and 0 errors**.
4. Test both the interactive UI (`.\portview.exe`) and static snapshot mode (`.\portview.exe --static`).
5. Open a Pull Request referencing any related issues.
