# portview — TODO

## Milestone 1: Skeleton
- [x] Create CMakeLists.txt with iphlpapi, ws2_32 linking
- [x] Create main.cpp with version banner and arg parsing
- [x] Verify it compiles and runs on Windows

## Milestone 2: TCP Table
- [x] Enumerate TCP connections using `GetExtendedTcpTable`
- [x] Parse `MIB_TCPROW_OWNER_PID` entries
- [x] Display local port, remote address:port, and TCP state
- [x] Format TCP states (LISTENING, ESTABLISHED, TIME_WAIT, etc.)

## Milestone 3: UDP Table
- [x] Enumerate UDP listeners using `GetExtendedUdpTable`
- [x] Parse `MIB_UDPROW_OWNER_PID` entries
- [x] Display local port

## Milestone 4: Process Resolution
- [x] Map PID to process name via `OpenProcess` + `QueryFullProcessImageNameW`
- [x] Handle access-denied gracefully (show PID only)
- [x] Extract basename from full image path
- [x] Cache PID lookups with thread-safe synchronization to avoid repeated calls

## Milestone 5: Traffic Stats
- [x] Detect if running elevated (`IsElevated()`)
- [x] Call `SetPerTcpConnectionEStats` to enable collection per connection
- [x] Call `GetPerTcpConnectionEStats` to read `DataBytesIn` / `DataBytesOut`
- [x] Format bytes human-readable (B, KB, MB, GB) and calculate throughput (B/s, KB/s)
- [x] Graceful fallback when not elevated (show "—" for stats)

## Milestone 6: Polish & Architecture Refactoring
- [x] Add summary line (total TCP/UDP, top talker, active firewall rules)
- [x] Column alignment, safe bounds formatting, and clean VT100 formatting
- [x] Error handling for all API calls and COM operations
- [x] Add MIT LICENSE file
- [x] Modularize into encapsulated domain services (`FirewallManager`, `NetworkTableScanner`, `ProcessResolver`, `Terminal`)
- [x] Implement RAII guards (`ScopedCom`, `ScopedWinsock`) eliminating resource leaks
- [x] Remove global mutable state from public headers and enforce bounded asynchronous DNS lookups
- [x] Enable flexible execution via `asInvoker` with graceful fallback for unprivileged environments

## Milestone 7: Modernized Rule Addition & TUI Modal
- [x] Centered interactive VT100 modal dialog for firewall rule creation
- [x] Smart pre-filling from selected connection details (local port, protocol)
- [x] Interactive protocol toggle (`Tab` for TCP/UDP) and action toggle (`F2` for ALLOW/BLOCK)
- [x] Flexible port string parsing (single port, comma-separated lists, and hyphenated ranges)
- [x] Real-time elevation detection warning when non-elevated
