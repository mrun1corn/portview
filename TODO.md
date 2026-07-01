# portview — TODO

## Milestone 1: Skeleton
- [ ] Create CMakeLists.txt with iphlpapi, ws2_32 linking
- [ ] Create main.cpp with version banner and arg parsing
- [ ] Verify it compiles and runs on Windows

## Milestone 2: TCP Table
- [ ] Enumerate TCP connections using `GetExtendedTcpTable`
- [ ] Parse `MIB_TCPROW_OWNER_PID` entries
- [ ] Display local port, remote address:port, and TCP state
- [ ] Format TCP states (LISTENING, ESTABLISHED, TIME_WAIT, etc.)

## Milestone 3: UDP Table
- [ ] Enumerate UDP listeners using `GetExtendedUdpTable`
- [ ] Parse `MIB_UDPROW_OWNER_PID` entries
- [ ] Display local port

## Milestone 4: Process Resolution
- [ ] Map PID to process name via `OpenProcess` + `QueryFullProcessImageNameW`
- [ ] Handle access-denied gracefully (show PID only)
- [ ] Extract basename from full image path
- [ ] Cache PID lookups to avoid repeated calls

## Milestone 5: Traffic Stats
- [ ] Detect if running elevated
- [ ] Call `SetPerTcpConnectionEStats` to enable collection per connection
- [ ] Call `GetPerTcpConnectionEStats` to read `DataBytesIn` / `DataBytesOut`
- [ ] Format bytes human-readable (B, KB, MB, GB)
- [ ] Graceful fallback when not elevated (show "—" for stats)

## Milestone 6: Polish
- [ ] Add summary line (total TCP/UDP, top talker)
- [ ] Column alignment and clean formatting
- [ ] Error handling for all API calls
- [ ] Add MIT LICENSE file
- [ ] Final README review
