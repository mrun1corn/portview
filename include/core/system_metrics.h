#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include "core/data_models.h"

class SystemMetrics {
public:
    static SystemMetrics& Instance();

    // Query overall host memory and CPU utilization
    SystemHostMetrics QueryHostMetrics();

    // Query CPU% and Working Set RAM in bytes for a specific process PID
    void QueryProcessMetrics(DWORD pid, double& outCpuPercent, ULONG64& outRamBytes);

    // Evict dead PIDs from CPU history
    void PruneDeadPids(const std::unordered_set<DWORD>& activePids);

    // Terminate a process by PID
    static bool KillProcess(DWORD pid, DWORD exitCode = 1);

private:
    SystemMetrics();
    ~SystemMetrics() = default;

    struct ProcessTimeSnapshot {
        FILETIME ftKernel;
        FILETIME ftUser;
        DWORD tickCount = 0;
        double smoothedCpu = 0.0;
        ULONG64 smoothedRam = 0;
        bool hasPrevious = false;
    };

    std::mutex mutex_;
    int numProcessors_ = 1;
    std::unordered_map<DWORD, ProcessTimeSnapshot> pidCpuHistory_;

    // Host CPU tracking
    FILETIME prevIdleTime_{0, 0};
    FILETIME prevKernelTime_{0, 0};
    FILETIME prevUserTime_{0, 0};
    bool hasPreviousHostTimes_ = false;
    double smoothedHostCpu_ = 0.0;
};
