#include "core/system_metrics.h"
#include "core/utils.h"
#include <psapi.h>
#include <algorithm>
#include <cstdio>

namespace {
    ULARGE_INTEGER FileTimeToUlarge(const FILETIME& ft) {
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        return u;
    }
}

SystemMetrics::SystemMetrics() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    numProcessors_ = static_cast<int>(sysInfo.dwNumberOfProcessors);
    if (numProcessors_ < 1) numProcessors_ = 1;
}

SystemMetrics& SystemMetrics::Instance() {
    static SystemMetrics s_instance;
    return s_instance;
}

SystemHostMetrics SystemMetrics::QueryHostMetrics() {
    SystemHostMetrics metrics;

    // RAM stats via GlobalMemoryStatusEx
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        metrics.totalRamBytes = memStatus.ullTotalPhys;
        metrics.usedRamBytes = memStatus.ullTotalPhys - memStatus.ullAvailPhys;
        metrics.ramPercent = static_cast<double>(memStatus.dwMemoryLoad);
        metrics.ramBannerStr = "RAM: " + FormatBytes(metrics.usedRamBytes) + " / " + FormatBytes(metrics.totalRamBytes) + " (" + std::to_string(memStatus.dwMemoryLoad) + "%)";
    } else {
        metrics.ramBannerStr = "RAM: N/A";
    }

    // Host CPU usage via GetSystemTimes
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (hasPreviousHostTimes_) {
            ULONGLONG idleDiff = FileTimeToUlarge(idleTime).QuadPart - FileTimeToUlarge(prevIdleTime_).QuadPart;
            ULONGLONG kernelDiff = FileTimeToUlarge(kernelTime).QuadPart - FileTimeToUlarge(prevKernelTime_).QuadPart;
            ULONGLONG userDiff = FileTimeToUlarge(userTime).QuadPart - FileTimeToUlarge(prevUserTime_).QuadPart;

            ULONGLONG totalSystem = kernelDiff + userDiff;
            if (totalSystem > 0) {
                ULONGLONG activeTime = (totalSystem > idleDiff) ? (totalSystem - idleDiff) : 0;
                metrics.totalCpuPercent = (static_cast<double>(activeTime) * 100.0) / static_cast<double>(totalSystem);
                if (metrics.totalCpuPercent > 100.0) metrics.totalCpuPercent = 100.0;
                if (metrics.totalCpuPercent < 0.0) metrics.totalCpuPercent = 0.0;
            }
        }
        prevIdleTime_ = idleTime;
        prevKernelTime_ = kernelTime;
        prevUserTime_ = userTime;
        hasPreviousHostTimes_ = true;

        char cpuBuf[32];
        std::snprintf(cpuBuf, sizeof(cpuBuf), "CPU: %.1f%%", metrics.totalCpuPercent);
        metrics.cpuBannerStr = cpuBuf;
    } else {
        metrics.cpuBannerStr = "CPU: N/A";
    }

    return metrics;
}

void SystemMetrics::QueryProcessMetrics(DWORD pid, double& outCpuPercent, ULONG64& outRamBytes) {
    outCpuPercent = 0.0;
    outRamBytes = 0;
    if (pid == 0 || pid == 4) {
        return; // System processes
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return;
    }

    // Working set RAM
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        outRamBytes = pmc.WorkingSetSize;
    }

    // CPU % calculation
    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
        DWORD now = GetTickCount();
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pidCpuHistory_.find(pid);
        if (it != pidCpuHistory_.end()) {
            ULONGLONG prevTotal = FileTimeToUlarge(it->second.ftKernel).QuadPart + FileTimeToUlarge(it->second.ftUser).QuadPart;
            ULONGLONG currTotal = FileTimeToUlarge(ftKernel).QuadPart + FileTimeToUlarge(ftUser).QuadPart;
            DWORD timeDiffMs = now - it->second.tickCount;

            if (timeDiffMs > 0 && currTotal >= prevTotal) {
                ULONGLONG procTimeDelta100ns = currTotal - prevTotal;
                // 1 ms = 10,000 * 100ns
                double procTimeMs = static_cast<double>(procTimeDelta100ns) / 10000.0;
                double cpu = (procTimeMs / (static_cast<double>(timeDiffMs) * static_cast<double>(numProcessors_))) * 100.0;
                if (cpu < 0.0) cpu = 0.0;
                if (cpu > 100.0) cpu = 100.0;
                outCpuPercent = cpu;
            }
            it->second.ftKernel = ftKernel;
            it->second.ftUser = ftUser;
            it->second.tickCount = now;
        } else {
            ProcessTimeSnapshot snap;
            snap.ftKernel = ftKernel;
            snap.ftUser = ftUser;
            snap.tickCount = now;
            pidCpuHistory_[pid] = snap;
        }
    }

    CloseHandle(hProcess);
}

bool SystemMetrics::KillProcess(DWORD pid, DWORD exitCode) {
    if (pid <= 4) return false;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;
    BOOL result = TerminateProcess(hProcess, exitCode);
    CloseHandle(hProcess);
    return (result != 0);
}
