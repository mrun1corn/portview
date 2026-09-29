#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <string>
#include "data_models.h"

// RAII Wrapper for Winsock initialization
class ScopedWinsock {
public:
    ScopedWinsock();
    ~ScopedWinsock();
    bool IsInitialized() const { return initialized_; }

    ScopedWinsock(const ScopedWinsock&) = delete;
    ScopedWinsock& operator=(const ScopedWinsock&) = delete;

private:
    bool initialized_ = false;
};

// RAII Wrapper for COM initialization
class ScopedCom {
public:
    explicit ScopedCom(DWORD coInit = COINIT_APARTMENTTHREADED);
    ~ScopedCom();
    HRESULT Result() const { return hr_; }

    ScopedCom(const ScopedCom&) = delete;
    ScopedCom& operator=(const ScopedCom&) = delete;

private:
    HRESULT hr_ = E_FAIL;
};

// String formatting and network conversion utilities
std::string TcpStateToString(DWORD state);
std::string IpToString(DWORD ipAddress);
std::string FormatBytes(ULONG64 bytes);
std::string FormatSpeed(double bytesPerSec);
std::string WStringToString(const std::wstring& wstr);
bool IsElevated();
