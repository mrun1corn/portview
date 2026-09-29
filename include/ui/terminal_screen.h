#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <string>

namespace Terminal {
    bool IsStdoutTerminal();
    void GetConsoleSize(int& width, int& height);
    void ShowConsoleCursor(bool showFlag);
    void SetCursorPosition(int x, int y);
    void PauseIfSpawnedConsole();
    bool EnableVirtualTerminalProcessing();
    void FlushFrame(const std::string& frame);
}
