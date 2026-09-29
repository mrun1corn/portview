#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <vector>
#include "data_models.h"
#include "utils.h"

namespace Terminal {
    bool IsStdoutTerminal();
    void GetConsoleSize(int& width, int& height);
    void ShowConsoleCursor(bool showFlag);
    void SetCursorPosition(int x, int y);
    void PauseIfSpawnedConsole();
    bool EnableVirtualTerminalProcessing();
}

// Inline forwarders for backward compatibility
inline bool IsStdoutTerminal() { return Terminal::IsStdoutTerminal(); }
inline void GetConsoleSize(int& width, int& height) { Terminal::GetConsoleSize(width, height); }
inline void ShowConsoleCursor(bool showFlag) { Terminal::ShowConsoleCursor(showFlag); }
inline void SetCursorPosition(int x, int y) { Terminal::SetCursorPosition(x, y); }
inline void PauseIfSpawnedConsole() { Terminal::PauseIfSpawnedConsole(); }
inline bool EnableVirtualTerminalProcessing() { return Terminal::EnableVirtualTerminalProcessing(); }

void PrintSummaryRow(const ProcessSummaryRow& row, bool selected, int width);
void PrintDetailRow(const ConnectionRow& row, bool selected, int width);
void PrintStaticOutput();
void RunInteractiveLoop();
