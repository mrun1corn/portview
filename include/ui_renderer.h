#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "core/data_models.h"
#include "ui/terminal_screen.h"
#include "ui/components.h"
#include "ui/app_controller.h"

// Forwarding functions for backward compatibility
inline bool IsStdoutTerminal() { return Terminal::IsStdoutTerminal(); }
inline void GetConsoleSize(int& width, int& height) { Terminal::GetConsoleSize(width, height); }
inline void ShowConsoleCursor(bool showFlag) { Terminal::ShowConsoleCursor(showFlag); }
inline void SetCursorPosition(int x, int y) { Terminal::SetCursorPosition(x, y); }
inline void PauseIfSpawnedConsole() { Terminal::PauseIfSpawnedConsole(); }
inline bool EnableVirtualTerminalProcessing() { return Terminal::EnableVirtualTerminalProcessing(); }

inline std::string FormatSummaryRow(const ProcessSummaryRow& row, bool selected, int width) {
    return UiComponents::FormatSummaryRow(row, selected, width);
}

inline std::string FormatDetailRow(const ConnectionRow& row, bool selected, int width) {
    return UiComponents::FormatDetailRow(row, selected, width);
}

inline void PrintSummaryRow(const ProcessSummaryRow& row, bool selected, int width) {
    std::cout << UiComponents::FormatSummaryRow(row, selected, width) << "\n";
}

inline void PrintDetailRow(const ConnectionRow& row, bool selected, int width) {
    std::cout << UiComponents::FormatDetailRow(row, selected, width) << "\n";
}
