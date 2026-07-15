#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "utils.h"
#include "process_resolver.h"
#include "firewall.h"

class ProcessSummaryRow;
bool IsStdoutTerminal();
void GetConsoleSize(int& width, int& height);
void ShowConsoleCursor(bool showFlag);
void SetCursorPosition(int x, int y);
void PauseIfSpawnedConsole();
bool EnableVirtualTerminalProcessing();
void PrintSummaryRow(const ProcessSummaryRow& row, bool selected, int width);
void PrintDetailRow(const ConnectionRow& row, bool selected, int width);
void PrintStaticOutput();
void RunInteractiveLoop();
