#include "ui/terminal_screen.h"
#include <iostream>
#include <io.h>
#include <cstdio>

namespace Terminal {

bool IsStdoutTerminal() {
    return _isatty(_fileno(stdout)) != 0;
}

void GetConsoleSize(int& width, int& height) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    } else {
        width = 80;
        height = 25;
    }
}

void ShowConsoleCursor(bool showFlag) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hOut, &cursorInfo);
    cursorInfo.bVisible = showFlag ? TRUE : FALSE;
    SetConsoleCursorInfo(hOut, &cursorInfo);
}

void SetCursorPosition(int x, int y) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        COORD coord = { static_cast<SHORT>(csbi.srWindow.Left + x), static_cast<SHORT>(csbi.srWindow.Top + y) };
        SetConsoleCursorPosition(hOut, coord);
    }
}

void PauseIfSpawnedConsole() {
    DWORD processList[2];
    DWORD count = GetConsoleProcessList(processList, 2);
    if (count == 1) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
}

bool EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return false;
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return false;
    dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    return SetConsoleMode(hOut, dwMode) != 0;
}

void FlushFrame(const std::string& frame) {
    if (!frame.empty()) {
        std::cout.write(frame.data(), frame.size());
        std::cout.flush();
    }
}

} // namespace Terminal
