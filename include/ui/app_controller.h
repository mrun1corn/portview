#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

class AppController {
public:
    static AppController& Instance();

    void RunInteractive();
    void PrintStatic();
};

inline void RunInteractiveLoop() {
    AppController::Instance().RunInteractive();
}

inline void PrintStaticOutput() {
    AppController::Instance().PrintStatic();
}
