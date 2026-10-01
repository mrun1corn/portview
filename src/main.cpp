#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "core/utils.h"
#include "ui/app_controller.h"
#include "ui/terminal_screen.h"

#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
  bool staticMode = false;

  // Command-line argument parsing
  if (argc > 1) {
    std::string arg = argv[1];
    if (arg == "-h" || arg == "--help") {
      std::cout << "portview v1.6 — Windows Port & Traffic Reviewer\n\n"
                << "Usage: portview.exe [options]\n\n"
                << "Options:\n"
                << "  -h, --help     Show this help message\n"
                << "  -v, --version  Show version information\n"
                << "  -s, --static   Print a single snapshot and exit "
                   "(non-interactive)\n\n"
                << "Note: Run as administrator to see per-connection traffic "
                   "stats.\n";
      return 0;
    } else if (arg == "-v" || arg == "--version") {
      std::cout << "portview v1.6\n";
      return 0;
    } else if (arg == "-s" || arg == "--static") {
      staticMode = true;
    }
  }

  // Default to static snapshot mode if redirected or piped
  if (!Terminal::IsStdoutTerminal()) {
    staticMode = true;
  }

  // RAII subsystem initialization
  ScopedCom comGuard(COINIT_APARTMENTTHREADED);
  ScopedWinsock winsockGuard;
  if (!winsockGuard.IsInitialized()) {
    return 1;
  }

  // Enable SeDebugPrivilege if running elevated to allow full process
  // inspection & termination
  EnableDebugPrivilege();

  if (!staticMode) {
    Terminal::EnableVirtualTerminalProcessing();
    RunInteractiveLoop();
    Terminal::PauseIfSpawnedConsole();
  } else {
    PrintStaticOutput();
    Terminal::PauseIfSpawnedConsole();
  }

  return 0;
}
