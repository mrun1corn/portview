#ifdef NDEBUG
#undef NDEBUG
#endif
#include "core/system_metrics.h"
#include "core/utils.h"
#include <cassert>
#include <iostream>
#include <windows.h>

int main() {
  std::cout << "[TEST] Running Process Termination & Privilege tests..."
            << std::endl;

  // 1. Safe execution of privilege request
  EnableDebugPrivilege();

  // 2. PID <= 4 must always fail safely with ERROR_INVALID_PARAMETER
  DWORD err = 0;
  assert(!SystemMetrics::KillProcess(0, &err));
  assert(err == ERROR_INVALID_PARAMETER);

  err = 0;
  assert(!SystemMetrics::KillProcess(4, &err));
  assert(err == ERROR_INVALID_PARAMETER);

  // 3. Non-existent PID must fail safely with an error code reported
  err = 0;
  assert(!SystemMetrics::KillProcess(0xFFFFFFFE, &err));
  assert(err != 0);

  std::cout << "[PASS] Process Termination & Privilege tests passed!"
            << std::endl;
  return 0;
}
