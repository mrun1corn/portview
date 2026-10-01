#ifdef NDEBUG
#undef NDEBUG
#endif
#include "security/firewall_manager.h"
#include <cassert>
#include <iostream>
#include <string>

int main() {
  std::cout << "[TEST] Running Firewall Port Adding & Validation tests..."
            << std::endl;

  // 1. Valid port strings
  assert(FirewallManager::ValidatePortRange("*"));
  assert(FirewallManager::ValidatePortRange("80"));
  assert(FirewallManager::ValidatePortRange("80,443"));
  assert(FirewallManager::ValidatePortRange("8000-8080"));
  assert(FirewallManager::ValidatePortRange("80,443,8080-8090"));
  assert(FirewallManager::ValidatePortRange("1-1024"));
  assert(FirewallManager::ValidatePortRange("65535"));

  // 2. Invalid port strings
  assert(!FirewallManager::ValidatePortRange(""));
  assert(!FirewallManager::ValidatePortRange("0"));
  assert(!FirewallManager::ValidatePortRange("-1"));
  assert(!FirewallManager::ValidatePortRange("65536"));
  assert(!FirewallManager::ValidatePortRange("999999"));
  assert(!FirewallManager::ValidatePortRange("abc"));
  assert(!FirewallManager::ValidatePortRange("80/tcp"));
  assert(!FirewallManager::ValidatePortRange("80-"));
  assert(!FirewallManager::ValidatePortRange("-80"));
  assert(!FirewallManager::ValidatePortRange("80--90"));
  assert(!FirewallManager::ValidatePortRange("500-100")); // Inverted range
  assert(!FirewallManager::ValidatePortRange("1-2000"));  // Range > 1024 ports

  // 3. AddRule input rejection
  assert(!FirewallManager::Instance().AddRule("", true, L"test.exe",
                                              L"C:\\test.exe"));
  assert(!FirewallManager::Instance().AddRule("invalid_port", true, L"test.exe",
                                              L"C:\\test.exe"));
  assert(!FirewallManager::Instance().AddRule("70000", false, L"test.exe",
                                              L"C:\\test.exe"));

  std::cout << "[PASS] Firewall Port Adding & Validation tests passed!"
            << std::endl;
  return 0;
}
