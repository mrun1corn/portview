#ifdef NDEBUG
#undef NDEBUG
#endif
#include "core/utils.h"
#include "security/firewall_manager.h"
#include <cassert>
#include <iostream>
#include <string>
#include <windows.h>

int main() {
  std::cout << "[TEST] Running Firewall Rule Deletion & Toggle tests..."
            << std::endl;

  // 1. Toggle operations on non-existent or empty rules must fail gracefully
  assert(!FirewallManager::Instance().ToggleRule(L"", false));

  const std::wstring dummyRule = L"PortView_NonExistent_Test_Rule_9999";
  bool toggleResult = FirewallManager::Instance().ToggleRule(dummyRule, false);
  assert(!toggleResult);

  // 2. If running elevated, test live creation and deletion of a test rule
  if (IsElevated()) {
    std::string testRuleName =
        "PortView_Temp_CI_Rule_" + std::to_string(GetCurrentProcessId());
    std::wstring testRuleNameW = StringToWString(testRuleName);
    bool added = FirewallManager::Instance().AddRule(
        "65432", true, L"ci_test.exe", L"", true, testRuleName);
    if (added) {
      bool deleted = FirewallManager::Instance().DeleteRule(testRuleNameW);
      assert(deleted);
      std::cout << "  (Verified live elevated rule creation and deletion)"
                << std::endl;
    }
  }

  std::cout << "[PASS] Firewall Rule Deletion & Toggle tests passed!"
            << std::endl;
  return 0;
}
