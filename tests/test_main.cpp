#ifdef NDEBUG
#undef NDEBUG
#endif
#include "core/system_metrics.h"
#include "core/utils.h"
#include "security/firewall_manager.h"
#include <cassert>
#include <iostream>
#include <string>
#include <windows.h>

void TestPortAdding() {
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
}

void TestRuleDeletion() {
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
}

void TestKillProcess() {
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
}

void TestStringUtils() {
  std::cout << "[TEST] Running String and Network Conversion tests..."
            << std::endl;

  // String to WString roundtrip
  std::string ascii = "Hello, PortView!";
  std::wstring wAscii = StringToWString(ascii);
  assert(WStringToString(wAscii) == ascii);

  std::wstring wUni = L"PortView \u2764\ufe0f";
  std::string sUni = WStringToString(wUni);
  assert(StringToWString(sUni) == wUni);

  assert(StringToWString("").empty());
  assert(WStringToString(L"").empty());

  // FormatBytes tests
  assert(FormatBytes(0) == "0 B");
  assert(FormatBytes(500) == "500 B");
  assert(FormatBytes(1024).find("KB") != std::string::npos);

  // FormatSpeed tests
  assert(FormatSpeed(0.0) == "0 B/s");
  assert(FormatSpeed(2048.0).find("KB/s") != std::string::npos);

  // IpToString tests
  assert(IpToString(0x0100007f) == "127.0.0.1");

  std::cout << "[PASS] String and Network Conversion tests passed!"
            << std::endl;
}

int main(int argc, char *argv[]) {
  std::string suite = (argc > 1) ? argv[1] : "--all";
  std::string suiteTitle = "All Suites";
  if (suite == "--port-add")
    suiteTitle = "Port Adding";
  else if (suite == "--delete")
    suiteTitle = "Rule Deletion";
  else if (suite == "--kill")
    suiteTitle = "Process Termination";
  else if (suite == "--utils")
    suiteTitle = "String & Network Utils";

  std::cout << "========================================" << std::endl;
  std::cout << " Running PortView Test Suite: " << suiteTitle << std::endl;
  std::cout << "========================================" << std::endl;

  if (suite == "--port-add") {
    TestPortAdding();
    std::cout << "\n[PASS] Port adding tests passed successfully!\n";
  } else if (suite == "--delete") {
    TestRuleDeletion();
    std::cout << "\n[PASS] Rule deletion tests passed successfully!\n";
  } else if (suite == "--kill") {
    TestKillProcess();
    std::cout << "\n[PASS] Kill process tests passed successfully!\n";
  } else if (suite == "--utils") {
    TestStringUtils();
    std::cout << "\n[PASS] String utils tests passed successfully!\n";
  } else {
    TestPortAdding();
    TestRuleDeletion();
    TestKillProcess();
    TestStringUtils();
    std::cout << "\n[PASS] All test checks passed successfully!\n";
  }

  return 0;
}
