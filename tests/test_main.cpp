#include <iostream>
#include <cassert>
#include <string>
#include "core/utils.h"
#include "security/firewall_manager.h"

void TestPortValidation() {
    std::cout << "[TEST] Running Firewall Port Validation tests..." << std::endl;

    // Valid inputs
    assert(FirewallManager::ValidatePortRange("*"));
    assert(FirewallManager::ValidatePortRange("80"));
    assert(FirewallManager::ValidatePortRange("80,443"));
    assert(FirewallManager::ValidatePortRange("8000-8080"));
    assert(FirewallManager::ValidatePortRange("80,443,8080-8090"));
    assert(FirewallManager::ValidatePortRange("1-1024"));
    assert(FirewallManager::ValidatePortRange("65535"));

    // Invalid inputs
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

    std::cout << "[PASS] Firewall Port Validation tests passed!" << std::endl;
}

void TestStringUtils() {
    std::cout << "[TEST] Running String and Unicode conversion tests..." << std::endl;

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

    std::cout << "[PASS] String and Unicode conversion tests passed!" << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " Running PortView Automated Test Suite " << std::endl;
    std::cout << "========================================" << std::endl;

    TestPortValidation();
    TestStringUtils();

    std::cout << "\nAll test suites passed successfully!\n";
    return 0;
}
