#ifdef NDEBUG
#undef NDEBUG
#endif
#include "core/utils.h"
#include <cassert>
#include <iostream>
#include <string>

int main() {
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
  return 0;
}
