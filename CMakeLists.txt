cmake_minimum_required(VERSION 3.15)
project(portview VERSION 1.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure static MSVC C++ runtime library (/MT, /MTd)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(portview 
    src/main.cpp 
    src/core/utils.cpp
    src/core/system_metrics.cpp
    src/network/process_resolver.cpp
    src/network/network_scanner.cpp
    src/security/firewall_manager.cpp
    src/ui/terminal_screen.cpp
    src/ui/search_filter.cpp
    src/ui/components.cpp
    src/ui/app_controller.cpp
    resource.rc
)

target_include_directories(portview PRIVATE include)

# Link Windows network, IP Helper, COM/OLE, and PSAPI
target_link_libraries(portview PRIVATE iphlpapi ws2_32 ole32 oleaut32 psapi)

# Strict warnings and security flags for MSVC
if(MSVC)
    target_compile_options(portview PRIVATE /W4 /WX /sdl /permissive-)
    target_link_options(portview PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
endif()

# Automated test suite
option(PORTVIEW_BUILD_TESTS "Build portview test suite" ON)
if(PORTVIEW_BUILD_TESTS)
    enable_testing()
    add_executable(portview_tests
        tests/test_main.cpp
        src/core/utils.cpp
        src/security/firewall_manager.cpp
    )
    target_include_directories(portview_tests PRIVATE include)
    target_link_libraries(portview_tests PRIVATE iphlpapi ws2_32 ole32 oleaut32)
    if(MSVC)
        target_compile_options(portview_tests PRIVATE /W4 /WX /sdl /permissive-)
    endif()
    add_test(NAME portview_tests COMMAND portview_tests)
endif()
