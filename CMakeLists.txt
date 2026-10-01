cmake_minimum_required(VERSION 3.15)
project(portview VERSION 1.6.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure static MSVC C++ runtime library (/MT, /MTd)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ------------------------------------------------------------------------------
# Core Static Library (Modular Monolith Domain Code)
# ------------------------------------------------------------------------------
add_library(portview_core STATIC
    src/core/utils.cpp
    src/core/system_metrics.cpp
    src/network/process_resolver.cpp
    src/network/network_scanner.cpp
    src/security/firewall_manager.cpp
    src/ui/terminal_screen.cpp
    src/ui/search_filter.cpp
    src/ui/components.cpp
    src/ui/app_controller.cpp
)

target_include_directories(portview_core PUBLIC include)

# Link Windows network, IP Helper, COM/OLE, and PSAPI
target_link_libraries(portview_core PUBLIC iphlpapi ws2_32 ole32 oleaut32 psapi advapi32)

if(MSVC)
    target_compile_options(portview_core PRIVATE /W4 /WX /sdl /permissive-)
endif()

# ------------------------------------------------------------------------------
# Main Application Executable
# ------------------------------------------------------------------------------
add_executable(portview 
    src/main.cpp 
    resources/resource.rc
)

target_link_libraries(portview PRIVATE portview_core)

if(MSVC)
    target_compile_options(portview PRIVATE /W4 /WX /sdl /permissive-)
    target_link_options(portview PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
endif()

# ------------------------------------------------------------------------------
# Automated Test Suites (CTest)
# ------------------------------------------------------------------------------
option(PORTVIEW_BUILD_TESTS "Build portview test suite" ON)
if(PORTVIEW_BUILD_TESTS)
    enable_testing()

    macro(add_portview_test test_name test_source)
        add_executable(${test_name} ${test_source})
        target_link_libraries(${test_name} PRIVATE portview_core)
        if(MSVC)
            target_compile_options(${test_name} PRIVATE /W4 /WX /sdl /permissive-)
        endif()
        add_test(NAME ${test_name} COMMAND ${test_name})
    endmacro()

    add_portview_test(test_port_adding tests/test_port_adding.cpp)
    add_portview_test(test_rule_deletion tests/test_rule_deletion.cpp)
    add_portview_test(test_kill_process tests/test_kill_process.cpp)
    add_portview_test(test_string_utils tests/test_string_utils.cpp)
endif()
