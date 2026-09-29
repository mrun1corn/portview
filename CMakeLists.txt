cmake_minimum_required(VERSION 3.15)
project(portview VERSION 1.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Manifest configuration: asInvoker with graceful unprivileged fallback
if(MSVC)
    target_link_options(portview PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
endif()
