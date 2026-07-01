cmake_minimum_required(VERSION 3.15)
project(portview LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(portview main.cpp resource.rc)

# Link Windows network, IP Helper, and COM/OLE APIs
target_link_libraries(portview PRIVATE iphlpapi ws2_32 ole32 oleaut32)

# Force UAC prompt for administrator privileges on launch (required for TCP EStats traffic monitoring)
if(MSVC)
    target_link_options(portview PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
endif()
