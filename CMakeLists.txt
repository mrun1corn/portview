cmake_minimum_required(VERSION 3.15)
project(portview LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(portview main.cpp)

# Link Windows network and IP Helper APIs
target_link_libraries(portview PRIVATE iphlpapi ws2_32)
