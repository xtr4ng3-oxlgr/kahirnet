cmake_minimum_required(VERSION 3.16)

project(kahirnet
    VERSION 1.0.0
    DESCRIPTION "Authorized local network reconnaissance"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(kahirnet
    src/main.cpp
    src/net.cpp
    src/services.cpp
    src/scanner.cpp
    src/report.cpp)

target_include_directories(kahirnet PRIVATE include)

find_package(Threads REQUIRED)
target_link_libraries(kahirnet PRIVATE Threads::Threads)

if(WIN32)
    target_link_libraries(kahirnet PRIVATE ws2_32)
endif()

if(MSVC)
    target_compile_options(kahirnet PRIVATE /W4 /permissive- /guard:cf)
    target_link_options(kahirnet PRIVATE /DYNAMICBASE /NXCOMPAT /guard:cf)
else()
    target_compile_options(kahirnet PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()

install(TARGETS kahirnet RUNTIME DESTINATION bin)
