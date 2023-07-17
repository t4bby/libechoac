cmake_minimum_required(VERSION 3.25)
project(libechoac)

set(CMAKE_CXX_STANDARD 17)

add_library(libechoac src/file_utils.cpp src/service_utils.cpp src/service_utils.cpp src/win_utils.cpp src/echoac.cpp src/libechoac.cpp)
target_include_directories(libechoac PUBLIC src)

add_executable(echoactest tests/main.cpp)
target_link_libraries(echoactest PUBLIC libechoac)
