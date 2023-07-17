# libechoac
A wrapper for echoac.sys vulnerable driver.

## Features
- [x] Read arbitrary memory
- [x] Get Process Handler

## Requirements
- Windows 10 1903 (x64) or above
- Visual Studio 2022 / CMake IDEs

## Usage
Include `libechoac.h` in your project and link `libechoac.lib` to your project.
```cpp
#include "libechoac.h"
```

Create an instance of `libechoac` and use it.
```cpp
libechoac::libechoac_init()
```

Function calls
```cpp
using namespace libechoac;
read_process_memory(target_process, addr, buf, size); /*or*/ read_process_memory<T>(target_process, addr);
get_process_handler(pid);
```

Unloading
```cpp
libechoac::libechoac_unload()
```

Sample `CMakeLists.txt`
```
cmake_minimum_required(VERSION 3.25)
project(libechoac)

set(CMAKE_CXX_STANDARD 17)

add_library(libechoac src/file_utils.cpp src/service_utils.cpp src/service_utils.cpp src/win_utils.cpp src/echoac.cpp src/libechoac.cpp)
target_include_directories(libechoac PUBLIC src)

add_executable(your_exec main.cpp)
target_link_libraries(your_exec PUBLIC libechoac)
```

## Tests
Tests are located in `tests` directory. You can run them by building `tests` project. It includes a simple code that reads `notepad.exe` from memory using the library.

## References
```
PoC - https://github.com/kite03/echoac-poc
libmhyprot - https://github.com/kkent030315/libmhyprot
``