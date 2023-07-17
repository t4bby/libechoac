// MIT License
//
// Copyright (c) 2023 t4bby
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <Windows.h>

//
// needed to prepare binary from memory to disk
//
#include <fstream>
#include <vector>

// This is a wrapper for the vulnerable driver `echo_driver.sys`
namespace libechoac
{

    //
    // initialization of this library
    //
    extern bool echoac_init();

    //
    // uninitialization of this library
    // note: if you did not call this, the driver will remain on your system.
    //
    extern void echoac_unload();

    //
    // read any process memory by specific process id
    // without process handle which granted permission by system
    // privilege level: kernel (ring-0)
    //
    extern bool read_process_memory(
            HANDLE target_process,
            const uint64_t& address,
            void* buffer, const size_t& size
    );

    //
    // template definition of reading user memory above
    //
    template<class T> T read_process_memory(
            HANDLE target_process, const uint64_t& address
    )
    {
        T buffer;
        read_process_memory(target_process, address, &buffer, sizeof(T));
        return buffer;
    }


    //
    // read any process handle
    // privilege level: kernel (ring-0)
    //
    extern HANDLE get_handle_for_pid(DWORD pid);

}