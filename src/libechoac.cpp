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

#include "libechoac.h"
#include "echoac.h"

#define ECHOAC_API_IMPL

namespace libechoac {
    ECHOAC_API_IMPL bool echoac_init() {
        if (!echoac::init())
        {

            return false;
        }

        if (!echoac::driver_impl::driver_init())
        {
            return false;
        }

        return true;
    }

    ECHOAC_API_IMPL void echoac_unload() {
        echoac::unload();
    }

    ECHOAC_API_IMPL bool read_process_memory(
            HANDLE process_id,
            const uint64_t& address,
            void* buffer, const size_t& size
    )
    {
        return echoac::driver_impl::read_process_memory(process_id, address, buffer, size);
    }


    ECHOAC_API_IMPL HANDLE get_handle_for_pid(DWORD pid) {
        return echoac::driver_impl::get_handle_for_pid(pid);
    }
}
