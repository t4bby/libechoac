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

#include "service_utils.h"

//
// open service control manager to operate services
//
SC_HANDLE service_utils::open_sc_manager()
{
    return OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
}

//
// create a new service
// sc create myservice binPath="" type=kernel
//
SC_HANDLE service_utils::create_service(const std::string_view driver_path)
{
    SC_HANDLE sc_manager_handle = open_sc_manager();

    CHECK_SC_MANAGER_HANDLE(sc_manager_handle, (SC_HANDLE)INVALID_HANDLE_VALUE);

    SC_HANDLE echoac_service_handle = CreateService(
            sc_manager_handle,
            ECHOAC_SERVICE_NAME,
            ECHOAC_DISPLAY_NAME,
            SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
            driver_path.data(), nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!CHECK_HANDLE(echoac_service_handle))
    {
        const auto last_error = GetLastError();

        if (last_error == ERROR_SERVICE_EXISTS ||
            last_error == ERROR_SERVICE_MARKED_FOR_DELETE ||
            last_error == ERROR_SERVICE_ALREADY_RUNNING)
        {
            echoac_service_handle = OpenService(
                    sc_manager_handle,
                    ECHOAC_SERVICE_NAME,
                    SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS
            );

            if (!CHECK_HANDLE(echoac_service_handle))
            {
                CloseServiceHandle(sc_manager_handle);
                return (SC_HANDLE)(INVALID_HANDLE_VALUE);
            }

            SERVICE_STATUS status;

            if (!QueryServiceStatus(echoac_service_handle, &status))
            {
                CloseServiceHandle(sc_manager_handle);
                CloseServiceHandle(echoac_service_handle);
                return (SC_HANDLE)(INVALID_HANDLE_VALUE);
            }

            if (status.dwCurrentState == SERVICE_STOPPED)
            {
                if (!start_service(echoac_service_handle))
                {
                    CloseServiceHandle(sc_manager_handle);
                    CloseServiceHandle(echoac_service_handle);
                    return (SC_HANDLE)(INVALID_HANDLE_VALUE);
                }
            }
            else if (status.dwCurrentState != SERVICE_RUNNING)
            {
                CloseServiceHandle(sc_manager_handle);
                CloseServiceHandle(echoac_service_handle);
                return (SC_HANDLE)(INVALID_HANDLE_VALUE);
            }

            CloseServiceHandle(sc_manager_handle);
            return echoac_service_handle;
        }

        //
        // failed to obtain handle
        //
        CloseServiceHandle(sc_manager_handle);
        return (SC_HANDLE)(INVALID_HANDLE_VALUE);
    }

    CloseServiceHandle(sc_manager_handle);
    return echoac_service_handle;
}

//
// delete the service
// sc delete myservice
//
bool service_utils::delete_service(
        SC_HANDLE service_handle, bool close_on_fail, bool close_on_success
)
{
    SC_HANDLE sc_manager_handle = open_sc_manager();

    CHECK_SC_MANAGER_HANDLE(sc_manager_handle, false);

    if (!DeleteService(service_handle))
    {
        const auto last_error = GetLastError();

        if (last_error == ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            CloseServiceHandle(sc_manager_handle);
            return true;
        }

        CloseServiceHandle(sc_manager_handle);
        if (close_on_fail) CloseServiceHandle(service_handle);
        return false;
    }

    CloseServiceHandle(sc_manager_handle);
    if (close_on_success) CloseServiceHandle(service_handle);

    return true;
}

//
// start the service
// sc start myservice
//
bool service_utils::start_service(SC_HANDLE service_handle)
{
    return StartService(service_handle, 0, nullptr);
}

//
// stop the service
// sc stop myservice
//
bool service_utils::stop_service(SC_HANDLE service_handle)
{
    SC_HANDLE sc_manager_handle = open_sc_manager();

    CHECK_SC_MANAGER_HANDLE(sc_manager_handle, false);

    SERVICE_STATUS service_status;

    if (!ControlService(service_handle, SERVICE_CONTROL_STOP, &service_status))
    {
        CloseServiceHandle(sc_manager_handle);
        return false;
    }

    CloseServiceHandle(sc_manager_handle);

    return true;
}