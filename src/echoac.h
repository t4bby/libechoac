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
#include <fstream>
#include <filesystem>

#include "raw_driver.h"
#include "file_utils.h"
#include "service_utils.h"
#include "libechoac.h"

#define ECHOAC_SERVICE_NAME "echo_driver"
#define ECHOAC_DISPLAY_NAME "echo_driver"
#define ECHOAC_SYSFILE_NAME "echo_driver.sys"
#define ECHOAC_SYSMODULE_NAME "echo_driver.sys"

#define ECHOAC_DEVICE_NAME "\\\\.\\EchoDrv"

#define ECHOAC_IOCTL_BUFFER_SIZE 4096
#define ECHOAC_IOCTL_INITIALIZE 0x9e6a0594
#define ECHOAC_IOCTL_PID_HANDLE 0xe6224248
#define ECHOAC_IOCTL_READ_PROCESS_MEMORY 0x60a26124


namespace echoac {

    struct k_param_readmem {
        HANDLE targetProcess;
        void* fromAddress;
        void* toAddress;
        size_t length;
        void* padding;
        uint32_t returnCode;
    };

    struct k_param_init {
        void* first;
        void* second;
        void* third;
    };

    struct k_get_handle {
        DWORD pid;
        ACCESS_MASK access;
        HANDLE handle;
    };

// This is a windows type to fetch NtQuerySystemInformation
// These structures are copied from Process Hacker source code (ntldr.h)
    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

    typedef struct _SYSTEM_HANDLE
    {
        PVOID Object;
        HANDLE UniqueProcessId;
        HANDLE HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE, *PSYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX
    {
        ULONG_PTR HandleCount;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    bool init();
    void unload();

    namespace detail
    {
        inline HANDLE device_handle;
        inline SC_HANDLE echoac_service_handle;
    }

    namespace driver_impl {

        bool request_ioctl(DWORD ioctl_code, LPVOID in_buffer, DWORD in_buffer_size);
        bool driver_init();

        bool read_process_memory(HANDLE target_process,
                                 const uint64_t& address, void* buffer, const size_t& size);

        template<class T> __forceinline T read_kernel_memory(const uint64_t address)
        {
            T buffer;
            read_kernel_memory(address, &buffer, sizeof(T));
            return buffer;
        }

        bool read_process_memory(
                const uint32_t& process_id,
                const uint64_t& address, void* buffer, const size_t& size
        );


        HANDLE get_handle_for_pid(DWORD pid);

    }
}