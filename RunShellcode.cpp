// InjectShellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#define BUFFERSIZE 1024

void display_error(LPTSTR lpszFunction)
{
    LPVOID lp_message_buffer;
    LPVOID lp_display_buffer;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lp_message_buffer,
        0,
        NULL);

    lp_display_buffer =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lp_message_buffer)
            + lstrlen((LPCTSTR)lpszFunction)
            + 40) // account for format string
            * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lp_display_buffer,
        LocalSize(lp_display_buffer) / sizeof(TCHAR),
        TEXT("%s failed with error code %d as follows:\n%s"),
        lpszFunction,
        dw,
        lp_message_buffer)))
    {
        printf("FATAL ERROR: Unable to output error code.\n");
    }

    _tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lp_display_buffer);

    LocalFree(lp_message_buffer);
    LocalFree(lp_display_buffer);
}

int wmain(int argc, WCHAR *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <shellcode file>", argv[0]);
        exit(0);
    }

    printf("Opening %S\n", argv[1]);
    HANDLE file_handle = CreateFile(
        argv[1],               // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);                 // no attr. template

    if (file_handle == INVALID_HANDLE_VALUE)
    {
        display_error(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file \"%s\" for read.\n"), argv[1]);
        return -1;
    }

    LARGE_INTEGER file_size;
    GetFileSizeEx(file_handle, &file_size);

    DWORD shellcodeSize = file_size.LowPart;

    BYTE *p_shellcode_buffer = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

    if (!p_shellcode_buffer)
    {
        printf("Failed to allocate %d\n", shellcodeSize);
        return -1;
    }

    printf("Allocated %d bytes at @%p\n", shellcodeSize, p_shellcode_buffer);

    DWORD read_bytes;
    DWORD offset = 0;
    char ReadBuffer[BUFFERSIZE] = { 0 };
    while (ReadFile(file_handle, ReadBuffer, BUFFERSIZE - 1, &read_bytes, NULL) == TRUE && read_bytes>0)
    {
        memcpy(p_shellcode_buffer + offset, reinterpret_cast<BYTE*>(ReadBuffer), read_bytes);
        offset += read_bytes;
    }

    printf("Read %d bytes\n", offset);
    int(*shellcode_ptr)() = (int(__cdecl *)(void))p_shellcode_buffer;

    printf("Calling function pointer: %p\n", shellcode_ptr);

    _asm {
        int 3;
    }
    shellcode_ptr();
    return 0;
}
