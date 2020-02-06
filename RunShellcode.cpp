// InjectShellcode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#define BUFFERSIZE 1024

void DisplayError(LPTSTR lpszFunction)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf)
            + lstrlen((LPCTSTR)lpszFunction)
            + 40) // account for format string
            * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error code %d as follows:\n%s"),
        lpszFunction,
        dw,
        lpMsgBuf)))
    {
        printf("FATAL ERROR: Unable to output error code.\n");
    }

    _tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

int wmain(int argc, WCHAR *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <shellcode file>", argv[0]);
        exit(0);
    }

    printf("Opening %S\n", argv[1]);
    HANDLE hFile = CreateFile(argv[1],               // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);                 // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DisplayError(TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file \"%s\" for read.\n"), argv[1]);
        return -1;
    }

    LARGE_INTEGER FileSize;
    GetFileSizeEx(hFile, &FileSize);

    DWORD shellcodeSize = FileSize.LowPart;

    BYTE *pRWX = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

    if (!pRWX)
    {
        printf("Failed to allocate %d\n", shellcodeSize);
        return -1;
    }

    printf("Allocated %d bytes at @%p\n", shellcodeSize, pRWX);

    DWORD readBytes;
    DWORD Offset = 0;
    char ReadBuffer[BUFFERSIZE] = { 0 };
    while (ReadFile(hFile, ReadBuffer, BUFFERSIZE - 1, &readBytes, NULL) == TRUE && readBytes>0)
    {
        printf("Read %d bytes\n", readBytes);
        memcpy(pRWX + Offset, reinterpret_cast<BYTE*>(ReadBuffer), readBytes);
        Offset += readBytes;
    }

    int(*fn)() = (int(__cdecl *)(void))pRWX;

    printf("Calling function pointer: %p\n", fn);

    _asm {
        int 3;
    }
    fn();
    return 0;
}
