#include "../include/crypto.h"
// HellShell was used here, credits to MalDev Academy

BOOL AesBCryptDecrypt(IN PBYTE pCipherText, IN DWORD dwCipherSize, IN PBYTE pKey, IN PBYTE pIv, OUT PBYTE* ppPlainText, OUT PDWORD pdwPlainSize)
{
    NTSTATUS            ntStatus = 0x00;
    BCRYPT_ALG_HANDLE   hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE   hKeyHandle = NULL;
    ULONG               cbResult = 0x00;
    ULONG               cbKeyObject = 0x00;
    PBYTE               pbKeyObject = NULL;
    PBYTE               pbPlainText = NULL;
    ULONG               cbPlainText = 0x00;
    BYTE                pIvCopy[AES_IV_SIZE] = { 0 };
    BOOL                bResult = FALSE;

    if (!pCipherText || !dwCipherSize || !pKey || !pIv || !ppPlainText || !pdwPlainSize)
        goto _END_OF_FUNC;

    memcpy(pIvCopy, pIv, AES_IV_SIZE);

    if (!BCRYPT_SUCCESS(ntStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X \n", ntStatus);
        goto _END_OF_FUNC;
    }

    if (!BCRYPT_SUCCESS(ntStatus = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0)))
    {
        printf("[!] BCryptGetProperty Failed With Error: 0x%08X \n", ntStatus);
        goto _END_OF_FUNC;
    }

    if (!(pbKeyObject = (PBYTE)LocalAlloc(LPTR, cbKeyObject)))
        goto _END_OF_FUNC;

    if (!BCRYPT_SUCCESS(ntStatus = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        printf("[!] BCryptSetProperty Failed With Error: 0x%08X \n", ntStatus);
        goto _END_OF_FUNC;
    }

    if (!BCRYPT_SUCCESS(ntStatus = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pKey, AES_KEY_SIZE, 0)))
    {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%08X \n", ntStatus);
        goto _END_OF_FUNC;
    }

    if (!BCRYPT_SUCCESS(ntStatus = BCryptDecrypt(hKeyHandle, pCipherText, (ULONG)dwCipherSize, NULL, pIvCopy, AES_IV_SIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING)))
    {
        printf("[!] BCryptDecrypt[%d] Failed With Error: 0x%08X \n", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    if (!(pbPlainText = (PBYTE)LocalAlloc(LPTR, cbPlainText)))
        goto _END_OF_FUNC;

    if (!BCRYPT_SUCCESS(ntStatus = BCryptDecrypt(hKeyHandle, pCipherText, (ULONG)dwCipherSize, NULL, pIvCopy, AES_IV_SIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING)))
    {
        printf("[!] BCryptDecrypt[%d] Failed With Error: 0x%08X \n", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    *ppPlainText = pbPlainText;
    *pdwPlainSize = (DWORD)cbResult;
    bResult = TRUE;

_END_OF_FUNC:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        LocalFree(pbKeyObject);
    if (pbPlainText && !bResult)
        LocalFree(pbPlainText);
    return bResult;
}
