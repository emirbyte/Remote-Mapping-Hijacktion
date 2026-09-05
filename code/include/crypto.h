#pragma once
#include "common.h"

BOOL AesBCryptDecrypt(
    IN PBYTE pCipherText, 
    IN DWORD dwCipherSize, 
    IN PBYTE pKey, 
    IN PBYTE pIv, 
    OUT PBYTE* ppPlainText, 
    OUT PDWORD pdwPlainSize
);
