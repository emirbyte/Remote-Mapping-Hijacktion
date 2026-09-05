#pragma once
#include "common.h"

BOOL CreateRemoteMapping(
    IN DWORD ProcId, 
    IN PBYTE pPayload, 
    IN SIZE_T payloadSize, 
    OUT PVOID* remoteMapPTR
);
