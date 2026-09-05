#pragma once
#include "common.h"

BOOL HijackRemoteThread(
    IN DWORD ProcId, 
    IN PVOID pPayload, 
    OUT PDWORD remoteThreadID
);
